package self_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"slices"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/qlog"
	"github.com/quic-go/quic-go/qlogwriter"
	"github.com/quic-go/quic-go/testutils/events"
	"github.com/quic-go/quic-go/testutils/simnet"

	"github.com/stretchr/testify/require"
)

// pathConditions describes the network path used for a goodput measurement.
// The bottleneck, reordering and loss are only applied in the server-to-client
// direction, which is the direction the bulk data flows in.
type pathConditions struct {
	rtt time.Duration
	// bandwidth is the capacity of the bottleneck, in bytes per second.
	bandwidth int
	// reorderFraction is the fraction of packets that are delayed by reorderDelay.
	reorderFraction float64
	reorderDelay    time.Duration
	// bufferBDP is the depth of the bottleneck queue, in bandwidth delay products.
	// Mobile links buffer deeply: the LTE capture reached 3.2 BDP in flight.
	bufferBDP float64
	// lossRate is the fraction of packets that are dropped at random, on top of the
	// drop-tail losses caused by the bottleneck queue.
	lossRate float64
	// seed selects the impairment pattern. Runs of the same scenario with different
	// seeds see different paths; runs with the same seed see the same one.
	seed uint64
}

func (c pathConditions) String() string {
	s := fmt.Sprintf("rtt=%s,bw=%dMbps,buf=%gBDP", c.rtt, c.bandwidth*8/1_000_000, c.bufferDepth())
	if c.reorderFraction > 0 {
		s += fmt.Sprintf(",reorder=%.0f%%@%s", c.reorderFraction*100, c.reorderDelay)
	}
	if c.lossRate > 0 {
		s += fmt.Sprintf(",loss=%.1f%%", c.lossRate*100)
	}
	return s
}

// bufferDepth is the bottleneck queue depth in bandwidth delay products.
func (c pathConditions) bufferDepth() float64 {
	if c.bufferBDP == 0 {
		return 1
	}
	return c.bufferBDP
}

// bottleneck models a fixed-rate link with a drop-tail queue, holding one bandwidth
// delay product worth of packets. All of its methods must be called from the same
// goroutine, in packet order.
type bottleneck struct {
	bandwidth       int // in bytes per second
	maxQueueingTime time.Duration

	// the time at which everything currently in the queue has been transmitted
	queueEnd time.Time
	// the delay computed by admit, to be consumed by the next call to delay
	queued time.Duration
}

// admit runs the queue admission decision for a packet, and computes the delay it
// will experience. It returns false if the packet is dropped because the queue is full.
func (b *bottleneck) admit(size int) bool {
	now := time.Now()
	if b.queueEnd.Before(now) {
		b.queueEnd = now
	}
	waiting := b.queueEnd.Sub(now)
	if waiting > b.maxQueueingTime {
		return false
	}
	transmission := time.Duration(size) * time.Second / time.Duration(b.bandwidth)
	b.queueEnd = b.queueEnd.Add(transmission)
	b.queued = waiting + transmission
	return true
}

// delay returns the delay computed by the preceding call to admit.
func (b *bottleneck) delay() time.Duration {
	return b.queued
}

// transferResult is the outcome of a single bulk transfer.
type transferResult struct {
	duration time.Duration
	goodput  float64 // in MiB/s, over the whole transfer
	// steadyGoodput covers the second half of the transfer only. The first half is
	// dominated by slow start, which is not what loss detection is being judged on.
	steadyGoodput float64

	// the number of packets the simulated path actually dropped
	droppedPackets int

	// loss detection verdicts, as observed on the sender
	reorderingThresholdLosses int
	timeThresholdLosses       int
	spuriousLosses            int

	// How long after sending a packet the sender declared it lost, for packets that
	// really were lost, as a multiple of the smoothed RTT at the end of the transfer.
	// This is what a wider threshold costs: it is paid on every genuine loss.
	medianDetectionDelay float64
	p90DetectionDelay    float64
	// the number of genuine losses the detection delays were computed from
	genuineLosses int
}

func (r transferResult) String() string {
	detect := "     n/a"
	if r.genuineLosses > 0 {
		detect = fmt.Sprintf("%.2f/%.2f", r.medianDetectionDelay, r.p90DetectionDelay)
	}
	return fmt.Sprintf(
		"%6.2f MiB/s steady (%6.2f overall, %11s)  dropped: %5d  verdicts: %4d reo + %4d time, %4d spurious  detect: %s RTT (n=%d)",
		r.steadyGoodput, r.goodput, r.duration, r.droppedPackets,
		r.reorderingThresholdLosses, r.timeThresholdLosses, r.spuriousLosses,
		detect, r.genuineLosses,
	)
}

// detectionDelays returns, for every packet that was declared lost and not subsequently
// acknowledged, the time between sending it and declaring it lost, in units of the RTT.
func detectionDelays(rec *events.Recorder, rtt time.Duration) (median, p90 float64, n int) {
	sentAt := make(map[protocol.PacketNumber]time.Time)
	for _, ev := range rec.EventsWithTime(qlog.PacketSent{}) {
		if h := ev.Event.(qlog.PacketSent).Header; h.PacketType == qlog.PacketType1RTT {
			sentAt[h.PacketNumber] = ev.Time
		}
	}
	spurious := make(map[protocol.PacketNumber]struct{})
	for _, ev := range rec.Events(qlog.SpuriousLoss{}) {
		spurious[ev.(qlog.SpuriousLoss).PacketNumber] = struct{}{}
	}
	var delays []float64
	for _, ev := range rec.EventsWithTime(qlog.PacketLost{}) {
		h := ev.Event.(qlog.PacketLost).Header
		if h.PacketType != qlog.PacketType1RTT {
			continue
		}
		if _, ok := spurious[h.PacketNumber]; ok {
			continue // not a real loss, so its detection delay is not a cost
		}
		if s, ok := sentAt[h.PacketNumber]; ok {
			delays = append(delays, float64(ev.Time.Sub(s))/float64(rtt))
		}
	}
	if len(delays) == 0 {
		return 0, 0, 0
	}
	slices.Sort(delays)
	return delays[len(delays)/2], delays[min(int(float64(len(delays))*0.9), len(delays)-1)], len(delays)
}

// unlimitedFlowControl makes sure that flow control is never the bottleneck,
// so that the measurement reflects the behavior of loss detection and congestion control.
func unlimitedFlowControl(conf *quic.Config) *quic.Config {
	const window = 64 << 20
	conf.InitialStreamReceiveWindow = window
	conf.MaxStreamReceiveWindow = window
	conf.InitialConnectionReceiveWindow = window
	conf.MaxConnectionReceiveWindow = window
	return conf
}

// runBulkTransfer sends data from a server to a client over a simulated path and
// measures the goodput, as well as the loss detection verdicts made by the sender.
// It must be called inside a synctest bubble, so the duration it reports is virtual time.
func runBulkTransfer(t *testing.T, data []byte, c pathConditions) transferResult {
	t.Helper()

	clientAddr := &net.UDPAddr{IP: net.ParseIP("1.0.0.1"), Port: 9001}
	serverAddr := &net.UDPAddr{IP: net.ParseIP("1.0.0.2"), Port: 9002}

	// The router calls Drop immediately before the destination link calls LatencyFunc,
	// on the same goroutine, so the two callbacks below run in lockstep for every packet.
	// The mutex only guards against the client's own packets racing with the server's.
	var mx sync.Mutex
	// Independent streams, so that changing one impairment does not change the draws the
	// others see. With a shared generator, adding loss would also alter the reordering.
	lossRnd := rand.New(rand.NewPCG(c.seed, 0x1055))
	reorderRnd := rand.New(rand.NewPCG(c.seed, 0x4e04))
	bn := &bottleneck{
		bandwidth:       c.bandwidth,
		maxQueueingTime: time.Duration(c.bufferDepth() * float64(c.rtt)),
	}
	var dropped int

	router := &directionAwareDroppingRouter{
		ClientAddr: clientAddr,
		ServerAddr: serverAddr,
		Drop: func(dir direction, p simnet.Packet) bool {
			if dir != directionToClient {
				return false
			}
			mx.Lock()
			defer mx.Unlock()
			if (c.lossRate > 0 && lossRnd.Float64() < c.lossRate) || !bn.admit(len(p.Data)) {
				dropped++
				return true
			}
			return false
		},
	}

	n := &simnet.Simnet{Router: router}
	// Latency is applied on the receiving endpoint's downlink, so setting LatencyFunc
	// on the client delays packets travelling from the server to the client.
	clientConn := n.NewEndpoint(clientAddr, simnet.NodeBiDiLinkSettings{
		LatencyFunc: func(simnet.Packet) time.Duration {
			mx.Lock()
			defer mx.Unlock()
			d := c.rtt/2 + bn.delay()
			if c.reorderFraction > 0 && reorderRnd.Float64() < c.reorderFraction {
				d += c.reorderDelay
			}
			return d
		},
	})
	serverConn := n.NewEndpoint(serverAddr, simnet.NodeBiDiLinkSettings{Latency: c.rtt / 2})
	require.NoError(t, n.Start())
	defer func() {
		require.NoError(t, clientConn.Close())
		require.NoError(t, serverConn.Close())
		require.NoError(t, n.Close())
	}()

	senderEvents := &events.Recorder{}
	ln, err := quic.Listen(serverConn, getTLSConfig(), getQuicConfig(unlimitedFlowControl(&quic.Config{
		Tracer: func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace {
			return &events.Trace{Recorder: senderEvents}
		},
	})))
	require.NoError(t, err)
	defer ln.Close()

	sconnChan := make(chan *quic.Conn, 1)
	go func() {
		conn, err := ln.Accept(context.Background())
		if err != nil {
			if !errors.Is(err, quic.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
				t.Logf("accept error: %v", err)
			}
			return
		}
		sconnChan <- conn
		str, err := conn.OpenUniStream()
		if err != nil {
			t.Logf("open stream error: %v", err)
			return
		}
		if _, err := str.Write(data); err != nil {
			t.Logf("write error: %v", err)
			return
		}
		str.Close()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), time.Hour)
	defer cancel()
	conn, err := quic.Dial(ctx, clientConn, serverAddr, getTLSClientConfig(), getQuicConfig(unlimitedFlowControl(&quic.Config{})))
	require.NoError(t, err)
	defer conn.CloseWithError(0, "")

	str, err := conn.AcceptUniStream(ctx)
	require.NoError(t, err)

	sconn := <-sconnChan
	defer sconn.CloseWithError(0, "")

	start := time.Now()
	half := make([]byte, len(data)/2)
	_, err = io.ReadFull(str, half)
	require.NoError(t, err)
	midpoint := time.Now()
	rest, err := io.ReadAll(str)
	require.NoError(t, err)
	duration := time.Since(start)
	require.Equal(t, data, append(half, rest...))

	mx.Lock()
	res := transferResult{
		duration:       duration,
		goodput:        float64(len(data)) / duration.Seconds() / (1 << 20),
		steadyGoodput:  float64(len(rest)) / time.Since(midpoint).Seconds() / (1 << 20),
		droppedPackets: dropped,
	}
	mx.Unlock()
	for _, ev := range senderEvents.Events(qlog.PacketLost{}) {
		switch ev.(qlog.PacketLost).Trigger {
		case qlog.PacketLossReorderingThreshold:
			res.reorderingThresholdLosses++
		case qlog.PacketLossTimeThreshold:
			res.timeThresholdLosses++
		}
	}
	res.spuriousLosses = len(senderEvents.Events(qlog.SpuriousLoss{}))
	res.medianDetectionDelay, res.p90DetectionDelay, res.genuineLosses = detectionDelays(senderEvents, conn.ConnectionStats().SmoothedRTT)
	return res
}

const (
	bw20Mbps = 20 * 1_000_000 / 8
	bw35Mbps = 35 * 1_000_000 / 8
	bw50Mbps = 50 * 1_000_000 / 8
)

// reorderingScenarios is the measurement matrix. The first four are calibrated to
// server-side qlogs captured on mobile carrier paths: base RTT 45-61ms, capacity
// 20-70 Mbit/s, buffers deep enough to hold several bandwidth delay products
// (the LTE capture reached 3.2), and packet reordering without packet loss.
// The remainder are controls: a clean path, and paths that lose packets rather
// than reorder them, where loss detection must not become more tolerant.
var reorderingScenarios = []pathConditions{
	// clean controls
	{rtt: 50 * time.Millisecond, bandwidth: bw35Mbps},
	{rtt: 60 * time.Millisecond, bandwidth: bw20Mbps, bufferBDP: 4},

	// 5G NSA: stable RTT, shallow tail, little reordering
	{rtt: 50 * time.Millisecond, bandwidth: bw35Mbps, bufferBDP: 4, reorderFraction: 0.02, reorderDelay: 5 * time.Millisecond},
	// LTE: deep buffer, heavy RTT tail
	{rtt: 60 * time.Millisecond, bandwidth: bw20Mbps, bufferBDP: 8, reorderFraction: 0.05, reorderDelay: 10 * time.Millisecond},
	// the path from #5768: reordering just above and just below the time threshold
	{rtt: 55 * time.Millisecond, bandwidth: bw35Mbps, bufferBDP: 4, reorderFraction: 0.05, reorderDelay: 5 * time.Millisecond},
	{rtt: 55 * time.Millisecond, bandwidth: bw35Mbps, bufferBDP: 4, reorderFraction: 0.05, reorderDelay: 15 * time.Millisecond},
	// high bandwidth delay product, where the packet threshold has the most room to help
	{rtt: 100 * time.Millisecond, bandwidth: bw50Mbps, bufferBDP: 4, reorderFraction: 0.05, reorderDelay: 15 * time.Millisecond},

	// loss controls: detection must not get slower
	{rtt: 50 * time.Millisecond, bandwidth: bw35Mbps, bufferBDP: 4, lossRate: 0.005},
	{rtt: 50 * time.Millisecond, bandwidth: bw35Mbps, bufferBDP: 4, lossRate: 0.02},
	{rtt: 100 * time.Millisecond, bandwidth: bw50Mbps, bufferBDP: 4, lossRate: 0.005},
	// reordering and loss together, the realistic combination
	{rtt: 55 * time.Millisecond, bandwidth: bw35Mbps, bufferBDP: 4, reorderFraction: 0.05, reorderDelay: 15 * time.Millisecond, lossRate: 0.005},
	{rtt: 100 * time.Millisecond, bandwidth: bw50Mbps, bufferBDP: 4, reorderFraction: 0.05, reorderDelay: 15 * time.Millisecond, lossRate: 0.005},
}

// TestGoodputMatrix measures the goodput of a bulk transfer across a matrix of
// path conditions. Since it runs in a synctest bubble, the results are deterministic
// and independent of the speed of the machine it runs on.
func TestGoodputMatrix(t *testing.T) {
	for _, c := range reorderingScenarios {
		t.Run(c.String(), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				res := runBulkTransfer(t, PRDataLong, c)
				t.Log(res)
			})
		})
	}
}
