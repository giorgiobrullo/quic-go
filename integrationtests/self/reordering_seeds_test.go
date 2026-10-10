package self_test

// This file extends the goodput harness in reordering_test.go, for comparing loss
// detection implementations against each other. It only uses APIs that upstream
// quic-go has as well, so that it can be copied unchanged, together with
// reordering_test.go, into the trees being compared. That is why the
// recovery:loss_threshold_updated event is read by its name, via reflection.
//
// It adds two things to TestGoodputMatrix:
//  1. GOODPUT_SCHEDULE=time draws reordering and random loss from a stateless,
//     time-indexed schedule (hash of seed and the 100us slot the packet leaves the
//     bottleneck in), so implementations that send different packets still
//     traverse the identical path. GOODPUT_SCHEDULE=packet keeps the per-packet
//     draws of TestGoodputMatrix (to check that this copy reproduces it).
//  2. Realisation metrics over the steady state (second half of the transfer).

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"os"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/qlog"
	"github.com/quic-go/quic-go/qlogwriter"
	"github.com/quic-go/quic-go/testutils/events"
	"github.com/quic-go/quic-go/testutils/simnet"

	"github.com/stretchr/testify/require"
)

const scheduleSlot = 100 * time.Microsecond

func splitmix64(x uint64) uint64 {
	x += 0x9e3779b97f4a7c15
	x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9
	x = (x ^ (x >> 27)) * 0x94d049bb133111eb
	return x ^ (x >> 31)
}

// slotDraw is a uniform draw in [0,1) that depends only on seed, salt and slot.
func slotDraw(seed, salt uint64, slot int64) float64 {
	h := splitmix64(splitmix64(seed^salt) ^ uint64(slot))
	return float64(h>>11) / (1 << 53)
}

type pktRecord struct {
	depart, arrive time.Time
	queue          time.Duration
	reordered      bool
}

type realisation struct {
	res                    transferResult
	start, mid, end        time.Time
	pkts                   []pktRecord
	queueDrops, randDrops  []time.Time
	sender                 *events.Recorder
	finalSRTT, finalMinRTT time.Duration
	finalLatestRTT         time.Duration
	baseRTT                time.Duration
}

func runBulkTransferRealised(t *testing.T, data []byte, c pathConditions, timeSchedule bool) realisation {
	t.Helper()

	clientAddr := &net.UDPAddr{IP: net.ParseIP("1.0.0.1"), Port: 9001}
	serverAddr := &net.UDPAddr{IP: net.ParseIP("1.0.0.2"), Port: 9002}

	var mx sync.Mutex
	lossRnd := rand.New(rand.NewPCG(c.seed, 0x1055))
	reorderRnd := rand.New(rand.NewPCG(c.seed, 0x4e04))
	bn := &bottleneck{
		bandwidth:       c.bandwidth,
		maxQueueingTime: time.Duration(c.bufferDepth() * float64(c.rtt)),
	}
	var dropped int
	var rl realisation
	rl.baseRTT = c.rtt
	epoch := time.Now()
	slotOf := func(t time.Time) int64 { return int64(t.Sub(epoch) / scheduleSlot) }

	router := &directionAwareDroppingRouter{
		ClientAddr: clientAddr,
		ServerAddr: serverAddr,
		Drop: func(dir direction, p simnet.Packet) bool {
			if dir != directionToClient {
				return false
			}
			mx.Lock()
			defer mx.Unlock()
			if !timeSchedule {
				if c.lossRate > 0 && lossRnd.Float64() < c.lossRate {
					dropped++
					rl.randDrops = append(rl.randDrops, time.Now())
					return true
				}
				if !bn.admit(len(p.Data)) {
					dropped++
					rl.queueDrops = append(rl.queueDrops, time.Now())
					return true
				}
				return false
			}
			// time schedule: the packet occupies the link, and is lost on it if the
			// slot it leaves the bottleneck in is a loss slot
			if !bn.admit(len(p.Data)) {
				dropped++
				rl.queueDrops = append(rl.queueDrops, time.Now())
				return true
			}
			if c.lossRate > 0 && slotDraw(c.seed, 0x1055, slotOf(time.Now().Add(bn.delay()))) < c.lossRate {
				dropped++
				rl.randDrops = append(rl.randDrops, time.Now())
				return true
			}
			return false
		},
	}

	n := &simnet.Simnet{Router: router}
	clientConn := n.NewEndpoint(clientAddr, simnet.NodeBiDiLinkSettings{
		LatencyFunc: func(simnet.Packet) time.Duration {
			mx.Lock()
			defer mx.Unlock()
			now := time.Now()
			q := bn.delay()
			d := c.rtt/2 + q
			var reo bool
			if c.reorderFraction > 0 {
				if timeSchedule {
					reo = slotDraw(c.seed, 0x4e04, slotOf(now.Add(q))) < c.reorderFraction
				} else {
					reo = reorderRnd.Float64() < c.reorderFraction
				}
			}
			if reo {
				d += c.reorderDelay
			}
			rl.pkts = append(rl.pkts, pktRecord{depart: now.Add(q), arrive: now.Add(d), queue: q, reordered: reo})
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
	end := time.Now()
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
	stats := sconn.ConnectionStats()
	res.medianDetectionDelay, res.p90DetectionDelay, res.genuineLosses = detectionDelays(senderEvents, conn.ConnectionStats().SmoothedRTT)

	mx.Lock()
	defer mx.Unlock()
	rl.res = res
	rl.start, rl.mid, rl.end = start, midpoint, end
	rl.sender = senderEvents
	rl.finalSRTT, rl.finalMinRTT, rl.finalLatestRTT = stats.SmoothedRTT, stats.MinRTT, stats.LatestRTT
	rl.pkts = slices.Clone(rl.pkts)
	return rl
}

func pct(xs []float64, p float64) float64 {
	if len(xs) == 0 {
		return -1
	}
	s := slices.Clone(xs)
	slices.Sort(s)
	return s[min(int(float64(len(s))*p), len(s)-1)]
}

func ms(d time.Duration) float64 { return float64(d) / float64(time.Millisecond) }

// episodes counts groups of timestamps separated by more than gap.
func episodes(ts []time.Time, from time.Time, gap time.Duration) (n, inWin int) {
	var last time.Time
	for _, t := range ts {
		if t.Before(from) {
			continue
		}
		inWin++
		if last.IsZero() || t.Sub(last) > gap {
			n++
		}
		last = t
	}
	return n, inWin
}

func (rl realisation) fields() string {
	var b strings.Builder
	kv := func(k string, v any) {
		switch x := v.(type) {
		case float64:
			fmt.Fprintf(&b, " %s=%.4g", k, x)
		default:
			fmt.Fprintf(&b, " %s=%v", k, x)
		}
	}
	r := rl.res
	steadyDur := rl.end.Sub(rl.mid).Seconds()
	kv("steady", r.steadyGoodput)
	kv("overall", r.goodput)
	kv("dur_s", r.duration.Seconds())
	kv("steady_s", steadyDur)
	kv("dropped", r.droppedPackets)
	kv("reo", r.reorderingThresholdLosses)
	kv("time", r.timeThresholdLosses)
	kv("spur", r.spuriousLosses)
	kv("genuine", r.genuineLosses)
	kv("det_p50", r.medianDetectionDelay)
	kv("det_p90", r.p90DetectionDelay)

	// sender side, steady state
	var sReo, sTime, sSpur, recov int
	var firstSpur time.Time
	var spurPkt, spurTimeMs []float64
	var thrUpdates int
	// -1 if the thresholds were never updated (a packet threshold of 0 means disabled)
	lastPT := int64(-1)
	lastTT := -1.0
	var cur qlog.MetricsUpdated
	var cwnd, bif, pif, lat, srtt []float64
	nextSample := rl.mid
	var spurAtLatestRatio []float64
	for _, ev := range rl.sender.EventsWithTime() {
		inSteady := !ev.Time.Before(rl.mid)
		for inSteady && !nextSample.After(ev.Time) && nextSample.Before(rl.end) {
			if cur.CongestionWindow > 0 {
				cwnd = append(cwnd, float64(cur.CongestionWindow)/1024)
				bif = append(bif, float64(cur.BytesInFlight)/1024)
				pif = append(pif, float64(cur.PacketsInFlight))
				lat = append(lat, ms(cur.LatestRTT))
				srtt = append(srtt, ms(cur.SmoothedRTT))
			}
			nextSample = nextSample.Add(10 * time.Millisecond)
		}
		switch e := ev.Event.(type) {
		case qlog.MetricsUpdated:
			if e.MinRTT != 0 {
				cur.MinRTT = e.MinRTT
			}
			if e.SmoothedRTT != 0 {
				cur.SmoothedRTT = e.SmoothedRTT
			}
			if e.LatestRTT != 0 {
				cur.LatestRTT = e.LatestRTT
			}
			if e.CongestionWindow != 0 {
				cur.CongestionWindow = e.CongestionWindow
			}
			if e.BytesInFlight != 0 {
				cur.BytesInFlight = e.BytesInFlight
			}
			if e.PacketsInFlight != 0 {
				cur.PacketsInFlight = e.PacketsInFlight
			}
		case qlog.PacketLost:
			if inSteady {
				switch e.Trigger {
				case qlog.PacketLossReorderingThreshold:
					sReo++
				case qlog.PacketLossTimeThreshold:
					sTime++
				}
			}
		case qlog.SpuriousLoss:
			if firstSpur.IsZero() {
				firstSpur = ev.Time
			}
			if inSteady {
				sSpur++
			}
			spurPkt = append(spurPkt, float64(e.PacketReordering))
			spurTimeMs = append(spurTimeMs, ms(e.TimeReordering))
			if cur.MinRTT > 0 {
				spurAtLatestRatio = append(spurAtLatestRatio, float64(e.TimeReordering)/float64(cur.MinRTT))
			}
		case qlog.CongestionStateUpdated:
			if inSteady && e.State == qlog.CongestionStateRecovery {
				recov++
			}
		default:
			if ev.Event.Name() == "recovery:loss_threshold_updated" {
				v := reflect.ValueOf(ev.Event)
				thrUpdates++
				lastPT = int64(v.FieldByName("PacketThreshold").Uint())
				lastTT = v.FieldByName("TimeThreshold").Float()
			}
		}
	}
	kv("s_reo", sReo)
	kv("s_time", sTime)
	kv("s_spur", sSpur)
	kv("s_recov", recov)
	kv("s_recov_per_s", float64(recov)/steadyDur)
	if firstSpur.IsZero() {
		kv("first_spur_s", -1.0)
	} else {
		kv("first_spur_s", firstSpur.Sub(rl.start).Seconds())
	}
	kv("spur_pkt_p50", pct(spurPkt, 0.5))
	kv("spur_pkt_p90", pct(spurPkt, 0.9))
	kv("spur_pkt_max", pct(spurPkt, 1))
	kv("spur_ms_p50", pct(spurTimeMs, 0.5))
	kv("spur_ms_p90", pct(spurTimeMs, 0.9))
	kv("spur_over_minrtt_p50", pct(spurAtLatestRatio, 0.5))
	kv("thr_updates", thrUpdates)
	kv("thr_pkt_final", lastPT)
	kv("thr_time_final", lastTT)
	kv("cwnd_kib_p50", pct(cwnd, 0.5))
	kv("bif_kib_p50", pct(bif, 0.5))
	kv("pif_p10", pct(pif, 0.1))
	kv("pif_p50", pct(pif, 0.5))
	kv("pif_p90", pct(pif, 0.9))
	kv("lat_ms_p50", pct(lat, 0.5))
	kv("lat_ms_p90", pct(lat, 0.9))
	kv("lat_ms_max", pct(lat, 1))
	kv("srtt_ms_p50", pct(srtt, 0.5))
	kv("srtt_ms_p90", pct(srtt, 0.9))
	kv("minrtt_ms", ms(rl.finalMinRTT))

	// path side, steady state (by departure from the bottleneck)
	pk := rl.pkts
	slices.SortStableFunc(pk, func(a, b pktRecord) int { return a.depart.Compare(b.depart) })
	var nSteady, nReo, nReoSlackMiss int
	var depth, pathRTT []float64
	for i, p := range pk {
		if p.depart.Before(rl.mid) {
			continue
		}
		nSteady++
		pathRTT = append(pathRTT, ms(rl.baseRTT+p.queue))
		if !p.reordered {
			continue
		}
		nReo++
		if extra := p.arrive.Sub(p.depart) - rl.baseRTT/2; extra*8 > rl.baseRTT+p.queue {
			nReoSlackMiss++
		}
		var dpt int
		for j := i + 1; j < len(pk) && pk[j].depart.Before(p.arrive); j++ {
			if pk[j].arrive.Before(p.arrive) {
				dpt++
			}
		}
		depth = append(depth, float64(dpt))
	}
	kv("path_pkts", nSteady)
	if nSteady > 0 {
		kv("path_reo_frac", float64(nReo)/float64(nSteady))
		kv("path_reo_gt_rtt8", float64(nReoSlackMiss)/float64(max(nReo, 1)))
	}
	kv("depth_p50", pct(depth, 0.5))
	kv("depth_p90", pct(depth, 0.9))
	kv("depth_max", pct(depth, 1))
	kv("path_rtt_p50", pct(pathRTT, 0.5))
	kv("path_rtt_p90", pct(pathRTT, 0.9))
	kv("path_rtt_max", pct(pathRTT, 1))
	qe, qn := episodes(rl.queueDrops, rl.mid, rl.baseRTT)
	re, rn := episodes(rl.randDrops, rl.mid, rl.baseRTT)
	kv("s_qdrops", qn)
	kv("s_qdrop_eps", qe)
	kv("s_rdrops", rn)
	kv("s_rdrop_eps", re)
	return b.String()
}

func parseSeeds(s string) []uint64 {
	var out []uint64
	for _, part := range strings.Split(s, ",") {
		if lo, hi, ok := strings.Cut(part, "-"); ok {
			a, _ := strconv.ParseUint(lo, 10, 64)
			b, _ := strconv.ParseUint(hi, 10, 64)
			for x := a; x <= b; x++ {
				out = append(out, x)
			}
			continue
		}
		x, _ := strconv.ParseUint(part, 10, 64)
		out = append(out, x)
	}
	return out
}

// TestGoodputSeeds runs reorderingScenarios x GOODPUT_SEEDS (e.g. "1-20" or "1,5,7"),
// in parallel, and prints one REAL line per run. GOODPUT_TREE labels the lines,
// GOODPUT_ARMS is an optional regexp on the arm name, GOODPUT_SCHEDULE is "time"
// (default) or "packet". It is skipped unless GOODPUT_SEEDS is set.
func TestGoodputSeeds(t *testing.T) {
	if os.Getenv("GOODPUT_SEEDS") == "" {
		t.Skip("set GOODPUT_SEEDS to run")
	}
	seeds := parseSeeds(os.Getenv("GOODPUT_SEEDS"))
	tree := os.Getenv("GOODPUT_TREE")
	timeSchedule := os.Getenv("GOODPUT_SCHEDULE") != "packet"
	arms := regexp.MustCompile(os.Getenv("GOODPUT_ARMS"))
	for ai, c := range reorderingScenarios {
		if !arms.MatchString(c.String()) {
			continue
		}
		for _, seed := range seeds {
			c := c
			c.seed = seed
			t.Run(fmt.Sprintf("%s/seed=%d", c.String(), seed), func(t *testing.T) {
				t.Parallel()
				synctest.Test(t, func(t *testing.T) {
					rl := runBulkTransferRealised(t, PRDataLong, c, timeSchedule)
					fmt.Printf("REAL tree=%s sched=%v arm=%d name=%s seed=%d%s\n", tree, map[bool]string{true: "time", false: "packet"}[timeSchedule], ai, c.String(), seed, rl.fields())
					t.Log(rl.res)
				})
			})
		}
	}
}
