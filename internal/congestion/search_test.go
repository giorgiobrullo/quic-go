package congestion

import (
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"

	"github.com/stretchr/testify/require"
)

// searchPath simulates slow start over a path: the sending rate doubles every RTT, and the path
// delivers what was sent one RTT earlier, up to its capacity.
type searchPath struct {
	rtt      time.Duration
	capacity float64 // bytes per millisecond, 0 for unlimited
	sentAt   []float64
}

// run feeds s for the given duration, one ACK per millisecond, and returns when SEARCH found
// the congestion point (or -1).
func (p *searchPath) run(t *testing.T, s *search, start monotime.Time, d time.Duration) time.Duration {
	t.Helper()
	rttMs := int(p.rtt / time.Millisecond)
	for ms := 0; ms < int(d/time.Millisecond); ms++ {
		// 10 packets of 1000 bytes per ms at the start, doubling every RTT
		rate := 10000 * float64(uint64(1)<<min(ms/rttMs, 40))
		p.sentAt = append(p.sentAt, rate)
		s.OnPacketSent(protocol.ByteCount(rate))
		if ms >= rttMs {
			delivered := p.sentAt[ms-rttMs]
			if p.capacity > 0 {
				delivered = min(delivered, p.capacity)
			}
			s.OnPacketAcked(protocol.ByteCount(delivered))
		}
		if ms >= rttMs && s.OnRTTSample(start.Add(time.Duration(ms)*time.Millisecond), p.rtt) {
			return time.Duration(ms) * time.Millisecond
		}
	}
	return -1
}

func TestSearchNoExitWhileDeliveriesKeepUp(t *testing.T) {
	s := newSearch(32 * 1252)
	p := &searchPath{rtt: 40 * time.Millisecond}
	require.Equal(t, time.Duration(-1), p.run(t, &s, monotime.Now(), 600*time.Millisecond))
	require.False(t, s.inDrain)
}

func TestSearchExitsAtCapacity(t *testing.T) {
	const rtt = 40 * time.Millisecond
	const capacity = 640000.0 // bytes per ms: reached in the 7th RTT (10000 * 2^6)
	s := newSearch(32 * 1252)
	p := &searchPath{rtt: rtt, capacity: capacity}
	exit := p.run(t, &s, monotime.Now(), 2*time.Second)
	require.Positive(t, exit)
	// Deliveries reach the capacity one RTT after the sending rate does, at 7 RTTs.
	atCapacity := 7 * rtt
	require.Greater(t, exit, atCapacity)
	require.Less(t, exit, atCapacity+3*rtt)
	require.True(t, s.inDrain)
	// The target is what the path delivers in an (initial) RTT: its bandwidth-delay product,
	// rounded up to whole bins.
	bdp := protocol.ByteCount(capacity * float64(rtt/time.Millisecond))
	require.GreaterOrEqual(t, s.targetCwnd, bdp*9/10)
	require.LessOrEqual(t, s.targetCwnd, bdp*13/10)
}

func TestSearchResetsAfterMissedBins(t *testing.T) {
	s := newSearch(32 * 1252)
	now := monotime.Now()
	s.OnRTTSample(now, 40*time.Millisecond)
	require.Equal(t, 0, s.currIdx)
	for i := 1; i <= 5; i++ {
		s.OnPacketSent(10000)
		s.OnPacketAcked(10000)
		s.OnRTTSample(now.Add(time.Duration(i)*s.binDuration+time.Millisecond), 40*time.Millisecond)
	}
	require.Equal(t, 5, s.currIdx)
	// Nothing acknowledged for 3 RTTs: start over.
	s.OnRTTSample(now.Add(5*s.binDuration+120*time.Millisecond), 40*time.Millisecond)
	require.Equal(t, 0, s.currIdx)
}

func TestSearchDrainWindow(t *testing.T) {
	s := newSearch(32 * 1252)
	s.inDrain = true
	s.targetCwnd = 50000
	// one packet let out for every 3 acknowledged
	s.OnPacketAcked(4 * 1000)
	require.Equal(t, protocol.ByteCount(80000+1000), s.DrainWindow(80000, 1000))
	require.Equal(t, protocol.ByteCount(1000), s.drainAcked)
	// never below the target
	require.Equal(t, protocol.ByteCount(50000), s.DrainWindow(10000, 1000))
}

func TestCubicSenderSearch(t *testing.T) {
	for _, tc := range []struct {
		name  string
		mode  slowStartExit
		drain bool
	}{
		{name: "with drain", mode: slowStartExitSearch, drain: true},
		{name: "without drain", mode: slowStartExitSearchNoDrain},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var clock mockClock
			clock.Advance(time.Second)
			rttStats := utils.NewRTTStats()
			sender := newCubicSender(&clock, rttStats, &utils.ConnectionStats{}, false, maxDatagramSize, 32*maxDatagramSize, protocol.MaxCongestionWindowPackets*maxDatagramSize, nil)
			sender.slowStartExit = tc.mode

			const rtt = 40 * time.Millisecond
			const capacity = 400 * maxDatagramSize // per RTT
			// In flight, by send time; the path delivers capacity/RTT, in order.
			type flight struct {
				pn   protocol.PacketNumber
				sent monotime.Time
			}
			var inFlight []flight
			var bytesInFlight protocol.ByteCount
			var pn protocol.PacketNumber
			perMs := int(capacity / maxDatagramSize / protocol.ByteCount(rtt/time.Millisecond))
			for ms := 0; ms < 3000 && sender.InSlowStart(); ms++ {
				for sender.CanSend(bytesInFlight) {
					sender.OnPacketSent(clock.Now(), bytesInFlight, pn, maxDatagramSize, true)
					inFlight = append(inFlight, flight{pn: pn, sent: clock.Now()})
					bytesInFlight += maxDatagramSize
					pn++
				}
				for i := 0; i < perMs && len(inFlight) > 0 && clock.Now().Sub(inFlight[0].sent) >= rtt; i++ {
					p := inFlight[0]
					inFlight = inFlight[1:]
					rttStats.UpdateRTT(clock.Now().Sub(p.sent), 0)
					sender.MaybeExitSlowStart(bytesInFlight)
					sender.OnPacketAcked(p.pn, maxDatagramSize, bytesInFlight, clock.Now())
					bytesInFlight -= maxDatagramSize
				}
				clock.Advance(time.Millisecond)
			}
			require.False(t, sender.InSlowStart())
			cwndAtExit := sender.slowStartThreshold
			if tc.drain {
				// drained to about the bandwidth-delay product
				require.InDelta(t, float64(capacity), float64(cwndAtExit), float64(capacity)*0.35)
			} else {
				// exits where slow start was, above the bandwidth-delay product
				require.Greater(t, cwndAtExit, protocol.ByteCount(capacity))
			}
		})
	}
}
