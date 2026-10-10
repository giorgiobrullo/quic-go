package congestion

import (
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/protocol"

	"github.com/stretchr/testify/require"
)

type hystartTester struct {
	h          hystart
	nextToSend protocol.PacketNumber
	nextToAck  protocol.PacketNumber
}

func newHystartTester() *hystartTester {
	return &hystartTester{h: newHystart()}
}

func (s *hystartTester) send(n int) {
	for range n {
		s.h.OnPacketSent(s.nextToSend)
		s.nextToSend++
	}
}

// ack acknowledges the next packet with an RTT sample, in the order the sender uses:
// the sample first, then the acknowledged packet. It returns whether HyStart++ left slow start.
func (s *hystartTester) ack(rtt time.Duration) bool {
	exit := s.h.OnRTTSample(rtt)
	s.h.OnPacketAcked(s.nextToAck)
	s.nextToAck++
	return exit
}

// round sends a round of n packets and acknowledges all of them.
func (s *hystartTester) round(n int, rtt time.Duration) (exit bool) {
	s.send(n)
	for range n {
		if s.ack(rtt) {
			exit = true
		}
	}
	return exit
}

func TestHystartStaysInSlowStartBelowThreshold(t *testing.T) {
	s := newHystartTester()
	require.False(t, s.round(20, 40*time.Millisecond))
	// The threshold is 40 ms / 8 = 5 ms.
	require.False(t, s.round(20, 44*time.Millisecond))
	require.False(t, s.round(20, 48*time.Millisecond))
	require.False(t, s.h.InConservativeSlowStart())
}

func TestHystartConservativeSlowStartAfterSpuriousIncrease(t *testing.T) {
	s := newHystartTester()
	s.round(20, 40*time.Millisecond)
	require.False(t, s.round(20, 50*time.Millisecond))
	require.True(t, s.h.InConservativeSlowStart())

	// Jitter: the next round's minimum is below the RTT that triggered CSS.
	require.False(t, s.round(20, 41*time.Millisecond))
	require.False(t, s.h.InConservativeSlowStart())
	require.False(t, s.h.done)
}

func TestHystartCongestionAvoidanceAfterCSSRounds(t *testing.T) {
	s := newHystartTester()
	s.round(20, 40*time.Millisecond)
	s.round(20, 50*time.Millisecond)
	require.True(t, s.h.InConservativeSlowStart())
	for range hystartCSSRounds - 1 {
		require.False(t, s.round(20, 50*time.Millisecond))
		require.True(t, s.h.InConservativeSlowStart())
	}
	// The next round completes the CSS rounds.
	require.True(t, s.round(20, 50*time.Millisecond))
	require.True(t, s.h.done)
	require.False(t, s.h.InConservativeSlowStart())
	require.False(t, s.round(20, 80*time.Millisecond))
}

func TestHystartDecidesOncePerRound(t *testing.T) {
	s := newHystartTester()
	s.round(20, 40*time.Millisecond)
	s.send(20)
	s.ack(60 * time.Millisecond) // still closes the previous round
	for range hystartNRTTSample {
		s.ack(60 * time.Millisecond)
	}
	require.True(t, s.h.InConservativeSlowStart())
	// Lower samples later in the round that entered CSS don't leave it again...
	for range 11 {
		s.ack(50 * time.Millisecond)
		require.True(t, s.h.InConservativeSlowStart())
	}
	// ...and the rounds spent in CSS keep counting.
	for range hystartCSSRounds - 1 {
		require.False(t, s.round(20, 60*time.Millisecond))
		require.True(t, s.h.InConservativeSlowStart())
	}
	require.True(t, s.round(20, 60*time.Millisecond))
}

func TestHystartNeedsEnoughSamples(t *testing.T) {
	s := newHystartTester()
	s.round(20, 40*time.Millisecond)
	s.send(20)
	// The first ACK of a round still closes the previous one.
	s.ack(60 * time.Millisecond)
	for range hystartNRTTSample - 1 {
		s.ack(60 * time.Millisecond)
	}
	require.False(t, s.h.InConservativeSlowStart())
	s.ack(60 * time.Millisecond)
	require.True(t, s.h.InConservativeSlowStart())
}

func TestHystartThresholdClamping(t *testing.T) {
	for _, tc := range []struct {
		name      string
		base, rtt time.Duration
		css       bool
	}{
		{name: "long RTT, below the 16 ms cap", base: 200 * time.Millisecond, rtt: 215 * time.Millisecond, css: false},
		{name: "long RTT, above the 16 ms cap", base: 200 * time.Millisecond, rtt: 216 * time.Millisecond, css: true},
		{name: "short RTT, below the 4 ms floor", base: 10 * time.Millisecond, rtt: 13 * time.Millisecond, css: false},
		{name: "short RTT, at the 4 ms floor", base: 10 * time.Millisecond, rtt: 14 * time.Millisecond, css: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newHystartTester()
			s.round(20, tc.base)
			s.round(20, tc.rtt)
			require.Equal(t, tc.css, s.h.InConservativeSlowStart())
		})
	}
}

func TestHystartStopAndReset(t *testing.T) {
	s := newHystartTester()
	s.round(20, 40*time.Millisecond)
	s.round(20, 50*time.Millisecond)
	require.True(t, s.h.InConservativeSlowStart())

	s.h.Stop()
	require.False(t, s.h.InConservativeSlowStart())
	for range 2 * hystartCSSRounds {
		require.False(t, s.round(20, 80*time.Millisecond))
	}

	s.h.Reset()
	s.round(20, 40*time.Millisecond)
	s.round(20, 50*time.Millisecond)
	require.True(t, s.h.InConservativeSlowStart())
}

func TestCubicSenderHystart(t *testing.T) {
	sender := newTestCubicSender(true)
	// ackRound acknowledges one window's worth of packets, refilling the window after each ACK.
	ackRound := func(rtt time.Duration) {
		sender.SendAvailableSendWindow()
		n := int(sender.sender.GetCongestionWindow() / maxDatagramSize)
		for range n {
			sender.rttStats.UpdateRTT(rtt, 0)
			sender.sender.MaybeExitSlowStart(sender.bytesInFlight)
			sender.ackedPacketNumber++
			sender.sender.OnPacketAcked(sender.ackedPacketNumber, maxDatagramSize, sender.bytesInFlight, sender.clock.Now())
			sender.bytesInFlight -= maxDatagramSize
			sender.SendAvailableSendWindow()
		}
		sender.clock.Advance(rtt)
	}

	// Slow start doubles the window every round.
	ackRound(40 * time.Millisecond)
	require.Equal(t, 2*defaultWindowTCP, sender.sender.GetCongestionWindow())

	// The RTT increase moves to Conservative Slow Start once enough samples were taken,
	// which grows the window by a quarter of a packet per acknowledged packet.
	ackRound(50 * time.Millisecond)
	require.True(t, sender.sender.InSlowStart())
	require.True(t, sender.sender.hystart.InConservativeSlowStart())
	cwnd := sender.sender.GetCongestionWindow()
	require.Less(t, cwnd, 4*defaultWindowTCP)
	require.Greater(t, cwnd, 2*defaultWindowTCP)

	// CSS paces like congestion avoidance.
	require.Equal(t, sender.sender.BandwidthEstimate()*5/4, sender.sender.pacingRate())

	n := cwnd / maxDatagramSize
	ackRound(50 * time.Millisecond)
	require.Equal(t, cwnd+n*(maxDatagramSize/hystartCSSGrowthDivisor), sender.sender.GetCongestionWindow())

	// Sustained, the increase ends slow start without a loss, at the window reached.
	for range hystartCSSRounds - 1 {
		ackRound(50 * time.Millisecond)
	}
	require.False(t, sender.sender.InSlowStart())
	require.Greater(t, sender.sender.slowStartThreshold, cwnd)
	require.GreaterOrEqual(t, sender.sender.GetCongestionWindow(), sender.sender.slowStartThreshold)
}

func TestCubicSenderHystartIgnoresApplicationLimitedSamples(t *testing.T) {
	sender := newTestCubicSender(true)
	// An application that only keeps a few packets in flight: the queue those build doesn't say
	// anything about the window.
	ackRound := func(rtt time.Duration) {
		for range 2 * hystartNRTTSample {
			sender.SendAvailableSendWindowLen(maxDatagramSize)
			sender.rttStats.UpdateRTT(rtt, 0)
			sender.sender.MaybeExitSlowStart(2 * maxDatagramSize)
			sender.ackedPacketNumber++
			sender.sender.OnPacketAcked(sender.ackedPacketNumber, maxDatagramSize, 2*maxDatagramSize, sender.clock.Now())
			sender.bytesInFlight -= maxDatagramSize
		}
	}
	ackRound(40 * time.Millisecond)
	ackRound(80 * time.Millisecond)
	ackRound(80 * time.Millisecond)
	require.False(t, sender.sender.hystart.InConservativeSlowStart())
	require.True(t, sender.sender.InSlowStart())
}
