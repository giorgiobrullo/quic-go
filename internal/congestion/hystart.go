package congestion

import (
	"math"
	"time"

	"github.com/quic-go/quic-go/internal/protocol"
)

// Constants of HyStart++, RFC 9406, Section 4.3.
const (
	hystartMinRTTThresh     = 4 * time.Millisecond
	hystartMaxRTTThresh     = 16 * time.Millisecond
	hystartMinRTTDivisor    = 8
	hystartNRTTSample       = 8
	hystartCSSGrowthDivisor = 4
	hystartCSSRounds        = 5
)

const hystartInfiniteRTT = time.Duration(math.MaxInt64)

// hystart implements HyStart++ (RFC 9406) for the initial slow start.
//
// The round-trip time is sampled once per ACK. When the minimum RTT of a round exceeds that of
// the previous round by more than an eighth (clamped to 4-16 ms), the sender does not leave
// slow start right away, as the hybrid slow start this replaces did, but enters Conservative
// Slow Start (CSS): the window keeps growing at a quarter of the slow start rate. If a later
// round's minimum RTT falls below the one that triggered CSS, the increase was jitter and slow
// start resumes. Only after CSS_ROUNDS rounds of CSS does the sender enter congestion avoidance.
// On a path with a few milliseconds of jitter, the old algorithm left slow start at a fraction of
// the bandwidth-delay product, and Cubic then took many seconds to grow the window.
type hystart struct {
	// A round ends when a packet sent after it started is acknowledged.
	lastSentPacketNumber protocol.PacketNumber
	windowEnd            protocol.PacketNumber
	roundEnded           bool

	lastRoundMinRTT    time.Duration
	currentRoundMinRTT time.Duration
	rttSampleCount     int

	inCSS             bool
	cssBaselineMinRTT time.Duration
	cssRounds         int
	// CSS is entered or left at most once per round: the samples that follow the entry in the
	// same round would otherwise flip it back and forth, restarting the count of CSS rounds,
	// so that a sender whose RTT samples vary within a round never left slow start.
	switchedThisRound bool

	// HyStart++ only runs during the initial slow start (RFC 9406, Section 4.2):
	// later slow starts end at the slow start threshold found by the loss.
	done bool
}

func newHystart() hystart {
	return hystart{
		lastSentPacketNumber: protocol.InvalidPacketNumber,
		windowEnd:            protocol.InvalidPacketNumber,
		roundEnded:           true,
		lastRoundMinRTT:      hystartInfiniteRTT,
		currentRoundMinRTT:   hystartInfiniteRTT,
		cssBaselineMinRTT:    hystartInfiniteRTT,
	}
}

// OnPacketSent is called for every ack-eliciting packet sent.
func (h *hystart) OnPacketSent(pn protocol.PacketNumber) {
	h.lastSentPacketNumber = pn
}

// OnPacketAcked is called for every newly acknowledged packet while in slow start.
func (h *hystart) OnPacketAcked(pn protocol.PacketNumber) {
	if pn > h.windowEnd {
		h.roundEnded = true
	}
}

// OnRTTSample is called once per ACK that yields an RTT sample while in slow start.
// It returns true when the sender should leave slow start for congestion avoidance.
func (h *hystart) OnRTTSample(rtt time.Duration) (exitSlowStart bool) {
	if h.done {
		return false
	}
	if h.roundEnded {
		h.roundEnded = false
		h.windowEnd = h.lastSentPacketNumber
		h.lastRoundMinRTT = h.currentRoundMinRTT
		h.currentRoundMinRTT = hystartInfiniteRTT
		h.rttSampleCount = 0
		h.switchedThisRound = false
		if h.inCSS {
			h.cssRounds++
			if h.cssRounds >= hystartCSSRounds {
				h.done = true
				return true
			}
		}
	}
	h.currentRoundMinRTT = min(h.currentRoundMinRTT, rtt)
	h.rttSampleCount++
	if h.rttSampleCount < hystartNRTTSample || h.switchedThisRound {
		return false
	}
	if h.inCSS {
		if h.currentRoundMinRTT < h.cssBaselineMinRTT {
			// The RTT increase was spurious: resume slow start.
			h.inCSS = false
			h.cssBaselineMinRTT = hystartInfiniteRTT
			h.switchedThisRound = true
		}
		return false
	}
	if h.lastRoundMinRTT == hystartInfiniteRTT {
		return false
	}
	thresh := min(max(h.lastRoundMinRTT/hystartMinRTTDivisor, hystartMinRTTThresh), hystartMaxRTTThresh)
	if h.currentRoundMinRTT >= h.lastRoundMinRTT+thresh {
		h.inCSS = true
		h.cssBaselineMinRTT = h.currentRoundMinRTT
		h.cssRounds = 0
		h.switchedThisRound = true
	}
	return false
}

// InConservativeSlowStart says whether the window should grow at the CSS rate.
func (h *hystart) InConservativeSlowStart() bool {
	return h.inCSS && !h.done
}

// Stop ends HyStart++ for the rest of the connection (after a loss or a retransmission timeout).
func (h *hystart) Stop() {
	h.done = true
	h.inCSS = false
}

// Reset starts over, for a new path.
func (h *hystart) Reset() {
	lastSent := h.lastSentPacketNumber
	*h = newHystart()
	h.lastSentPacketNumber = lastSent
}
