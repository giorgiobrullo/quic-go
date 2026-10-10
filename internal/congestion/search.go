package congestion

import (
	"time"

	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
)

// Constants of SEARCH 4.0 (draft-chung-ccwg-search-10, Section 3.2).
const (
	// WINDOW_SIZE = 3.5 x INITIAL_RTT, as a fraction searchWindowNum / searchWindowDen.
	searchWindowNum = 35
	searchWindowDen = 10
	searchW         = 10 // bins per window
	searchExtraBins = 15 // bins to look back by an RTT for the sent bytes
	// The draft has W + EXTRA_BINS sent bins, but compute_sent reads the bin before the window
	// as well: one more is needed (neqo found the same).
	searchNumAckedBins = searchW + 1
	searchNumSentBins  = searchNumAckedBins + searchExtraBins
	searchThresh       = 0.26
	searchDrainRate    = 3
	// Reset when more than about 2 RTTs of bins pass without an ACK (Section 4.6, optional):
	// the bins no longer describe the path, e.g. after the application stopped sending.
	searchMissedBinRTTs = 2
)

// search implements SEARCH (Slow start Exit At Right CHokepoint, draft-chung-ccwg-search-10).
//
// Instead of the RTT, SEARCH watches the delivery rate: it compares the bytes delivered over the
// last window (3.5 initial RTTs, in 10 bins) with the bytes sent over the window one RTT earlier.
// In slow start, deliveries keep up with what was sent; once the bottleneck is full they fall
// behind. When the shortfall reaches 26%, SEARCH estimates the window at the path's capacity
// (the bytes delivered over the last initial RTT) and drains toward it before congestion
// avoidance. On a path whose RTT samples swing by tens of milliseconds with no queue behind
// them, HyStart++ never ended slow start and every transfer overshot to a loss at several times
// the bandwidth-delay product.
type search struct {
	// cumulative byte counters
	sentBytes  uint64
	ackedBytes uint64

	ackedBins   [searchNumAckedBins]uint64 // ackedBytes at the end of each bin
	sentBins    [searchNumSentBins]uint64  // sentBytes at the end of each bin
	currIdx     int                        // -1 until the first RTT sample
	binEnd      monotime.Time
	binDuration time.Duration
	initialRTT  time.Duration

	inDrain     bool
	targetCwnd  protocol.ByteCount
	drainAcked  protocol.ByteCount
	done        bool
	initialCwnd protocol.ByteCount
}

func newSearch(initialCwnd protocol.ByteCount) search {
	return search{currIdx: -1, initialCwnd: initialCwnd}
}

// OnPacketSent is called for every packet counted in bytes in flight.
func (s *search) OnPacketSent(bytes protocol.ByteCount) {
	s.sentBytes += uint64(bytes)
}

// OnPacketAcked is called for every newly acknowledged packet counted in bytes in flight.
func (s *search) OnPacketAcked(bytes protocol.ByteCount) {
	s.ackedBytes += uint64(bytes)
	if s.inDrain {
		s.drainAcked += bytes
	}
}

// OnRTTSample is called once per ACK that yields an RTT sample while in slow start.
// It returns true when the congestion point was found: the drain phase starts.
func (s *search) OnRTTSample(now monotime.Time, rtt time.Duration) bool {
	if s.done || s.inDrain {
		return false
	}
	if s.currIdx < 0 {
		s.initialize(now, rtt)
		return false
	}
	if !now.After(s.binEnd) {
		return false
	}
	if !s.updateBins(now) {
		return false
	}
	binsLastRTT := int(rtt / s.binDuration)
	fraction := float64(rtt%s.binDuration) / float64(s.binDuration)
	prevIdx := s.currIdx - binsLastRTT
	if prevIdx <= searchW || binsLastRTT >= searchExtraBins {
		// not enough history yet, or the RTT grew beyond what the sent bins can look back
		return false
	}
	currDelivered := float64(s.delivered(s.currIdx-searchW, s.currIdx))
	prevSent := s.sent(prevIdx-searchW, prevIdx, fraction)
	if prevSent <= 0 {
		return false
	}
	if (prevSent-currDelivered)/prevSent < searchThresh {
		return false
	}
	rttBins := int((s.initialRTT + s.binDuration - 1) / s.binDuration)
	s.targetCwnd = max(protocol.ByteCount(s.delivered(s.currIdx-rttBins, s.currIdx)), s.initialCwnd)
	s.inDrain = true
	s.drainAcked = 0
	return true
}

func (s *search) initialize(now monotime.Time, rtt time.Duration) {
	binDuration := rtt * searchWindowNum / searchWindowDen / searchW
	if binDuration <= 0 {
		return
	}
	s.initialRTT = rtt
	s.binDuration = binDuration
	s.binEnd = now.Add(binDuration)
	s.currIdx = 0
	s.ackedBins[0] = s.ackedBytes
	s.sentBins[0] = s.sentBytes
}

// updateBins closes the bins that ended before now. It returns false if SEARCH had to start over.
func (s *search) updateBins(now monotime.Time) bool {
	passed := int(now.Sub(s.binEnd)/s.binDuration) + 1
	if missedLimit := searchMissedBinRTTs * int(s.initialRTT/s.binDuration); passed > missedLimit {
		s.currIdx = -1
		s.initialize(now, s.initialRTT)
		return false
	}
	// Bins without ACKs keep the value of the last one.
	for i := s.currIdx + 1; i < s.currIdx+passed; i++ {
		s.ackedBins[i%searchNumAckedBins] = s.ackedBins[s.currIdx%searchNumAckedBins]
		s.sentBins[i%searchNumSentBins] = s.sentBins[s.currIdx%searchNumSentBins]
	}
	s.currIdx += passed
	s.binEnd = s.binEnd.Add(time.Duration(passed) * s.binDuration)
	s.ackedBins[s.currIdx%searchNumAckedBins] = s.ackedBytes
	s.sentBins[s.currIdx%searchNumSentBins] = s.sentBytes
	return true
}

func (s *search) delivered(from, to int) uint64 {
	return s.ackedBins[to%searchNumAckedBins] - s.ackedBins[from%searchNumAckedBins]
}

// sent returns the bytes sent between two bin indices, interpolated when one RTT back falls
// within a bin (fraction is how far into the bin before to).
func (s *search) sent(from, to int, fraction float64) float64 {
	lower := float64(s.sentBins[(to-1)%searchNumSentBins] - s.sentBins[(from-1)%searchNumSentBins])
	upper := float64(s.sentBins[to%searchNumSentBins] - s.sentBins[from%searchNumSentBins])
	return lower*fraction + upper*(1-fraction)
}

// DrainWindow returns the congestion window for the drain phase, given the bytes in flight:
// it follows the bytes in flight down, letting one packet out for every DRAIN_RATE acknowledged,
// and never goes below the target.
func (s *search) DrainWindow(bytesInFlight, maxDatagramSize protocol.ByteCount) protocol.ByteCount {
	adds := s.drainAcked / (searchDrainRate * maxDatagramSize)
	s.drainAcked -= adds * searchDrainRate * maxDatagramSize
	return max(bytesInFlight+adds*maxDatagramSize, s.targetCwnd)
}

// Stop ends SEARCH for the rest of the connection: it only runs in the initial slow start.
func (s *search) Stop() {
	s.done = true
	s.inDrain = false
}

// Reset starts over, for a new path.
func (s *search) Reset() {
	*s = newSearch(s.initialCwnd)
}
