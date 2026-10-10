package congestion

import (
	"fmt"

	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/qlog"
	"github.com/quic-go/quic-go/qlogwriter"
)

const (
	// maxDatagramSize is the default maximum packet size used in the Linux TCP implementation.
	// Used in QUIC for congestion window computations in bytes.
	initialMaxDatagramSize     = protocol.ByteCount(protocol.InitialPacketSize)
	maxBurstPackets            = 3
	renoBeta                   = 0.7 // Reno backoff factor.
	minCongestionWindowPackets = 2
	initialCongestionWindow    = 32
)

type cubicSender struct {
	hystart   hystart
	rttStats  *utils.RTTStats
	connStats *utils.ConnectionStats
	cubic     *Cubic
	pacer     *pacer
	clock     Clock

	reno bool

	// Track the largest packet that has been sent.
	largestSentPacketNumber protocol.PacketNumber

	// Track the largest packet that has been acked.
	largestAckedPacketNumber protocol.PacketNumber

	// Track the largest packet number outstanding when a CWND cutback occurs.
	largestSentAtLastCutback protocol.PacketNumber

	// Whether the last loss event caused us to exit slowstart.
	// Used for stats collection of slowstartPacketsLost
	lastCutbackExitedSlowstart bool

	// Congestion window in bytes.
	congestionWindow protocol.ByteCount

	// Slow start congestion window in bytes, aka ssthresh.
	slowStartThreshold protocol.ByteCount

	// ACK counter for the Reno implementation.
	numAckedPackets uint64

	initialCongestionWindow    protocol.ByteCount
	initialMaxCongestionWindow protocol.ByteCount

	maxDatagramSize protocol.ByteCount

	lastState qlog.CongestionState
	qlogger   qlogwriter.Recorder

	undo cutbackUndo
}

// cutbackUndo remembers the state from before a window reduction, to restore it if every packet
// whose loss caused it turns out to have been delivered: packets reordered past the loss
// detection thresholds are declared lost, and the window would otherwise stay reduced (in slow
// start, with HyStart++ over and Cubic regrowing slowly from a small window) although nothing
// was congested. Linux TCP undoes such reductions as well.
type cutbackUndo struct {
	active    bool
	undoable  bool // false once an ECN congestion signal is part of the episode
	startTime monotime.Time
	// The packets declared lost since the reduction, until reported as spurious.
	lostPackets map[protocol.PacketNumber]struct{}

	congestionWindow           protocol.ByteCount
	slowStartThreshold         protocol.ByteCount
	largestSentAtLastCutback   protocol.PacketNumber
	lastCutbackExitedSlowstart bool
	numAckedPackets            uint64
	cubic                      Cubic
	hystart                    hystart
	state                      qlog.CongestionState
}

var (
	_ SendAlgorithm               = &cubicSender{}
	_ SendAlgorithmWithDebugInfos = &cubicSender{}
)

// NewCubicSender makes a new cubic sender
func NewCubicSender(
	clock Clock,
	rttStats *utils.RTTStats,
	connStats *utils.ConnectionStats,
	initialMaxDatagramSize protocol.ByteCount,
	reno bool,
	qlogger qlogwriter.Recorder,
) *cubicSender {
	return newCubicSender(
		clock,
		rttStats,
		connStats,
		reno,
		initialMaxDatagramSize,
		initialCongestionWindow*initialMaxDatagramSize,
		protocol.MaxCongestionWindowPackets*initialMaxDatagramSize,
		qlogger,
	)
}

func newCubicSender(
	clock Clock,
	rttStats *utils.RTTStats,
	connStats *utils.ConnectionStats,
	reno bool,
	initialMaxDatagramSize,
	initialCongestionWindow,
	initialMaxCongestionWindow protocol.ByteCount,
	qlogger qlogwriter.Recorder,
) *cubicSender {
	c := &cubicSender{
		hystart:                    newHystart(),
		rttStats:                   rttStats,
		connStats:                  connStats,
		largestSentPacketNumber:    protocol.InvalidPacketNumber,
		largestAckedPacketNumber:   protocol.InvalidPacketNumber,
		largestSentAtLastCutback:   protocol.InvalidPacketNumber,
		initialCongestionWindow:    initialCongestionWindow,
		initialMaxCongestionWindow: initialMaxCongestionWindow,
		congestionWindow:           initialCongestionWindow,
		slowStartThreshold:         protocol.MaxByteCount,
		cubic:                      NewCubic(clock),
		pacer:                      newPacer(),
		clock:                      clock,
		reno:                       reno,
		qlogger:                    qlogger,
		maxDatagramSize:            initialMaxDatagramSize,
	}
	c.connStats.CongestionWindow.Store(uint64(c.congestionWindow))
	if c.qlogger != nil {
		c.lastState = qlog.CongestionStateSlowStart
		c.qlogger.RecordEvent(qlog.CongestionStateUpdated{
			State: qlog.CongestionStateSlowStart,
		})
	}
	return c
}

// TimeUntilSend returns when the next packet should be sent.
func (c *cubicSender) TimeUntilSend(_ protocol.ByteCount) monotime.Time {
	return c.pacer.TimeUntilSend(c.pacingRate())
}

func (c *cubicSender) HasPacingBudget(now monotime.Time) bool {
	return c.pacer.Budget(now, c.pacingRate()) >= c.maxDatagramSize
}

func (c *cubicSender) maxCongestionWindow() protocol.ByteCount {
	return c.maxDatagramSize * protocol.MaxCongestionWindowPackets
}

func (c *cubicSender) minCongestionWindow() protocol.ByteCount {
	return c.maxDatagramSize * minCongestionWindowPackets
}

func (c *cubicSender) OnPacketSent(
	sentTime monotime.Time,
	_ protocol.ByteCount,
	packetNumber protocol.PacketNumber,
	bytes protocol.ByteCount,
	isRetransmittable bool,
) {
	c.pacer.SentPacket(sentTime, bytes, c.pacingRate())
	if !isRetransmittable {
		return
	}
	c.largestSentPacketNumber = packetNumber
	c.hystart.OnPacketSent(packetNumber)
}

func (c *cubicSender) CanSend(bytesInFlight protocol.ByteCount) bool {
	return bytesInFlight < c.GetCongestionWindow()
}

func (c *cubicSender) InRecovery() bool {
	return c.largestAckedPacketNumber != protocol.InvalidPacketNumber && c.largestAckedPacketNumber <= c.largestSentAtLastCutback
}

func (c *cubicSender) InSlowStart() bool {
	return c.GetCongestionWindow() < c.slowStartThreshold
}

func (c *cubicSender) GetCongestionWindow() protocol.ByteCount {
	return c.congestionWindow
}

func (c *cubicSender) MaybeExitSlowStart() {
	if c.InSlowStart() && c.hystart.OnRTTSample(c.rttStats.LatestRTT()) {
		// exit slow start
		c.slowStartThreshold = c.congestionWindow
		c.maybeQlogStateChange(qlog.CongestionStateCongestionAvoidance)
	}
}

func (c *cubicSender) OnPacketAcked(
	ackedPacketNumber protocol.PacketNumber,
	ackedBytes protocol.ByteCount,
	priorInFlight protocol.ByteCount,
	eventTime monotime.Time,
) {
	c.largestAckedPacketNumber = max(ackedPacketNumber, c.largestAckedPacketNumber)
	if c.InRecovery() {
		return
	}
	c.maybeIncreaseCwnd(ackedPacketNumber, ackedBytes, priorInFlight, eventTime)
	c.connStats.CongestionWindow.Store(uint64(c.congestionWindow))
	if c.InSlowStart() {
		c.hystart.OnPacketAcked(ackedPacketNumber)
	}
}

func (c *cubicSender) OnCongestionEvent(packetNumber protocol.PacketNumber, lostBytes, priorInFlight protocol.ByteCount) {
	c.connStats.PacketsLost.Add(1)
	c.connStats.BytesLost.Add(uint64(lostBytes))

	// TCP NewReno (RFC6582) says that once a loss occurs, any losses in packets
	// already sent should be treated as a single loss event, since it's expected.
	if packetNumber <= c.largestSentAtLastCutback {
		c.undo.addLoss(packetNumber, lostBytes)
		return
	}
	c.saveForUndo(packetNumber, lostBytes)
	c.lastCutbackExitedSlowstart = c.InSlowStart()
	c.hystart.Stop()
	c.maybeQlogStateChange(qlog.CongestionStateRecovery)

	if c.reno {
		c.congestionWindow = protocol.ByteCount(float64(c.congestionWindow) * renoBeta)
	} else {
		c.congestionWindow = c.cubic.CongestionWindowAfterPacketLoss(c.congestionWindow)
	}
	if minCwnd := c.minCongestionWindow(); c.congestionWindow < minCwnd {
		c.congestionWindow = minCwnd
	}
	c.connStats.CongestionWindow.Store(uint64(c.congestionWindow))
	c.slowStartThreshold = c.congestionWindow
	c.largestSentAtLastCutback = c.largestSentPacketNumber
	// reset packet count from congestion avoidance mode. We start
	// counting again when we're out of recovery.
	c.numAckedPackets = 0
}

// saveForUndo is called on a window reduction caused by the loss of packetNumber (or, with
// lostBytes 0, by an ECN congestion signal). Reductions that follow one another while the
// losses of the first are not resolved yet form one episode, undone as a whole.
func (c *cubicSender) saveForUndo(packetNumber protocol.PacketNumber, lostBytes protocol.ByteCount) {
	now := c.clock.Now()
	// The ack handler forgets lost packets after 3 PTOs: losses still unresolved by then never
	// will be.
	if !c.undo.active || now.Sub(c.undo.startTime) > 3*c.rttStats.PTO(true) || len(c.undo.lostPackets) == 0 {
		c.undo = cutbackUndo{
			active:                     true,
			undoable:                   true,
			startTime:                  now,
			lostPackets:                make(map[protocol.PacketNumber]struct{}),
			congestionWindow:           c.congestionWindow,
			slowStartThreshold:         c.slowStartThreshold,
			largestSentAtLastCutback:   c.largestSentAtLastCutback,
			lastCutbackExitedSlowstart: c.lastCutbackExitedSlowstart,
			numAckedPackets:            c.numAckedPackets,
			cubic:                      *c.cubic,
			hystart:                    c.hystart,
			state:                      c.lastState,
		}
	}
	c.undo.addLoss(packetNumber, lostBytes)
}

func (u *cutbackUndo) addLoss(packetNumber protocol.PacketNumber, lostBytes protocol.ByteCount) {
	if !u.active {
		return
	}
	if lostBytes == 0 {
		u.undoable = false
		return
	}
	u.lostPackets[packetNumber] = struct{}{}
}

// OnSpuriousLoss is called when a packet that was declared lost is acknowledged.
func (c *cubicSender) OnSpuriousLoss(packetNumber protocol.PacketNumber) {
	if !c.undo.active {
		return
	}
	if _, ok := c.undo.lostPackets[packetNumber]; !ok {
		return
	}
	delete(c.undo.lostPackets, packetNumber)
	if len(c.undo.lostPackets) > 0 || !c.undo.undoable {
		return
	}
	u := c.undo
	c.undo = cutbackUndo{}
	c.congestionWindow = min(max(c.congestionWindow, u.congestionWindow), c.maxCongestionWindow())
	c.slowStartThreshold = max(c.slowStartThreshold, u.slowStartThreshold)
	c.largestSentAtLastCutback = u.largestSentAtLastCutback
	c.lastCutbackExitedSlowstart = u.lastCutbackExitedSlowstart
	c.numAckedPackets = u.numAckedPackets
	*c.cubic = u.cubic
	c.hystart = u.hystart
	c.connStats.CongestionWindow.Store(uint64(c.congestionWindow))
	if c.InSlowStart() {
		if c.hystart.InConservativeSlowStart() {
			c.maybeQlogStateChange(qlog.CongestionStateConservativeSlowStart)
		} else {
			c.maybeQlogStateChange(qlog.CongestionStateSlowStart)
		}
	} else {
		c.maybeQlogStateChange(qlog.CongestionStateCongestionAvoidance)
	}
}

// Called when we receive an ack. Normal TCP tracks how many packets one ack
// represents, but quic has a separate ack for each packet.
func (c *cubicSender) maybeIncreaseCwnd(
	_ protocol.PacketNumber,
	ackedBytes protocol.ByteCount,
	priorInFlight protocol.ByteCount,
	eventTime monotime.Time,
) {
	// Do not increase the congestion window unless the sender is close to using
	// the current window.
	if !c.isCwndLimited(priorInFlight) {
		c.cubic.OnApplicationLimited()
		c.maybeQlogStateChange(qlog.CongestionStateApplicationLimited)
		return
	}
	if c.congestionWindow >= c.maxCongestionWindow() {
		return
	}
	if c.InSlowStart() {
		if c.hystart.InConservativeSlowStart() {
			// HyStart++ Conservative Slow Start: a quarter of the slow start growth.
			c.congestionWindow += c.maxDatagramSize / hystartCSSGrowthDivisor
			c.maybeQlogStateChange(qlog.CongestionStateConservativeSlowStart)
			return
		}
		// TCP slow start, exponential growth, increase by one for each ACK.
		c.congestionWindow += c.maxDatagramSize
		c.maybeQlogStateChange(qlog.CongestionStateSlowStart)
		return
	}
	// Congestion avoidance
	c.maybeQlogStateChange(qlog.CongestionStateCongestionAvoidance)
	if c.reno {
		// Classic Reno congestion avoidance.
		c.numAckedPackets++
		if c.numAckedPackets >= uint64(c.congestionWindow/c.maxDatagramSize) {
			c.congestionWindow += c.maxDatagramSize
			c.numAckedPackets = 0
		}
	} else {
		c.congestionWindow = min(
			c.maxCongestionWindow(),
			c.cubic.CongestionWindowAfterAck(ackedBytes, c.congestionWindow, c.rttStats.MinRTT(), eventTime),
		)
	}
}

func (c *cubicSender) isCwndLimited(bytesInFlight protocol.ByteCount) bool {
	congestionWindow := c.GetCongestionWindow()
	if bytesInFlight >= congestionWindow {
		return true
	}
	availableBytes := congestionWindow - bytesInFlight
	// The window counts as used, and may grow, while more than half of it is in flight, as in
	// RFC 7661 (congestion window validation) and Linux TCP, and as slow start already did here.
	// Requiring the flight to come within a few packets of the window left a sender that the
	// application feeds in bursts (an HTTP reverse proxy) application limited between bursts:
	// each of those ACKs reset the Cubic epoch, and the window stopped growing after a loss.
	halfUsed := bytesInFlight > congestionWindow/2
	return halfUsed || availableBytes <= maxBurstPackets*c.maxDatagramSize
}

// BandwidthEstimate returns the current bandwidth estimate
func (c *cubicSender) BandwidthEstimate() Bandwidth {
	srtt := c.rttStats.SmoothedRTT()
	if srtt == 0 {
		// This should never happen, but if it does, avoid division by zero.
		srtt = protocol.TimerGranularity
	}
	return BandwidthFromDelta(c.GetCongestionWindow(), srtt)
}

func (c *cubicSender) pacingRate() Bandwidth {
	// Conservative Slow Start grows the window by a quarter per round, it doesn't need to send at
	// twice the rate: that only builds a queue at the bottleneck.
	if c.InSlowStart() && !c.hystart.InConservativeSlowStart() {
		// Allow slow start to double the sending rate every RTT.
		return 2 * c.BandwidthEstimate()
	}
	// Allow for RTT variations when filling the congestion window.
	return c.BandwidthEstimate() * 5 / 4
}

// OnRetransmissionTimeout is called on an retransmission timeout
func (c *cubicSender) OnRetransmissionTimeout(packetsRetransmitted bool) {
	c.largestSentAtLastCutback = protocol.InvalidPacketNumber
	if !packetsRetransmitted {
		return
	}
	c.undo = cutbackUndo{}
	c.hystart.Stop()
	c.cubic.Reset()
	c.slowStartThreshold = c.congestionWindow / 2
	c.congestionWindow = c.minCongestionWindow()
	c.connStats.CongestionWindow.Store(uint64(c.congestionWindow))
}

// OnConnectionMigration is called when the connection is migrated (?)
func (c *cubicSender) OnConnectionMigration() {
	c.undo = cutbackUndo{}
	c.hystart.Reset()
	c.largestSentPacketNumber = protocol.InvalidPacketNumber
	c.largestAckedPacketNumber = protocol.InvalidPacketNumber
	c.largestSentAtLastCutback = protocol.InvalidPacketNumber
	c.lastCutbackExitedSlowstart = false
	c.cubic.Reset()
	c.numAckedPackets = 0
	c.congestionWindow = c.initialCongestionWindow
	c.connStats.CongestionWindow.Store(uint64(c.congestionWindow))
	c.slowStartThreshold = c.initialMaxCongestionWindow
}

func (c *cubicSender) maybeQlogStateChange(new qlog.CongestionState) {
	if c.qlogger == nil || new == c.lastState {
		return
	}
	c.qlogger.RecordEvent(qlog.CongestionStateUpdated{State: new})
	c.lastState = new
}

func (c *cubicSender) SetMaxDatagramSize(s protocol.ByteCount) {
	if s < c.maxDatagramSize {
		panic(fmt.Sprintf("congestion BUG: decreased max datagram size from %d to %d", c.maxDatagramSize, s))
	}
	cwndIsMinCwnd := c.congestionWindow == c.minCongestionWindow()
	c.maxDatagramSize = s
	if cwndIsMinCwnd {
		c.congestionWindow = c.minCongestionWindow()
		c.connStats.CongestionWindow.Store(uint64(c.congestionWindow))
	}
	c.pacer.SetMaxDatagramSize(s)
}
