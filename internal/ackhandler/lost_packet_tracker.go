package ackhandler

import (
	"iter"
	"slices"
	"time"

	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
)

const maxTrackedLostPackets = 64

type lostPacket struct {
	PacketNumber protocol.PacketNumber
	SendTime     monotime.Time
	// RTT is the RTT estimate that was used to declare the packet lost.
	RTT time.Duration
}

type lostPacketTracker struct {
	lostPackets []lostPacket
}

func newLostPacketTracker() *lostPacketTracker {
	return &lostPacketTracker{
		// Preallocate a small slice only.
		// Hopefully we won't lose many packets.
		lostPackets: make([]lostPacket, 0, 4),
	}
}

func (t *lostPacketTracker) Add(p protocol.PacketNumber, sendTime monotime.Time, rtt time.Duration) {
	if len(t.lostPackets) == maxTrackedLostPackets {
		t.lostPackets = t.lostPackets[1:]
	}
	t.lostPackets = append(t.lostPackets, lostPacket{
		PacketNumber: p,
		SendTime:     sendTime,
		RTT:          rtt,
	})
}

// Delete deletes a packet from the lost packet tracker.
// This function is not optimized for performance if many packets are lost,
// but it is only used when a spurious loss is detected, which is rare.
func (t *lostPacketTracker) Delete(pn protocol.PacketNumber) {
	t.lostPackets = slices.DeleteFunc(t.lostPackets, func(p lostPacket) bool {
		return p.PacketNumber == pn
	})
}

func (t *lostPacketTracker) All() iter.Seq[lostPacket] {
	return func(yield func(lostPacket) bool) {
		for _, p := range t.lostPackets {
			if !yield(p) {
				return
			}
		}
	}
}

func (t *lostPacketTracker) DeleteBefore(ti monotime.Time) {
	if len(t.lostPackets) == 0 {
		return
	}
	if !t.lostPackets[0].SendTime.Before(ti) {
		return
	}
	var idx int
	for ; idx < len(t.lostPackets); idx++ {
		if !t.lostPackets[idx].SendTime.Before(ti) {
			break
		}
	}
	t.lostPackets = slices.Delete(t.lostPackets, 0, idx)
}

func (t *lostPacketTracker) Reset() {
	t.lostPackets = t.lostPackets[:0]
}
