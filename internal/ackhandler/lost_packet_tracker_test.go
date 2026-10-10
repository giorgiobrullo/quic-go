package ackhandler

import (
	"slices"
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"

	"github.com/stretchr/testify/require"
)

func TestLostPacketTracker(t *testing.T) {
	lt := newLostPacketTracker()

	start := monotime.Now()
	want := make([]lostPacket, 0, maxTrackedLostPackets)
	for i := range maxTrackedLostPackets {
		p := lostPacket{
			PacketNumber: protocol.PacketNumber(i + 1),
			SendTime:     start.Add(time.Duration(i)),
			RTT:          time.Duration(i+1) * time.Millisecond,
		}
		lt.Add(p.PacketNumber, p.SendTime, p.RTT)
		want = append(want, p)
	}
	require.Equal(t, want, slices.Collect(lt.All()))

	// Lose one more packet. The first one should be removed.
	p := lostPacket{
		PacketNumber: maxTrackedLostPackets + 1,
		SendTime:     start.Add(time.Duration(maxTrackedLostPackets)),
		RTT:          time.Second,
	}
	lt.Add(p.PacketNumber, p.SendTime, p.RTT)
	want = append(want[1:], p)
	require.Equal(t, want, slices.Collect(lt.All()))

	lt.Delete(5)
	lt.Delete(10)
	want = slices.DeleteFunc(want, func(p lostPacket) bool { return p.PacketNumber == 5 || p.PacketNumber == 10 })
	require.Equal(t, want, slices.Collect(lt.All()))

	lt.Reset()
	require.Empty(t, slices.Collect(lt.All()))
	lt.Add(42, start, time.Millisecond)
	require.Equal(t, []lostPacket{{PacketNumber: 42, SendTime: start, RTT: time.Millisecond}}, slices.Collect(lt.All()))
}

func TestLostPacketTrackerDeleteBefore(t *testing.T) {
	lt := newLostPacketTracker()

	trackedPackets := func(lt *lostPacketTracker) []protocol.PacketNumber {
		var pns []protocol.PacketNumber
		for p := range lt.All() {
			pns = append(pns, p.PacketNumber)
		}
		return pns
	}

	start := monotime.Now()
	lt.Add(1, start, time.Second)
	lt.Add(5, start.Add(time.Second), time.Second)
	lt.Add(8, start.Add(2*time.Second), time.Second)
	lt.Add(10, start.Add(3*time.Second), time.Second)

	require.Equal(t, []protocol.PacketNumber{1, 5, 8, 10}, trackedPackets(lt))

	lt.DeleteBefore(start) // this should be a no-op
	require.Equal(t, []protocol.PacketNumber{1, 5, 8, 10}, trackedPackets(lt))

	lt.DeleteBefore(start.Add(2 * time.Second))
	require.Equal(t, []protocol.PacketNumber{8, 10}, trackedPackets(lt))

	lt.DeleteBefore(start.Add(time.Second * 5 / 2))
	require.Equal(t, []protocol.PacketNumber{10}, trackedPackets(lt))

	lt.DeleteBefore(start.Add(time.Hour))
	require.Empty(t, trackedPackets(lt))
}
