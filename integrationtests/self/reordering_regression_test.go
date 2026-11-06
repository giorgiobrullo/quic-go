package self_test

import (
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/require"
)

// TestReorderingDoesNotCollapseGoodput asserts that a path that reorders packets but
// drops none sustains a goodput comparable to the same path without reordering. The two
// delays straddle the initial time threshold of 9/8 of the RTT, so the shallow case is
// governed by the packet threshold and the deep one by the time threshold.
//
// The comparison is on the steady state. The first half of a transfer is dominated by
// slow start, where reordering delays the exit and therefore flatters whatever runs it.
func TestReorderingDoesNotCollapseGoodput(t *testing.T) {
	base := pathConditions{rtt: 55 * time.Millisecond, bandwidth: bw35Mbps, bufferBDP: 4}

	var baseline transferResult
	synctest.Test(t, func(t *testing.T) { baseline = runBulkTransfer(t, PRDataLong, base) })
	t.Logf("baseline:   %s", baseline)

	for _, delay := range []time.Duration{5 * time.Millisecond, 10 * time.Millisecond} {
		t.Run(delay.String(), func(t *testing.T) {
			c := base
			c.reorderFraction = 0.05
			c.reorderDelay = delay

			var reordered transferResult
			synctest.Test(t, func(t *testing.T) { reordered = runBulkTransfer(t, PRDataLong, c) })
			t.Logf("reordered:  %s", reordered)

			require.Greater(t, reordered.steadyGoodput, 0.7*baseline.steadyGoodput,
				"reordering without loss must not cost more than 30%% of the steady state goodput")
		})
	}
}
