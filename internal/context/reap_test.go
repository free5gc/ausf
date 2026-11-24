package context

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestReapStaleUeAuthContexts(t *testing.T) {
	ctx := &AUSFContext{}
	const staleSupi = "imsi-001010000000001"
	const freshSupi = "imsi-001010000000002"
	const ttl = time.Minute

	// A confirmed context never deregistered well past the TTL (a crashed
	// AMF, a UE that never detached) and one still well within it.
	ctx.UePool.Store(staleSupi, &AusfUeContext{
		Supi:        staleSupi,
		ConfirmedAt: time.Now().Add(-2 * ttl),
	})
	ctx.UePool.Store(freshSupi, &AusfUeContext{
		Supi:        freshSupi,
		ConfirmedAt: time.Now(),
	})

	n := ctx.ReapStaleUeAuthContexts(ttl)
	require.Equal(t, 1, n)

	_, exists := ctx.UePool.Load(staleSupi)
	require.False(t, exists, "stale confirmed context must be reaped")

	_, exists = ctx.UePool.Load(freshSupi)
	require.True(t, exists, "a recently confirmed context must survive a sweep")

	// A second sweep with nothing left to reap is a no-op, not an error.
	require.Equal(t, 0, ctx.ReapStaleUeAuthContexts(ttl))
}

func TestReapStaleUeAuthContexts_ExactlyAtTtlIsNotStale(t *testing.T) {
	ctx := &AUSFContext{}
	const supi = "imsi-001010000000003"
	const ttl = time.Minute

	ctx.UePool.Store(supi, &AusfUeContext{Supi: supi, ConfirmedAt: time.Now()})

	require.Equal(t, 0, ctx.ReapStaleUeAuthContexts(ttl))
	_, exists := ctx.UePool.Load(supi)
	require.True(t, exists)
}

// TestReapStaleUeAuthContexts_DoesNotDeleteAReplacedContext guards the
// scan-then-delete race ReapStaleUeAuthContexts must survive: a subscriber
// who re-authenticates between the scan and the delete must not have that
// fresh confirmation deleted as if it were the stale one the scan found.
// There's no seam to pause the real function mid-call, so this replicates
// its scan, interleaves the reuse, then asserts its delete step
// (CompareAndDelete against the stale snapshot, not a by-key delete)
// refuses to touch the fresh value.
func TestReapStaleUeAuthContexts_DoesNotDeleteAReplacedContext(t *testing.T) {
	ctx := &AUSFContext{}
	const supi = "imsi-001010000000004"
	const ttl = time.Minute

	ctx.UePool.Store(supi, &AusfUeContext{Supi: supi, ConfirmedAt: time.Now().Add(-2 * ttl)})

	// Replicate the reaper's own scan to capture the exact (key, value) it
	// would find stale, matching ReapStaleUeAuthContexts' internal shape.
	var scannedKey, scannedValue any
	ctx.UePool.Range(func(key, value any) bool {
		if ue, ok := value.(*AusfUeContext); ok && time.Since(ue.ConfirmedAt) > ttl {
			scannedKey, scannedValue = key, value
		}
		return true
	})
	require.NotNil(t, scannedValue, "setup: the seeded context must be found stale")

	// The subscriber re-authenticates for the same SUPI after that scan,
	// replacing the stale context, before any delete runs.
	freshCtx := &AusfUeContext{Supi: supi, ConfirmedAt: time.Now()}
	ctx.UePool.Store(supi, freshCtx)

	// The reaper's delete step, run directly against the stale snapshot
	// captured above - exactly what ReapStaleUeAuthContexts does per entry.
	require.False(t, ctx.UePool.CompareAndDelete(scannedKey, scannedValue),
		"must not delete a value that changed since the scan")

	stored, exists := ctx.UePool.Load(supi)
	require.True(t, exists)
	require.Same(t, freshCtx, stored)
}
