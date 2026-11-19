package context

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRemoveUEAuthenticationContext(t *testing.T) {
	ctx := &AUSFContext{}
	const supi = "imsi-001010000000001"

	// Set up a stale UE context, an authentication of it in progress, and
	// another UE context that must be preserved.
	ctx.UePool.Store(supi, &AusfUeContext{Supi: supi, Kausf: "stale-key"})
	ctx.UePool.Store("other", &AusfUeContext{Supi: "other", Kausf: "keep-key"})
	inProgress := &AusfUeContext{Supi: supi, Kausf: "new-key"}
	ctx.AddAuthCtx("suci-one", inProgress)

	// Verify that the target UE context is removed and the authentication in
	// progress is kept.
	require.True(t, ctx.RemoveUEAuthenticationContext(supi))
	_, exists := ctx.UePool.Load(supi)
	require.False(t, exists)
	got, exists := ctx.GetAuthCtx("suci-one")
	require.True(t, exists)
	require.Same(t, inProgress, got)

	// Ensure unrelated UE data remains intact and repeated removal returns false.
	_, exists = ctx.UePool.Load("other")
	require.True(t, exists)
	require.False(t, ctx.RemoveUEAuthenticationContext(supi))
}
