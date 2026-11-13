package context

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRemoveUEAuthenticationContext(t *testing.T) {
	ctx := &AUSFContext{}
	const supi = "imsi-001010000000001"

	// Set up a stale UE context and another UE context that must be preserved.
	ctx.UePool.Store(supi, &AusfUeContext{Supi: supi, Kausf: "stale-key"})
	ctx.UePool.Store("other", &AusfUeContext{Supi: "other", Kausf: "keep-key"})
	for _, alias := range []string{supi, "suci-one", "suci-two"} {
		ctx.suciSupiMap.Store(alias, &SuciSupiMap{Supi: supi})
	}
	ctx.suciSupiMap.Store("other-alias", &SuciSupiMap{Supi: "other"})

	// Verify that the target UE context and all associated SUPI/SUCI mappings are removed.
	require.True(t, ctx.RemoveUEAuthenticationContext(supi))
	_, exists := ctx.UePool.Load(supi)
	require.False(t, exists)
	for _, alias := range []string{supi, "suci-one", "suci-two"} {
		_, exists = ctx.suciSupiMap.Load(alias)
		require.False(t, exists)
	}

	// Ensure unrelated UE data remains intact and repeated removal returns false.
	_, exists = ctx.UePool.Load("other")
	require.True(t, exists)
	_, exists = ctx.suciSupiMap.Load("other-alias")
	require.True(t, exists)
	require.False(t, ctx.RemoveUEAuthenticationContext(supi))
}
