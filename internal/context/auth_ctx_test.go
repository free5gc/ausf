package context

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const (
	authCtxTestSupi = "imsi-208930000000001"
	authCtxTestSuci = "suci-0-208-93-0000-0-0-0000000001"
)

// useClock makes the authentication context store read the time from *clock
// until the end of the test.
func useClock(t *testing.T, clock *time.Time) {
	now = func() time.Time { return *clock }
	t.Cleanup(func() { now = time.Now })
}

func TestAuthCtxExpires(t *testing.T) {
	clock := time.Unix(1_000_000, 0)
	useClock(t, &clock)
	ctx := &AUSFContext{}
	ue := &AusfUeContext{Supi: authCtxTestSupi}
	ctx.AddAuthCtx(authCtxTestSuci, ue)

	clock = clock.Add(authCtxLifetime - time.Nanosecond)
	got, ok := ctx.GetAuthCtx(authCtxTestSuci)
	require.True(t, ok)
	require.Same(t, ue, got)

	clock = clock.Add(time.Nanosecond)
	_, ok = ctx.GetAuthCtx(authCtxTestSuci)
	require.False(t, ok, "an expired authentication is found")

	// The next authentication removes the expired one from the store.
	ctx.AddAuthCtx("suci-0-208-93-0000-0-0-0000000002", &AusfUeContext{Supi: "imsi-208930000000002"})
	require.Len(t, ctx.authCtxs, 1)
	require.Len(t, ctx.authCtxExpiries, 1)
}

func TestConfirmAuthCtxMovesToSupi(t *testing.T) {
	ctx := &AUSFContext{}
	first := &AusfUeContext{Supi: authCtxTestSupi, Kausf: "first"}
	second := &AusfUeContext{Supi: authCtxTestSupi, Kausf: "second"}
	ctx.AddAuthCtx(authCtxTestSuci, first)
	ctx.AddAuthCtx(authCtxTestSupi, second)

	ctx.ConfirmAuthCtx(authCtxTestSuci, first)
	_, ok := ctx.GetAuthCtx(authCtxTestSuci)
	require.False(t, ok)
	confirmed, ok := ctx.UePool.Load(authCtxTestSupi)
	require.True(t, ok)
	require.Same(t, first, confirmed)

	// A later confirmation replaces the subscriber's confirmed context.
	ctx.ConfirmAuthCtx(authCtxTestSupi, second)
	_, ok = ctx.GetAuthCtx(authCtxTestSupi)
	require.False(t, ok)
	confirmed, ok = ctx.UePool.Load(authCtxTestSupi)
	require.True(t, ok)
	require.Same(t, second, confirmed)
}

// An authentication whose authCtxId is the SUPI must not replace the
// subscriber's confirmed context, and its expiry must not remove it.
func TestAuthCtxUnderSupiKeepsConfirmedContext(t *testing.T) {
	clock := time.Unix(1_000_000, 0)
	useClock(t, &clock)
	ctx := &AUSFContext{}
	confirmed := &AusfUeContext{Supi: authCtxTestSupi, Kausf: "confirmed"}
	ctx.AddAuthCtx(authCtxTestSuci, confirmed)
	ctx.ConfirmAuthCtx(authCtxTestSuci, confirmed)

	inProgress := &AusfUeContext{Supi: authCtxTestSupi, Kausf: "in progress"}
	ctx.AddAuthCtx(authCtxTestSupi, inProgress)
	got, ok := ctx.GetAuthCtx(authCtxTestSupi)
	require.True(t, ok)
	require.Same(t, inProgress, got)
	stored, ok := ctx.UePool.Load(authCtxTestSupi)
	require.True(t, ok)
	require.Same(t, confirmed, stored)

	clock = clock.Add(authCtxLifetime)
	ctx.AddAuthCtx("suci-0-208-93-0000-0-0-0000000002", &AusfUeContext{Supi: "imsi-208930000000002"})
	_, ok = ctx.GetAuthCtx(authCtxTestSupi)
	require.False(t, ok)
	stored, ok = ctx.UePool.Load(authCtxTestSupi)
	require.True(t, ok)
	require.Same(t, confirmed, stored)
}

// A resynchronisation stores its new authentication under the authCtxId of the
// one it replaces; the expiry of the replaced one must not remove it.
func TestAuthCtxReplacedUnderSameAuthCtxId(t *testing.T) {
	clock := time.Unix(1_000_000, 0)
	useClock(t, &clock)
	ctx := &AUSFContext{}
	ctx.AddAuthCtx(authCtxTestSuci, &AusfUeContext{Supi: authCtxTestSupi, Rand: "first"})
	clock = clock.Add(authCtxLifetime / 2)
	resynced := &AusfUeContext{Supi: authCtxTestSupi, Rand: "resynced"}
	ctx.AddAuthCtx(authCtxTestSuci, resynced)
	require.Len(t, ctx.authCtxs, 1)

	clock = clock.Add(authCtxLifetime / 2)
	ctx.AddAuthCtx("suci-0-208-93-0000-0-0-0000000002", &AusfUeContext{Supi: "imsi-208930000000002"})
	got, ok := ctx.GetAuthCtx(authCtxTestSuci)
	require.True(t, ok)
	require.Same(t, resynced, got)
}

// The confirmation of an authentication that a newer one under the same
// authCtxId has replaced must not remove the newer one.
func TestConfirmAuthCtxKeepsReplacement(t *testing.T) {
	ctx := &AUSFContext{}
	old := &AusfUeContext{Supi: authCtxTestSupi, Kausf: "old"}
	replacement := &AusfUeContext{Supi: authCtxTestSupi, Kausf: "replacement"}
	ctx.AddAuthCtx(authCtxTestSuci, old)
	ctx.AddAuthCtx(authCtxTestSuci, replacement)

	ctx.ConfirmAuthCtx(authCtxTestSuci, old)
	got, ok := ctx.GetAuthCtx(authCtxTestSuci)
	require.True(t, ok)
	require.Same(t, replacement, got)
	confirmed, ok := ctx.UePool.Load(authCtxTestSupi)
	require.True(t, ok)
	require.Same(t, old, confirmed)
}
