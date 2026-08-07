package consumer

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	ausf_context "github.com/free5gc/ausf/internal/context"
	"github.com/free5gc/ausf/pkg/app"
)

func newTestConsumer(t *testing.T, ctx *ausf_context.AUSFContext) *Consumer {
	t.Helper()

	controller := gomock.NewController(t)
	mockApp := app.NewMockApp(controller)
	mockApp.EXPECT().Context().Return(ctx).AnyTimes()

	testConsumer, err := NewConsumer(mockApp)
	require.NoError(t, err)
	return testConsumer
}
