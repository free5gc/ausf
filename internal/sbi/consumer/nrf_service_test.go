package consumer

import (
	"testing"

	"github.com/h2non/gock"
	"github.com/stretchr/testify/require"

	ausf_context "github.com/free5gc/ausf/internal/context"
	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/models"
	Nnrf_NFDiscovery "github.com/free5gc/openapi/nrf/NFDisc"
)

func TestSendSearchNFInstancesUsesMigratedResponseBody(t *testing.T) {
	openapi.InterceptInnerHttp2Client(t, false)
	gock.New("http://nrf.test").
		Get("/nnrf-disc/v1/nf-instances").
		MatchParam("target-nf-type", "UDM").
		MatchParam("requester-nf-type", "AUSF").
		Reply(200).
		JSON(map[string]interface{}{
			"validityPeriod": 60,
			"nfInstances":    []interface{}{},
		})

	testConsumer := newTestConsumer(t, &ausf_context.AUSFContext{})
	targetNFType := models.Nrf_NFMgmt_NFType_UDM
	requesterNFType := models.Nrf_NFMgmt_NFType_AUSF
	request := Nnrf_NFDiscovery.SearchNFInstancesRequest{
		TargetNfType:    &targetNFType,
		RequesterNfType: &requesterNFType,
	}

	result, err := testConsumer.SendSearchNFInstances(
		"http://nrf.test",
		targetNFType,
		requesterNFType,
		request,
	)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, int32(60), result.ValidityPeriod)
	require.Empty(t, result.NfInstances)
	require.True(t, gock.IsDone())
}
