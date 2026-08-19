package consumer

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/h2non/gock"
	"github.com/stretchr/testify/require"

	ausf_context "github.com/free5gc/ausf/internal/context"
	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/models"
)

func TestGenerateAuthDataUsesMigratedRequestBody(t *testing.T) {
	openapi.InterceptInnerHttp2Client(t, false)
	request := models.Udm_UEAU_AuthenticationInfoRequest{
		ServingNetworkName: "5G:mnc001.mcc001.3gppnetwork.org",
		AusfInstanceId:     "ausf-instance-id",
		SupportedFeatures:  "1",
	}
	gock.New("http://udm.test").
		Post("/nudm-ueau/v1/suci-0-001-01-0000-0-0-0000000001/security-information/generate-auth-data").
		JSON(request).
		Reply(200).
		JSON(map[string]interface{}{})

	testConsumer := newTestConsumer(t, &ausf_context.AUSFContext{})
	result, err := testConsumer.GenerateAuthDataApi(
		"http://udm.test",
		"suci-0-001-01-0000-0-0-0000000001",
		request,
	)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.True(t, gock.IsDone())
}

func TestSendAuthResultUsesMigratedRequestBody(t *testing.T) {
	openapi.InterceptInnerHttp2Client(t, false)
	var received models.Udm_UEAU_AuthEvent
	gock.New("http://udm.test").
		Post("/nudm-ueau/v1/imsi-001010000000001/auth-events").
		AddMatcher(func(request *http.Request, _ *gock.Request) (bool, error) {
			body, err := io.ReadAll(request.Body)
			if err != nil {
				return false, err
			}
			request.Body = io.NopCloser(bytes.NewReader(body))
			if err = json.Unmarshal(body, &received); err != nil {
				return false, err
			}
			return received.AuthType == models.Udm_UEAU_AuthType_5_G_AKA &&
				received.Success &&
				received.ServingNetworkName == "5G:mnc001.mcc001.3gppnetwork.org" &&
				received.NfInstanceId == "ausf-instance-id", nil
		}).
		Reply(201).
		JSON(map[string]interface{}{})

	testContext := &ausf_context.AUSFContext{NfId: "ausf-instance-id"}
	testConsumer := newTestConsumer(t, testContext)
	err := testConsumer.SendAuthResultToUDM(
		"imsi-001010000000001",
		models.Udm_UEAU_AuthType_5_G_AKA,
		true,
		"5G:mnc001.mcc001.3gppnetwork.org",
		"http://udm.test",
	)

	require.NoError(t, err)
	require.NotNil(t, received.TimeStamp)
	require.True(t, gock.IsDone())
}
