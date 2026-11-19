package processor

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/h2non/gock"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	ausf_context "github.com/free5gc/ausf/internal/context"
	"github.com/free5gc/ausf/internal/sbi/consumer"
	"github.com/free5gc/ausf/pkg/app"
	"github.com/free5gc/ausf/pkg/factory"
	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/models"
)

const (
	resyncSupi       = "imsi-208930000000001"
	resyncSuci       = "suci-0-208-93-0000-0-0-0000000001"
	resyncSnName     = "5G:mnc093.mcc208.3gppnetwork.org"
	resyncStoredRand = "0123456789abcdef0123456789abcdef"
	resyncAuts       = "00112233445566778899aabbccdd"
)

type resyncTestApp struct {
	*app.MockApp
	consumer *consumer.Consumer
}

func (a *resyncTestApp) Consumer() *consumer.Consumer { return a.consumer }

// newResyncTestProcessor stores an authentication context for resyncSupi and
// mocks NRF discovery and the UDM. The UDM rejects every request, as the real
// one would for these made-up AUTS values; the returned slice records the
// resynchronizationInfo of each request it received.
func newResyncTestProcessor(t *testing.T) (*Processor, *[]models.Udm_UEAU_ResynchronizationInfo) {
	gin.SetMode(gin.TestMode)
	factory.AusfConfig = &factory.Config{
		Info: &factory.Info{Version: "1.0.3"},
		Configuration: &factory.Configuration{
			Sbi:    &factory.Sbi{Scheme: "http", RegisterIPv4: "127.0.0.9", Port: 8000},
			NrfUri: "http://nrf.test",
		},
	}
	ausf_context.Init()
	ausf_context.AddAusfUeContextToPool(&ausf_context.AusfUeContext{
		Supi:               resyncSupi,
		ServingNetworkName: resyncSnName,
		AuthStatus:         models.Ausf_UEAU_AuthResult_ONGOING,
		Rand:               resyncStoredRand,
	})
	ausf_context.AddSuciSupiPairToMap(resyncSuci, resyncSupi)
	t.Cleanup(func() { ausf_context.GetSelf().UePool.Delete(resyncSupi) })

	openapi.InterceptInnerHttp2Client(t, false)
	t.Cleanup(gock.Off)
	gock.New("http://nrf.test").Get("/nnrf-disc/v1/nf-instances").Persist().Reply(http.StatusOK).
		JSON(map[string]interface{}{"nfInstances": []interface{}{map[string]interface{}{
			"nfInstanceId": "udm", "nfType": "UDM", "nfStatus": "REGISTERED",
			"nfServices": []interface{}{map[string]interface{}{
				"serviceInstanceId": "1", "serviceName": "nudm-ueau", "scheme": "http",
				"nfServiceStatus": "REGISTERED",
				"versions":        []interface{}{map[string]interface{}{"apiVersionInUri": "v1"}},
				"ipEndPoints":     []interface{}{map[string]interface{}{"ipv4Address": "127.0.0.3", "port": 8000}},
			}},
		}}})
	forwarded := []models.Udm_UEAU_ResynchronizationInfo{}
	gock.New("http://127.0.0.3:8000").Post("/nudm-ueau/v1/" + resyncSuci + "/security-information/generate-auth-data").
		Persist().
		AddMatcher(func(r *http.Request, _ *gock.Request) (bool, error) {
			body, err := io.ReadAll(r.Body)
			r.Body = io.NopCloser(bytes.NewReader(body))
			var req models.Udm_UEAU_AuthenticationInfoRequest
			if err == nil {
				err = json.Unmarshal(body, &req)
			}
			if err == nil && req.ResynchronizationInfo != nil {
				forwarded = append(forwarded, *req.ResynchronizationInfo)
			}
			return err == nil, err
		}).
		Reply(http.StatusForbidden).
		JSON(models.ProblemDetails{Status: http.StatusForbidden, Cause: "AUTHENTICATION_REJECTED"})

	mockApp := app.NewMockApp(gomock.NewController(t))
	mockApp.EXPECT().Context().Return(ausf_context.GetSelf()).AnyTimes()
	c, err := consumer.NewConsumer(mockApp)
	require.NoError(t, err)
	p, err := NewProcessor(&resyncTestApp{MockApp: mockApp, consumer: c})
	require.NoError(t, err)
	return p, &forwarded
}

func TestUeAuthResyncBindsRandToAuthContext(t *testing.T) {
	testCases := []struct {
		name      string
		rand      string
		snName    string
		forwarded bool
	}{
		{"RAND of the context", resyncStoredRand, resyncSnName, true},
		{"RAND of the context in upper case", "0123456789ABCDEF0123456789ABCDEF", resyncSnName, true},
		{"RAND of another challenge", "fedcba9876543210fedcba9876543210", resyncSnName, false},
		{"other serving network", resyncStoredRand, "5G:mnc001.mcc001.3gppnetwork.org", false},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			p, forwarded := newResyncTestProcessor(t)
			rec := httptest.NewRecorder()
			ginCtx, _ := gin.CreateTestContext(rec)
			p.UeAuthPostRequestProcedure(ginCtx, models.Ausf_UEAU_AuthenticationInfo{
				SupiOrSuci:         resyncSuci,
				ServingNetworkName: tc.snName,
				ResynchronizationInfo: &models.Udm_UEAU_ResynchronizationInfo{
					Rand: tc.rand, Auts: resyncAuts,
				},
			})

			require.Equal(t, http.StatusForbidden, rec.Code)
			if tc.forwarded {
				require.Equal(t, []models.Udm_UEAU_ResynchronizationInfo{{Rand: tc.rand, Auts: resyncAuts}}, *forwarded)
			} else {
				require.Empty(t, *forwarded, "request must not reach the UDM")
			}
		})
	}
}

func TestEapAkaPrimeSynchronizationFailureUsesContextRand(t *testing.T) {
	p, forwarded := newResyncTestProcessor(t)
	auts, err := hex.DecodeString(resyncAuts)
	require.NoError(t, err)
	// EAP-Response/AKA'-Synchronization-Failure carrying AT_AUTS and AT_KDF, but no RAND.
	pkt := append([]byte{
		2, 1, 0, 28, ausf_context.EAP_AKA_PRIME_TYPENUM, ausf_context.AKA_SYNCHRONIZATION_FAILURE_SUBTYPE, 0, 0,
		ausf_context.AT_AUTS_ATTRIBUTE, 4,
	}, auts...)
	pkt = append(pkt, ausf_context.AT_KDF_ATTRIBUTE, 1, 0, 1)

	ginCtx, _ := gin.CreateTestContext(httptest.NewRecorder())
	p.EapAuthComfirmRequestProcedure(ginCtx,
		models.Ausf_UEAU_EapSession{EapPayload: base64.StdEncoding.EncodeToString(pkt)}, resyncSuci)

	require.Equal(t, []models.Udm_UEAU_ResynchronizationInfo{{Rand: resyncStoredRand, Auts: resyncAuts}}, *forwarded)
}
