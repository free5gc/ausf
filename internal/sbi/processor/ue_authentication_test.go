package processor

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
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
	"github.com/free5gc/util/ueauth"
)

func TestAuth5gAkaConfirmRejectsMissingResStar(t *testing.T) {
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)

	processor := &Processor{}
	processor.Auth5gAkaComfirmRequestProcedure(
		c,
		models.Ausf_UEAU_ConfirmationData{},
		"suci-0-001-01-0000-0-0-0000000001",
	)

	require.Equal(t, http.StatusBadRequest, recorder.Code)
	var problemDetails models.ProblemDetails
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &problemDetails))
	require.Equal(t, "MANDATORY_IE_MISSING", problemDetails.Cause)
}

type testApp struct {
	*app.MockApp
	consumer *consumer.Consumer
}

func (a *testApp) Consumer() *consumer.Consumer { return a.consumer }

// newTestProcessor returns a processor whose NRF discovery finds a UDM at
// http://127.0.0.3:8000; the caller mocks the UDM. The authentication
// contexts that the test stores are removed at its end.
func newTestProcessor(t *testing.T) *Processor {
	gin.SetMode(gin.TestMode)
	factory.AusfConfig = &factory.Config{
		Info: &factory.Info{Version: "1.0.3"},
		Configuration: &factory.Configuration{
			Sbi:    &factory.Sbi{Scheme: "http", RegisterIPv4: "127.0.0.9", Port: 8000},
			NrfUri: "http://nrf.test",
		},
	}
	ausf_context.Init()
	t.Cleanup(func() {
		ausf_context.GetSelf().UePool.Range(func(key, _ any) bool {
			ausf_context.GetSelf().UePool.Delete(key)
			return true
		})
	})

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

	mockApp := app.NewMockApp(gomock.NewController(t))
	mockApp.EXPECT().Context().Return(ausf_context.GetSelf()).AnyTimes()
	c, err := consumer.NewConsumer(mockApp)
	require.NoError(t, err)
	p, err := NewProcessor(&testApp{MockApp: mockApp, consumer: c})
	require.NoError(t, err)
	return p
}

// Two 5G AKA authentications of one subscriber, under two SUCIs, run at the
// same time. Each confirmation must be checked against the XRES* of its own
// authentication and return its own KSEAF.
func TestAuth5gAkaConfirmKeepsEachAuthenticationOfOneSupi(t *testing.T) {
	const (
		supi   = "imsi-208930000000001"
		snName = "5G:mnc093.mcc208.3gppnetwork.org"
	)
	auths := []struct {
		suci, rand, xresStar, kausf string
		authCtxId                   string
	}{
		{
			suci:     "suci-0-208-93-0000-0-0-0000000001",
			rand:     "11111111111111111111111111111111",
			xresStar: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			kausf:    strings.Repeat("a1", 32),
		},
		{
			suci:     "suci-0-208-93-9999-0-0-0000000001",
			rand:     "22222222222222222222222222222222",
			xresStar: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			kausf:    strings.Repeat("b2", 32),
		},
	}

	p := newTestProcessor(t)
	for _, a := range auths {
		gock.New("http://127.0.0.3:8000").
			Post("/nudm-ueau/v1/" + a.suci + "/security-information/generate-auth-data").
			Reply(http.StatusOK).
			JSON(models.Udm_UEAU_AuthenticationInfoResult{
				AuthType: models.Udm_UEAU_AuthType_5_G_AKA,
				Supi:     supi,
				AuthenticationVector: &models.Udm_UEAU_AuthenticationVector{
					AvType:   models.Udm_UEAU_AvType_5_G_HE_AKA,
					Rand:     a.rand,
					Autn:     "33333333333333333333333333333333",
					XresStar: a.xresStar,
					Kausf:    a.kausf,
				},
			})
	}
	gock.New("http://127.0.0.3:8000").Post("/nudm-ueau/v1/.*/auth-events").Persist().
		Reply(http.StatusCreated).JSON(models.Udm_UEAU_AuthEvent{})

	for i := range auths {
		rec := httptest.NewRecorder()
		ginCtx, _ := gin.CreateTestContext(rec)
		p.UeAuthPostRequestProcedure(ginCtx, models.Ausf_UEAU_AuthenticationInfo{
			SupiOrSuci:         auths[i].suci,
			ServingNetworkName: snName,
		})
		require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
		var authCtx models.Ausf_UEAU_UEAuthenticationCtx
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &authCtx))
		href := authCtx.Links["5g-aka"][0].Href
		_, path, _ := strings.Cut(href, "/ue-authentications/")
		auths[i].authCtxId = strings.TrimSuffix(path, "/5g-aka-confirmation")
	}

	for _, a := range auths {
		kausf, err := hex.DecodeString(a.kausf)
		require.NoError(t, err)
		kseaf, err := ueauth.GetKDFValue(kausf, ueauth.FC_FOR_KSEAF_DERIVATION, []byte(snName),
			ueauth.KDFLen([]byte(snName)))
		require.NoError(t, err)

		rec := httptest.NewRecorder()
		ginCtx, _ := gin.CreateTestContext(rec)
		resStar := a.xresStar
		p.Auth5gAkaComfirmRequestProcedure(ginCtx, models.Ausf_UEAU_ConfirmationData{ResStar: &resStar}, a.authCtxId)

		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		var rsp models.Ausf_UEAU_ConfirmationDataResponse
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &rsp))
		require.Equal(t, models.Ausf_UEAU_AuthResult_SUCCESS, rsp.AuthResult, "confirmation of %s", a.suci)
		require.Equal(t, supi, rsp.Supi)
		require.Equal(t, hex.EncodeToString(kseaf), rsp.Kseaf)
	}
}
