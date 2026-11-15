package processor

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
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
)

const (
	confirmTestSupi   = "imsi-208930000000001"
	confirmTestSuci   = "suci-0-208-93-0000-0-0-0000000001"
	confirmTestSnName = "5G:mnc093.mcc208.3gppnetwork.org"
)

type confirmTestApp struct {
	*app.MockApp
	consumer *consumer.Consumer
}

func (a *confirmTestApp) Consumer() *consumer.Consumer { return a.consumer }

// startAuthentication runs the POST of a UE authentication for confirmTestSuci,
// for which a mocked UDM answers with the given result, and returns the
// processor and the authCtxId of the authentication.
func startAuthentication(t *testing.T, result models.Udm_UEAU_AuthenticationInfoResult) (*Processor, string) {
	gin.SetMode(gin.TestMode)
	factory.AusfConfig = &factory.Config{
		Info: &factory.Info{Version: "1.0.3"},
		Configuration: &factory.Configuration{
			Sbi:    &factory.Sbi{Scheme: "http", RegisterIPv4: "127.0.0.9", Port: 8000},
			NrfUri: "http://nrf.test",
		},
	}
	ausf_context.Init()
	t.Cleanup(func() { ausf_context.GetSelf().RemoveUEAuthenticationContext(confirmTestSupi) })

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
	gock.New("http://127.0.0.3:8000").
		Post("/nudm-ueau/v1/" + confirmTestSuci + "/security-information/generate-auth-data").
		Reply(http.StatusOK).JSON(result)
	gock.New("http://127.0.0.3:8000").Post("/nudm-ueau/v1/.*/auth-events").Persist().
		Reply(http.StatusCreated).JSON(models.Udm_UEAU_AuthEvent{})

	mockApp := app.NewMockApp(gomock.NewController(t))
	mockApp.EXPECT().Context().Return(ausf_context.GetSelf()).AnyTimes()
	c, err := consumer.NewConsumer(mockApp)
	require.NoError(t, err)
	p, err := NewProcessor(&confirmTestApp{MockApp: mockApp, consumer: c})
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	ginCtx, _ := gin.CreateTestContext(rec)
	p.UeAuthPostRequestProcedure(ginCtx, models.Ausf_UEAU_AuthenticationInfo{
		SupiOrSuci:         confirmTestSuci,
		ServingNetworkName: confirmTestSnName,
	})
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	_, authCtxId, _ := strings.Cut(rec.Header().Get("Location"), "/ue-authentications/")
	return p, authCtxId
}

// A 5G AKA confirmation for an authentication that the UDM made EAP-AKA' must
// be refused: that context has no XRES*, which an empty RES* matched.
func TestAuth5gAkaConfirmRejectsEapAkaPrimeContext(t *testing.T) {
	p, authCtxId := startAuthentication(t, models.Udm_UEAU_AuthenticationInfoResult{
		AuthType: models.Udm_UEAU_AuthType_EAP_AKA_PRIME,
		Supi:     confirmTestSupi,
		AuthenticationVector: &models.Udm_UEAU_AuthenticationVector{
			AvType:  models.Udm_UEAU_AvType_EAP_AKA_PRIME,
			Rand:    "11111111111111111111111111111111",
			Autn:    "22222222222222222222222222222222",
			Xres:    "3333333333333333",
			CkPrime: "44444444444444444444444444444444",
			IkPrime: "55555555555555555555555555555555",
		},
	})

	for _, tc := range []struct{ resStar, cause string }{
		{"", "MANDATORY_IE_INCORRECT"},
		{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "USER_NOT_FOUND"},
	} {
		rec := httptest.NewRecorder()
		ginCtx, _ := gin.CreateTestContext(rec)
		resStar := tc.resStar
		p.Auth5gAkaComfirmRequestProcedure(ginCtx, models.Ausf_UEAU_ConfirmationData{ResStar: &resStar}, authCtxId)

		require.Equal(t, http.StatusBadRequest, rec.Code, "resStar %q: %s", tc.resStar, rec.Body.String())
		var problemDetails models.ProblemDetails
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &problemDetails))
		require.Equal(t, tc.cause, problemDetails.Cause)
	}
}

// eapChallengeResponseWithEmptyKey returns an EAP-Response/AKA'-Challenge with
// a 4-octet AT_RES and an AT_MAC computed with an empty K_aut.
func eapChallengeResponseWithEmptyKey() []byte {
	pkt := []byte{2, 7, 0, 0, ausf_context.EAP_AKA_PRIME_TYPENUM, ausf_context.AKA_CHALLENGE_SUBTYPE, 0, 0}
	pkt = append(pkt, ausf_context.AT_RES_ATTRIBUTE, 2, 0, 32, 0, 0, 0, 0)
	pkt = append(pkt, ausf_context.AT_MAC_ATTRIBUTE, 5, 0, 0)
	macAt := len(pkt)
	pkt = append(pkt, make([]byte, 16)...)
	pkt[2], pkt[3] = byte(len(pkt)>>8), byte(len(pkt))
	h := hmac.New(sha256.New, nil)
	h.Write(pkt)
	copy(pkt[macAt:], h.Sum(nil)[:16])
	return pkt
}

// An EAP-AKA' session for an authentication that the UDM made 5G AKA must be
// refused: that context has no K_aut, so a MAC computed with an empty key
// passed the integrity check.
func TestEapAuthConfirmRejects5gAkaContext(t *testing.T) {
	p, authCtxId := startAuthentication(t, models.Udm_UEAU_AuthenticationInfoResult{
		AuthType: models.Udm_UEAU_AuthType_5_G_AKA,
		Supi:     confirmTestSupi,
		AuthenticationVector: &models.Udm_UEAU_AuthenticationVector{
			AvType:   models.Udm_UEAU_AvType_5_G_HE_AKA,
			Rand:     "11111111111111111111111111111111",
			Autn:     "22222222222222222222222222222222",
			XresStar: "33333333333333333333333333333333",
			Kausf:    strings.Repeat("44", 32),
		},
	})

	rec := httptest.NewRecorder()
	ginCtx, _ := gin.CreateTestContext(rec)
	p.EapAuthComfirmRequestProcedure(ginCtx, models.Ausf_UEAU_EapSession{
		EapPayload: base64.StdEncoding.EncodeToString(eapChallengeResponseWithEmptyKey()),
	}, authCtxId)

	require.Equal(t, http.StatusNotFound, rec.Code, rec.Body.String())
	var problemDetails models.ProblemDetails
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &problemDetails))
	require.Equal(t, "USER_NOT_FOUND", problemDetails.Cause)
}

func TestConstantTimeEqualRejectsEmptyValues(t *testing.T) {
	require.False(t, constantTimeEqual(nil, nil))
	require.False(t, constantTimeHexEqual("", ""))
	require.True(t, constantTimeHexEqual("00ff", "00FF"))
}

func TestAuth5gAkaConfirmRejectsEmptyResStar(t *testing.T) {
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)

	resStar := ""
	processor := &Processor{}
	processor.Auth5gAkaComfirmRequestProcedure(
		c,
		models.Ausf_UEAU_ConfirmationData{ResStar: &resStar},
		"suci-0-001-01-0000-0-0-0000000001",
	)

	require.Equal(t, http.StatusBadRequest, recorder.Code)
	var problemDetails models.ProblemDetails
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &problemDetails))
	require.Equal(t, "MANDATORY_IE_INCORRECT", problemDetails.Cause)
}
