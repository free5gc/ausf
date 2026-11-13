package consumer

import (
	"context"
	"fmt"
	"mime"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"golang.org/x/oauth2"

	ausf_context "github.com/free5gc/ausf/internal/context"
	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/models"
	Nnrf_NFDiscovery "github.com/free5gc/openapi/nrf/NFDisc"
	"github.com/free5gc/util/nfheartbeat"
)

type oauthDownstreamRequest struct {
	Method        string
	Path          string
	Authorization string
}

type oauthTokenServer struct {
	*httptest.Server
	mu         sync.Mutex
	forms      []url.Values
	downstream []oauthDownstreamRequest
}

// Use real HTTP/2 cleartext, matching the production OpenAPI client. No gock
// interception, global transport replacement, or access to private caches.
func newOAuthTokenServer(t *testing.T, reply func(int) (int, string)) *oauthTokenServer {
	t.Helper()
	s := &oauthTokenServer{}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/oauth2/token" {
			mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
			if err != nil || mediaType != "application/x-www-form-urlencoded" || r.Method != http.MethodPost {
				t.Errorf("unexpected token request: %s %s, Content-Type %q", r.Method, r.URL, r.Header.Get("Content-Type"))
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if err := r.ParseForm(); err != nil {
				t.Errorf("parse token form: %v", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			s.mu.Lock()
			s.forms = append(s.forms, r.PostForm)
			count := len(s.forms)
			s.mu.Unlock()
			status, body := http.StatusOK, fmt.Sprintf(
				`{"access_token":"token-%d","token_type":"Bearer","expires_in":3600}`, count,
			)
			if reply != nil {
				status, body = reply(count)
			}
			w.WriteHeader(status)
			if _, err := w.Write([]byte(body)); err != nil {
				t.Errorf("write token response: %v", err)
			}
			return
		}

		s.mu.Lock()
		s.downstream = append(s.downstream, oauthDownstreamRequest{
			Method: r.Method, Path: r.URL.Path, Authorization: r.Header.Get("Authorization"),
		})
		s.mu.Unlock()
		switch {
		case r.Method == http.MethodPatch && strings.HasPrefix(r.URL.Path, "/nnrf-nfm/v1/nf-instances/"):
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/nnrf-nfm/v1/nf-instances/"):
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet && r.URL.Path == "/nnrf-disc/v1/nf-instances":
			if _, err := w.Write([]byte(`{"nfInstances":[],"validityPeriod":60}`)); err != nil {
				t.Errorf("write discovery response: %v", err)
			}
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/security-information/generate-auth-data"):
			if _, err := w.Write([]byte(`{}`)); err != nil {
				t.Errorf("write authentication data response: %v", err)
			}
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/auth-events"):
			w.WriteHeader(http.StatusCreated)
			if _, err := w.Write([]byte(`{}`)); err != nil {
				t.Errorf("write authentication event response: %v", err)
			}
		default:
			http.NotFound(w, r)
		}
	})
	s.Server = httptest.NewServer(h2c.NewHandler(handler, &http2.Server{}))
	t.Cleanup(s.Close)
	return s
}

func (s *oauthTokenServer) requests() ([]url.Values, []oauthDownstreamRequest) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]url.Values(nil), s.forms...), append([]oauthDownstreamRequest(nil), s.downstream...)
}

func requireOAuthTokenForm(t *testing.T, form url.Values, consumerID string,
	target models.Nrf_NFMgmt_NFType, targetID string, scope models.Nrf_NFMgmt_ServiceName,
) {
	t.Helper()
	want := url.Values{
		"grant_type":   {"client_credentials"},
		"nfInstanceId": {consumerID},
		"nfType":       {"AUSF"},
		"targetNfType": {string(target)},
		"scope":        {string(scope)},
	}
	if targetID != "" {
		want.Set("targetNfInstanceId", targetID)
	}
	require.Equal(t, want, form)
}

func TestOAuthTokenRequestAndCacheIsolation(t *testing.T) {
	s := newOAuthTokenServer(t, nil)
	consumerID, nrfID, otherNRFID := uuid.NewString(), uuid.NewString(), uuid.NewString()
	tests := []struct {
		name       string
		consumerID string
		target     models.Nrf_NFMgmt_NFType
		targetID   string
		scope      models.Nrf_NFMgmt_ServiceName
	}{
		{"UDM type token", consumerID, models.Nrf_NFMgmt_NFType_UDM, "", models.Nrf_NFMgmt_ServiceName_NUDM_UEAU},
		{"different target NF type", consumerID, models.Nrf_NFMgmt_NFType_AMF, "", models.Nrf_NFMgmt_ServiceName_NUDM_UEAU},
		{"NRF instance token", consumerID, models.Nrf_NFMgmt_NFType_NRF, nrfID, models.Nrf_NFMgmt_ServiceName_NNRF_NFM},
		{"different scope", consumerID, models.Nrf_NFMgmt_NFType_NRF, nrfID, models.Nrf_NFMgmt_ServiceName_NNRF_DISC},
		{
			"different target instance", consumerID,
			models.Nrf_NFMgmt_NFType_NRF, otherNRFID, models.Nrf_NFMgmt_ServiceName_NNRF_NFM,
		},
		{
			"type and instance targets stay separate", consumerID,
			models.Nrf_NFMgmt_NFType_NRF, "", models.Nrf_NFMgmt_ServiceName_NNRF_NFM,
		},
		{
			"different consumer instance", uuid.NewString(),
			models.Nrf_NFMgmt_NFType_NRF, nrfID, models.Nrf_NFMgmt_ServiceName_NNRF_NFM,
		},
	}
	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			self := &ausf_context.AUSFContext{
				NfId: tt.consumerID, NrfUri: s.URL, NrfNfInstanceID: tt.targetID, OAuth2Required: true,
			}
			for range 2 {
				var ctx context.Context
				var pd *models.ProblemDetails
				var err error
				if tt.targetID != "" {
					ctx, pd, err = self.GetTokenCtxForNRF(tt.scope)
				} else {
					ctx, pd, err = self.GetTokenCtx(tt.scope, tt.target)
				}
				require.NoError(t, err)
				require.Nil(t, pd)
				source, ok := ctx.Value(openapi.ContextOAuth2).(oauth2.TokenSource)
				require.True(t, ok)
				token, err := source.Token()
				require.NoError(t, err)
				require.Equal(t, fmt.Sprintf("token-%d", i+1), token.AccessToken)
			}
			forms, _ := s.requests()
			require.Len(t, forms, i+1)
			requireOAuthTokenForm(t, forms[i], tt.consumerID, tt.target, tt.targetID, tt.scope)
		})
	}
	// The NRF URI is also a cache dimension, even for the same consumer/target.
	other := newOAuthTokenServer(t, nil)
	self := &ausf_context.AUSFContext{NfId: consumerID, NrfUri: other.URL, OAuth2Required: true}
	_, _, err := self.GetTokenCtx(models.Nrf_NFMgmt_ServiceName_NUDM_UEAU, models.Nrf_NFMgmt_NFType_UDM)
	require.NoError(t, err)
	forms, _ := other.requests()
	require.Len(t, forms, 1)
}

func TestOAuthTokenCacheRefreshAfterExpiry(t *testing.T) {
	s := newOAuthTokenServer(t, func(count int) (int, string) {
		return http.StatusOK, fmt.Sprintf(`{"access_token":"token-%d","token_type":"Bearer","expires_in":1}`, count)
	})
	self := &ausf_context.AUSFContext{NfId: uuid.NewString(), NrfUri: s.URL, OAuth2Required: true}
	getToken := func() string {
		t.Helper()
		ctx, _, err := self.GetTokenCtx(models.Nrf_NFMgmt_ServiceName_NUDM_UEAU, models.Nrf_NFMgmt_NFType_UDM)
		require.NoError(t, err)
		source, ok := ctx.Value(openapi.ContextOAuth2).(oauth2.TokenSource)
		require.True(t, ok)
		token, err := source.Token()
		require.NoError(t, err)
		return token.AccessToken
	}
	require.Equal(t, "token-1", getToken())
	// The implementation uses Unix seconds and a real HTTP server, so wait past
	// the one-second lifetime instead of altering private caches or the clock.
	time.Sleep(1100 * time.Millisecond)
	require.Equal(t, "token-2", getToken())
	forms, _ := s.requests()
	require.Len(t, forms, 2)
}

func TestOAuthConsumersSendBearerTokens(t *testing.T) {
	s := newOAuthTokenServer(t, nil)
	self := ausf_context.GetSelf()
	// UDM currently reads the singleton. Restore only the fields this serial
	// test changes; never copy a context containing sync.Map or replace services.
	id, uri, nrfID, required := self.NfId, self.NrfUri, self.NrfNfInstanceID, self.OAuth2Required
	t.Cleanup(func() {
		self.NfId, self.NrfUri, self.NrfNfInstanceID, self.OAuth2Required = id, uri, nrfID, required
	})
	self.NfId, self.NrfUri, self.NrfNfInstanceID, self.OAuth2Required = uuid.NewString(), s.URL, uuid.NewString(), true
	c := newTestConsumer(t, self)
	_, pd, err := c.SendUpdateNFInstance(testCtx(t), nfheartbeat.PatchItems())
	require.NoError(t, err)
	require.Nil(t, pd)
	pd, err = c.SendDeregisterNFInstance()
	require.NoError(t, err)
	require.Nil(t, pd)
	target, requester := models.Nrf_NFMgmt_NFType_UDM, models.Nrf_NFMgmt_NFType_AUSF
	result, err := c.SendSearchNFInstances(s.URL, target, requester, Nnrf_NFDiscovery.SearchNFInstancesRequest{
		TargetNfType: &target, RequesterNfType: &requester,
	})
	require.NoError(t, err)
	require.NotNil(t, result)
	authData, err := c.GenerateAuthDataApi(s.URL, "imsi-001010000000001", models.Udm_UEAU_AuthenticationInfoRequest{})
	require.NoError(t, err)
	require.NotNil(t, authData)
	require.NoError(t, c.SendAuthResultToUDM("imsi-001010000000001", models.Udm_UEAU_AuthType_5_G_AKA, true,
		"5G:mnc001.mcc001.3gppnetwork.org", s.URL))

	forms, downstream := s.requests()
	require.Len(t, forms, 3)
	requireOAuthTokenForm(t, forms[0], self.NfId,
		models.Nrf_NFMgmt_NFType_NRF, self.NrfNfInstanceID, models.Nrf_NFMgmt_ServiceName_NNRF_NFM)
	requireOAuthTokenForm(t, forms[1], self.NfId,
		models.Nrf_NFMgmt_NFType_NRF, self.NrfNfInstanceID, models.Nrf_NFMgmt_ServiceName_NNRF_DISC)
	requireOAuthTokenForm(t, forms[2], self.NfId,
		models.Nrf_NFMgmt_NFType_UDM, "", models.Nrf_NFMgmt_ServiceName_NUDM_UEAU)
	require.Equal(t, []oauthDownstreamRequest{
		{http.MethodPatch, "/nnrf-nfm/v1/nf-instances/" + self.NfId, "Bearer token-1"},
		{http.MethodDelete, "/nnrf-nfm/v1/nf-instances/" + self.NfId, "Bearer token-1"},
		{http.MethodGet, "/nnrf-disc/v1/nf-instances", "Bearer token-2"},
		{http.MethodPost, "/nudm-ueau/v1/imsi-001010000000001/security-information/generate-auth-data", "Bearer token-3"},
		{http.MethodPost, "/nudm-ueau/v1/imsi-001010000000001/auth-events", "Bearer token-3"},
	}, downstream)
}

func TestOAuthTokenEndpointErrors(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
	}{
		{"NRF rejects request", http.StatusBadRequest, `{"error":"invalid_request"}`},
		{"NRF server error", http.StatusInternalServerError, `{"status":500,"cause":"SYSTEM_FAILURE"}`},
		{"malformed JSON", http.StatusOK, `{"access_token":`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newOAuthTokenServer(t, func(int) (int, string) { return tt.status, tt.body })
			c := newTestConsumer(t, &ausf_context.AUSFContext{
				NfId: uuid.NewString(), NrfUri: s.URL, NrfNfInstanceID: uuid.NewString(), OAuth2Required: true,
			})
			for range 2 {
				var requestErr error
				require.NotPanics(t, func() { _, requestErr = c.SendDeregisterNFInstance() })
				assert.Error(t, requestErr, "invalid token responses must stop the downstream request")
			}
			forms, downstream := s.requests()
			assert.Len(t, forms, 2, "errors must not populate the token cache")
			assert.Empty(t, downstream, "no DELETE may be sent after a token acquisition error")
		})
	}
}
