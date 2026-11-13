package sbi

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"

	ausf_context "github.com/free5gc/ausf/internal/context"
	"github.com/free5gc/ausf/internal/sbi/consumer"
	"github.com/free5gc/ausf/internal/sbi/processor"
	"github.com/free5gc/ausf/pkg/app"
	"github.com/free5gc/ausf/pkg/factory"
	"github.com/free5gc/openapi/models"
)

type deregisterTestApp struct {
	app.App
	ctx *ausf_context.AUSFContext
	p   *processor.Processor
}

func (a *deregisterTestApp) Context() *ausf_context.AUSFContext { return a.ctx }
func (a *deregisterTestApp) Processor() *processor.Processor    { return a.p }
func (a *deregisterTestApp) Consumer() *consumer.Consumer       { return nil }

type deregisterClaims struct {
	Scope string `json:"scope"`
	jwt.RegisteredClaims
}

func TestDeregisterRouteOAuthAndCleanup(t *testing.T) {
	gin.SetMode(gin.TestMode)
	const (
		nrfID     = "73beea45-663c-4bb7-8ad7-c9a2c488dc17"
		ausfID    = "28ef647d-1033-4ad8-b761-2c08012534b9"
		udmID     = "c9d557aa-a344-44a8-b046-9550ff9aa29b"
		supi      = "imsi-001010000000001"
		alias     = "suci-0-001-01-0000-0-0-0000000001"
		otherSUPI = "imsi-001010000000002"
		path      = "/nausf-auth/v1/ue-authentications/deregister"
	)

	// Generate a trusted NRF certificate and an untrusted signing key
	// to verify JWT signature validation.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	untrustedKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	uri, err := url.Parse("urn:uuid:" + nrfID)
	require.NoError(t, err)
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "NRF"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		URIs: []*url.URL{uri},
	}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	require.NoError(t, err)
	certPath := filepath.Join(t.TempDir(), "nrf.pem")
	require.NoError(t, os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600))

	// Enable OAuth for this test and use t.Cleanup to restore the changed global
	// configuration fields and remove the test UE contexts.
	self := ausf_context.GetSelf()
	id, nrfURI, certPEM := self.NfId, self.NrfUri, self.NrfCertPem
	nrfInstanceID, required := self.NrfNfInstanceID, self.OAuth2Required
	previousConfig := factory.AusfConfig
	t.Cleanup(func() {
		self.RemoveUEAuthenticationContext(supi)
		self.RemoveUEAuthenticationContext(otherSUPI)
		self.NfId, self.NrfUri, self.NrfCertPem = id, nrfURI, certPEM
		self.NrfNfInstanceID, self.OAuth2Required = nrfInstanceID, required
		factory.AusfConfig = previousConfig
	})
	self.NfId, self.NrfUri, self.NrfCertPem = ausfID, "https://nrf.invalid", certPath
	require.NoError(t, self.SetOAuth2Required(true))
	factory.AusfConfig = &factory.Config{Configuration: &factory.Configuration{
		ServiceNameList: []string{"nausf-auth"},
	}}
	a := &deregisterTestApp{ctx: self}
	a.p, err = processor.NewProcessor(a)
	require.NoError(t, err)
	router := newRouter(&Server{ServerAusf: a})

	// Cover successful deregistration, OAuth rejection, invalid payloads,
	// and missing UE contexts through the actual router, OAuth middleware,
	// handler, and processor.
	tests := []struct {
		name   string
		change func(*deregisterClaims)
		body   string
		header string
		badKey bool
		want   int
		cause  string
	}{
		{name: "valid instance audience", want: 204},
		{name: "valid type audience", change: func(c *deregisterClaims) { c.Audience = jwt.ClaimStrings{"AUSF"} }, want: 204},
		{
			name:   "scope among multiple services",
			change: func(c *deregisterClaims) { c.Scope = "nnrf-disc nausf-auth" },
			want:   204,
		},
		{name: "missing token", header: "missing", want: 401},
		{name: "malformed token", header: "Bearer invalid", want: 401},
		{name: "wrong signature", badKey: true, want: 401},
		{name: "wrong issuer", change: func(c *deregisterClaims) { c.Issuer = udmID }, want: 401},
		{name: "wrong audience", change: func(c *deregisterClaims) { c.Audience = jwt.ClaimStrings{"UDM"} }, want: 401},
		{name: "wrong scope", change: func(c *deregisterClaims) { c.Scope = "nudm-ueau" }, want: 401},
		{name: "scope substring", change: func(c *deregisterClaims) { c.Scope = "nausf-auth-extra" }, want: 401},
		{
			name: "expired token",
			change: func(c *deregisterClaims) {
				c.ExpiresAt = jwt.NewNumericDate(time.Now().Add(-time.Hour))
			},
			want: 401,
		},
		{name: "missing expiration", change: func(c *deregisterClaims) { c.ExpiresAt = nil }, want: 401},
		{name: "malformed body", body: "{", want: 400, cause: "INVALID_MSG_FORMAT"},
		{name: "missing SUPI", body: "{}", want: 400, cause: "MANDATORY_IE_MISSING"},
		{name: "null body", body: "null", want: 400, cause: "MANDATORY_IE_MISSING"},
		{name: "SUCI is not SUPI", body: `{"supi":"` + alias + `"}`, want: 400, cause: "MANDATORY_IE_INCORRECT"},
		{name: "unknown context", body: `{"supi":"imsi-001010000000099"}`, want: 404, cause: "CONTEXT_NOT_FOUND"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ausf_context.AddAusfUeContextToPool(&ausf_context.AusfUeContext{Supi: supi, Kausf: "old-key"})
			ausf_context.AddSuciSupiPairToMap(alias, supi)
			ausf_context.AddSuciSupiPairToMap(supi, supi)
			ausf_context.AddAusfUeContextToPool(&ausf_context.AusfUeContext{Supi: otherSUPI, Kausf: "other-key"})
			claims := deregisterClaims{Scope: "nausf-auth", RegisteredClaims: jwt.RegisteredClaims{
				Issuer: nrfID, Subject: udmID, Audience: jwt.ClaimStrings{ausfID},
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			}}
			if tt.change != nil {
				tt.change(&claims)
			}
			signingKey := key
			if tt.badKey {
				signingKey = untrustedKey
			}
			token, err := jwt.NewWithClaims(jwt.SigningMethodRS512, claims).SignedString(signingKey)
			require.NoError(t, err)
			header := "Bearer " + token
			if tt.header != "" {
				header = tt.header
			}
			body := tt.body
			if body == "" {
				body = `{"supi":"` + supi + `"}`
			}
			request := httptest.NewRequestWithContext(t.Context(), http.MethodPost, path, strings.NewReader(body))
			request.Header.Set("Content-Type", "application/json")
			if header != "missing" {
				request.Header.Set("Authorization", header)
			}
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)

			// Only successful requests may remove the target UE context and SUCI mapping;
			// unrelated UE contexts must remain intact.
			require.Equal(t, tt.want, response.Code, response.Body.String())
			require.Equal(t, tt.want != 204, ausf_context.CheckIfAusfUeContextExists(supi))
			require.Equal(t, tt.want != 204, ausf_context.CheckIfSuciSupiPairExists(alias))
			require.True(t, ausf_context.CheckIfAusfUeContextExists(otherSUPI))
			if tt.cause != "" {
				var pd models.ProblemDetails
				require.NoError(t, json.Unmarshal(response.Body.Bytes(), &pd))
				require.Equal(t, tt.cause, pd.Cause)
				require.Equal(t, "application/problem+json", response.Header().Get("Content-Type"))
			}

			// A repeated deregistration must return 404 after successful cleanup.
			if tt.want == 204 {
				require.Empty(t, response.Body.String())
				retry := httptest.NewRequestWithContext(t.Context(), http.MethodPost, path, strings.NewReader(body))
				retry.Header = request.Header.Clone()
				repeat := httptest.NewRecorder()
				router.ServeHTTP(repeat, retry)
				require.Equal(t, http.StatusNotFound, repeat.Code)
			}
		})
	}
	// Existing AMF authentication entry points still use the same service token
	// middleware. Malformed payloads reach their original validation handlers.
	token, err := jwt.NewWithClaims(jwt.SigningMethodRS512, deregisterClaims{
		Scope: "nausf-auth", RegisteredClaims: jwt.RegisteredClaims{
			Issuer: nrfID, Subject: "amf-instance", Audience: jwt.ClaimStrings{ausfID},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}).SignedString(key)
	require.NoError(t, err)
	for _, route := range []struct{ method, path string }{
		{http.MethodPost, "/nausf-auth/v1/ue-authentications"},
		{http.MethodPost, "/nausf-auth/v1/ue-authentications/example/eap-session"},
		{http.MethodPut, "/nausf-auth/v1/ue-authentications/example/5g-aka-confirmation"},
	} {
		for _, authorized := range []bool{true, false} {
			request := httptest.NewRequestWithContext(t.Context(), route.method, route.path, strings.NewReader("{"))
			if authorized {
				request.Header.Set("Authorization", "Bearer "+token)
			}
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			want := http.StatusUnauthorized
			if authorized {
				want = http.StatusBadRequest
			}
			require.Equal(t, want, response.Code, route.path)
		}
	}
}
