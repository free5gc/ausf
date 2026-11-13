package context_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"

	ausf_context "github.com/free5gc/ausf/internal/context"
	"github.com/free5gc/openapi/models"
)

type oauthAuthorizationClaims struct {
	Scope string `json:"scope"`
	jwt.RegisteredClaims
}

func TestAuthorizationCheckJWT(t *testing.T) {
	const (
		nrfID  = "73beea45-663c-4bb7-8ad7-c9a2c488dc17"
		ausfID = "28ef647d-1033-4ad8-b761-2c08012534b9"
		amfID  = "c9d557aa-a344-44a8-b046-9550ff9aa29b"
	)
	service := models.Nrf_NFMgmt_ServiceName_NAUSF_AUTH
	trustedKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	untrustedKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	certPath := newOAuthNRFCertificate(t, trustedKey, nrfID)

	tests := []struct {
		name        string
		modify      func(*oauthAuthorizationClaims)
		signingKey  *rsa.PrivateKey
		wantErr     error
		wantMessage string
	}{
		{name: "valid instance audience"},
		{
			name: "valid NF type audience",
			modify: func(claims *oauthAuthorizationClaims) {
				claims.Audience = jwt.ClaimStrings{string(models.Nrf_NFMgmt_NFType_AUSF)}
			},
		},
		{
			name: "valid scope among multiple services",
			modify: func(claims *oauthAuthorizationClaims) {
				claims.Scope = "nnrf-disc " + string(service)
			},
		},
		{
			name: "wrong issuer",
			modify: func(claims *oauthAuthorizationClaims) {
				claims.Issuer = amfID
			},
			wantErr: jwt.ErrTokenInvalidIssuer,
		},
		{
			name: "wrong audience",
			modify: func(claims *oauthAuthorizationClaims) {
				claims.Audience = jwt.ClaimStrings{amfID, string(models.Nrf_NFMgmt_NFType_AMF)}
			},
			wantMessage: "OAuth audience verification failed",
		},
		{
			name:       "wrong signature",
			signingKey: untrustedKey,
			wantErr:    jwt.ErrTokenSignatureInvalid,
		},
		{
			name: "wrong scope",
			modify: func(claims *oauthAuthorizationClaims) {
				claims.Scope = "nudm-ueau"
			},
			wantMessage: "OAuth scope verification failed",
		},
		{
			name: "scope substring is rejected",
			modify: func(claims *oauthAuthorizationClaims) {
				claims.Scope = string(service) + "-extra"
			},
			wantMessage: "OAuth scope verification failed",
		},
		{
			name: "expired token",
			modify: func(claims *oauthAuthorizationClaims) {
				claims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(-time.Hour))
			},
			wantErr: jwt.ErrTokenExpired,
		},
		{
			name: "missing expiration",
			modify: func(claims *oauthAuthorizationClaims) {
				claims.ExpiresAt = nil
			},
			wantErr: jwt.ErrTokenRequiredClaimMissing,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Use a private context, not the global AUSF singleton or a mock.
			self := &ausf_context.AUSFContext{
				NfId:       ausfID,
				NrfUri:     "https://nrf.invalid",
				NrfCertPem: certPath,
			}
			require.NoError(t, self.SetOAuth2Required(true))
			require.True(t, self.OAuth2Required)
			require.Equal(t, nrfID, self.NrfNfInstanceID)

			claims := oauthAuthorizationClaims{
				Scope: string(service),
				RegisteredClaims: jwt.RegisteredClaims{
					Issuer:    nrfID,
					Subject:   amfID,
					Audience:  jwt.ClaimStrings{ausfID},
					ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
				},
			}
			if tt.modify != nil {
				tt.modify(&claims)
			}
			key := trustedKey
			if tt.signingKey != nil {
				key = tt.signingKey
			}
			token, signErr := jwt.NewWithClaims(jwt.SigningMethodRS512, claims).SignedString(key)
			require.NoError(t, signErr)

			// AuthorizationCheck delegates to the pinned OpenAPI VerifyOAuth implementation.
			verifyErr := self.AuthorizationCheck("Bearer "+token, service)
			if tt.wantErr == nil && tt.wantMessage == "" {
				require.NoError(t, verifyErr)
				return
			}
			if tt.wantErr != nil {
				require.ErrorIs(t, verifyErr, tt.wantErr)
			}
			if tt.wantMessage != "" {
				require.ErrorContains(t, verifyErr, tt.wantMessage)
			}
		})
	}
}

func newOAuthNRFCertificate(t *testing.T, key *rsa.PrivateKey, nfInstanceID string) string {
	t.Helper()
	uri, err := url.Parse("urn:uuid:" + nfInstanceID)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "NRF OAuth JWT test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		URIs:         []*url.URL{uri},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	certPath := filepath.Join(t.TempDir(), "nrf.pem")
	require.NoError(t, os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE", Bytes: der,
	}), 0o600))
	return certPath
}
