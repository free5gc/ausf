package consumer

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/h2non/gock"
	"github.com/stretchr/testify/require"

	ausf_context "github.com/free5gc/ausf/internal/context"
	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/models"
	Nnrf_NFDiscovery "github.com/free5gc/openapi/nrf/NFDisc"
	"github.com/free5gc/util/nfheartbeat"
)

const (
	testNrfUri   = "http://127.0.0.10:8000"
	testNfId     = "6ba7b810-9dad-41d1-80b4-00c04fd430c8"
	testNfIdPath = "/nnrf-nfm/v1/nf-instances/" + testNfId

	// testDeadline bounds calls that may reach a retry loop, decoupled from
	// registerRetryInterval so tuning production timing cannot break tests.
	testDeadline = 2 * time.Second
)

// newNrfTestConsumer builds a Consumer over a private AUSF context pointed at the
// test NRF and intercepts the openapi cleartext HTTP/2 client with gock.
func newNrfTestConsumer(t *testing.T) *Consumer {
	t.Helper()

	consumer := newTestConsumer(t, &ausf_context.AUSFContext{
		NfId:   testNfId,
		NrfUri: testNrfUri,
	})

	openapi.InterceptInnerHttp2Client(t, false)
	t.Cleanup(gock.OffAll)
	return consumer
}

// testCtx bounds every call that may reach the RegisterNFInstance retry loop, so
// that an unmatched mock fails the test instead of retrying forever.
func testCtx(t *testing.T) context.Context {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), testDeadline)
	t.Cleanup(cancel)
	return ctx
}

// synctestCtx is testCtx for synctest bubbles: the deadline is fake time, so a minute costs nothing and does not
// tie with the retry interval, yet a mock mismatch still fails fast instead of spinning until the test timeout.
func synctestCtx(t *testing.T) context.Context {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	t.Cleanup(cancel)
	return ctx
}

// nfProfileJSON is an NRF NF profile reply body. It omits heartBeatTimer when
// timer is 0 and customInfo when it is nil.
func nfProfileJSON(timer int32, customInfo map[string]any) map[string]any {
	body := map[string]any{
		"nfInstanceId": testNfId,
		"nfType":       "AUSF",
		"nfStatus":     "REGISTERED",
	}
	if timer > 0 {
		body["heartBeatTimer"] = timer
	}
	if customInfo != nil {
		body["customInfo"] = customInfo
	}
	return body
}

func problemJSON(status int, cause string) map[string]any {
	return map[string]any{"status": status, "cause": cause}
}

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

func TestSendUpdateNFInstance(t *testing.T) {
	tests := []struct {
		name      string
		status    int
		body      map[string]any
		wantTimer int32
		wantErr   bool
	}{
		{
			name:      "200 returns the updated profile",
			status:    http.StatusOK,
			body:      nfProfileJSON(20, nil),
			wantTimer: 20,
		},
		{
			name:   "204 returns an empty profile",
			status: http.StatusNoContent,
		},
		{
			name:    "404 reports the unknown profile",
			status:  http.StatusNotFound,
			body:    problemJSON(http.StatusNotFound, "RESOURCE_URI_STRUCTURE_NOT_FOUND"),
			wantErr: true,
		},
		{
			name:    "500 reports the NRF failure",
			status:  http.StatusInternalServerError,
			body:    problemJSON(http.StatusInternalServerError, "SYSTEM_FAILURE"),
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			consumer := newNrfTestConsumer(t)

			reply := gock.New(testNrfUri).
				Patch(testNfIdPath).
				MatchHeader("Content-Type", "application/json-patch+json").
				JSON([]map[string]any{
					{"op": "replace", "path": "/nfStatus", "value": "REGISTERED"},
				}).
				Reply(tt.status)
			if tt.body != nil {
				reply.JSON(tt.body)
			}

			nf, pd, err := consumer.SendUpdateNFInstance(t.Context(), nfheartbeat.PatchItems())

			if !gock.IsDone() {
				t.Fatal("the heartbeat PATCH was not sent as expected")
			}
			if !tt.wantErr {
				if err != nil {
					t.Fatalf("SendUpdateNFInstance: pd=%+v err=%v", pd, err)
				}
				if nf.HeartBeatTimer != tt.wantTimer {
					t.Errorf("HeartBeatTimer = %d, want %d", nf.HeartBeatTimer, tt.wantTimer)
				}
				return
			}

			var apiErr openapi.GenericOpenAPIError
			if !errors.As(err, &apiErr) {
				t.Fatalf("err = %T (%v), want openapi.GenericOpenAPIError", err, err)
			}
			if apiErr.ErrorStatus != tt.status {
				t.Errorf("ErrorStatus = %d, want %d", apiErr.ErrorStatus, tt.status)
			}
			if pd == nil || pd.Status != int32(tt.status) {
				t.Errorf("ProblemDetails = %+v, want status %d", pd, tt.status)
			}
		})
	}
}

func TestSendUpdateNFInstanceWithoutNrfUri(t *testing.T) {
	consumer := newTestConsumer(t, &ausf_context.AUSFContext{NfId: testNfId})

	if _, _, err := consumer.SendUpdateNFInstance(t.Context(), nfheartbeat.PatchItems()); err == nil {
		t.Error("SendUpdateNFInstance must report the missing NRF instead of panicking")
	}
}

func TestSendDeregisterNFInstance(t *testing.T) {
	tests := []struct {
		name       string
		status     int
		body       map[string]any
		wantErr    bool
		wantDetail bool
	}{
		{
			name:   "204 deregisters the profile",
			status: http.StatusNoContent,
		},
		{
			name:       "404 reports the unknown profile",
			status:     http.StatusNotFound,
			body:       problemJSON(http.StatusNotFound, "RESOURCE_URI_STRUCTURE_NOT_FOUND"),
			wantErr:    true,
			wantDetail: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			consumer := newNrfTestConsumer(t)

			reply := gock.New(testNrfUri).
				Delete(testNfIdPath).
				Reply(tt.status)
			if tt.body != nil {
				reply.JSON(tt.body)
			}

			pd, err := consumer.SendDeregisterNFInstance()

			if !gock.IsDone() {
				t.Fatal("the deregistration DELETE was not sent as expected")
			}
			if gotErr := err != nil; gotErr != tt.wantErr {
				t.Errorf("SendDeregisterNFInstance err = %v, want error %v", err, tt.wantErr)
			}
			if gotDetail := pd != nil; gotDetail != tt.wantDetail {
				t.Errorf("ProblemDetails = %+v, want detail %v", pd, tt.wantDetail)
			}
			if tt.wantDetail && pd.Status != int32(tt.status) {
				t.Errorf("ProblemDetails.Status = %d, want %d", pd.Status, tt.status)
			}
		})
	}
}

// TestRegisterNFInstanceRetriesUntilSuccess drives the retry loop: the first
// PUT fails on the NRF, the retry one interval later succeeds.
func TestRegisterNFInstanceRetriesUntilSuccess(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		consumer := newNrfTestConsumer(t)

		gock.New(testNrfUri).
			Put(testNfIdPath).
			Reply(http.StatusInternalServerError).
			JSON(problemJSON(http.StatusInternalServerError, "SYSTEM_FAILURE"))
		gock.New(testNrfUri).
			Put(testNfIdPath).
			Reply(http.StatusCreated).
			JSON(nfProfileJSON(15, nil))

		if err := consumer.RegisterNFInstance(synctestCtx(t), false); err != nil {
			t.Fatalf("RegisterNFInstance: %v", err)
		}
		if !gock.IsDone() {
			t.Fatal("expected a failed PUT followed by a successful retry")
		}
		if consumer.heartbeatTimer != 15 {
			t.Errorf("heartbeatTimer = %d, want 15 from the retry", consumer.heartbeatTimer)
		}
	})
}

// TestRegisterNFInstanceStopsOnCancel proves the retry loop gives up once the
// context is cancelled instead of retrying forever.
func TestRegisterNFInstanceStopsOnCancel(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		consumer := newNrfTestConsumer(t)

		gock.New(testNrfUri).
			Put(testNfIdPath).
			Persist().
			Reply(http.StatusInternalServerError).
			JSON(problemJSON(http.StatusInternalServerError, "SYSTEM_FAILURE"))

		ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
		defer cancel()

		if err := consumer.RegisterNFInstance(ctx, false); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("err = %v, want context.DeadlineExceeded", err)
		}
	})
}

func newNrfTestCertificate(t *testing.T, nfInstanceID string) string {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "NRF"},
		DNSNames:     []string{"NRF"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	if nfInstanceID != "" {
		uri, parseErr := url.Parse("urn:uuid:" + nfInstanceID)
		require.NoError(t, parseErr)
		template.URIs = []*url.URL{uri}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	certPath := filepath.Join(t.TempDir(), "nrf.pem")
	err = os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	require.NoError(t, err)
	return certPath
}

func TestRegisterNFInstance(t *testing.T) {
	const testNrfID = "73beea45-663c-4bb7-8ad7-c9a2c488dc17"

	tests := []struct {
		name         string
		status       int
		body         map[string]any
		applyOAuth2  bool
		withNrfCert  bool
		nrfCertID    string
		initialTimer int32
		wantTimer    int32
		wantOAuth2   bool
		wantErr      string
	}{
		{
			name:        "200 adopts the returned timer",
			status:      http.StatusOK,
			body:        nfProfileJSON(15, map[string]any{"oauth2": true}),
			applyOAuth2: true,
			withNrfCert: true,
			nrfCertID:   testNrfID,
			wantTimer:   15,
			wantOAuth2:  true,
		},
		{
			name:         "OAuth certificate without URI SAN preserves the heartbeat timer",
			status:       http.StatusOK,
			body:         nfProfileJSON(15, map[string]any{"oauth2": true}),
			applyOAuth2:  true,
			withNrfCert:  true,
			initialTimer: 30,
			wantTimer:    30,
			wantErr:      "certificate does not contain an NF instance urn:uuid URI SAN",
		},
		{
			name:      "201 adopts the returned timer",
			status:    http.StatusCreated,
			body:      nfProfileJSON(15, nil),
			wantTimer: 15,
		},
		{
			name:      "profile without heartBeatTimer leaves the fallback in charge",
			status:    http.StatusOK,
			body:      nfProfileJSON(0, nil),
			wantTimer: 0,
		},
		{
			name:      "re-registration leaves the oauth2 setting untouched",
			status:    http.StatusOK,
			body:      nfProfileJSON(15, map[string]any{"oauth2": true}),
			wantTimer: 15,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			consumer := newNrfTestConsumer(t)
			consumer.heartbeatTimer = tt.initialTimer
			if tt.withNrfCert {
				consumer.Context().NrfCertPem = newNrfTestCertificate(t, tt.nrfCertID)
			}

			gock.New(testNrfUri).
				Put(testNfIdPath).
				Reply(tt.status).
				JSON(tt.body)

			err := consumer.RegisterNFInstance(testCtx(t), tt.applyOAuth2)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
			}
			require.True(t, gock.IsDone(), "expected the NFRegister PUT to be consumed")
			// The NF picks its own instance ID, the NRF only echoes it back.
			if got := consumer.Context().NfId; got != testNfId {
				t.Errorf("NfId = %q, want %q", got, testNfId)
			}
			if got := consumer.heartbeatTimer; got != tt.wantTimer {
				t.Errorf("heartbeatTimer = %d, want %d", got, tt.wantTimer)
			}
			if got := consumer.Context().OAuth2Required; got != tt.wantOAuth2 {
				t.Errorf("OAuth2Required = %v, want %v", got, tt.wantOAuth2)
			}
			if tt.wantOAuth2 {
				require.Equal(t, testNrfID, consumer.Context().NrfNfInstanceID)
			} else {
				require.Empty(t, consumer.Context().NrfNfInstanceID)
			}
		})
	}
}

func TestRegisterNFInstanceRejectsInvalidResponse(t *testing.T) {
	tests := []struct {
		name    string
		rawBody string
		change  func(map[string]any)
		wantErr string
	}{
		{name: "empty object", rawBody: `{}`, wantErr: "nfInstanceId is missing"},
		{name: "null profile", rawBody: `null`, wantErr: "nfInstanceId is missing"},
		{
			name:    "missing instance ID",
			change:  func(body map[string]any) { delete(body, "nfInstanceId") },
			wantErr: "nfInstanceId is missing",
		},
		{
			name: "different instance ID",
			change: func(body map[string]any) {
				body["nfInstanceId"] = "73beea45-663c-4bb7-8ad7-c9a2c488dc17"
			},
			wantErr: "nfInstanceId does not match AUSF",
		},
		{
			name:    "missing NF type",
			change:  func(body map[string]any) { delete(body, "nfType") },
			wantErr: "nfType must be AUSF",
		},
		{
			name:    "different NF type",
			change:  func(body map[string]any) { body["nfType"] = "AMF" },
			wantErr: "nfType must be AUSF",
		},
		{
			name:    "missing NF status",
			change:  func(body map[string]any) { delete(body, "nfStatus") },
			wantErr: "nfStatus is empty",
		},
		{
			name:    "empty NF status",
			change:  func(body map[string]any) { body["nfStatus"] = "" },
			wantErr: "nfStatus is empty",
		},
		{
			name:    "whitespace NF status",
			change:  func(body map[string]any) { body["nfStatus"] = " \t\n " },
			wantErr: "nfStatus is empty",
		},
		{
			name:    "null NF status",
			change:  func(body map[string]any) { body["nfStatus"] = nil },
			wantErr: "nfStatus is empty",
		},
		{
			name:    "null OAuth setting",
			change:  func(body map[string]any) { body["customInfo"] = map[string]any{"oauth2": nil} },
			wantErr: "customInfo.oauth2 must be boolean",
		},
		{
			name:    "string OAuth setting",
			change:  func(body map[string]any) { body["customInfo"] = map[string]any{"oauth2": "true"} },
			wantErr: "customInfo.oauth2 must be boolean",
		},
		{
			name:    "numeric OAuth setting",
			change:  func(body map[string]any) { body["customInfo"] = map[string]any{"oauth2": 0} },
			wantErr: "customInfo.oauth2 must be boolean",
		},
		{
			name: "object OAuth setting",
			change: func(body map[string]any) {
				body["customInfo"] = map[string]any{"oauth2": map[string]any{}}
			},
			wantErr: "customInfo.oauth2 must be boolean",
		},
	}
	for _, status := range []int{http.StatusOK, http.StatusCreated} {
		for _, applyOAuth2 := range []bool{true, false} {
			for _, initialOAuth2 := range []bool{true, false} {
				for _, tt := range tests {
					name := fmt.Sprintf("%d/apply_%t/initial_%t/%s", status, applyOAuth2, initialOAuth2, tt.name)
					t.Run(name, func(t *testing.T) {
						consumer := newNrfTestConsumer(t)
						self := consumer.Context()
						self.OAuth2Required = initialOAuth2
						if initialOAuth2 {
							self.NrfNfInstanceID = "73beea45-663c-4bb7-8ad7-c9a2c488dc17"
						}
						initialNrfID := self.NrfNfInstanceID
						consumer.heartbeatTimer = 30
						body := tt.rawBody
						if body == "" {
							profile := nfProfileJSON(15, map[string]any{"oauth2": false})
							tt.change(profile)
							encoded, err := json.Marshal(profile)
							require.NoError(t, err)
							body = string(encoded)
						}
						gock.New(testNrfUri).Put(testNfIdPath).Reply(status).
							SetHeader("Content-Type", "application/json").
							SetHeader("Location", testNrfUri+testNfIdPath).BodyString(body)

						err := consumer.RegisterNFInstance(testCtx(t), applyOAuth2)
						require.ErrorContains(t, err, tt.wantErr)
						require.NotErrorIs(t, err, context.DeadlineExceeded, "validation must not enter the retry loop")
						require.True(t, gock.IsDone())
						require.Equal(t, int32(30), consumer.heartbeatTimer)
						require.Equal(t, initialOAuth2, self.OAuth2Required)
						require.Equal(t, initialNrfID, self.NrfNfInstanceID)
						require.Equal(t, testNfId, self.NfId)
					})
				}
			}
		}
	}
}

func TestRegisterNFInstanceAcceptsCompatibleResponse(t *testing.T) {
	const testNrfID = "73beea45-663c-4bb7-8ad7-c9a2c488dc17"
	certPath := newNrfTestCertificate(t, testNrfID)
	type testCase struct {
		name          string
		customInfo    map[string]any
		change        func(map[string]any)
		applyOAuth2   bool
		initialOAuth2 bool
		wantOAuth2    bool
		wantTimer     int32
	}
	tests := []testCase{
		{
			name: "enable OAuth", customInfo: map[string]any{"oauth2": true},
			applyOAuth2: true, wantOAuth2: true, wantTimer: 15,
		},
		{
			name: "explicitly disable OAuth without certificate", customInfo: map[string]any{"oauth2": false},
			applyOAuth2: true, initialOAuth2: true, wantTimer: 15,
		},
		{
			name:        "missing customInfo preserves legacy default",
			applyOAuth2: true, initialOAuth2: true, wantTimer: 15,
		},
		{
			name: "customInfo without OAuth setting", customInfo: map[string]any{"vendor": "example"},
			applyOAuth2: true, wantTimer: 15,
		},
		{
			name: "re-registration preserves enabled OAuth", customInfo: map[string]any{"oauth2": false},
			initialOAuth2: true, wantOAuth2: true, wantTimer: 15,
		},
		{
			name: "re-registration preserves disabled OAuth", customInfo: map[string]any{"oauth2": true},
			wantTimer: 15,
		},
		{
			name:          "re-registration without customInfo preserves enabled OAuth",
			initialOAuth2: true, wantOAuth2: true, wantTimer: 15,
		},
		{
			name:        "uppercase UUID represents the same instance",
			change:      func(body map[string]any) { body["nfInstanceId"] = strings.ToUpper(testNfId) },
			applyOAuth2: true, wantTimer: 15,
		},
		{
			name: "mandatory fields in profile changes response",
			change: func(body map[string]any) {
				delete(body, "heartBeatTimer")
				body["nfProfileChangesInd"] = true
			},
			applyOAuth2: true,
		},
	}
	for _, status := range []models.Nrf_NFMgmt_NFStatus{
		models.Nrf_NFMgmt_NFStatus_REGISTERED,
		models.Nrf_NFMgmt_NFStatus_SUSPENDED,
		models.Nrf_NFMgmt_NFStatus_UNDISCOVERABLE,
		"FUTURE_STATUS",
	} {
		tests = append(tests, testCase{
			name:        "NF status " + string(status),
			change:      func(body map[string]any) { body["nfStatus"] = status },
			applyOAuth2: true, wantTimer: 15,
		})
	}
	for _, status := range []int{http.StatusOK, http.StatusCreated} {
		for _, tt := range tests {
			t.Run(fmt.Sprintf("%d/%s", status, tt.name), func(t *testing.T) {
				consumer := newNrfTestConsumer(t)
				self := consumer.Context()
				self.OAuth2Required = tt.initialOAuth2
				if tt.initialOAuth2 {
					self.NrfNfInstanceID = testNrfID
				}
				if tt.applyOAuth2 && tt.wantOAuth2 {
					self.NrfCertPem = certPath
				}
				consumer.heartbeatTimer = 30
				body := nfProfileJSON(15, tt.customInfo)
				if tt.change != nil {
					tt.change(body)
				}
				gock.New(testNrfUri).Put(testNfIdPath).Reply(status).
					SetHeader("Location", testNrfUri+testNfIdPath).JSON(body)

				require.NoError(t, consumer.RegisterNFInstance(testCtx(t), tt.applyOAuth2))
				require.True(t, gock.IsDone())
				require.Equal(t, tt.wantTimer, consumer.heartbeatTimer)
				require.Equal(t, tt.wantOAuth2, self.OAuth2Required)
				if tt.wantOAuth2 {
					require.Equal(t, testNrfID, self.NrfNfInstanceID)
				} else {
					require.Empty(t, self.NrfNfInstanceID)
				}
				require.Equal(t, testNfId, self.NfId)
			})
		}
	}
}
