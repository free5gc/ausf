package consumer

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"testing/synctest"
	"time"

	"github.com/h2non/gock"
	"go.uber.org/mock/gomock"

	ausf_context "github.com/free5gc/ausf/internal/context"
	"github.com/free5gc/ausf/pkg/app"
	"github.com/free5gc/ausf/pkg/factory"
	"github.com/free5gc/openapi"
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

// newTestConsumer builds a Consumer over a private AUSF context and intercepts
// the openapi cleartext HTTP/2 client with gock.
func newTestConsumer(t *testing.T) *Consumer {
	t.Helper()

	mockApp := app.NewMockApp(gomock.NewController(t))
	mockApp.EXPECT().Context().Return(&ausf_context.AUSFContext{
		NfId:   testNfId,
		NrfUri: testNrfUri,
	}).AnyTimes()
	mockApp.EXPECT().Config().Return(&factory.Config{
		Configuration: &factory.Configuration{},
	}).AnyTimes()

	consumer, err := NewConsumer(mockApp)
	if err != nil {
		t.Fatalf("NewConsumer: %v", err)
	}

	openapi.InterceptH2CClient()
	t.Cleanup(func() {
		openapi.RestoreH2CClient()
		// OffAll, not Off: only OffAll clears the unmatched request registry the
		// shutdown tests assert on.
		gock.OffAll()
	})
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
			consumer := newTestConsumer(t)

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
	mockApp := app.NewMockApp(gomock.NewController(t))
	mockApp.EXPECT().Context().Return(&ausf_context.AUSFContext{NfId: testNfId}).AnyTimes()

	consumer, err := NewConsumer(mockApp)
	if err != nil {
		t.Fatalf("NewConsumer: %v", err)
	}

	if _, _, err = consumer.SendUpdateNFInstance(t.Context(), nfheartbeat.PatchItems()); err == nil {
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
			consumer := newTestConsumer(t)

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
		consumer := newTestConsumer(t)

		gock.New(testNrfUri).
			Put(testNfIdPath).
			Reply(http.StatusInternalServerError).
			JSON(problemJSON(http.StatusInternalServerError, "SYSTEM_FAILURE"))
		gock.New(testNrfUri).
			Put(testNfIdPath).
			Reply(http.StatusCreated).
			JSON(nfProfileJSON(15, nil))

		if err := consumer.RegisterNFInstance(t.Context(), false); err != nil {
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
		consumer := newTestConsumer(t)

		gock.New(testNrfUri).
			Put(testNfIdPath).
			Persist().
			Reply(http.StatusInternalServerError).
			JSON(problemJSON(http.StatusInternalServerError, "SYSTEM_FAILURE"))

		ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
		defer cancel()

		if err := consumer.RegisterNFInstance(ctx, false); err == nil {
			t.Fatal("RegisterNFInstance must fail once the context is cancelled")
		}
	})
}

func TestRegisterNFInstance(t *testing.T) {
	tests := []struct {
		name        string
		status      int
		body        map[string]any
		applyOAuth2 bool
		wantTimer   int32
		wantOAuth2  bool
	}{
		{
			name:        "200 adopts the returned timer",
			status:      http.StatusOK,
			body:        nfProfileJSON(15, map[string]any{"oauth2": true}),
			applyOAuth2: true,
			wantTimer:   15,
			wantOAuth2:  true,
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
			consumer := newTestConsumer(t)

			gock.New(testNrfUri).
				Put(testNfIdPath).
				Reply(tt.status).
				JSON(tt.body)

			if err := consumer.RegisterNFInstance(testCtx(t), tt.applyOAuth2); err != nil {
				t.Fatalf("RegisterNFInstance: %v", err)
			}
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
		})
	}
}
