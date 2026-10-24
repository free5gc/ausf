package consumer

import (
	tlsContext "context"
	tlsX509 "crypto/x509"
	tlsErrors "errors"
	tlsIO "io"
	tlsLog "log"
	tlsHTTP "net/http"
	tlsServer "net/http/httptest"
	tlsAtomic "sync/atomic"
	"testing"

	"github.com/h2non/gock"
	"github.com/stretchr/testify/require"
	tlsYAML "gopkg.in/yaml.v2"

	ausf_context "github.com/free5gc/ausf/internal/context"
	tlsFactory "github.com/free5gc/ausf/pkg/factory"
	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/models"
	Nnrf_NFDiscovery "github.com/free5gc/openapi/nrf/NFDisc"
	tlsNFM "github.com/free5gc/openapi/nrf/NFMgmt"
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

// Exercise parsed NF config through the same startup configuration API and
// generated NRF client used in production. No deployment files are modified.
func TestSBIConfigTLSVerification(t *testing.T) {
	t.Cleanup(func() {
		if err := openapi.ConfigureHTTP2Clients(
			openapi.TransportReadIdleTimeout, openapi.TransportPingTimeout, false,
		); err != nil {
			t.Errorf("restore HTTP clients: %v", err)
		}
	})
	var requests tlsAtomic.Int32
	server := tlsServer.NewUnstartedServer(tlsHTTP.HandlerFunc(func(w tlsHTTP.ResponseWriter, r *tlsHTTP.Request) {
		requests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		if _, err := tlsIO.WriteString(w, `{}`); err != nil {
			t.Errorf("write response: %v", err)
		}
	}))
	server.EnableHTTP2 = true
	server.Config.ErrorLog = tlsLog.New(tlsIO.Discard, "", 0)
	server.StartTLS()
	defer server.Close()
	for _, value := range []string{"", "false", "true"} {
		t.Run("verify="+value, func(t *testing.T) {
			data := "configuration:\n  sbi:\n    scheme: https\n"
			if value != "" {
				data += "    tls:\n      verify: " + value + "\n"
			}
			var cfg tlsFactory.Config
			if err := tlsYAML.Unmarshal([]byte(data), &cfg); err != nil {
				t.Fatal(err)
			}
			if cfg.GetTLSVerify() != (value == "true") {
				t.Fatal("verify parsing mismatch")
			}
			if err := openapi.ConfigureHTTP2Clients(
				cfg.GetReadIdleTimeout(), cfg.GetPingTimeout(), cfg.GetTLSVerify(),
			); err != nil {
				t.Fatal(err)
			}
			apiCfg := tlsNFM.NewConfiguration()
			apiCfg.SetBasePath(server.URL)
			client := tlsNFM.NewAPIClient(apiCfg)
			req := &tlsNFM.GetNFInstanceRequest{}
			req.SetNfInstanceID("tls-test")
			before := requests.Load()
			_, err := client.NFInstanceIDDocumentApi.GetNFInstance(tlsContext.Background(), req)
			if value == "true" {
				var unknown tlsX509.UnknownAuthorityError
				if !tlsErrors.As(err, &unknown) {
					t.Fatalf("expected unknown authority, got %v", err)
				}
				if requests.Load() != before {
					t.Fatal("HTTP handler reached despite rejected certificate")
				}
			} else if err != nil {
				t.Fatal(err)
			} else if requests.Load() != before+1 {
				t.Fatal("request not received")
			}
		})
	}
}
