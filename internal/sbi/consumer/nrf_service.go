package consumer

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/pkg/errors"

	ausf_context "github.com/free5gc/ausf/internal/context"
	"github.com/free5gc/ausf/internal/logger"
	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/models"
	Nnrf_NFDiscovery "github.com/free5gc/openapi/nrf/NFDisc"
	Nnrf_NFManagement "github.com/free5gc/openapi/nrf/NFMgmt"
	sbi_metrics "github.com/free5gc/util/metrics/sbi"
	"github.com/free5gc/util/nfheartbeat"
)

const registerRetryInterval = 2 * time.Second

type nnrfService struct {
	consumer *Consumer

	nfMngmntMu sync.RWMutex
	nfDiscMu   sync.RWMutex

	nfMngmntClients map[string]*Nnrf_NFManagement.APIClient
	nfDiscClients   map[string]*Nnrf_NFDiscovery.APIClient

	heartbeat *nfheartbeat.Runner

	// Interval in seconds from the last registration response. Written before the heartbeat starts, then only on
	// the heartbeat goroutine.
	heartbeatTimer int32
}

func (s *nnrfService) getNFManagementClient(uri string) *Nnrf_NFManagement.APIClient {
	if uri == "" {
		return nil
	}
	s.nfMngmntMu.RLock()
	client, ok := s.nfMngmntClients[uri]
	s.nfMngmntMu.RUnlock()
	if ok {
		return client
	}

	s.nfMngmntMu.Lock()
	defer s.nfMngmntMu.Unlock()
	// Another caller may have stored a client while the read lock was down.
	if client, ok = s.nfMngmntClients[uri]; ok {
		return client
	}

	configuration := Nnrf_NFManagement.NewConfiguration()
	configuration.SetBasePath(uri)
	configuration.SetMetrics(sbi_metrics.SbiMetricHook)
	client = Nnrf_NFManagement.NewAPIClient(configuration)

	s.nfMngmntClients[uri] = client
	return client
}

func (s *nnrfService) getNFDiscClient(uri string) *Nnrf_NFDiscovery.APIClient {
	if uri == "" {
		return nil
	}
	s.nfDiscMu.RLock()
	client, ok := s.nfDiscClients[uri]
	s.nfDiscMu.RUnlock()
	if ok {
		return client
	}

	s.nfDiscMu.Lock()
	defer s.nfDiscMu.Unlock()
	// Another caller may have stored a client while the read lock was down.
	if client, ok = s.nfDiscClients[uri]; ok {
		return client
	}

	configuration := Nnrf_NFDiscovery.NewConfiguration()
	configuration.SetBasePath(uri)
	configuration.SetMetrics(sbi_metrics.SbiMetricHook)
	client = Nnrf_NFDiscovery.NewAPIClient(configuration)

	s.nfDiscClients[uri] = client
	return client
}

func (s *nnrfService) SendSearchNFInstances(
	nrfUri string, targetNfType,
	requestNfType models.Nrf_NFMgmt_NFType,
	param Nnrf_NFDiscovery.SearchNFInstancesRequest,
) (
	*models.Nrf_NFDisc_SearchResult, error,
) {
	// Set client and set url
	client := s.getNFDiscClient(nrfUri)
	if client == nil {
		return nil, openapi.ReportError("nrf not found")
	}

	ctx, _, err := ausf_context.GetSelf().GetTokenCtx(
		models.Nrf_NFMgmt_ServiceName_NNRF_DISC,
		models.Nrf_NFMgmt_NFType_NRF,
	)
	if err != nil {
		return nil, err
	}

	res, err := client.NFInstancesStoreApi.SearchNFInstances(ctx, &param)

	if err != nil || res == nil {
		logger.ConsumerLog.Errorf("SearchNFInstances failed: %+v", err)
		return nil, err
	}

	return res.Nrf_NFDisc_SearchResult, err
}

func (s *nnrfService) SendDeregisterNFInstance() (*models.ProblemDetails, error) {
	logger.ConsumerLog.Infof("[AUSF] Send Deregister NFInstance")

	ausfContext := s.consumer.Context()
	ctx, pd, err := ausfContext.GetTokenCtx(
		models.Nrf_NFMgmt_ServiceName_NNRF_NFM,
		models.Nrf_NFMgmt_NFType_NRF,
	)
	if err != nil {
		return pd, err
	}

	client := s.getNFManagementClient(ausfContext.NrfUri)
	if client == nil {
		return nil, openapi.ReportError("nrf not found")
	}

	request := &Nnrf_NFManagement.DeregisterNFInstanceRequest{
		NfInstanceID: &ausfContext.NfId,
	}

	_, err = client.NFInstanceIDDocumentApi.DeregisterNFInstance(ctx, request)
	var apiErr openapi.GenericOpenAPIError
	if errors.As(err, &apiErr) {
		// API error
		if deregNfError, okDeg := apiErr.Model().(Nnrf_NFManagement.DeregisterNFInstanceError); okDeg {
			return deregNfError.ProblemDetails, err
		}
		return nil, err
	}
	return nil, err
}

// RegisterNFInstance PUTs the profile on the AUSF's own instance ID (3GPP TS 29.510 clause 5.2.2.2.2) until it
// succeeds or ctx is done. Only the startup call may pass applyOAuth2: it writes OAuth2Required unsynchronized.
func (s *nnrfService) RegisterNFInstance(ctx context.Context, applyOAuth2 bool) error {
	ausfContext := s.consumer.Context()
	client := s.getNFManagementClient(ausfContext.NrfUri)
	if client == nil {
		return openapi.ReportError("nrf not found")
	}

	nfProfile, err := s.buildNfProfile(ausfContext)
	if err != nil {
		return errors.Wrap(err, "RegisterNFInstance buildNfProfile()")
	}

	var res *Nnrf_NFManagement.RegisterNFInstanceResponse
	registerNFInstanceRequest := &Nnrf_NFManagement.RegisterNFInstanceRequest{
		NfInstanceID: &ausfContext.NfId,
		RequestBody:  &nfProfile,
	}
	for ctx.Err() == nil {
		res, err = client.NFInstanceIDDocumentApi.RegisterNFInstance(ctx, registerNFInstanceRequest)
		if err == nil && res != nil {
			var nf models.Nrf_NFMgmt_NFProfile
			if res.Nrf_NFMgmt_NFProfile != nil {
				nf = *res.Nrf_NFMgmt_NFProfile
			}
			s.processRegisterResponse(ausfContext, nf, applyOAuth2)
			return nil
		}
		logger.ConsumerLog.Errorf("AUSF register to NRF Error[%v]", err)
		select {
		case <-ctx.Done():
		case <-time.After(registerRetryInterval):
		}
	}
	return fmt.Errorf("NFRegister aborted: %w (last error: %v)", ctx.Err(), err)
}

// processRegisterResponse adopts what the NRF answered to the NFRegister PUT: the
// heartbeat interval and the oauth2 custom info.
func (s *nnrfService) processRegisterResponse(
	ausfContext *ausf_context.AUSFContext,
	nf models.Nrf_NFMgmt_NFProfile,
	applyOAuth2 bool,
) {
	s.heartbeatTimer = nf.HeartBeatTimer

	oauth2 := false
	if customInfo, ok := nf.CustomInfo.(map[string]interface{}); ok {
		if v, isBool := customInfo["oauth2"].(bool); isBool {
			oauth2 = v
			logger.MainLog.Infoln("OAuth2 setting receive from NRF:", oauth2)
		}
	}
	if applyOAuth2 {
		ausfContext.OAuth2Required = oauth2
		if oauth2 && ausfContext.NrfCertPem == "" {
			logger.CfgLog.Error("OAuth2 enable but no nrfCertPem provided in config.")
		}
	} else if oauth2 != ausfContext.OAuth2Required {
		logger.ConsumerLog.Warnf("NRF OAuth2 setting changed to %v, restart AUSF to apply it", oauth2)
	}
}

// SendUpdateNFInstance sends an NFUpdate PATCH to the NRF, honoring ctx. The
// raw err comes back alongside any ProblemDetails so callers can read its
// GenericOpenAPIError status.
func (s *nnrfService) SendUpdateNFInstance(ctx context.Context, patchItems []models.PatchItem) (
	nf models.Nrf_NFMgmt_NFProfile, problemDetails *models.ProblemDetails, err error,
) {
	ausfContext := s.consumer.Context()
	tokCtx, pd, err := ausfContext.GetTokenCtx(
		models.Nrf_NFMgmt_ServiceName_NNRF_NFM,
		models.Nrf_NFMgmt_NFType_NRF,
	)
	if err != nil {
		return nf, pd, err
	}
	// GetTokenCtx takes no parent, so the token request stays uncancellable;
	// transplanting the token lets at least the PATCH honor ctx.
	if tok := tokCtx.Value(openapi.ContextOAuth2); tok != nil {
		ctx = context.WithValue(ctx, openapi.ContextOAuth2, tok)
	}

	client := s.getNFManagementClient(ausfContext.NrfUri)
	if client == nil {
		return nf, nil, openapi.ReportError("nrf not found")
	}

	request := &Nnrf_NFManagement.UpdateNFInstanceRequest{
		NfInstanceID: &ausfContext.NfId,
		RequestBody:  patchItems,
	}

	res, err := client.NFInstanceIDDocumentApi.UpdateNFInstance(ctx, request)
	if err != nil {
		var apiErr openapi.GenericOpenAPIError
		if errors.As(err, &apiErr) {
			if updateErr, okModel := apiErr.Model().(Nnrf_NFManagement.UpdateNFInstanceError); okModel {
				return nf, updateErr.ProblemDetails, err
			}
		}
		return nf, nil, err
	}
	if res == nil {
		return nf, nil, openapi.ReportError("empty NFUpdate response")
	}
	if res.Nrf_NFMgmt_NFProfile != nil {
		nf = *res.Nrf_NFMgmt_NFProfile
	}
	return nf, nil, nil
}

func (s *nnrfService) buildNfProfile(ausfContext *ausf_context.AUSFContext) (
	profile models.Nrf_NFMgmt_NFProfile, err error,
) {
	profile.NfInstanceId = ausfContext.NfId
	profile.NfType = models.Nrf_NFMgmt_NFType_AUSF
	profile.NfStatus = models.Nrf_NFMgmt_NFStatus_REGISTERED
	profile.Ipv4Addresses = append(profile.Ipv4Addresses, ausfContext.RegisterIPv4)
	services := []models.Nrf_NFMgmt_NFService{}
	for _, nfService := range ausfContext.NfService {
		services = append(services, nfService)
	}
	if len(services) > 0 {
		profile.NfServices = services
	}
	profile.AusfInfo = &models.Nrf_NFMgmt_AusfInfo{
		// Todo
		// SupiRanges: &[]models.Nrf_NFMgmt_SupiRange{
		// 	{
		// 		//from TS 29.510 6.1.6.2.9 example2
		//		//no need to set supirange in this moment 2019/10/4
		// 		Start:   "123456789040000",
		// 		End:     "123456789059999",
		// 		Pattern: "^imsi-12345678904[0-9]{4}$",
		// 	},
		// },
	}
	return
}

func (s *nnrfService) GetUdmUrl(nrfUri string) (string, error) {
	targetNfType := models.Nrf_NFMgmt_NFType_UDM
	requestNfType := models.Nrf_NFMgmt_NFType_AUSF
	nfDiscoverParam := Nnrf_NFDiscovery.SearchNFInstancesRequest{
		RequesterNfType: &requestNfType,
		TargetNfType:    &targetNfType,
		ServiceNames:    []models.Nrf_NFMgmt_ServiceName{models.Nrf_NFMgmt_ServiceName_NUDM_UEAU},
	}
	res, err := s.SendSearchNFInstances(
		nrfUri,
		models.Nrf_NFMgmt_NFType_UDM,
		models.Nrf_NFMgmt_NFType_AUSF,
		nfDiscoverParam,
	)
	if err != nil {
		return "", err
	}

	_, udmUrl, err := openapi.GetServiceNfProfileAndUri(res.NfInstances, models.Nrf_NFMgmt_ServiceName_NUDM_UEAU)
	if err != nil {
		return "", err
	}
	return udmUrl, nil
}
