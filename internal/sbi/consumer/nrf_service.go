package consumer

import (
	"context"
	"sync"
	"time"

	"github.com/pkg/errors"

	ausf_context "github.com/free5gc/ausf/internal/context"
	"github.com/free5gc/ausf/internal/logger"
	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/models"
	Nnrf_NFDiscovery "github.com/free5gc/openapi/nrf/NFDiscovery"
	Nnrf_NFManagement "github.com/free5gc/openapi/nrf/NFManagement"
	sbi_metrics "github.com/free5gc/util/metrics/sbi"
	"github.com/free5gc/util/nfheartbeat"
)

// registerRetryInterval is the wait between two NFRegister attempts while the NRF
// is unreachable.
const registerRetryInterval = 2 * time.Second

type nnrfService struct {
	consumer *Consumer

	nfMngmntMu sync.RWMutex
	nfDiscMu   sync.RWMutex

	nfMngmntClients map[string]*Nnrf_NFManagement.APIClient
	nfDiscClients   map[string]*Nnrf_NFDiscovery.APIClient

	heartbeat *nfheartbeat.Runner

	// heartbeatTimer is the interval in seconds last assigned in a registration
	// response; PATCH-adopted values live in the Runner. Set by the startup
	// registration before the heartbeat goroutine starts, then only rewritten
	// from re-registrations on that same goroutine.
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
	requestNfType models.NrfNfManagementNfType,
	param Nnrf_NFDiscovery.SearchNFInstancesRequest,
) (
	*models.SearchResult, error,
) {
	// Set client and set url
	client := s.getNFDiscClient(nrfUri)
	if client == nil {
		return nil, openapi.ReportError("nrf not found")
	}

	ctx, _, err := ausf_context.GetSelf().GetTokenCtx(models.ServiceName_NNRF_DISC, models.NrfNfManagementNfType_NRF)
	if err != nil {
		return nil, err
	}

	res, err := client.NFInstancesStoreApi.SearchNFInstances(ctx, &param)

	if err != nil || res == nil {
		logger.ConsumerLog.Errorf("SearchNFInstances failed: %+v", err)
		return nil, err
	}

	result := res.SearchResult
	return &result, err
}

func (s *nnrfService) SendDeregisterNFInstance() (*models.ProblemDetails, error) {
	logger.ConsumerLog.Infof("[AUSF] Send Deregister NFInstance")

	ausfContext := s.consumer.Context()
	ctx, pd, err := ausfContext.GetTokenCtx(models.ServiceName_NNRF_NFM, models.NrfNfManagementNfType_NRF)
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
			return &deregNfError.ProblemDetails, err
		}
		return nil, err
	}
	return nil, err
}

// RegisterNFInstance registers the NF profile with the NRF, retrying until it
// succeeds or ctx is cancelled. applyOAuth2 must be true only for the startup
// registration: it writes OAuth2Required, which SBI handlers read concurrently
// once the server is running.
//
// The profile keeps ausfContext.NfId: NFRegister is a PUT on the instance ID the
// AUSF chose, per 3GPP TS 29.510 clause 6.1.3.2.2.
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
		NfInstanceID:             &ausfContext.NfId,
		NrfNfManagementNfProfile: &nfProfile,
	}
	for ctx.Err() == nil {
		res, err = client.NFInstanceIDDocumentApi.RegisterNFInstance(ctx, registerNFInstanceRequest)
		if err == nil && res != nil {
			s.processRegisterResponse(ausfContext, res.NrfNfManagementNfProfile, applyOAuth2)
			return nil
		}
		logger.ConsumerLog.Errorf("AUSF register to NRF Error[%v]", err)
		select {
		case <-ctx.Done():
		case <-time.After(registerRetryInterval):
		}
	}
	return errors.Errorf("Context Cancel before RegisterNFInstance")
}

// processRegisterResponse adopts what the NRF answered to the NFRegister PUT: the
// heartbeat interval and the oauth2 custom info.
func (s *nnrfService) processRegisterResponse(
	ausfContext *ausf_context.AUSFContext,
	nf models.NrfNfManagementNfProfile,
	applyOAuth2 bool,
) {
	s.heartbeatTimer = nf.HeartBeatTimer

	oauth2 := false
	if v, ok := nf.CustomInfo["oauth2"].(bool); ok {
		oauth2 = v
		logger.MainLog.Infoln("OAuth2 setting receive from NRF:", oauth2)
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
func (s *nnrfService) SendUpdateNFInstance(ctx context.Context, patchItem []models.PatchItem) (
	nf models.NrfNfManagementNfProfile, problemDetails *models.ProblemDetails, err error,
) {
	ausfContext := s.consumer.Context()
	tokCtx, pd, err := ausfContext.GetTokenCtx(models.ServiceName_NNRF_NFM, models.NrfNfManagementNfType_NRF)
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
		PatchItem:    patchItem,
	}

	res, err := client.NFInstanceIDDocumentApi.UpdateNFInstance(ctx, request)
	if err != nil {
		var apiErr openapi.GenericOpenAPIError
		if errors.As(err, &apiErr) {
			if updateErr, okModel := apiErr.Model().(Nnrf_NFManagement.UpdateNFInstanceError); okModel {
				return nf, &updateErr.ProblemDetails, err
			}
		}
		return nf, nil, err
	}
	if res == nil {
		return nf, nil, openapi.ReportError("empty NFUpdate response")
	}
	return res.NrfNfManagementNfProfile, nil, nil
}

func (s *nnrfService) buildNfProfile(ausfContext *ausf_context.AUSFContext) (
	profile models.NrfNfManagementNfProfile, err error,
) {
	profile.NfInstanceId = ausfContext.NfId
	profile.NfType = models.NrfNfManagementNfType_AUSF
	profile.NfStatus = models.NrfNfManagementNfStatus_REGISTERED
	profile.Ipv4Addresses = append(profile.Ipv4Addresses, ausfContext.RegisterIPv4)
	services := []models.NrfNfManagementNfService{}
	for _, nfService := range ausfContext.NfService {
		services = append(services, nfService)
	}
	if len(services) > 0 {
		profile.NfServices = services
	}
	profile.AusfInfo = &models.AusfInfo{
		// Todo
		// SupiRanges: &[]models.SupiRange{
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
	targetNfType := models.NrfNfManagementNfType_UDM
	requestNfType := models.NrfNfManagementNfType_AUSF
	nfDiscoverParam := Nnrf_NFDiscovery.SearchNFInstancesRequest{
		RequesterNfType: &requestNfType,
		TargetNfType:    &targetNfType,
		ServiceNames:    []models.ServiceName{models.ServiceName_NUDM_UEAU},
	}
	res, err := s.SendSearchNFInstances(
		nrfUri,
		models.NrfNfManagementNfType_UDM,
		models.NrfNfManagementNfType_AUSF,
		nfDiscoverParam,
	)
	if err != nil {
		return "", err
	}

	_, udmUrl, err := openapi.GetServiceNfProfileAndUri(res.NfInstances, models.ServiceName_NUDM_UEAU)
	if err != nil {
		return "", err
	}
	return udmUrl, nil
}
