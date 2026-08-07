package consumer

import (
	"sync"
	"time"

	ausf_context "github.com/free5gc/ausf/internal/context"
	"github.com/free5gc/ausf/internal/logger"
	"github.com/free5gc/openapi/models"
	Nudm_UEAU "github.com/free5gc/openapi/udm/UEAU"
	sbi_metrics "github.com/free5gc/util/metrics/sbi"
)

type nudmService struct {
	consumer *Consumer

	ueauMu sync.RWMutex

	ueauClients map[string]*Nudm_UEAU.APIClient
}

func (s *nudmService) getUdmUeauClient(uri string) *Nudm_UEAU.APIClient {
	if uri == "" {
		return nil
	}
	s.ueauMu.RLock()
	client, ok := s.ueauClients[uri]
	if ok {
		s.ueauMu.RUnlock()
		return client
	}

	configuration := Nudm_UEAU.NewConfiguration()
	configuration.SetBasePath(uri)
	configuration.SetMetrics(sbi_metrics.SbiMetricHook)
	client = Nudm_UEAU.NewAPIClient(configuration)

	s.ueauMu.RUnlock()
	s.ueauMu.Lock()
	defer s.ueauMu.Unlock()
	s.ueauClients[uri] = client
	return client
}

func (s *nudmService) SendAuthResultToUDM(
	id string,
	authType models.Udm_UEAU_AuthType,
	success bool,
	servingNetworkName, udmUrl string,
) error {
	timeNow := time.Now()
	timePtr := &timeNow

	self := s.consumer.Context()

	authEvent := models.Udm_UEAU_AuthEvent{
		TimeStamp:          timePtr,
		AuthType:           authType,
		Success:            success,
		ServingNetworkName: servingNetworkName,
		NfInstanceId:       self.GetSelfID(),
	}

	client := s.getUdmUeauClient(udmUrl)

	ctx, _, err := ausf_context.GetSelf().GetTokenCtx(
		models.Nrf_NFMgmt_ServiceName_NUDM_UEAU,
		models.Nrf_NFMgmt_NFType_UDM,
	)
	if err != nil {
		return err
	}

	request := &Nudm_UEAU.ConfirmAuthRequest{
		Supi:        &id,
		RequestBody: &authEvent,
	}

	_, confirmAuthErr := client.ConfirmAuthApi.ConfirmAuth(ctx, request)
	if confirmAuthErr != nil {
		logger.ConsumerLog.Errorf("Error in ConfirmAuth: %v", confirmAuthErr)
	}

	return confirmAuthErr
}

func (s *nudmService) GenerateAuthDataApi(
	udmUrl string,
	supiOrSuci string,
	authInfoReq models.Udm_UEAU_AuthenticationInfoRequest,
) (*models.Udm_UEAU_AuthenticationInfoResult, error) {
	client := s.getUdmUeauClient(udmUrl)

	ctx, _, err := ausf_context.GetSelf().GetTokenCtx(
		models.Nrf_NFMgmt_ServiceName_NUDM_UEAU,
		models.Nrf_NFMgmt_NFType_UDM,
	)
	if err != nil {
		return nil, err
	}

	request := &Nudm_UEAU.GenerateAuthDataRequest{
		SupiOrSuci:  &supiOrSuci,
		RequestBody: &authInfoReq,
	}

	rsp, err := client.GenerateAuthDataApi.GenerateAuthData(ctx, request)
	if err != nil {
		return nil, err
	}
	return rsp.Udm_UEAU_AuthenticationInfoResult, nil
}
