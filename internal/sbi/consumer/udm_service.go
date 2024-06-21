package consumer

import (
	"sync"
	"time"

	ausf_context "github.com/free5gc/ausf/internal/context"
	"github.com/free5gc/ausf/internal/logger"
	Nudm_UEAU "github.com/free5gc/openapi/Nudm_UEAuthentication"
	"github.com/free5gc/openapi/models"
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
	client = Nudm_UEAU.NewAPIClient(configuration)

	s.ueauMu.RUnlock()
	s.ueauMu.Lock()
	defer s.ueauMu.Unlock()
	s.ueauClients[uri] = client
	return client
}

func (s *nudmService) SendAuthResultToUDM(
	id string,
	authType models.AuthType,
	success bool,
	servingNetworkName, udmUrl string,
) error {
	timeNow := time.Now()
	timePtr := &timeNow

	self := s.consumer.Context()

	authEvent := models.AuthEvent{
		TimeStamp:          timePtr,
		AuthType:           authType,
		Success:            success,
		ServingNetworkName: servingNetworkName,
		NfInstanceId:       self.GetSelfID(),
	}

	client := s.getUdmUeauClient(udmUrl)

	ctx, _, err := ausf_context.GetSelf().GetTokenCtx(models.ServiceName_NUDM_UEAU, models.NfType_UDM)
	if err != nil {
		return err
	}

	_, rsp, confirmAuthErr := client.ConfirmAuthApi.ConfirmAuth(ctx, id, authEvent)
	defer func() {
		if rspCloseErr := rsp.Body.Close(); rspCloseErr != nil {
			logger.ConsumerLog.Errorf("ConfirmAuth Response cannot close: %v", rspCloseErr)
		}
	}()
	return confirmAuthErr
}

func (s *nudmService) GenerateAuthDataApi(
	udmUrl string,
	supiOrSuci string,
	authInfoReq models.AuthenticationInfoRequest,
) (*models.AuthenticationInfoResult, error, *models.ProblemDetails) {
	client := s.getUdmUeauClient(udmUrl)

	ctx, pd, err := ausf_context.GetSelf().GetTokenCtx(models.ServiceName_NUDM_UEAU, models.NfType_UDM)
	if err != nil {
		return nil, err, pd
	}

	authInfoResult, rsp, err := client.GenerateAuthDataApi.GenerateAuthData(ctx, supiOrSuci, authInfoReq)
	if err != nil {
		var problemDetails models.ProblemDetails
		if authInfoResult.AuthenticationVector == nil {
			problemDetails.Cause = "AV_GENERATION_PROBLEM"
		} else {
			problemDetails.Cause = "UPSTREAM_SERVER_ERROR"
		}
		problemDetails.Status = int32(rsp.StatusCode)
		return nil, err, &problemDetails
	}
	defer func() {
		if rspCloseErr := rsp.Body.Close(); rspCloseErr != nil {
			logger.UeAuthLog.Errorf("GenerateAuthDataApi response body cannot close: %+v", rspCloseErr)
		}
	}()
	return &authInfoResult, nil, nil
}
