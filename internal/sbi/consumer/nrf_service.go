package consumer

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"

	"github.com/ShouheiNishi/openapi5g/models"
	nrf_discovery "github.com/ShouheiNishi/openapi5g/nrf/discovery"
	nrf_management "github.com/ShouheiNishi/openapi5g/nrf/management"
	utils_error "github.com/ShouheiNishi/openapi5g/utils/error"
	"github.com/ShouheiNishi/openapi5g/utils/problem"
	ausf_context "github.com/free5gc/ausf/internal/context"
	"github.com/free5gc/ausf/internal/logger"
	"github.com/free5gc/util/httpclient"
	"github.com/google/uuid"
)

type nnrfService struct {
	consumer *Consumer

	nfMngmntMu sync.RWMutex
	nfDiscMu   sync.RWMutex

	nfMngmntClients map[string]*nrf_management.ClientWithResponses
	nfDiscClients   map[string]*nrf_discovery.ClientWithResponses
}

func (s *nnrfService) getNFManagementClient(uri string) (*nrf_management.ClientWithResponses, error) {
	if uri == "" {
		return nil, fmt.Errorf("empty URI")
	}
	s.nfMngmntMu.RLock()
	client, ok := s.nfMngmntClients[uri]
	if ok {
		s.nfMngmntMu.RUnlock()
		return client, nil
	}

	editor, err := ausf_context.GetSelf().GetTokenRequestEditor(context.TODO(), models.ServiceNameNnrfNfm, models.NFTypeNRF)
	if err != nil {
		s.nfMngmntMu.RUnlock()
		return nil, err
	}

	uriFull := uri + "/nnrf-nfm/v1"
	client, err = nrf_management.NewClientWithResponses(uriFull, func(c *nrf_management.Client) error {
		c.Client = httpclient.GetHttpClient(uriFull)
		return nil
	}, nrf_management.WithRequestEditorFn(editor))
	if err != nil {
		s.nfMngmntMu.RUnlock()
		return nil, err
	}

	s.nfMngmntMu.RUnlock()
	s.nfMngmntMu.Lock()
	defer s.nfMngmntMu.Unlock()
	s.nfMngmntClients[uri] = client
	return client, nil
}

func (s *nnrfService) getNFDiscClient(uri string) (*nrf_discovery.ClientWithResponses, error) {
	if uri == "" {
		return nil, fmt.Errorf("empty URI")
	}
	s.nfDiscMu.RLock()
	client, ok := s.nfDiscClients[uri]
	if ok {
		s.nfDiscMu.RUnlock()
		return client, nil
	}

	editor, err := ausf_context.GetSelf().GetTokenRequestEditor(context.TODO(), models.ServiceNameNnrfDisc, models.NFTypeNRF)
	if err != nil {
		s.nfDiscMu.RUnlock()
		return nil, err
	}

	uriFull := uri + "/nnrf-disc/v1"
	client, err = nrf_discovery.NewClientWithResponses(uriFull, func(c *nrf_discovery.Client) error {
		c.Client = httpclient.GetHttpClient(uriFull)
		return nil
	}, nrf_discovery.WithRequestEditorFn(editor))
	if err != nil {
		s.nfDiscMu.RUnlock()
		return nil, err
	}

	s.nfDiscMu.RUnlock()
	s.nfDiscMu.Lock()
	defer s.nfDiscMu.Unlock()
	s.nfDiscClients[uri] = client
	return client, nil
}

func (s *nnrfService) SendSearchNFInstances(
	nrfUri string, targetNfType, requestNfType models.NFType, param nrf_discovery.SearchNFInstancesParams) (
	*models.SearchResult, error,
) {
	// Set client and set url
	client, err := s.getNFDiscClient(nrfUri)
	if err != nil {
		return nil, err
	}
	param.TargetNfType = targetNfType
	param.RequesterNfType = requestNfType
	rsp, err := client.SearchNFInstancesWithResponse(context.TODO(), &param)

	if err != nil || rsp.JSON200 == nil {
		return nil, utils_error.ExtractAndWrapOpenAPIError("nrf_discovery.SearchNFInstancesWithResponse", rsp, err)
	}
	return rsp.JSON200, nil
}

func (s *nnrfService) SendDeregisterNFInstance() (*models.ProblemDetails, error) {
	logger.ConsumerLog.Infof("Send Deregister NFInstance")

	ausfContext := s.consumer.Context()
	client, err := s.getNFManagementClient(ausfContext.NrfUri)
	if err != nil {
		return nil, err
	}

	res, err := client.DeregisterNFInstanceWithResponse(context.Background(), ausfContext.NfId)
	if err != nil {
		return nil, fmt.Errorf("nrf_management.DeregisterNFInstanceWithResponse: %w", err)
	}
	if res.StatusCode() != http.StatusNoContent {
		_, pd, err := problem.ExtractStatusCodeAndProblemDetails(res)
		return pd, err
	}
	return nil, nil
}

func (s *nnrfService) RegisterNFInstance(ctx context.Context) (
	resouceNrfUri string, retrieveNfInstanceID uuid.UUID, err error,
) {
	ausfContext := s.consumer.Context()

	client, err := s.getNFManagementClient(ausfContext.NrfUri)
	if err != nil {
		return "", uuid.Nil, err
	}

	nfProfile, err := s.buildNfProfile(ausfContext)
	if err != nil {
		return "", uuid.Nil, errors.Wrap(err, "RegisterNFInstance buildNfProfile()")
	}

	for {
		res, err := client.RegisterNFInstanceWithResponse(context.TODO(), ausfContext.NfId, nil, nfProfile)
		if err != nil || res == nil {
			logger.ConsumerLog.Errorf("AUSF register to NRF Error[%v]", err)
			time.Sleep(2 * time.Second)
			continue
		}
		status := res.StatusCode()
		if status == http.StatusOK {
			// NFUpdate
			break
		} else if nf := res.JSON201; nf != nil {
			// NFRegister
			resourceUri := res.HTTPResponse.Header.Get("Location")
			resouceNrfUri = resourceUri[:strings.Index(resourceUri, "/nnrf-nfm/")]
			retrieveNfInstanceID, err = uuid.Parse(resourceUri[strings.LastIndex(resourceUri, "/")+1:])
			if err != nil {
				return "", uuid.Nil, err
			}

			oauth2 := false
			if nf.CustomInfo != nil {
				v, ok := (*nf.CustomInfo)["oauth2"].(bool)
				if ok {
					oauth2 = v
					logger.MainLog.Infoln("OAuth2 setting receive from NRF:", oauth2)
				}
			}
			ausf_context.GetSelf().OAuth2Required = oauth2
			if oauth2 && ausf_context.GetSelf().NrfCertPem == "" {
				logger.CfgLog.Error("OAuth2 enable but no nrfCertPem provided in config.")
			}

			break
		} else {
			logger.ConsumerLog.Errorln("NRF return wrong status code", status)
		}
	}
	return resouceNrfUri, retrieveNfInstanceID, err
}

func (s *nnrfService) buildNfProfile(ausfContext *ausf_context.AUSFContext) (profile models.NFManagementNFProfile, err error) {
	profile.NfInstanceId = ausfContext.NfId
	profile.NfType = models.NFTypeAUSF
	profile.NfStatus = models.NFStatusREGISTERED
	profile.Ipv4Addresses = append(profile.Ipv4Addresses, ausfContext.RegisterIPv4)
	services := []models.NrfNFService{}
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

func (s *nnrfService) GetUdmUrl(nrfUri string) string {
	udmUrl := "https://localhost:29503" // default
	nfDiscoverParam := nrf_discovery.SearchNFInstancesParams{
		ServiceNames: &[]models.ServiceName{models.ServiceNameNudmUeau},
	}
	res, err := s.SendSearchNFInstances(
		nrfUri,
		models.NFTypeUDM,
		models.NFTypeAUSF,
		nfDiscoverParam,
	)
	if err != nil {
		logger.ConsumerLog.Errorln("[Search UDM UEAU] ", err.Error(), "use defalt udmUrl", udmUrl)
	} else if len(res.NfInstances) > 0 {
		udmInstance := res.NfInstances[0]
		if len(udmInstance.Ipv4Addresses) > 0 && len(udmInstance.NfServices) != 0 {
			ueauService := udmInstance.NfServices[0]
			if len(ueauService.IpEndPoints) != 0 {
				ueauEndPoint := ueauService.IpEndPoints[0]
				if ueauEndPoint.Port != nil {
					udmUrl = string(ueauService.Scheme) + "://" + ueauEndPoint.Ipv4Address + ":" + strconv.Itoa(*ueauEndPoint.Port)
				}
			}
		}
	} else {
		logger.ConsumerLog.Errorln("[Search UDM UEAU] len(NfInstances) = 0")
	}
	return udmUrl
}
