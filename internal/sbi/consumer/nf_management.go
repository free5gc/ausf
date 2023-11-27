package consumer

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/ShouheiNishi/openapi5g/commondata"
	nrf_management "github.com/ShouheiNishi/openapi5g/nrf/management"
	"github.com/ShouheiNishi/openapi5g/utils/problem"
	"github.com/google/uuid"

	ausf_context "github.com/free5gc/ausf/internal/context"
	"github.com/free5gc/ausf/internal/logger"
	"github.com/free5gc/util/httpclient"
)

func BuildNFInstance(ausfContext *ausf_context.AUSFContext) (profile nrf_management.NFProfile, err error) {
	profile.NfInstanceId = ausfContext.NfId
	profile.NfType = nrf_management.NFTypeAUSF
	profile.NfStatus = nrf_management.NFStatusREGISTERED
	profile.Ipv4Addresses = append(profile.Ipv4Addresses, ausfContext.RegisterIPv4)
	services := []nrf_management.NFService{}
	for _, nfService := range ausfContext.NfService {
		services = append(services, nfService)
	}
	if len(services) > 0 {
		profile.NfServices = services
	}
	var ausfInfo nrf_management.AusfInfo
	ausfInfo.GroupId = &ausfContext.GroupID
	profile.AusfInfo = &ausfInfo
	profile.PlmnList = ausfContext.PlmnList
	return
}

// func SendRegisterNFInstance(nrfUri, nfInstanceId string, profile models.NfProfile) (resouceNrfUri string,
//
//	retrieveNfInstanceID string, err error) {
func SendRegisterNFInstance(nrfUri string, nfInstanceId uuid.UUID, profile nrf_management.NFProfile,
) (string, uuid.UUID, error) {
	uri := nrfUri + "/nnrf-nfm/v1"
	client, err := nrf_management.NewClientWithResponses(uri, func(c *nrf_management.Client) error {
		c.Client = httpclient.GetHttpClient(uri)
		return nil
	})
	if err != nil {
		return "", uuid.Nil, err
	}

	var res *nrf_management.RegisterNFInstanceResponse
	for {
		if resTmp, err := client.RegisterNFInstanceWithResponse(context.TODO(),
			nfInstanceId,
			&nrf_management.RegisterNFInstanceParams{},
			profile); err != nil {
			logger.ConsumerLog.Errorf("AUSF register to NRF Error[%v]", err)
			time.Sleep(2 * time.Second)
			continue
		} else {
			res = resTmp
		}
		status := res.StatusCode()
		if status == http.StatusOK {
			// NFUpdate
			break
		} else if status == http.StatusCreated {
			// NFRegister
			resourceUri := res.HTTPResponse.Header.Get("Location")
			resourceNrfUri := resourceUri[:strings.Index(resourceUri, "/nnrf-nfm/")]
			retrieveNfInstanceID, err := uuid.Parse(resourceUri[strings.LastIndex(resourceUri, "/")+1:])
			if err != nil {
				return "", uuid.Nil, err
			}
			return resourceNrfUri, retrieveNfInstanceID, nil
		} else {
			fmt.Println(fmt.Errorf("handler returned wrong status code %d", status))
			fmt.Println(fmt.Errorf("NRF return wrong status code %d", status))
		}
	}
	return "", uuid.Nil, nil
}

func SendDeregisterNFInstance() (*commondata.ProblemDetails, error) {
	logger.ConsumerLog.Infof("Send Deregister NFInstance")

	ausfSelf := ausf_context.GetSelf()
	// Set client and set url
	uri := ausfSelf.NrfUri + "/nnrf-nfm/v1"
	client, err := nrf_management.NewClientWithResponses(uri, func(c *nrf_management.Client) error {
		c.Client = httpclient.GetHttpClient(uri)
		return nil
	})
	if err != nil {
		return nil, err
	}

	res, err := client.DeregisterNFInstanceWithResponse(context.Background(), ausfSelf.NfId)
	if err != nil {
		return nil, fmt.Errorf("nrf_management.DeregisterNFInstanceWithResponse: %w", err)
	}
	if res.StatusCode() != http.StatusNoContent {
		_, pd, err := problem.ExtractStatusCodeAndProblemDetails(res)
		return pd, err
	}
	return nil, nil
}
