package consumer

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/ShouheiNishi/openapi5g/commondata"
	nrf_management "github.com/ShouheiNishi/openapi5g/nrf/management"
	ausf_context "github.com/free5gc/ausf/internal/context"
	"github.com/free5gc/ausf/internal/logger"
	"github.com/free5gc/openapi"
	"github.com/free5gc/util/httpclient"
	"github.com/google/uuid"
)

func BuildNFInstance(ausfContext *ausf_context.AUSFContext) (profile nrf_management.NFProfile, err error) {
	profile.NfInstanceId, err = uuid.Parse(ausfContext.NfId)
	if err != nil {
		return nrf_management.NFProfile{}, err
	}
	profile.NfType = nrf_management.NFTypeAUSF
	profile.NfStatus = nrf_management.NFStatusREGISTERED
	if profile.Ipv4Addresses == nil {
		profile.Ipv4Addresses = &[]string{}
	}
	*profile.Ipv4Addresses = append(*profile.Ipv4Addresses, ausfContext.RegisterIPv4)
	services := []nrf_management.NFService{}
	for _, nfService := range ausfContext.NfService {
		services = append(services, nfService)
	}
	if len(services) > 0 {
		profile.NfServices = &services
	}
	var ausfInfo nrf_management.AusfInfo
	ausfInfo.GroupId = &ausfContext.GroupID
	profile.AusfInfo = &ausfInfo
	profile.PlmnList = &ausfContext.PlmnList
	return
}

// func SendRegisterNFInstance(nrfUri, nfInstanceId string, profile models.NfProfile) (resouceNrfUri string,
//
//	retrieveNfInstanceID string, err error) {
func SendRegisterNFInstance(nrfUri, nfInstanceId string, profile nrf_management.NFProfile) (string, string, error) {
	uri := nrfUri + "/nnrf-nfm/v1"
	client, err := nrf_management.NewClientWithResponses(uri, func(c *nrf_management.Client) error {
		c.Client = httpclient.GetHttpClient(uri)
		return nil
	})
	if err != nil {
		return "", "", err
	}

	binNfInstanceId, err := uuid.Parse(nfInstanceId)
	if err != nil {
		return "", "", err
	}
	var res *nrf_management.RegisterNFInstanceResponse
	for {
		if resTmp, err := client.RegisterNFInstanceWithResponse(context.TODO(),
			binNfInstanceId,
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
			retrieveNfInstanceID := resourceUri[strings.LastIndex(resourceUri, "/")+1:]
			return resourceNrfUri, retrieveNfInstanceID, nil
		} else {
			fmt.Println(fmt.Errorf("handler returned wrong status code %d", status))
			fmt.Println(fmt.Errorf("NRF return wrong status code %d", status))
		}
	}
	return "", "", nil
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

	binNfId, err := uuid.Parse(ausfSelf.NfId)
	if err != nil {
		return nil, err
	}
	res, err := client.DeregisterNFInstanceWithResponse(context.Background(), binNfId)
	// TODO: remove if-return-else repeat
	if err == nil {
		return nil, err
	} else if res.ApplicationproblemJSON400 != nil {
		return res.ApplicationproblemJSON400, nil
	} else if res.ApplicationproblemJSON401 != nil {
		return res.ApplicationproblemJSON401, nil
	} else if res.ApplicationproblemJSON403 != nil {
		return res.ApplicationproblemJSON403, nil
	} else if res.ApplicationproblemJSON404 != nil {
		return res.ApplicationproblemJSON404, nil
	} else if res.ApplicationproblemJSON411 != nil {
		return res.ApplicationproblemJSON411, nil
	} else if res.ApplicationproblemJSON429 != nil {
		return res.ApplicationproblemJSON429, nil
	} else if res.ApplicationproblemJSON500 != nil {
		return res.ApplicationproblemJSON500, nil
	} else if res.ApplicationproblemJSON501 != nil {
		return res.ApplicationproblemJSON501, nil
	} else if res.ApplicationproblemJSON503 != nil {
		return res.ApplicationproblemJSON503, nil
	} else {
		return nil, openapi.ReportError("server no response")
	}
}
