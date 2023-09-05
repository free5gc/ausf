package consumer

import (
	"context"
	"fmt"
	"net/http"

	nrf_discovery "github.com/ShouheiNishi/openapi5g/nrf/discovery"
	nrf_management "github.com/ShouheiNishi/openapi5g/nrf/management"
	"github.com/free5gc/util/httpclient"
)

func SendSearchNFInstances(nrfUri string, targetNfType, requestNfType nrf_management.NFType,
	param nrf_discovery.SearchNFInstancesParams,
) (*nrf_discovery.SearchResult, error) {
	uri := nrfUri + "/nnrf-disc/v1"
	client, err := nrf_discovery.NewClientWithResponses(uri, func(c *nrf_discovery.Client) error {
		c.Client = httpclient.GetHttpClient(uri)
		return nil
	})
	if err != nil {
		return nil, err
	}

	param.TargetNfType = targetNfType
	param.RequesterNfType = requestNfType
	rsp, rspErr := client.SearchNFInstancesWithResponse(context.TODO(),
		&param)
	if rspErr != nil {
		return nil, fmt.Errorf("NFInstancesStoreApi Response error: %+w", rspErr)
	}
	if rsp != nil && rsp.StatusCode() == http.StatusTemporaryRedirect {
		return nil, fmt.Errorf("Temporary Redirect For Non NRF Consumer")
	}
	return rsp.JSON200, nil
}
