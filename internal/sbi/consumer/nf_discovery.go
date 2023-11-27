package consumer

import (
	"context"

	nrf_discovery "github.com/ShouheiNishi/openapi5g/nrf/discovery"
	nrf_management "github.com/ShouheiNishi/openapi5g/nrf/management"
	utils_error "github.com/ShouheiNishi/openapi5g/utils/error"

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
	rsp, err := client.SearchNFInstancesWithResponse(context.TODO(),
		&param)
	if err != nil || rsp.JSON200 == nil {
		return nil, utils_error.ExtractAndWrapOpenAPIError("nrf_discovery.SearchNFInstancesWithResponse", rsp, err)
	}
	return rsp.JSON200, nil
}
