package consumer

import (
	nrf_discovery "github.com/ShouheiNishi/openapi5g/nrf/discovery"
	nrf_management "github.com/ShouheiNishi/openapi5g/nrf/management"
	utils_error "github.com/ShouheiNishi/openapi5g/utils/error"

	ausf_context "github.com/free5gc/ausf/internal/context"
	"github.com/free5gc/util/httpclient"
)

func SendSearchNFInstances(nrfUri string, targetNfType, requestNfType nrf_management.NFType,
	param nrf_discovery.SearchNFInstancesParams,
) (*nrf_discovery.SearchResult, error) {
	ctx, _, err := ausf_context.GetSelf().GetTokenCtx("nnrf-disc", "NRF")
	if err != nil {
		return nil, err
	}

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
	rsp, err := client.SearchNFInstancesWithResponse(ctx,
		&param)
	if err != nil || rsp.JSON200 == nil {
		return nil, utils_error.ExtractAndWrapOpenAPIError("nrf_discovery.SearchNFInstancesWithResponse", rsp, err)
	}
	return rsp.JSON200, nil
}
