package consumer

import (
	"github.com/free5gc/ausf/internal/logger"
	"github.com/free5gc/ausf/pkg/app"
	Nnrf_NFDiscovery "github.com/free5gc/openapi/nrf/NFDiscovery"
	Nnrf_NFManagement "github.com/free5gc/openapi/nrf/NFManagement"
	Nudm_UEAuthentication "github.com/free5gc/openapi/udm/UEAuthentication"
	"github.com/free5gc/util/nfheartbeat"
)

type ConsumerAusf interface {
	app.App
}

type Consumer struct {
	ConsumerAusf

	*nnrfService
	*nudmService
}

func NewConsumer(ausf ConsumerAusf) (*Consumer, error) {
	c := &Consumer{
		ConsumerAusf: ausf,
	}

	c.nnrfService = &nnrfService{
		consumer:        c,
		nfMngmntClients: make(map[string]*Nnrf_NFManagement.APIClient),
		nfDiscClients:   make(map[string]*Nnrf_NFDiscovery.APIClient),
	}
	heartbeat, err := nfheartbeat.NewRunner(
		nrfRegistrar{c.nnrfService},
		func() int32 { return c.Config().GetNfHeartBeatTimer() },
		logger.ConsumerLog,
	)
	if err != nil {
		return nil, err
	}
	c.nnrfService.heartbeat = heartbeat

	c.nudmService = &nudmService{
		consumer:    c,
		ueauClients: make(map[string]*Nudm_UEAuthentication.APIClient),
	}

	return c, nil
}
