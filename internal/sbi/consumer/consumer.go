package consumer

import (
	nrf_discovery "github.com/ShouheiNishi/openapi5g/nrf/discovery"
	nrf_management "github.com/ShouheiNishi/openapi5g/nrf/management"
	udm_ueau "github.com/ShouheiNishi/openapi5g/udm/ueau"

	"github.com/free5gc/ausf/pkg/app"
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
		nfMngmntClients: make(map[string]*nrf_management.ClientWithResponses),
		nfDiscClients:   make(map[string]*nrf_discovery.ClientWithResponses),
	}

	c.nudmService = &nudmService{
		consumer:    c,
		ueauClients: make(map[string]*udm_ueau.ClientWithResponses),
	}

	return c, nil
}
