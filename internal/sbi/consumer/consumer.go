package consumer

import (
	"github.com/free5gc/ausf/pkg/app"
	"github.com/free5gc/openapi/Nnrf_NFDiscovery"
	"github.com/free5gc/openapi/Nnrf_NFManagement"
	"github.com/free5gc/openapi/Nudm_UEAuthentication"
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

	c.nudmService = &nudmService{
		consumer:    c,
		ueauClients: make(map[string]*Nudm_UEAuthentication.APIClient),
	}

	return c, nil
}
