package consumer

import (
	"github.com/free5gc/ausf/pkg/app"
	"github.com/free5gc/openapi/Nnrf_NFDiscovery"
	"github.com/free5gc/openapi/Nnrf_NFManagement"
)

var consumer *Consumer

type ConsumerAusf interface {
	app.App
}

type Consumer struct {
	ConsumerAusf

	*nnrfService
}

func GetConsumer() *Consumer {
	return consumer
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
	consumer = c
	return c, nil
}
