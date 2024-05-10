package processor

import "github.com/free5gc/ausf/pkg/app"

type ProcessorAusf interface {
	app.App
}

type Processor struct {
	ProcessorAusf
}

type HandlerResponse struct {
	Status  int
	Headers map[string][]string
	Body    interface{}
}

func NewProcessor(ausf ProcessorAusf) (*Processor, error) {
	p := &Processor{
		ProcessorAusf: ausf,
	}
	return p, nil
}
