package processor

import (
	"context"
	"errors"

	ausf_upu_protection "github.com/ShouheiNishi/openapi5g/ausf/upu"
	"github.com/ShouheiNishi/openapi5g/utils/error/middleware"
	strictgin "github.com/oapi-codegen/runtime/strictmiddleware/gin"
)

func NewServerAusfUpuProtection(processor *Processor) ausf_upu_protection.ServerInterface {
	return ausf_upu_protection.NewStrictHandler(
		processor, []strictgin.StrictGinMiddlewareFunc{middleware.GinStrictServerMiddleware},
	)
}

// (POST /{supi}/ue-upu)
func (p *Processor) PostSupiUeUpu(ctx context.Context, request ausf_upu_protection.PostSupiUeUpuRequestObject,
) (ausf_upu_protection.PostSupiUeUpuResponseObject, error) {
	return nil, errors.New("not implemented")
}
