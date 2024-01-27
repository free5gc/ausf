package util

import (
	"net/http"

	"github.com/gin-gonic/gin"

	ausf_context "github.com/free5gc/ausf/internal/context"
	"github.com/free5gc/ausf/internal/logger"
)

type RouterAuthorizationCheck struct {
	serviceName string
}

func NewRouterAuthorizationCheck(serviceName string) *RouterAuthorizationCheck {
	return &RouterAuthorizationCheck{
		serviceName: serviceName,
	}
}

func (rac *RouterAuthorizationCheck) Check(c *gin.Context, ausfContext ausf_context.NFContext) {
	token := c.Request.Header.Get("Authorization")
	err := ausfContext.AuthorizationCheck(token, rac.serviceName)
	if err != nil {
		logger.UtilLog.Debugf("RouterAuthorizationCheck: Check Unauthorized: %s", err.Error())
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		c.Abort()
		return
	}

	logger.UtilLog.Debugf("RouterAuthorizationCheck: Check Authorized")
}
