package processor

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/free5gc/openapi/models"
)

// UeAuthenticationsDeregisterProcedure implements TS 29.509 5.2.2.3.
// The consumer selects the AUSF holding the stale context; this operation does
// not remove the authentication result stored in UDM.
func (p *Processor) UeAuthenticationsDeregisterProcedure(c *gin.Context,
	info models.Ausf_UEAU_DeregistrationInfo,
) {
	if !p.Context().RemoveUEAuthenticationContext(info.Supi) {
		c.Header("Content-Type", "application/problem+json")

		// If the context is not found,
		// return 404 CONTEXT_NOT_FOUND.
		c.JSON(http.StatusNotFound, models.ProblemDetails{
			Status: http.StatusNotFound, Cause: "CONTEXT_NOT_FOUND",
		})
		return
	}

	// If the context is removed successfully,
	// return 204 No Content.
	c.Status(http.StatusNoContent)
}
