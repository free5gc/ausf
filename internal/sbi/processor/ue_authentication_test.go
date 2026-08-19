package processor

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"

	"github.com/free5gc/openapi/models"
)

func TestAuth5gAkaConfirmRejectsMissingResStar(t *testing.T) {
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)

	processor := &Processor{}
	processor.Auth5gAkaComfirmRequestProcedure(
		c,
		models.Ausf_UEAU_ConfirmationData{},
		"suci-0-001-01-0000-0-0-0000000001",
	)

	require.Equal(t, http.StatusBadRequest, recorder.Code)
	var problemDetails models.ProblemDetails
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &problemDetails))
	require.Equal(t, "MANDATORY_IE_MISSING", problemDetails.Cause)
}
