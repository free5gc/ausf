package sbi

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func (s *Server) getSorprotectionRoutes() []Route {
	return []Route{
		{
			Method:  http.MethodGet,
			Pattern: "/",
			APIFunc: Index,
		},
		{
			Method:  http.MethodPost,
			Pattern: "/:supi/ue-sor",
			APIFunc: s.SupiUeSorPost,
		},
	}
}

func (s *Server) SupiUeSorPost(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{})
}
