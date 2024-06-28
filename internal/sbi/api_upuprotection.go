package sbi

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func (s *Server) getUpuprotectionRoutes() []Route {
	return []Route{
		{
			Method:  http.MethodGet,
			Pattern: "/",
			APIFunc: Index,
		},
		{
			Method:  http.MethodPost,
			Pattern: "/:supi/ue-upu",
			APIFunc: s.SupiUeUpuPost,
		},
	}
}

func (s *Server) SupiUeUpuPost(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{})
}
