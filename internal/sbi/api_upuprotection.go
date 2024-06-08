package sbi

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func (s *Server) SupiUeUpuPost(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{})
}
