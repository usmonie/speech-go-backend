package api

import (
	"log"
	"time"

	"github.com/gin-gonic/gin"
)

func Logger() gin.HandlerFunc {
	return func(c *gin.Context) {
		t := time.Now()

		// Process request
		c.Next()

		// Log the request
		latency := time.Since(t)
		log.Printf("Latency: %v | Status: %v | Method: %s | Path: %s",
			latency,
			c.Writer.Status(),
			c.Request.Method,
			c.Request.URL.Path,
		)
	}
}

func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// This is a placeholder. In a real app, you'd validate the token here.
		token := c.GetHeader("Authorization")
		if token == "" {
			c.JSON(401, gin.H{"error": "Authorization token required"})
			c.Abort()
			return
		}
		// For now, we'll just set a dummy user ID
		c.Set("userID", "dummy-user-id")
		c.Next()
	}
}
