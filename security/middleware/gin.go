package middleware

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/AndresGT/GoKit/logger"
	"github.com/AndresGT/GoKit/security"
	"github.com/AndresGT/GoKit/security/token"
	"github.com/gin-gonic/gin"
)

// GinAuth es el middleware de autenticación nativo para Gin
func GinAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": security.ErrTokenInvalid.Error()})
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": security.ErrTokenInvalid.Error()})
			return
		}

		claims, err := token.ValidateToken(parts[1])
		if err != nil {
			logger.WarnWithFields("Intento de acceso token inválido (Gin)", map[string]interface{}{
				"ip":    c.ClientIP(),
				"path":  c.Request.URL.Path,
				"error": err.Error(),
			})
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": security.ErrTokenInvalid.Error()})
			return
		}

		// En Gin guardamos los datos en el contexto propio de Gin
		c.Set("user_id", claims.UserID)
		c.Set("user_claims", claims)

		c.Next()
	}
}

// GinLogger registra peticiones usando el Logger Global de GoKit
func GinLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path

		c.Next()

		fields := map[string]interface{}{
			"method":   c.Request.Method,
			"path":     path,
			"status":   c.Writer.Status(),
			"duration": time.Since(start).String(),
			"ip":       c.ClientIP(),
		}

		if len(c.Errors) > 0 {
			fields["errors"] = c.Errors.String()
		}

		if c.Writer.Status() >= 500 {
			logger.ErrorWithFields("HTTP Request Error", fields)
		} else if c.Writer.Status() >= 400 {
			logger.WarnWithFields("HTTP Request Warning", fields)
		} else {
			logger.InfoWithFields("HTTP Request Handled", fields)
		}
	}
}

// GinRecovery captura panics en los handlers de Gin
func GinRecovery() gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if err := recover(); err != nil {
				logger.ErrorWithFields("PANIC RECUPERADO EN GIN", map[string]interface{}{
					"error": fmt.Sprintf("%v", err),
					"path":  c.Request.URL.Path,
				})
				c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "error interno del servidor"})
			}
		}()
		c.Next()
	}
}
