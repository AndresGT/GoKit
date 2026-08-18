package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/AndresGT/GoKit/logger"
	"github.com/AndresGT/GoKit/security"
	"github.com/AndresGT/GoKit/security/token"
	"github.com/gin-gonic/gin"
)

// GinAuth es el middleware de autenticación nativo para Gin.
// Valida el JWT y guarda los claims tanto en el mapa interno de Gin
// como en el context.Context estándar de GoKit.
func GinAuth() gin.HandlerFunc {
	return GinAuthWithManager(nil)
}

// GinAuthWithManager permite usar una instancia específica de JWTManager.
func GinAuthWithManager(manager *token.JWTManager) gin.HandlerFunc {
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

		var claims *token.Claims
		var err error

		if manager != nil {
			claims, err = manager.ValidateToken(parts[1])
		} else {
			claims, err = token.ValidateToken(parts[1])
		}

		if err != nil {
			logger.WarnWithFields("Intento de acceso con token inválido (Gin)", map[string]interface{}{
				"ip":    c.ClientIP(),
				"path":  c.Request.URL.Path,
				"error": err.Error(),
			})
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": security.ErrTokenInvalid.Error()})
			return
		}

		// -----------------------------------------------------------------
		// 1. Integración con el contexto estándar de GoKit
		// -----------------------------------------------------------------
		// Guardamos *token.Claims en el context.Context estándar de Go.
		// Esto permite que middleware.ClaimsFromContext(r.Context()) funcione
		// perfectamente dentro de cualquier utilidad de GoKit (como RateLimiter).
		ctx := context.WithValue(c.Request.Context(), claimsContextKey, claims)
		c.Request = c.Request.WithContext(ctx)

		// -----------------------------------------------------------------
		// 2. Integración con las facilidades de Gin (c.Get / c.GetString)
		// -----------------------------------------------------------------
		c.Set("user_id", claims.UserID)
		c.Set("user_claims", claims)

		// Aplanamos CustomData ("entity_id", "plan_code", etc.) en el contexto de Gin
		if claims.CustomData != nil {
			for key, val := range claims.CustomData {
				c.Set(key, val)
			}
		}

		c.Next()
	}
}

func UserIDKeyFunc(req *http.Request) string {
	if claims, ok := ClaimsFromContext(req.Context()); ok && claims != nil && claims.UserID != "" {
		return "user:" + claims.UserID
	}
	return RemoteIPKeyFunc(req)
}

func GinRateLimit(limiter RateLimiter, keyFunc KeyFunc) gin.HandlerFunc {
	if keyFunc == nil {
		keyFunc = RemoteIPKeyFunc
	}

	return func(c *gin.Context) {
		key := keyFunc(c.Request)
		if !limiter.Allow(key) {
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error": "demasiadas peticiones, intenta de nuevo más tarde",
			})
			return
		}
		c.Next()
	}
}
