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
	"github.com/gofiber/fiber/v2"
)

type Route[H any] struct {
	Method      string
	Path        string
	Handler     H
	RateLimit   int 
	Protected   bool
}

type RegisterOptions struct {
	AuthManager *token.JWTManager
	GroupName   string
}

type RegisterOption func(*RegisterOptions)

func WithAuthManager(manager *token.JWTManager) RegisterOption {
	return func(o *RegisterOptions) {
		o.AuthManager = manager
	}
}

func WithGroupName(name string) RegisterOption {
	return func(o *RegisterOptions) {
		o.GroupName = name
	}
}

func buildRegisterOptions(opts []RegisterOption) RegisterOptions {
	var o RegisterOptions
	for _, opt := range opts {
		opt(&o)
	}
	return o
}

func logRouteRegistered(method, path string, protected, authApplied bool, groupName string) {
	icon := "🔓"
	authStatus := "pública"
	if protected {
		icon = "🔒"
		if authApplied {
			authStatus = "protegida (middleware activo)"
		} else {
			authStatus = "protegida (requiere auth)"
		}
	}
	msg := fmt.Sprintf("%s [%s] %s | grupo: %s | estado: %s", icon, method, path, groupName, authStatus)
	logger.Debug(msg)
}

func RegisterGinRoutes(group *gin.RouterGroup, routes []Route[gin.HandlerFunc], opts ...RegisterOption) {
	options := buildRegisterOptions(opts)
	for _, route := range routes {
		var handlers []gin.HandlerFunc
		authApplied := false

		if route.RateLimit > 0 {
			lim := NewMemoryRateLimiter(route.RateLimit, time.Minute)
			handlers = append(handlers, GinRateLimit(lim, nil))
		}

		if route.Protected && options.AuthManager != nil {
			handlers = append(handlers, ginAuthWithManager(options.AuthManager))
			authApplied = true
		}

		handlers = append(handlers, route.Handler)
		group.Handle(route.Method, route.Path, handlers...)

		fullPath := strings.ReplaceAll(group.BasePath()+"/"+route.Path, "//", "/")
		logRouteRegistered(route.Method, fullPath, route.Protected, authApplied, options.GroupName)
	}
}

func ginAuthWithManager(manager *token.JWTManager) gin.HandlerFunc {
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
		claims, err := manager.ValidateToken(parts[1])
		if err != nil {
			logger.WarnWithFields("Intento de acceso token inválido (Gin/RegisterRoutes)", map[string]interface{}{
				"ip": c.ClientIP(), "path": c.Request.URL.Path, "error": err.Error(),
			})
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": security.ErrTokenInvalid.Error()})
			return
		}
		if claims.TokenType != token.TokenTypeAccess {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "token type is not authorized"})
			return
		}
		c.Set("user_id", claims.UserID)
		c.Set("user_claims", claims)
		c.Next()
	}
}

func RegisterFiberRoutes(group fiber.Router, routes []Route[fiber.Handler], opts ...RegisterOption) {
	options := buildRegisterOptions(opts)
	for _, route := range routes {
		var handlers []fiber.Handler
		authApplied := false

		if route.RateLimit > 0 {
			lim := NewMemoryRateLimiter(route.RateLimit, time.Minute)
			handlers = append(handlers, fiberRateLimit(lim))
		}

		if route.Protected && options.AuthManager != nil {
			handlers = append(handlers, fiberAuthWithManager(options.AuthManager))
			authApplied = true
		}

		handlers = append(handlers, route.Handler)
		group.Add(route.Method, route.Path, handlers...)
		logRouteRegistered(route.Method, route.Path, route.Protected, authApplied, options.GroupName)
	}
}

func fiberAuthWithManager(manager *token.JWTManager) fiber.Handler {
	return func(c *fiber.Ctx) error {
		authHeader := c.Get("Authorization")
		if authHeader == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": security.ErrTokenInvalid.Error()})
		}
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": security.ErrTokenInvalid.Error()})
		}
		claims, err := manager.ValidateToken(parts[1])
		if err != nil {
			logger.WarnWithFields("Intento de acceso token inválido (Fiber/RegisterRoutes)", map[string]interface{}{
				"ip": c.IP(), "path": c.Path(), "error": err.Error(),
			})
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": security.ErrTokenInvalid.Error()})
		}
		c.Locals("user_id", claims.UserID)
		c.Locals("user_claims", claims)
		return c.Next()
	}
}

func fiberRateLimit(limiter RateLimiter) fiber.Handler {
	return func(c *fiber.Ctx) error {
		key := c.IP()
		if !limiter.Allow(key) {
			return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
				"error": "demasiadas peticiones, intenta de nuevo más tarde",
			})
		}
		return c.Next()
	}
}