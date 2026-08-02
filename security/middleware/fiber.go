package middleware

import (
	"fmt"
	"strings"
	"time"

	"github.com/AndresGT/GoKit/logger"
	"github.com/AndresGT/GoKit/security"
	"github.com/AndresGT/GoKit/security/token"
	"github.com/gofiber/fiber/v2"
)

// FiberAuth es el middleware de autenticación nativo para Fiber
func FiberAuth() fiber.Handler {
	return func(c *fiber.Ctx) error {
		authHeader := c.Get("Authorization")
		if authHeader == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": security.ErrTokenInvalid.Error()})
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": security.ErrTokenInvalid.Error()})
		}

		claims, err := token.ValidateToken(parts[1])
		if err != nil {
			logger.WarnWithFields("Intento de acceso token inválido (Fiber)", map[string]interface{}{
				"ip":    c.IP(),
				"path":  c.Path(),
				"error": err.Error(),
			})
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": security.ErrTokenInvalid.Error()})
		}

		// En Fiber usamos Locals para pasar variables en el request
		c.Locals("user_id", claims.UserID)
		c.Locals("user_claims", claims)

		return c.Next()
	}
}

// FiberLogger registra peticiones usando el Logger Global de GoKit
func FiberLogger() fiber.Handler {
	return func(c *fiber.Ctx) error {
		start := time.Now()

		err := c.Next()

		fields := map[string]interface{}{
			"method":   c.Method(),
			"path":     c.Path(),
			"status":   c.Response().StatusCode(),
			"duration": time.Since(start).String(),
			"ip":       c.IP(),
		}

		if c.Response().StatusCode() >= 500 {
			logger.ErrorWithFields("HTTP Request Error", fields)
		} else if c.Response().StatusCode() >= 400 {
			logger.WarnWithFields("HTTP Request Warning", fields)
		} else {
			logger.InfoWithFields("HTTP Request Handled", fields)
		}

		return err
	}
}

// FiberRecovery captura panics en Fiber
func FiberRecovery() fiber.Handler {
	return func(c *fiber.Ctx) error {
		defer func() {
			if err := recover(); err != nil {
				logger.ErrorWithFields("PANIC RECUPERADO EN FIBER", map[string]interface{}{
					"error": fmt.Sprintf("%v", err),
					"path":  c.Path(),
				})
				_ = c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "error interno del servidor"})
			}
		}()
		return c.Next()
	}
}
