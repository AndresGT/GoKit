package middleware

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/AndresGT/GoKit/logger"
	"github.com/AndresGT/GoKit/security"
	"github.com/AndresGT/GoKit/security/token"
	"github.com/gin-gonic/gin"
	"github.com/gofiber/fiber/v2"
)

// =============================================================================
// Route: definición de endpoint agnóstica al framework
// =============================================================================

// Route describe un endpoint a registrar en un router concreto. H es el tipo
// de handler nativo del framework (gin.HandlerFunc o fiber.Handler), lo que
// permite reutilizar la misma estructura tanto para Gin como para Fiber sin
// duplicar la definición de rutas.
//
// Ejemplo:
//
//	routes := []middleware.Route[gin.HandlerFunc]{
//	    {Method: "POST", Path: "/signup", Handler: handler.SignUp, Protected: false},
//	    {Method: "POST", Path: "/signin", Handler: handler.SignIn, Protected: false},
//	}
type Route[H any] struct {
	// Method es el verbo HTTP en mayúsculas ("GET", "POST", "PUT", "DELETE", ...).
	Method string
	// Path es la ruta relativa al grupo/router en el que se registra.
	Path string
	// Handler es el handler nativo del framework para este endpoint.
	Handler H
	// Protected indica si el endpoint requiere autenticación. Por sí solo
	// solo afecta al log de arranque; para que además se aplique el
	// middleware de autenticación automáticamente, registra las rutas con
	// WithAuthManager.
	Protected bool
}

// =============================================================================
// Opciones de registro
// =============================================================================

// RegisterOptions configura el comportamiento de RegisterGinRoutes y
// RegisterFiberRoutes.
type RegisterOptions struct {
	// AuthManager, si se proporciona, hace que las rutas con
	// Protected: true reciban automáticamente un middleware de
	// autenticación validado contra este manager, además de reflejarlo en
	// el log. Si se omite, Protected es solo informativo.
	AuthManager *token.JWTManager

	// GroupName es una etiqueta opcional (ej. "auth", "admin") que se
	// incluye en el log de arranque para identificar a qué grupo
	// pertenece cada ruta registrada.
	GroupName string
}

// RegisterOption modifica un RegisterOptions.
type RegisterOption func(*RegisterOptions)

// WithAuthManager habilita la aplicación automática de autenticación en las
// rutas marcadas como Protected: true, validando contra el manager dado.
func WithAuthManager(manager *token.JWTManager) RegisterOption {
	return func(o *RegisterOptions) {
		o.AuthManager = manager
	}
}

// WithGroupName etiqueta el grupo de rutas en el log de arranque.
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

// logRouteRegistered deja constancia en el logger global de GoKit de un
// endpoint registrado al arrancar la aplicación.
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

	// Construcción estructurada y ordenada
	msg := fmt.Sprintf("%s [%-6s] %-35s | grupo: %-12s | estado: %s",
		icon,
		method,
		path,
		groupName,
		authStatus,
	)

	// Usar Debug en lugar de Info para no saturar los logs de producción
	logger.Debug(msg)
}

// =============================================================================
// Gin
// =============================================================================

// RegisterGinRoutes registra un conjunto de rutas en un *gin.RouterGroup y
// deja constancia de cada endpoint en el logger global de GoKit.
//
// Si se pasa WithAuthManager, las rutas con Protected: true reciben
// automáticamente el middleware de autenticación (validado contra ese
// manager) antes de llegar al handler. Sin WithAuthManager, Protected solo
// aparece en el log.
//
// Ejemplo:
//
//	authGroup := r.Group("/auth")
//	middleware.RegisterGinRoutes(authGroup, []middleware.Route[gin.HandlerFunc]{
//	    {Method: "POST", Path: "/signup", Handler: handler.SignUp, Protected: false},
//	    {Method: "POST", Path: "/signin", Handler: handler.SignIn, Protected: false},
//	}, middleware.WithGroupName("auth"))
//
// RegisterGinRoutes
func RegisterGinRoutes(group *gin.RouterGroup, routes []Route[gin.HandlerFunc], opts ...RegisterOption) {
	options := buildRegisterOptions(opts)

	for _, route := range routes {
		var handlers []gin.HandlerFunc
		authApplied := false

		if route.Protected && options.AuthManager != nil {
			handlers = append(handlers, ginAuthWithManager(options.AuthManager))
			authApplied = true
		}
		handlers = append(handlers, route.Handler)

		group.Handle(route.Method, route.Path, handlers...)

		// Normalización de la ruta para evitar //
		fullPath := strings.ReplaceAll(group.BasePath()+"/"+route.Path, "//", "/")
		logRouteRegistered(route.Method, fullPath, route.Protected, authApplied, options.GroupName)
	}
}

// ginAuthWithManager es equivalente a GinAuth() pero valida contra un
// *token.JWTManager explícito en lugar del manager global por defecto.
// Se usa internamente por RegisterGinRoutes cuando se pasa WithAuthManager.
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
				"ip":    c.ClientIP(),
				"path":  c.Request.URL.Path,
				"error": err.Error(),
			})
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": security.ErrTokenInvalid.Error()})
			return
		}

		c.Set("user_id", claims.UserID)
		c.Set("user_claims", claims)

		c.Next()
	}
}

// =============================================================================
// Fiber
// =============================================================================

// RegisterFiberRoutes registra un conjunto de rutas en un fiber.Router y
// deja constancia de cada endpoint en el logger global de GoKit.
//
// Si se pasa WithAuthManager, las rutas con Protected: true reciben
// automáticamente el middleware de autenticación (validado contra ese
// manager) antes de llegar al handler. Sin WithAuthManager, Protected solo
// aparece en el log.
//
// Ejemplo:
//
//	authGroup := r.Group("/auth")
//	middleware.RegisterFiberRoutes(authGroup, []middleware.Route[fiber.Handler]{
//	    {Method: "POST", Path: "/signup", Handler: handler.SignUp, Protected: false},
//	    {Method: "POST", Path: "/signin", Handler: handler.SignIn, Protected: false},
//	}, middleware.WithGroupName("auth"))
func RegisterFiberRoutes(group fiber.Router, routes []Route[fiber.Handler], opts ...RegisterOption) {
	options := buildRegisterOptions(opts)

	for _, route := range routes {
		var handlers []fiber.Handler
		authApplied := false

		if route.Protected && options.AuthManager != nil {
			handlers = append(handlers, fiberAuthWithManager(options.AuthManager))
			authApplied = true
		}
		handlers = append(handlers, route.Handler)

		group.Add(route.Method, route.Path, handlers...)
		logRouteRegistered(route.Method, route.Path, route.Protected, authApplied, options.GroupName)
	}
}

// fiberAuthWithManager es equivalente a FiberAuth() pero valida contra un
// *token.JWTManager explícito en lugar del manager global por defecto.
// Se usa internamente por RegisterFiberRoutes cuando se pasa WithAuthManager.
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
				"ip":    c.IP(),
				"path":  c.Path(),
				"error": err.Error(),
			})
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": security.ErrTokenInvalid.Error()})
		}

		c.Locals("user_id", claims.UserID)
		c.Locals("user_claims", claims)

		return c.Next()
	}
}
