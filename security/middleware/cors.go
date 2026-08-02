package middleware

import (
	"net/http"
	"strconv"
	"strings"
)

// =============================================================================
// CORS
// =============================================================================

// CORSConfig define la configuración del middleware CORS.
type CORSConfig struct {
	// AllowedOrigins es la lista de orígenes permitidos (ej.
	// "https://app.example.com"). Usa "*" para permitir cualquier origen —
	// pero ten en cuenta que la especificación CORS prohíbe combinar "*"
	// con AllowCredentials = true; en ese caso, "*" se ignora.
	AllowedOrigins []string

	// AllowedMethods es la lista de métodos HTTP permitidos en la petición
	// real. Si está vacía, se usa un conjunto por defecto razonable
	// (GET, POST, PUT, PATCH, DELETE, OPTIONS).
	AllowedMethods []string

	// AllowedHeaders es la lista de headers que el cliente puede enviar.
	// Si está vacía, se usa un conjunto por defecto (Authorization, Content-Type).
	AllowedHeaders []string

	// AllowCredentials indica si se permite el envío de cookies/credenciales
	// (Access-Control-Allow-Credentials). No es compatible con
	// AllowedOrigins = ["*"] según la especificación CORS.
	AllowCredentials bool

	// MaxAge es cuánto tiempo, en segundos, el navegador puede cachear la
	// respuesta a una petición preflight (OPTIONS). Si es 0, no se envía
	// la cabecera y el navegador usa su valor por defecto.
	MaxAge int
}

var (
	defaultCORSMethods = []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
	defaultCORSHeaders = []string{"Authorization", "Content-Type"}
)

// CORS aplica las cabeceras CORS según la configuración proporcionada y
// responde directamente (204 No Content) a las peticiones preflight
// (OPTIONS), sin llegar al siguiente handler.
//
// Ejemplo de uso:
//
//	cfg := middleware.CORSConfig{
//	    AllowedOrigins:   []string{"https://app.example.com"},
//	    AllowCredentials: true,
//	}
//	handler := middleware.CORS(cfg)(mux)
func CORS(cfg CORSConfig) Middleware {
	methods := cfg.AllowedMethods
	if len(methods) == 0 {
		methods = defaultCORSMethods
	}
	headers := cfg.AllowedHeaders
	if len(headers) == 0 {
		headers = defaultCORSHeaders
	}

	allowedOrigins := make(map[string]struct{}, len(cfg.AllowedOrigins))
	wildcard := false
	for _, o := range cfg.AllowedOrigins {
		if o == "*" {
			wildcard = true
		}
		allowedOrigins[o] = struct{}{}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")

			if origin != "" {
				_, allowed := allowedOrigins[origin]
				switch {
				case wildcard && !cfg.AllowCredentials:
					w.Header().Set("Access-Control-Allow-Origin", "*")
				case allowed:
					w.Header().Set("Access-Control-Allow-Origin", origin)
					// El origen permitido varía según el request: evita que
					// caches intermedios sirvan esta respuesta a otro origen.
					w.Header().Set("Vary", "Origin")
				}

				if cfg.AllowCredentials {
					w.Header().Set("Access-Control-Allow-Credentials", "true")
				}
			}

			if r.Method == http.MethodOptions {
				w.Header().Set("Access-Control-Allow-Methods", strings.Join(methods, ", "))
				w.Header().Set("Access-Control-Allow-Headers", strings.Join(headers, ", "))
				if cfg.MaxAge > 0 {
					w.Header().Set("Access-Control-Max-Age", strconv.Itoa(cfg.MaxAge))
				}
				w.WriteHeader(http.StatusNoContent)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
