package middleware

import (
	"fmt"
	"net/http"
	"time"
)

// =============================================================================
// Logging de Peticiones
// =============================================================================

// Logger es la interfaz mínima que necesita RequestLogger. El *logger.Logger
// de GoKit (paquete github.com/AndresGT/GoKit/logger) la implementa
// directamente, ya que su método Info tiene esta misma firma; cualquier otro
// logger compatible funciona igual. No se importa el paquete logger aquí a
// propósito, para no forzar esa dependencia en quien no lo use.
type Logger interface {
	Info(message string)
}

// statusRecorder envuelve http.ResponseWriter para capturar el código de
// estado HTTP finalmente escrito, ya que net/http no lo expone directamente.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

// RequestLogger registra cada petición HTTP (método, ruta, status y
// duración) usando el Logger proporcionado. Si el handler nunca llama
// explícitamente a WriteHeader, se asume el código 200 por defecto, tal
// como hace net/http.
//
// Ejemplo de uso:
//
//	log := logger.New()
//	handler := middleware.RequestLogger(log)(mux)
func RequestLogger(log Logger) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}

			next.ServeHTTP(rec, r)

			duration := time.Since(start)
			log.Info(fmt.Sprintf("%s %s %d %s", r.Method, r.URL.Path, rec.status, duration))
		})
	}
}
