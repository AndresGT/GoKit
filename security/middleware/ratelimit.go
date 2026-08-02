package middleware

import (
	"net"
	"net/http"
	"sync"
	"time"
)

// =============================================================================
// Interfaz de Limitación de Tasa
// =============================================================================

// RateLimiter define el contrato para backends de limitación de tasa.
// Permite implementar el algoritmo o backend que prefieras (memoria, Redis,
// etc.) sin modificar el middleware RateLimit que lo consume.
type RateLimiter interface {
	// Allow indica si, en este momento, se permite una nueva petición para
	// la clave indicada (ej. una IP, un userID, una API key).
	Allow(key string) bool
}

// =============================================================================
// Implementación en Memoria (ventana fija)
// =============================================================================

// MemoryRateLimiter implementa RateLimiter en memoria usando el algoritmo de
// ventana fija (fixed window): permite como máximo 'limit' peticiones por
// 'window' y por clave.
//
// Adecuado para una sola instancia del servicio. En despliegues con varias
// instancias/réplicas, el límite se aplica de forma independiente en cada
// una (no es un límite global) — para eso necesitas un backend compartido
// (ej. Redis) implementando la interfaz RateLimiter.
type MemoryRateLimiter struct {
	mu       sync.Mutex
	limit    int
	window   time.Duration
	counters map[string]*windowCounter
}

type windowCounter struct {
	count      int
	windowFrom time.Time
}

// NewMemoryRateLimiter crea un limitador de tasa en memoria: como máximo
// 'limit' peticiones por 'window' y por clave. Si los valores no son
// válidos, se usan valores por defecto seguros (1 petición / 1 minuto).
func NewMemoryRateLimiter(limit int, window time.Duration) *MemoryRateLimiter {
	if limit < 1 {
		limit = 1
	}
	if window <= 0 {
		window = time.Minute
	}
	return &MemoryRateLimiter{
		limit:    limit,
		window:   window,
		counters: make(map[string]*windowCounter),
	}
}

// Allow implementa RateLimiter.
func (l *MemoryRateLimiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	c, exists := l.counters[key]

	// Sin contador previo, o la ventana anterior ya expiró: empezar una nueva.
	if !exists || now.Sub(c.windowFrom) >= l.window {
		l.counters[key] = &windowCounter{count: 1, windowFrom: now}
		return true
	}

	if c.count >= l.limit {
		return false
	}

	c.count++
	return true
}

// Cleanup elimina las claves cuya ventana ya expiró. El mapa interno de
// MemoryRateLimiter crece con cada clave nueva vista (IP, usuario...) y
// nunca se reduce por sí solo; en un proceso de larga duración esto es un
// crecimiento de memoria no acotado. Llama a Cleanup periódicamente (por
// ejemplo, con un time.Ticker cada pocos minutos) para evitarlo.
//
// Ejemplo de uso:
//
//	limiter := middleware.NewMemoryRateLimiter(100, time.Minute)
//	go func() {
//	    ticker := time.NewTicker(5 * time.Minute)
//	    for range ticker.C {
//	        limiter.Cleanup()
//	    }
//	}()
func (l *MemoryRateLimiter) Cleanup() {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	for key, c := range l.counters {
		if now.Sub(c.windowFrom) >= l.window {
			delete(l.counters, key)
		}
	}
}

// =============================================================================
// Middleware
// =============================================================================

// KeyFunc extrae la clave de limitación de tasa a partir de la petición
// (ej. la IP remota, un userID ya autenticado, una API key del header).
type KeyFunc func(r *http.Request) string

// RemoteIPKeyFunc usa la IP remota de la conexión TCP como clave de rate
// limit. Es el KeyFunc por defecto si RateLimit recibe nil.
//
// Advertencia: si tu servicio está detrás de un proxy o balanceador de
// carga, r.RemoteAddr será la IP del proxy, no la del cliente real, y todas
// las peticiones compartirán el mismo límite. En ese caso, provee tu propio
// KeyFunc que lea (y valide) X-Forwarded-For o X-Real-IP según la
// configuración de tu infraestructura — sin validación, un cliente podría
// falsificar ese header para evadir el límite o afectar a otros.
func RemoteIPKeyFunc(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// RateLimit limita el número de peticiones permitidas por clave (ver
// KeyFunc). Responde 429 Too Many Requests cuando se supera el límite.
//
// Si keyFunc es nil, se usa RemoteIPKeyFunc.
//
// Ejemplo de uso:
//
//	limiter := middleware.NewMemoryRateLimiter(60, time.Minute) // 60 req/min por IP
//	handler := middleware.RateLimit(limiter, nil)(mux)
//
//	// Limitar por usuario autenticado en vez de por IP:
//	byUser := func(r *http.Request) string {
//	    if claims, ok := middleware.ClaimsFromContext(r.Context()); ok {
//	        return claims.UserID
//	    }
//	    return middleware.RemoteIPKeyFunc(r)
//	}
//	handler := middleware.RequireAuth(jwtManager)(
//	    middleware.RateLimit(limiter, byUser)(mux),
//	)
func RateLimit(limiter RateLimiter, keyFunc KeyFunc) Middleware {
	if keyFunc == nil {
		keyFunc = RemoteIPKeyFunc
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := keyFunc(r)
			if !limiter.Allow(key) {
				writeError(w, http.StatusTooManyRequests, "demasiadas peticiones, intenta de nuevo más tarde")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
