package middleware

import "net/http"

// =============================================================================
// Tipo Middleware y Composición
// =============================================================================

// Middleware es el tipo estándar de middleware HTTP usado en este paquete:
// una función que envuelve un http.Handler con otro http.Handler.
// Es compatible con la firma que usan la mayoría de routers de Go.
type Middleware func(http.Handler) http.Handler

// Chain compone varios middlewares en un único http.Handler. Se aplican en
// el orden en que se pasan: el primero de la lista es el más externo (se
// ejecuta primero en la petición, último en la respuesta).
//
// Ejemplo de uso:
//
//	handler := middleware.Chain(finalHandler,
//	    middleware.RequestLogger(log),        // se ejecuta primero
//	    middleware.CORS(corsConfig),
//	    middleware.RequireAuth(jwtManager),    // se ejecuta justo antes del handler
//	)
func Chain(h http.Handler, mws ...Middleware) http.Handler {
	for i := len(mws) - 1; i >= 0; i-- {
		h = mws[i](h)
	}
	return h
}
