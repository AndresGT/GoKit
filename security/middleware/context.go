package middleware

import (
	"context"

	"github.com/AndresGT/GoKit/security/token"
)

// =============================================================================
// Contexto de Petición
// =============================================================================

// contextKey es un tipo privado para las claves de contexto de este paquete,
// evitando colisiones con claves definidas por otros paquetes.
type contextKey string

// claimsContextKey es la clave bajo la que RequireAuth guarda los claims
// del JWT validado en el contexto de la petición.
const claimsContextKey contextKey = "gokit-middleware-claims"

// ClaimsFromContext extrae los claims del JWT validado por RequireAuth desde
// el contexto de la petición. El segundo valor devuelto es false si
// RequireAuth no se ejecutó antes en la cadena de middlewares (por ejemplo,
// si se llama desde una ruta pública).
//
// Ejemplo de uso dentro de un handler protegido por RequireAuth:
//
//	func perfilHandler(w http.ResponseWriter, r *http.Request) {
//	    claims, ok := middleware.ClaimsFromContext(r.Context())
//	    if !ok {
//	        http.Error(w, "no autorizado", http.StatusUnauthorized)
//	        return
//	    }
//	    fmt.Fprintf(w, "Hola, %s", claims.Username)
//	}
func ClaimsFromContext(ctx context.Context) (*token.Claims, bool) {
	claims, ok := ctx.Value(claimsContextKey).(*token.Claims)
	return claims, ok
}
