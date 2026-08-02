package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/AndresGT/GoKit/security/token"
)

// =============================================================================
// Autenticación
// =============================================================================

// RequireAuth valida el access token Bearer del header Authorization usando
// el JWTManager proporcionado. Si el token es válido, inyecta sus claims en
// el contexto de la petición (recuperables con ClaimsFromContext) y continúa
// la cadena; en caso contrario responde 401 Unauthorized sin llegar al
// siguiente handler.
//
// Rechaza explícitamente los refresh tokens: solo un token cuyo TokenType
// sea token.TokenTypeAccess se considera una credencial de acceso válida.
//
// Ejemplo de uso:
//
//	authed := middleware.RequireAuth(jwtManager)
//	mux.Handle("/perfil", authed(http.HandlerFunc(perfilHandler)))
func RequireAuth(manager *token.JWTManager) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tokenString, err := extractBearerToken(r)
			if err != nil {
				writeError(w, http.StatusUnauthorized, "no autorizado")
				return
			}

			claims, err := manager.ValidateToken(tokenString)
			if err != nil {
				writeError(w, http.StatusUnauthorized, "token inválido o expirado")
				return
			}

			// Un refresh token nunca debe aceptarse como credencial de acceso.
			if claims.TokenType != token.TokenTypeAccess {
				writeError(w, http.StatusUnauthorized, "tipo de token inválido")
				return
			}

			ctx := context.WithValue(r.Context(), claimsContextKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// =============================================================================
// Autorización por Rol
// =============================================================================

// RequireRole restringe el acceso a los usuarios cuyo claim Role esté entre
// los roles permitidos. Responde 403 Forbidden si el rol no está permitido.
//
// Debe encadenarse DESPUÉS de RequireAuth: depende de los claims que este
// último inyecta en el contexto. Si RequireAuth no se ejecutó antes, responde
// 401 Unauthorized.
//
// Ejemplo de uso:
//
//	authed := middleware.RequireAuth(jwtManager)
//	adminOnly := middleware.RequireRole("admin", "superadmin")
//	mux.Handle("/admin", authed(adminOnly(http.HandlerFunc(adminHandler))))
func RequireRole(roles ...string) Middleware {
	allowed := make(map[string]struct{}, len(roles))
	for _, role := range roles {
		allowed[role] = struct{}{}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := ClaimsFromContext(r.Context())
			if !ok {
				// RequireAuth no se ejecutó antes: no hay claims que evaluar.
				writeError(w, http.StatusUnauthorized, "no autorizado")
				return
			}

			if _, permitted := allowed[claims.Role]; !permitted {
				writeError(w, http.StatusForbidden, "permisos insuficientes")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// =============================================================================
// Verificación de Sesión Activa
// =============================================================================

// RequireActiveSession verifica, además de la firma y expiración del JWT,
// que la sesión asociada (claims.SessionID) siga activa según el
// SessionManager proporcionado. Responde 401 Unauthorized si la sesión fue
// revocada, expiró o no existe.
//
// Esto cubre una limitación inherente de los JWT: un access token firmado
// correctamente sigue siendo válido hasta que expira por sí solo, aunque el
// usuario haya cerrado sesión, cambiado su contraseña o se le haya revocado
// el acceso. Encadenar este middleware permite invalidar el acceso de forma
// inmediata a costa de una consulta adicional al SessionStore en cada
// petición — una decisión de diseño consciente entre rendimiento y capacidad
// de revocación instantánea; úsalo en las rutas donde esa garantía importe.
//
// Debe encadenarse DESPUÉS de RequireAuth.
//
// Ejemplo de uso:
//
//	authed := middleware.RequireAuth(jwtManager)
//	activeSession := middleware.RequireActiveSession(sessionManager)
//	mux.Handle("/perfil", authed(activeSession(http.HandlerFunc(perfilHandler))))
func RequireActiveSession(sessions *token.SessionManager) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := ClaimsFromContext(r.Context())
			if !ok || claims.SessionID == "" {
				writeError(w, http.StatusUnauthorized, "no autorizado")
				return
			}

			if _, err := sessions.ValidateSession(claims.SessionID); err != nil {
				writeError(w, http.StatusUnauthorized, "sesión inválida o revocada")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// =============================================================================
// Utilidades Internas
// =============================================================================

// extractBearerToken extrae el token del header "Authorization: Bearer <token>".
func extractBearerToken(r *http.Request) (string, error) {
	header := r.Header.Get("Authorization")
	if header == "" {
		return "", ErrMissingAuthHeader
	}

	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return "", ErrInvalidAuthHeader
	}

	tokenString := strings.TrimSpace(parts[1])
	if tokenString == "" {
		return "", ErrInvalidAuthHeader
	}

	return tokenString, nil
}
