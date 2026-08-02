# GoKit Middleware

Middlewares HTTP reutilizables para el ecosistema **GoKit**: autenticación JWT, autorización por rol, verificación de sesión activa, limitación de tasa (rate limiting), CORS y logging de peticiones. Es la pieza que conecta `security/token`, `security/crypto` y `logger` con cualquier servidor HTTP en Go.

## 🌟 Características

- **100% compatible con `net/http`**: todos los middlewares tienen la firma estándar `func(http.Handler) http.Handler` (tipo `Middleware`), por lo que funcionan con `net/http`, `chi`, `gorilla/mux` o cualquier router que siga esta convención.
- **`RequireAuth`**: valida el access token Bearer con tu `token.JWTManager` e inyecta los claims en el contexto de la petición.
- **`RequireRole`**: autorización simple por rol, encadenable después de `RequireAuth`.
- **`RequireActiveSession`**: revocación real de acceso consultando `token.SessionManager`, algo que un JWT por sí solo no puede ofrecer.
- **`RateLimit`**: limitación de tasa por clave (IP, usuario, API key...) con una implementación en memoria incluida y una interfaz `RateLimiter` para conectar tu propio backend (Redis, etc.).
- **`CORS`**: configuración explícita de orígenes, métodos y headers permitidos, con manejo correcto de preflight y de la incompatibilidad `"*"` + credenciales.
- **`RequestLogger`**: logging estructurado de cada petición (método, ruta, status, duración) usando tu logger favorito.
- **`Chain`**: helper para componer varios middlewares sin anidar paréntesis manualmente.
- **Respuestas de error consistentes**: siempre JSON `{"error": "..."}`, sin filtrar nunca el error interno al cliente.

## 📦 Instalación

```bash
go get github.com/AndresGT/GoKit/security/middleware
```

> Este módulo depende de `github.com/AndresGT/GoKit/security/token` (`JWTManager`, `Claims`, `SessionManager`). La integración con `logger` es opcional y se hace mediante una interfaz mínima (`Logger`), no importando el paquete directamente.

## 🚀 Inicio rápido

```go
package main

import (
    "net/http"
    "time"

    "github.com/AndresGT/GoKit/logger"
    "github.com/AndresGT/GoKit/security/middleware"
    "github.com/AndresGT/GoKit/security/token"
)

func main() {
    jwtManager, _ := token.NewJWTManager(token.JWTConfig{
        SecretKey: []byte("una-clave-secreta-de-al-menos-32-bytes"),
        Issuer:    "gokit-auth",
    })

    log := logger.New()
    limiter := middleware.NewMemoryRateLimiter(100, time.Minute) // 100 req/min por IP

    mux := http.NewServeMux()
    mux.HandleFunc("/salud", func(w http.ResponseWriter, r *http.Request) {
        w.Write([]byte("ok"))
    })

    authed := middleware.RequireAuth(jwtManager)
    mux.Handle("/perfil", authed(http.HandlerFunc(perfilHandler)))

    handler := middleware.Chain(mux,
        middleware.RequestLogger(log),
        middleware.CORS(middleware.CORSConfig{
            AllowedOrigins: []string{"https://app.example.com"},
        }),
        middleware.RateLimit(limiter, nil),
    )

    http.ListenAndServe(":8080", handler)
}

func perfilHandler(w http.ResponseWriter, r *http.Request) {
    claims, _ := middleware.ClaimsFromContext(r.Context())
    w.Write([]byte("Hola, " + claims.Username))
}
```

## 🔐 Autenticación y autorización

### `RequireAuth`

Valida el header `Authorization: Bearer <token>` contra tu `token.JWTManager`. Si es válido, inyecta los `*token.Claims` en el contexto; si no, responde `401 Unauthorized` sin ejecutar el handler protegido.

```go
authed := middleware.RequireAuth(jwtManager)
mux.Handle("/perfil", authed(http.HandlerFunc(perfilHandler)))
```

Rechaza explícitamente cualquier token cuyo `TokenType` no sea `token.TokenTypeAccess` — un refresh token nunca se acepta como credencial de acceso.

### `ClaimsFromContext`

Recupera los claims inyectados por `RequireAuth` dentro de cualquier handler protegido:

```go
func perfilHandler(w http.ResponseWriter, r *http.Request) {
    claims, ok := middleware.ClaimsFromContext(r.Context())
    if !ok {
        http.Error(w, "no autorizado", http.StatusUnauthorized)
        return
    }
    fmt.Fprintf(w, "UserID: %s, Role: %s", claims.UserID, claims.Role)
}
```

### `RequireRole`

Restringe el acceso según el claim `Role`. **Debe encadenarse después de `RequireAuth`** — depende de los claims que este inyecta. Responde `403 Forbidden` si el rol no está permitido, o `401 Unauthorized` si `RequireAuth` no se ejecutó antes.

```go
adminOnly := middleware.RequireRole("admin", "superadmin")
mux.Handle("/admin", authed(adminOnly(http.HandlerFunc(adminHandler))))
```

### `RequireActiveSession`

Un JWT verificado por firma sigue siendo válido hasta que expira, aunque el usuario haya cerrado sesión o se le haya revocado el acceso. `RequireActiveSession` cierra esa brecha consultando tu `token.SessionManager` en cada petición (usando `claims.SessionID`), a costa de una lectura adicional al `SessionStore`. Úsalo en las rutas donde la revocación inmediata importe.

```go
activeSession := middleware.RequireActiveSession(sessionManager)
mux.Handle("/perfil", authed(activeSession(http.HandlerFunc(perfilHandler))))
```

## 🚦 Limitación de tasa (Rate Limiting)

```go
type RateLimiter interface {
    Allow(key string) bool
}
```

Incluye `MemoryRateLimiter`, una implementación en memoria con algoritmo de ventana fija:

```go
limiter := middleware.NewMemoryRateLimiter(60, time.Minute) // 60 peticiones/minuto por clave
handler := middleware.RateLimit(limiter, nil)(mux) // nil → usa la IP remota como clave
```

- **Por defecto** la clave es la IP remota (`RemoteIPKeyFunc`). Detrás de un proxy/load balancer, `r.RemoteAddr` es la IP del proxy — provee tu propio `KeyFunc` que lea `X-Forwarded-For`/`X-Real-IP` con la validación adecuada para tu infraestructura.
- **Limitar por usuario autenticado** en vez de por IP:

```go
byUser := func(r *http.Request) string {
    if claims, ok := middleware.ClaimsFromContext(r.Context()); ok {
        return claims.UserID
    }
    return middleware.RemoteIPKeyFunc(r)
}
handler := authed(middleware.RateLimit(limiter, byUser)(mux))
```

- **`MemoryRateLimiter` es solo para una instancia**: en despliegues con varias réplicas, el límite se aplica por réplica, no de forma global. Para un límite compartido, implementa `RateLimiter` sobre Redis u otro backend centralizado.
- **Llama a `limiter.Cleanup()` periódicamente**: el mapa interno crece con cada clave nueva vista y nunca se reduce solo; sin limpieza periódica es un crecimiento de memoria no acotado en procesos de larga duración.

```go
go func() {
    ticker := time.NewTicker(5 * time.Minute)
    for range ticker.C {
        limiter.Cleanup()
    }
}()
```

## 🌐 CORS

```go
cfg := middleware.CORSConfig{
    AllowedOrigins:   []string{"https://app.example.com"},
    AllowedMethods:   []string{"GET", "POST"},   // opcional, por defecto un set razonable
    AllowedHeaders:   []string{"Authorization"}, // opcional
    AllowCredentials: true,
    MaxAge:           600,
}
handler := middleware.CORS(cfg)(mux)
```

- Responde directamente a las peticiones preflight (`OPTIONS`) con `204 No Content`, sin llegar al handler siguiente.
- `AllowedOrigins: []string{"*"}` junto con `AllowCredentials: true` **no está permitido por la especificación CORS**: en ese caso el comodín se ignora y solo se refleja el origen si está en la lista explícita.
- Coloca `CORS` **antes** de `RequireAuth` en la cadena: las peticiones preflight (`OPTIONS`) no llevan el header `Authorization`, así que si `RequireAuth` se ejecuta primero, el preflight fallaría con 401.

## 📝 Logging de peticiones

```go
type Logger interface {
    Info(message string)
}
```

`RequestLogger` acepta cualquier tipo que implemente esta interfaz mínima — el `*logger.Logger` de GoKit la cumple directamente, sin necesidad de un adaptador:

```go
log := logger.New()
handler := middleware.RequestLogger(log)(mux)
// 2026-07-19 10:32:15 [INFO] GET /perfil 200 1.2ms
```

## 🔗 Componer middlewares con `Chain`

```go
handler := middleware.Chain(mux,
    middleware.RequestLogger(log),   // se ejecuta primero
    middleware.CORS(corsConfig),
    middleware.RateLimit(limiter, nil),
    // el último de la lista es el más cercano al handler final
)
```

El primero de la lista es el más externo (se ejecuta primero en la petición, último en la respuesta) — equivalente a anidar `mw1(mw2(mw3(handler)))` pero más legible.

## ❗ Errores del paquete

```go
var (
    ErrMissingAuthHeader = errors.New("falta el header Authorization")
    ErrInvalidAuthHeader = errors.New("el header Authorization debe tener el formato 'Bearer <token>'")
)
```

Todas las respuestas de error de este paquete usan el mismo formato JSON:

```json
{"error": "token inválido o expirado"}
```

Estos mensajes son deliberadamente genéricos: el paquete nunca expone al cliente el error interno de validación (por ejemplo, la razón exacta por la que un JWT falló su verificación), para no dar pistas útiles a un atacante.

## 🔒 Notas de seguridad

- `RequireAuth` verifica el `TokenType` del claim, no solo la firma: evita que un refresh token se use como credencial de acceso.
- `RequireActiveSession` es la única forma de revocar el acceso de un access token *antes* de que expire por sí solo; sin este middleware, revocar una sesión no invalida los access tokens ya emitidos hasta que caducan.
- Encadena `RequireRole` y `RequireActiveSession` siempre después de `RequireAuth`; sin claims en el contexto, ambos responden `401 Unauthorized` por defecto (fail-closed, no fail-open).
- El orden importa: `CORS` debe ir antes que `RequireAuth` para que el preflight `OPTIONS` no requiera autenticación.
- `RateLimit` con `RemoteIPKeyFunc` confía en `r.RemoteAddr`; detrás de un proxy, valida cuidadosamente qué header de IP usas como clave para que un cliente no pueda falsificarlo y evadir el límite.
- Ningún middleware de este paquete devuelve detalles internos de error al cliente.

## 📜 Licencia

MIT
