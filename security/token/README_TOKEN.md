# GoKit Token — JWT & Sesiones

Módulo de autenticación para el ecosistema **GoKit**: emisión/validación de JSON Web Tokens (access + refresh) y gestión completa del ciclo de vida de sesiones de usuario, con soporte para revocación, expiración por inactividad y límite de sesiones concurrentes.

## 🌟 Características

**JWT**
- Access tokens y refresh tokens con claims personalizados (`UserID`, `Role`, `SessionID`, etc.)
- Firma HMAC-SHA256, con verificación estricta del método de firma (previene ataques de confusión de algoritmos)
- Distinción explícita entre access token y refresh token (`TokenType`), para que un access token filtrado no pueda usarse para generar nuevos tokens
- Duraciones configurables o derivadas automáticamente de un `security.Level`

**Sesiones**
- Ciclo de vida completo: creación, validación, revocación individual y masiva, limpieza de expiradas
- Expiración absoluta (`ExpiresAt`) e inactividad (`IdleTimeout`, "sliding expiration")
- Límite de sesiones concurrentes por usuario, revocando automáticamente las más antiguas
- Abstracción `SessionStore` para usar el backend que quieras (Redis, base de datos...); incluye `MemorySessionStore` para desarrollo/testing

## 📦 Instalación

```bash
go get github.com/AndresGT/GoKit/security/token
```

> Este módulo depende de `github.com/AndresGT/GoKit/security` (para `security.Level`, `.GetDefaults()` y `security.ErrSessionExpired`) y de `github.com/AndresGT/GoKit/security/crypto` (para `crypto.GenerateUUID` y `crypto.RandomString`), además de `github.com/golang-jwt/jwt/v5`.

## 🚀 Inicio rápido — JWT

```go
package main

import (
    "fmt"
    "time"

    "github.com/AndresGT/GoKit/security"
    "github.com/AndresGT/GoKit/security/token"
)

func main() {
    manager, err := token.NewJWTManager(token.JWTConfig{
        SecretKey:            []byte("una-clave-secreta-de-al-menos-32-bytes"),
        Issuer:               "gokit-auth",
        AccessTokenDuration:  15 * time.Minute,
        RefreshTokenDuration: 7 * 24 * time.Hour,
        // O, en vez de duraciones manuales, usar:
        // SecurityLevel: security.LevelHigh,
    })
    if err != nil {
        panic(err)
    }

    claims := token.Claims{
        UserID:    "user-123",
        Username:  "john_doe",
        Role:      "admin",
        SessionID: "session-abc-123",
    }

    accessToken, _ := manager.GenerateAccessToken(claims)
    refreshToken, _ := manager.GenerateRefreshToken(claims)

    validated, err := manager.ValidateToken(accessToken)
    if err != nil {
        // token inválido o expirado
    }
    fmt.Println(validated.UserID, validated.Role)

    newAccessToken, err := manager.RefreshAccessToken(refreshToken)
    if err != nil {
        // refresh token inválido/expirado → requerir re-login
    }
    _ = newAccessToken
}
```

### La interfaz de `JWTManager`

| Método | Descripción |
|---|---|
| `NewJWTManager(config)` | Crea el manager. Exige `SecretKey` de al menos 32 bytes (HMAC-SHA256). |
| `GenerateAccessToken(claims)` | Emite un access token, válido por `AccessTokenDuration`. |
| `GenerateRefreshToken(claims)` | Emite un refresh token, válido por `RefreshTokenDuration`. |
| `ValidateToken(tokenString)` | Verifica firma, expiración y método de firma; devuelve los claims. |
| `RefreshAccessToken(refreshTokenString)` | Valida el refresh token y emite un nuevo access token. |
| `GetConfig()` | Devuelve la configuración activa del manager. |

### Tipo de token (`TokenType`)

Cada token incluye un claim `token_type` (`"access"` o `"refresh"`), asignado automáticamente por `GenerateAccessToken`/`GenerateRefreshToken`. `RefreshAccessToken` rechaza cualquier token cuyo `TokenType` no sea `"refresh"` — así un access token filtrado no puede usarse para obtener tokens nuevos indefinidamente.

### Duraciones por nivel de seguridad

Si `AccessTokenDuration`/`RefreshTokenDuration` no se especifican (o son `0`), se toman de `config.SecurityLevel.GetDefaults()` (definido en el paquete `security`). Por defecto se usa `LevelMedium` si no se indica ningún nivel.

### Rotación de refresh tokens

`RefreshAccessToken` **no** rota el refresh token por sí solo. Para prevenir ataques de replay, la recomendación es: al usar un refresh token, invalídalo (por ejemplo revocando la sesión asociada o llevando una lista de revocación) y emite uno nuevo junto con el access token.

## 🚀 Inicio rápido — Sesiones

```go
package main

import (
    "fmt"

    "github.com/AndresGT/GoKit/security"
    "github.com/AndresGT/GoKit/security/token"
)

func main() {
    sessions, err := token.NewSessionManager(token.SessionConfig{
        SecurityLevel: security.LevelHigh,
        // Store: redisStore, // en producción, usar un backend persistente
    })
    if err != nil {
        panic(err)
    }

    sessionID, err := sessions.CreateSession(token.SessionInfo{
        UserID:    "user-123",
        Username:  "john_doe",
        IPAddress: "192.168.1.100",
        UserAgent: "Mozilla/5.0...",
    })
    if err != nil {
        panic(err)
    }

    session, err := sessions.ValidateSession(sessionID)
    if err != nil {
        // sesión expirada, revocada o inexistente → requerir re-login
    }
    fmt.Println(session.UserID)

    // Logout de esta sesión
    _ = sessions.RevokeSession(sessionID, "user_logout")

    // Logout en todos los dispositivos (ej. tras cambio de contraseña)
    _ = sessions.RevokeAllUserSessions("user-123", "password_changed")
}
```

### La interfaz de `SessionManager`

| Método | Descripción |
|---|---|
| `NewSessionManager(config)` | Crea el manager. Usa `MemorySessionStore` si no se indica `Store`. |
| `CreateSession(info)` | Crea una sesión, aplicando el límite de sesiones concurrentes. Devuelve el `sessionID`. |
| `GetSession(id)` | Recupera una sesión por ID (sin validar expiración/revocación). |
| `ValidateSession(id)` | Verifica que esté activa, actualiza `LastActivityAt` (sliding expiration). |
| `RevokeSession(id, reason)` | Revoca una sesión puntual (logout). |
| `RevokeAllUserSessions(userID, reason)` | Revoca todas las sesiones activas de un usuario. |
| `GetUserSessions(userID)` | Lista las sesiones activas de un usuario ("dónde estás conectado"). |
| `CleanExpiredSessions()` | Elimina sesiones expiradas del store; pensado para correr periódicamente. |

### `SessionStore`: memoria vs. producción

`MemorySessionStore` (incluido) es **solo para desarrollo/testing**: no persiste ni es distribuido. Para producción, implementa la interfaz `SessionStore` (`Save`, `Get`, `GetByUserID`, `Delete`, `DeleteByUserID`, `CleanExpired`) sobre Redis, una base de datos, etc., y pásala en `SessionConfig.Store`.

`MemorySessionStore` es seguro para uso concurrente: `Get`/`GetByUserID` devuelven copias de las sesiones (no punteros al estado interno), así que modificarlas y luego llamar a `Save` no genera condiciones de carrera con otras goroutines leyendo el store al mismo tiempo. Si implementas tu propio `SessionStore`, se recomienda mantener esta misma garantía.

### Expiración: absoluta e inactividad

- `ExpiresAt`: tiempo máximo de vida de la sesión, sin importar la actividad.
- `IdleTimeout`: si pasa más tiempo que este valor desde `LastActivityAt`, la sesión se considera expirada aunque no se haya llegado a `ExpiresAt`.

`ValidateSession` debe llamarse en cada request autenticado: revisa ambas condiciones y actualiza `LastActivityAt` en cada llamada exitosa.

### Límite de sesiones concurrentes

Al crear una sesión, si el usuario ya tiene `MaxConcurrentSessions` sesiones activas, se revocan automáticamente las más antiguas (por `CreatedAt`) para dejar espacio a la nueva, con `RevokeReason = "max_concurrent_sessions_exceeded"`.

## ❗ Errores del paquete

**JWT** (`jwt.go`)
```go
var (
    ErrJWTInvalid              = errors.New("token JWT inválido")
    ErrJWTExpired               = errors.New("token JWT expirado")
    ErrJWTSigningMethodInvalid  = errors.New("método de firma JWT inválido")
)
```

**Sesiones** (`session.go`)
```go
var (
    ErrSessionNotFound    = errors.New("sesión no encontrada")
    ErrSessionStoreFailed = errors.New("fallo en el almacenamiento de sesiones")
)
```

`ValidateSession` también puede devolver `security.ErrSessionExpired` (definido en el paquete `security`) cuando la sesión está revocada o expiró.

## 🔒 Notas de seguridad

- Verificación estricta del método de firma en `ValidateToken`: evita que un atacante fuerce el algoritmo `none` u otro no esperado.
- `RefreshAccessToken` valida el claim `TokenType`, evitando que un access token se use como si fuera un refresh token.
- Los IDs de sesión se generan con `crypto.RandomString` (base criptográficamente segura, `crypto/rand`).
- `MemorySessionStore` nunca debe usarse en producción: no persiste entre reinicios y no es apta para más de un proceso/instancia.
- Al revocar una sesión, revoca también (o rota) el refresh token asociado si tu flujo los vincula, para que ambos mecanismos de invalidación queden sincronizados.

## 📜 Licencia

MIT