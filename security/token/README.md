# GoKit Token — JWT & Sesiones

Módulo de autenticación para el ecosistema **GoKit**: emisión/validación de JSON Web Tokens (access + refresh) y gestión completa del ciclo de vida de sesiones de usuario, con soporte para revocación, expiración por inactividad y límite de sesiones concurrentes.

## 🌟 Características

### **JWT (JSON Web Tokens)**
- ✅ Access tokens y refresh tokens con claims personalizados (`UserID`, `Role`, `SessionID`, `Email`, etc.)
- ✅ Firma HMAC-SHA256 con verificación estricta del método (previene ataques de confusión de algoritmos)
- ✅ Distinción explícita entre access token y refresh token (`TokenType`)
- ✅ Duraciones configurables manualmente o derivadas automáticamente de `security.Level`
- ✅ API dual: Manager configurable + funciones globales de uso rápido
- ✅ Helpers para prototipado rápido (`GenerateQuickToken`, `ValidateQuickToken`, etc.)

### **Sesiones**
- ✅ Ciclo de vida completo: creación, validación, revocación individual/masiva, limpieza
- ✅ Expiración absoluta (`ExpiresAt`) e inactividad (`IdleTimeout`, "sliding expiration")
- ✅ Límite de sesiones concurrentes por usuario con revocación automática de las más antiguas
- ✅ Abstracción `SessionStore` para usar cualquier backend (Redis, BD, etc.)
- ✅ `MemorySessionStore` incluido para desarrollo/testing
- ✅ API dual: Manager configurable + funciones globales de uso rápido

## 📦 Instalación

```bash
go get github.com/AndresGT/GoKit/security/token
```

> **Dependencias:**
> - `github.com/AndresGT/GoKit/security` (niveles de seguridad, errores)
> - `github.com/AndresGT/GoKit/security/crypto` (generación de UUIDs y strings seguros)
> - `github.com/golang-jwt/jwt/v5` (librería JWT)

---

## 🚀 Inicio Rápido

### **Opción 1: Uso Rápido (Prototipado)**

Ideal para empezar rápido sin configuración:

```go
package main

import (
    "fmt"
    "github.com/AndresGT/GoKit/security/token"
)

func main() {
    // Generar token rápido
    tokenStr, err := token.GenerateQuickToken("user-123", "admin")
    if err != nil {
        panic(err)
    }
    
    // Validar token
    if token.ValidateQuickToken(tokenStr) {
        userID := token.ExtractUserID(tokenStr)
        fmt.Printf("Token válido, UserID: %s\n", userID)
    }
    
    // Crear sesión rápida
    sessionID, err := token.CreateQuickSession(token.SessionInfo{
        UserID:    "user-123",
        Username:  "john_doe",
        IPAddress: "192.168.1.100",
    })
    if err != nil {
        panic(err)
    }
    
    // Validar sesión
    if token.QuickSessionExists(sessionID) {
        fmt.Println("Sesión activa")
    }
}
```

### **Opción 2: Configuración Completa (Producción)**

Para producción, configura managers personalizados:

```go
package main

import (
    "fmt"
    "time"
    "github.com/AndresGT/GoKit/security"
    "github.com/AndresGT/GoKit/security/token"
)

func main() {
    // === JWT Manager ===
    jwtManager, err := token.NewJWTManager(token.JWTConfig{
        SecretKey:            []byte("clave-secreta-de-al-menos-32-bytes!!"),
        Issuer:               "mi-api",
        AccessTokenDuration:  15 * time.Minute,
        RefreshTokenDuration: 7 * 24 * time.Hour,
    })
    if err != nil {
        panic(err)
    }
    
    // O usar nivel de seguridad (usa valores predeterminados)
    jwtManagerHigh, _ := token.NewJWTManager(token.JWTConfig{
        SecretKey:     []byte("otra-clave-secreta-de-32-bytes-min!!"),
        Issuer:        "mi-api",
        SecurityLevel: security.LevelHigh,
    })
    
    // === Session Manager ===
    sessionManager, err := token.NewSessionManager(token.SessionConfig{
        SecurityLevel:         security.LevelHigh,
        MaxConcurrentSessions: 3,
        // Store: redisStore, // En producción, usa un backend persistente
    })
    if err != nil {
        panic(err)
    }
    
    // === Ejemplo de flujo completo ===
    // 1. Login → Generar tokens
    claims := token.Claims{
        UserID:    "user-123",
        Username:  "john_doe",
        Role:      "admin",
        Email:     "john@example.com",
    }
    
    accessToken, _ := jwtManager.GenerateAccessToken(claims)
    refreshToken, _ := jwtManager.GenerateRefreshToken(claims)
    
    // 2. Crear sesión
    sessionID, _ := sessionManager.CreateSession(token.SessionInfo{
        UserID:    "user-123",
        Username:  "john_doe",
        IPAddress: "192.168.1.100",
        UserAgent: "Mozilla/5.0...",
    })
    
    // 3. Validar token en cada request
    validatedClaims, err := jwtManager.ValidateToken(accessToken)
    if err != nil {
        // Token inválido o expirado
        return
    }
    fmt.Printf("Usuario: %s, Rol: %s\n", validatedClaims.UserID, validatedClaims.Role)
    
    // 4. Validar sesión en cada request
    session, err := sessionManager.ValidateSession(sessionID)
    if err != nil {
        // Sesión inválida o expirada
        return
    }
    fmt.Printf("Sesión activa desde: %s\n", session.IPAddress)
    
    // 5. Refresh token cuando expire el access token
    newAccessToken, err := jwtManager.RefreshAccessToken(refreshToken)
    if err != nil {
        // Refresh token expirado → requerir re-login
        return
    }
    _ = newAccessToken
    
    // 6. Logout → Revocar sesión
    _ = sessionManager.RevokeSession(sessionID, "user_logout")
    
    // 7. Logout global (ej. tras cambio de contraseña)
    _ = sessionManager.RevokeAllUserSessions("user-123", "password_changed")
}
```

---

## 📚 API Reference

### **JWT Manager**

#### Configuración

```go
type JWTConfig struct {
    SecretKey            []byte        // Mínimo 32 bytes para HMAC-SHA256
    Issuer               string        // Emisor del token (ej. "api.example.com")
    AccessTokenDuration  time.Duration // Duración del access token
    RefreshTokenDuration time.Duration // Duración del refresh token
    SecurityLevel        security.Level // Nivel de seguridad para valores por defecto
}
```

#### Métodos del Manager

| Método | Descripción | Retorna |
|--------|-------------|---------|
| `NewJWTManager(config)` | Crea un manager de JWT | `(*JWTManager, error)` |
| `GenerateAccessToken(claims)` | Genera access token | `(string, error)` |
| `GenerateRefreshToken(claims)` | Genera refresh token | `(string, error)` |
| `ValidateToken(tokenString)` | Valida token y extrae claims | `(*Claims, error)` |
| `RefreshAccessToken(refreshToken)` | Renueva access token | `(string, error)` |
| `GetConfig()` | Obtiene configuración actual | `JWTConfig` |

#### Claims Personalizados

```go
type Claims struct {
    jwt.RegisteredClaims
    UserID     string `json:"user_id"`
    Username   string `json:"username,omitempty"`
    Role       string `json:"role,omitempty"`
    Email      string `json:"email,omitempty"`
    SessionID  string `json:"session_id,omitempty"`
    DeviceInfo string `json:"device_info,omitempty"`
    IPAddress  string `json:"ip_address,omitempty"`
    TokenType  string `json:"token_type,omitempty"` // "access" o "refresh"
}
```

#### Funciones Globales (Uso Rápido)

| Función | Descripción | Ejemplo |
|---------|-------------|---------|
| `Init(config)` | Inicializa manager global | `token.Init(JWTConfig{...})` |
| `GetDefault()` | Obtiene manager global | `manager := token.GetDefault()` |
| `GenerateAccessToken(claims)` | Genera access token global | `t, _ := token.GenerateAccessToken(c)` |
| `GenerateRefreshToken(claims)` | Genera refresh token global | `t, _ := token.GenerateRefreshToken(c)` |
| `ValidateToken(token)` | Valida token global | `c, _ := token.ValidateToken(t)` |
| `RefreshAccessToken(token)` | Renueva access token | `nt, _ := token.RefreshAccessToken(rt)` |

#### Funciones Helper (Prototipado)

| Función | Descripción | Ejemplo |
|---------|-------------|---------|
| `GenerateQuickToken(userID, role)` | Token rápido sin config | `t, _ := token.GenerateQuickToken("u1", "admin")` |
| `GenerateQuickTokenWithEmail(userID, email, role)` | Token rápido con email | `t, _ := token.GenerateQuickTokenWithEmail("u1", "a@b.com", "user")` |
| `ValidateQuickToken(token)` | Valida y retorna bool | `if token.ValidateQuickToken(t) {...}` |
| `ExtractUserID(token)` | Extrae UserID | `id := token.ExtractUserID(t)` |
| `ExtractClaims(token)` | Extrae todos los claims | `c := token.ExtractClaims(t)` |

---

### **Session Manager**

#### Configuración

```go
type SessionConfig struct {
    SessionTimeout        time.Duration // Tiempo máximo de vida absoluto
    IdleTimeout           time.Duration // Tiempo máximo de inactividad
    MaxConcurrentSessions int           // Máximo sesiones por usuario
    SecurityLevel         security.Level // Nivel de seguridad para defaults
    Store                 SessionStore   // Backend de almacenamiento
}
```

#### SessionStore Interface

```go
type SessionStore interface {
    Save(session *Session) error
    Get(sessionID string) (*Session, error)
    GetByUserID(userID string) ([]*Session, error)
    Delete(sessionID string) error
    DeleteByUserID(userID string) error
    CleanExpired() (int, error)
}
```

> **Implementaciones disponibles:**
> - `MemorySessionStore`: Para desarrollo/testing (no persistente)
> - **Producción**: Implementa tu propio store con Redis, PostgreSQL, MongoDB, etc.

#### Estructura Session

```go
type Session struct {
    ID             string
    UserID         string
    Username       string
    IPAddress      string
    UserAgent      string
    DeviceInfo     string
    CreatedAt      time.Time
    LastActivityAt time.Time
    ExpiresAt      time.Time
    IdleTimeout    time.Duration
    IsValid        bool
    RevokedAt      time.Time
    RevokeReason   string
}
```

#### Métodos del Manager

| Método | Descripción | Retorna |
|--------|-------------|---------|
| `NewSessionManager(config)` | Crea manager de sesiones | `(*SessionManager, error)` |
| `CreateSession(info)` | Crea nueva sesión | `(sessionID, error)` |
| `GetSession(id)` | Obtiene sesión sin validar | `(*Session, error)` |
| `ValidateSession(id)` | Valida y actualiza actividad | `(*Session, error)` |
| `RevokeSession(id, reason)` | Revoca sesión específica | `error` |
| `RevokeAllUserSessions(uid, reason)` | Revoca todas las sesiones de un usuario | `error` |
| `GetUserSessions(uid)` | Obtiene sesiones activas de usuario | `([]*Session, error)` |
| `CleanExpiredSessions()` | Limpia sesiones expiradas | `(count, error)` |
| `GetConfig()` | Obtiene configuración | `SessionConfig` |

#### Funciones Globales (Uso Rápido)

| Función | Descripción | Ejemplo |
|---------|-------------|---------|
| `InitSession(config)` | Inicializa manager global | `token.InitSession(SessionConfig{...})` |
| `GetDefaultSession()` | Obtiene manager global | `m := token.GetDefaultSession()` |
| `CreateQuickSession(info)` | Crea sesión rápida | `id, _ := token.CreateQuickSession(info)` |
| `ValidateQuickSession(id)` | Valida sesión rápida | `s, _ := token.ValidateQuickSession(id)` |
| `RevokeQuickSession(id, reason)` | Revoca sesión rápida | `token.RevokeQuickSession(id, "logout")` |
| `RevokeAllQuickSessions(uid, reason)` | Revoca todas las sesiones | `token.RevokeAllQuickSessions("u1", "pwd")` |
| `GetQuickUserSessions(uid)` | Obtiene sesiones de usuario | `sessions, _ := token.GetQuickUserSessions("u1")` |
| `QuickSessionExists(id)` | Verifica si existe sesión | `if token.QuickSessionExists(id) {...}` |
| `GetSessionUserID(id)` | Extrae UserID de sesión | `uid := token.GetSessionUserID(id)` |

---

## 🔐 Seguridad

### **JWT Best Practices**

1. **Secret Key Segura**: Mínimo 32 bytes, usa `crypto.GenerateRandomBytes(32)` en producción
2. **Rotación de Refresh Tokens**: Invalida y reemplaza después de cada uso
3. **Validación Estricta**: Verifica firma, expiración, emisor y método de firma
4. **TokenType Claim**: Previene que access tokens se usen como refresh tokens
5. **No almacenes datos sensibles** en los claims (los tokens son codificados en base64, no cifrados)

### **Sesiones Best Practices**

1. **Backend Persistente**: Usa Redis o BD en producción, nunca MemorySessionStore
2. **Límite de Sesiones**: Configura `MaxConcurrentSessions` según tus necesidades (3-5 típico)
3. **Idle Timeout**: Configura según el tipo de aplicación (15-30 min para apps bancarias, 2-8 horas para otras)
4. **Revocación Sincrónica**: Al cambiar contraseña, revoca TODAS las sesiones
5. **Limpieza Periódica**: Ejecuta `CleanExpiredSessions()` cada hora con un cron job

### **Niveles de Seguridad**

El módulo integra con `security.Level` para configuración automática:

| Nivel | Access Token | Refresh Token | Sesión | Idle | Max Sesiones |
|-------|--------------|---------------|--------|------|--------------|
| **Low** | 1h | 24h | 8h | 1h | 10 |
| **Medium** | 15m | 7d | 8h | 30m | 5 |
| **High** | 5m | 1d | 2h | 15m | 3 |
| **Critical** | 1m | 1h | 30m | 5m | 1 |

---

## ⚠️ Errores del Paquete

### **JWT Errors**

```go
var (
    ErrJWTInvalid              = errors.New("token JWT inválido")
    ErrJWTExpired              = errors.New("token JWT expirado")
    ErrJWTSigningMethodInvalid = errors.New("método de firma JWT inválido")
)
```

### **Session Errors**

```go
var (
    ErrSessionNotFound    = errors.New("sesión no encontrada")
    ErrSessionStoreFailed = errors.New("fallo en el almacenamiento de sesiones")
)
```

> También puede retornar `security.ErrSessionExpired` cuando una sesión expira o es revocada.

---

## 🧪 Testing

El módulo incluye tests unitarios exhaustivos que cubren:

- ✅ Generación y validación de JWT
- ✅ Refresh token y rotación
- ✅ Claims personalizados y extracción
- ✅ Creación y validación de sesiones
- ✅ Revocación de sesiones (individual y masiva)
- ✅ Límite de sesiones concurrentes
- ✅ Expiración por tiempo absoluto e inactividad
- ✅ MemorySessionStore thread-safe
- ✅ Funciones helper de uso rápido

Ejecutar tests:

```bash
cd security/token
go test -v -cover
```

---

## 📌 Production Checklist

- [ ] Usar secret key generada criptográficamente (`crypto.GenerateRandomBytes(32)`)
- [ ] Configurar `Issuer` apropiado para tu dominio
- [ ] Implementar `SessionStore` persistente (Redis/BD)
- [ ] Configurar límites de sesiones según necesidades
- [ ] Habilitar HTTPS para transmitir tokens de forma segura
- [ ] Implementar rotación de refresh tokens
- [ ] Agregar logging de eventos de seguridad (login, logout, revocación)
- [ ] Configurar CORS apropiadamente si es API web
- [ ] Establecer cookies HttpOnly + Secure + SameSite si usas cookies

### **No Hacer**

- ❌ No uses MemorySessionStore en producción
- ❌ No almacenes contraseñas o datos ultrasensibles en JWT claims
- ❌ No extiendas excesivamente la duración de access tokens (>1h)
- ❌ No compartas la misma secret key entre diferentes entornos
- ❌ No ignores la validación del TokenType en refresh tokens
- ❌ No olvides revocar sesiones al cerrar sesión o cambiar contraseña

---

## 📜 Licencia

MIT License
