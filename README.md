# GoKit

[![Go Version](https://img.shields.io/badge/Go-1.26+-00ADD8?style=flat&logo=go)](https://golang.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

Toolkit interno de Go con utilidades listas para producción: logging, hashing de contraseñas, cifrado simétrico, generación de datos aleatorios seguros, JWT, sesiones y middlewares HTTP (net/http, Gin y Fiber). Cada módulo funciona de forma independiente y también se integra con los demás (por ejemplo, los middlewares usan el `logger` global para registrar peticiones).

## 📦 Índice

- [Instalación](#-instalación)
- [Estructura del proyecto](#-estructura-del-proyecto)
- [Quickstart combinado](#-quickstart-combinado)
- [Módulo `logger`](#-módulo-logger)
- [Módulo `security` (raíz)](#-módulo-security-raíz)
- [Módulo `security/crypto`](#-módulo-securitycrypto)
- [Módulo `security/token`](#-módulo-securitytoken)
- [Módulo `security/middleware`](#-módulo-securitymiddleware)
- [Ejemplo completo de integración](#-ejemplo-completo-de-integración)
- [Manejo de errores](#-manejo-de-errores)
- [Licencia](#-licencia)

## 📥 Instalación

```bash
go get github.com/AndresGT/GoKit
```

Puedes importar solo lo que necesites; cada módulo es un paquete independiente:

```go
import (
    "github.com/AndresGT/GoKit/logger"
    "github.com/AndresGT/GoKit/security"
    "github.com/AndresGT/GoKit/security/crypto"
    "github.com/AndresGT/GoKit/security/token"
    "github.com/AndresGT/GoKit/security/middleware"
)
```

## 🗂 Estructura del proyecto

```
GoKit/
├── logger/                    # Logging con niveles, colores y salidas flexibles
├── security/
│   ├── levels.go              # Niveles de seguridad (Low/Medium/High/Critical) y sus defaults
│   ├── errors.go              # Errores transversales de todo el dominio "security"
│   ├── crypto/                # Hashing de contraseñas, cifrado AES-256-GCM, random seguro
│   ├── token/                 # JWT (access/refresh) y gestión de sesiones
│   └── middleware/             # Middlewares HTTP: net/http, Gin, Fiber + registro de rutas
└── main.go                    # Ejemplo de humo (smoke test) de todos los módulos
```

## 🚀 Quickstart combinado

Un vistazo mínimo tocando logger, hashing y JWT:

```go
package main

import (
    "github.com/AndresGT/GoKit/logger"
    "github.com/AndresGT/GoKit/security/crypto"
    "github.com/AndresGT/GoKit/security/token"
)

func main() {
    log := logger.New(logger.WithLevel(logger.DebugLevel))

    hash, _ := crypto.HashPassword("MiContraseñaSuperSegura123!")
    ok, _ := crypto.VerifyPassword("MiContraseñaSuperSegura123!", hash)
    log.InfoWithFields("password_verificada", map[string]interface{}{"ok": ok})

    accessToken, _ := token.GenerateAccessToken(token.Claims{UserID: "user-123", Role: "admin"})
    log.Success("token generado: " + accessToken[:20] + "...")
}
```

---

## 📘 Módulo `logger`

Logging con 8 niveles, colores ANSI configurables, salida a consola/archivo/ambas, y una instancia global lista para usar sin configuración (`out-of-the-box`). Es **thread-safe** (usa `sync.Mutex` internamente).

```go
import "github.com/AndresGT/GoKit/logger"
```

### Niveles disponibles

| Nivel   | Cuándo usarlo                                      |
|---------|-----------------------------------------------------|
| Trace   | Diagnóstico profundo, flujos internos                |
| Debug   | Depuración durante desarrollo                        |
| Info    | Eventos normales de la aplicación                    |
| Success | Confirmación de una tarea completada                 |
| Warn    | Situación potencialmente problemática, no crítica     |
| Error   | Fallo que no detiene la ejecución                     |
| Fatal   | Error crítico — llama a `os.Exit(1)` tras loguear     |
| Panic   | Dispara `panic(message)` tras loguear                 |

### Uso rápido (instancia global, sin configurar nada)

```go
logger.Info("Servidor iniciado en el puerto 8080")
logger.Debug("Conectando a la base de datos...")
logger.Warn("Uso de memoria por encima del 80%")
logger.Error("No se pudo conectar a la API externa")
logger.Success("Usuario autenticado correctamente")
```

### `logger.New(opts ...Option) *Logger` — crear una instancia propia

```go
log := logger.New(
    logger.WithLevel(logger.DebugLevel),
    logger.WithColor(true),
)
log.Debug("Instancia propia, no la global")
```

### `logger.SetDefault(l *Logger)` / `logger.GetDefault() *Logger`

```go
custom := logger.New(logger.WithFileOutput("logs/app.log"))
logger.SetDefault(custom) // a partir de aquí, logger.Info(...) usa custom

current := logger.GetDefault()
current.Info("obtenida desde GetDefault")
```

### Métodos de texto plano (global o de instancia)

```go
// Global (usa defaultLogger)
logger.Trace("...")
logger.Debug("...")
logger.Info("...")
logger.Success("...")
logger.Warn("...")
logger.Error("...")
logger.Fatal("...")  // termina el proceso
logger.Panic("...")  // hace panic()

// De instancia — mismo comportamiento, logger propio
log := logger.New()
log.Info("mensaje desde instancia propia")
```

### Métodos con campos contextuales (`...WithFields`)

```go
logger.InfoWithFields("usuario_creado", map[string]interface{}{
    "user_id": "usr_123",
    "email":   "ana@example.com",
})
logger.ErrorWithFields("fallo_al_guardar", map[string]interface{}{"error": err.Error()})
logger.DebugWithFields("payload_recibido", map[string]interface{}{"size": 1024})
logger.WarnWithFields("intento_login_fallido", map[string]interface{}{"ip": "203.0.113.5"})
logger.SuccessWithFields("pago_procesado", map[string]interface{}{"monto": 49.90})

// también disponibles como método de instancia: log.InfoWithFields(...), etc.
```

### `Config` y Functional Options

```go
type Config struct {
    Writer      io.Writer // destino de salida (por defecto os.Stdout)
    Level       Level     // nivel mínimo a registrar (por defecto InfoLevel)
    EnableColor bool      // colores ANSI (por defecto true)
    ShowDate    bool      // incluir fecha YYYY-MM-DD (por defecto true)
    ShowTime    bool      // incluir hora HH:MM:SS (por defecto true)
}
```

| Opción                                    | Qué hace                                                                 |
|--------------------------------------------|---------------------------------------------------------------------------|
| `logger.WithLevel(level Level)`             | Nivel mínimo de severidad (se ignora si no es válido).                    |
| `logger.WithWriter(w io.Writer)`            | Destino de salida (se ignora si `w` es `nil`).                            |
| `logger.WithColor(enable bool)`             | Activa/desactiva colores ANSI.                                            |
| `logger.WithDateTime(showDate, showTime bool)` | Incluye/oculta fecha y hora.                                            |
| `logger.WithFileOutput(filePath string)`    | Escribe a archivo (append) y desactiva color automáticamente. Falla en silencio si no puede crear el archivo. |

```go
log := logger.New(
    logger.WithLevel(logger.DebugLevel),
    logger.WithColor(false),
    logger.WithFileOutput("logs/app.log"),
)
```

`logger.NewConfig() Config` devuelve una copia de la configuración por defecto para modificarla manualmente antes de construir el logger.

### Salidas (`output.go`)

```go
// Solo consola (comportamiento por defecto)
writer := logger.NewConsoleWriter()

// Solo archivo (crea directorios intermedios si no existen)
fileWriter, err := logger.NewFileWriter("logs/app.log")

// Consola + archivo al mismo tiempo
combined := logger.NewMultiWriter(logger.NewConsoleWriter(), fileWriter)

log := logger.New(logger.WithWriter(combined))
```

### Temas y colores (`color.go`)

```go
customTheme := logger.Theme{
    Trace: "\033[90m", Debug: "\033[34m", Info: "\033[36m",
    Success: "\033[32m", Warn: "\033[33m", Error: "\033[31m",
    Fatal: "\033[35m", Panic: "\033[41m\033[97m", Reset: "\033[0m",
}
logger.SetTheme(customTheme)
// ...
logger.ResetTheme() // vuelve al tema por defecto de GoKit
```

> ⚠️ `SetTheme`/`ResetTheme` modifican una variable global compartida por todo el proceso, no un tema por instancia.

### Errores del paquete

```go
logger.ErrInvalidLevel     // nivel de log fuera de rango
logger.ErrWriteFailed      // fallo al escribir en el Writer configurado
logger.ErrInvalidFilePath  // ruta de archivo inválida o sin permisos
```

### Ejemplo conjunto del módulo

```go
cfg := logger.NewConfig()
cfg.Level = logger.DebugLevel

fileWriter, err := logger.NewFileWriter("logs/app.log")
if err != nil {
    panic(err)
}
cfg.Writer = logger.NewMultiWriter(logger.NewConsoleWriter(), fileWriter)

log := logger.New(logger.WithLevel(cfg.Level), logger.WithWriter(cfg.Writer))

log.Debug("Conectando a la base de datos...")
log.Info("Aplicación iniciada correctamente")
log.WarnWithFields("uso_memoria_alto", map[string]interface{}{"porcentaje": 82})
log.Error("No se pudo conectar a la base de datos")
```

---

## 🔐 Módulo `security` (raíz)

Define **niveles de seguridad** (una forma de configurar todo el ecosistema `security/*` con un solo valor) y los **errores transversales** que usan `crypto`, `token` y `middleware`.

```go
import "github.com/AndresGT/GoKit/security"
```

### `security.Level` y `GetDefaults()`

| Nivel            | Bcrypt cost | Access token | Refresh token | Intentos login | 2FA |
|-------------------|-------------|--------------|----------------|-----------------|-----|
| `LevelLow`         | 10          | 24h          | 30d            | 10              | No  |
| `LevelMedium` (def.)| 12          | 1h           | 7d             | 5               | No  |
| `LevelHigh`        | 14          | 15min        | 24h            | 3               | Sí  |
| `LevelCritical`    | 15          | 5min         | 12h            | 3               | Sí  |

```go
defaults := security.LevelHigh.GetDefaults()
fmt.Println(defaults.BcryptCost)          // 14
fmt.Println(defaults.AccessTokenDuration) // 15m0s

security.LevelHigh.String()   // "HIGH"
security.LevelHigh.IsValid()  // true
```

Este `Level` se pasa directamente a `token.JWTConfig.SecurityLevel` y `token.SessionConfig.SecurityLevel` (ver módulo `security/token`) para heredar sus valores por defecto sin repetirlos.

### Errores transversales (uso rápido con `errors.Is`)

```go
security.ErrAuthenticationFailed      // credenciales inválidas (anti-enumeración)
security.ErrPermissionDenied
security.ErrInsufficientSecurityLevel // ej. requiere 2FA
security.ErrTokenInvalid
security.ErrTokenRevoked
security.ErrSessionExpired
security.ErrRateLimitExceeded
security.ErrAccountLocked
security.ErrIPBlocked
security.ErrInvalidInput
security.ErrWeakPassword
security.ErrOperationNotAllowed
security.ErrPasswordChangeRequired
security.ErrInvalidHash
security.ErrIncompatibleVersion
security.ErrInvalidCiphertext
security.ErrInvalidKeyLength
```

```go
if errors.Is(err, security.ErrSessionExpired) {
    // pedir re-login
}
```

---

## 🔑 Módulo `security/crypto`

Tres capacidades independientes: **hashing de contraseñas** (4 algoritmos intercambiables), **cifrado simétrico AES-256-GCM**, y **generación de datos aleatorios criptográficamente seguros**.

```go
import "github.com/AndresGT/GoKit/security/crypto"
```

### Hashing de contraseñas — API global rápida (recomendada)

Usa Argon2id por defecto (estándar OWASP) sin necesidad de configurar nada:

```go
hash, err := crypto.HashPassword("MiContraseñaSuperSegura123!") // valida 8–72 chars
ok, err := crypto.VerifyPassword("MiContraseñaSuperSegura123!", hash)
needsUpgrade := crypto.NeedsUpgrade(hash) // true si los parámetros actuales son más estrictos

// Cambiar el algoritmo/parámetros globales (ej. en main.go al arrancar)
customHasher, _ := crypto.NewHasher(crypto.HasherConfig{
    Algorithm:  crypto.AlgorithmBcrypt,
    BcryptCost: 14,
})
crypto.SetDefaultHasher(customHasher)
```

`VerifyPassword` detecta automáticamente el algoritmo original del hash (`DetectAlgorithm`), así que puedes migrar de algoritmo sin invalidar contraseñas existentes.

### Hashing — usando un algoritmo específico vía la interfaz `Hasher`

```go
type Hasher interface {
    Hash(password string) (string, error)
    Verify(password, hash string) (bool, error)
    NeedsUpgrade(hash string) bool
}
```

```go
// Argon2id — recomendado por OWASP, resistente a GPU/ASIC
hasher, _ := crypto.NewHasher(crypto.HasherConfig{
    Algorithm:         crypto.AlgorithmArgon2id,
    Argon2Memory:      64 * 1024, // 64 MB
    Argon2Iterations:  3,
    Argon2Parallelism: 4,
    Argon2KeyLength:   32,
    Argon2SaltLength:  16,
})

// Bcrypt — estándar de la industria, ajustable por costo
hasher, _ = crypto.NewHasher(crypto.HasherConfig{
    Algorithm:  crypto.AlgorithmBcrypt,
    BcryptCost: 12, // 10 dev, 12 producción, 14 alta seguridad, 15+ crítico
})

// Scrypt — alternativa intensiva en memoria
hasher, _ = crypto.NewHasher(crypto.HasherConfig{
    Algorithm: crypto.AlgorithmScrypt,
    ScryptN:   16384, ScryptR: 8, ScryptP: 1, ScryptKeyLen: 32, ScryptSaltLen: 16,
})

// PBKDF2-SHA256 — estándar NIST para entornos legacy/enterprise
hasher, _ = crypto.NewHasher(crypto.HasherConfig{
    Algorithm:        crypto.AlgorithmPBKDF2,
    PBKDF2Iterations: 600000, // recomendación OWASP 2023
})

hash, _ := hasher.Hash("password")
valid, _ := hasher.Verify("password", hash)
upgrade := hasher.NeedsUpgrade(hash)
```

Todos los parámetros numéricos son opcionales: si se dejan en cero, cada implementación aplica valores seguros por defecto automáticamente.

### `crypto.DetectAlgorithm(hash string) (Algorithm, error)`

```go
algo, err := crypto.DetectAlgorithm(storedHash)
// algo: crypto.AlgorithmBcrypt | AlgorithmArgon2id | AlgorithmScrypt | AlgorithmPBKDF2
```

### Cifrado simétrico AES-256-GCM

```go
// 1. Generar y guardar una clave de 32 bytes de forma segura (ej. variable de entorno)
key, _ := crypto.GenerateEncryptionKey()             // []byte, 32 bytes
keyB64, _ := crypto.GenerateEncryptionKeyBase64()     // string en base64, lista para .env

// 2. Crear el cifrador
encrypter, err := crypto.NewAESEncrypter(key)

// 3. Cifrar / descifrar bytes
ciphertext, _ := encrypter.Encrypt([]byte("dato sensible"))
plaintext, _ := encrypter.Decrypt(ciphertext)

// 4. Conveniencia para strings
encryptedStr, _ := encrypter.EncryptString("Número de tarjeta: 4111-1111-1111-1111")
decryptedStr, _ := encrypter.DecryptString(encryptedStr)
```

GCM incluye autenticación integrada: si el ciphertext fue manipulado, `Decrypt`/`DecryptString` devuelven `ErrDecryptionFailed` en vez de datos corruptos.

### Generación de datos aleatorios seguros

```go
bytes, _  := crypto.RandomBytes(32)        // []byte aleatorios (base de todo lo demás)
str, _    := crypto.RandomString(32)       // alfanumérico URL-safe — session IDs, CSRF
hex, _    := crypto.RandomHex(32)          // hexadecimal (64 chars) — refresh tokens, API keys
uuid, _   := crypto.GenerateUUID()         // UUID v4 (RFC 4122)
apiKey, _ := crypto.GenerateAPIKey("usr")  // "usr_a1b2c3..." — prefix "" usa "gk_" por defecto
otp, _    := crypto.GenerateNumericCode(6) // "482913" — OTPs por SMS/email, 2FA, PINs
```

### Ejemplo conjunto del módulo (signup con hashing + dato cifrado)

```go
password := "MiContraseñaSuperSegura123!"

hash, err := crypto.HashPassword(password)
if err != nil {
    // password fuera de rango (8–72) u otro fallo
}

key, _ := crypto.GenerateEncryptionKey()
encrypter, _ := crypto.NewAESEncrypter(key)
encryptedEmail, _ := encrypter.EncryptString("ana@example.com")

apiKey, _ := crypto.GenerateAPIKey("usr")

// ... guardar hash, encryptedEmail y apiKey en la base de datos ...

// En el login:
ok, _ := crypto.VerifyPassword(password, hash)
if !ok {
    // security.ErrAuthenticationFailed
}
```

---

## 🪪 Módulo `security/token`

Dos piezas que suelen usarse juntas: **JWT** (access/refresh tokens firmados) y **gestión de sesiones** (para poder revocar el acceso antes de que el JWT expire por sí solo).

```go
import "github.com/AndresGT/GoKit/security/token"
```

### JWT — crear un manager

```go
manager, err := token.NewJWTManager(token.JWTConfig{
    SecretKey:     []byte("mi-clave-secreta-de-al-menos-32-bytes!"), // mínimo 32 bytes
    Issuer:        "mi-api",
    SecurityLevel: security.LevelHigh, // usa sus defaults: 15min access, 24h refresh
})

// O con duraciones explícitas (tienen prioridad sobre SecurityLevel)
manager, err = token.NewJWTManager(token.JWTConfig{
    SecretKey:            []byte("mi-clave-secreta-de-al-menos-32-bytes!"),
    Issuer:               "mi-api",
    AccessTokenDuration:  15 * time.Minute,
    RefreshTokenDuration: 7 * 24 * time.Hour,
})
```

### JWT — generar y validar tokens

```go
claims := token.Claims{
    UserID:    "user-123",
    Username:  "john_doe",
    Role:      "admin",
    Email:     "john@example.com",
    SessionID: "session-abc-123", // enlaza el JWT con una sesión revocable
}

accessToken, err := manager.GenerateAccessToken(claims)   // claims.TokenType = "access"
refreshToken, err := manager.GenerateRefreshToken(claims) // claims.TokenType = "refresh"

validClaims, err := manager.ValidateToken(accessToken)
if err != nil {
    if errors.Is(err, token.ErrJWTExpired) {
        // requerir refresh
    }
    // token inválido
}

newAccessToken, err := manager.RefreshAccessToken(refreshToken) // rota el access token
cfg := manager.GetConfig() // inspeccionar configuración activa
```

`ValidateToken` rechaza explícitamente tokens con un método de firma distinto a HS256 (previene ataques de confusión de algoritmos) y verifica el `Issuer` si fue configurado.

### JWT — API global (manager por defecto, útil para prototipos)

```go
// Reconfigurar el manager global al arrancar la app
err := token.Init(token.JWTConfig{
    SecretKey: []byte(os.Getenv("JWT_SECRET")),
    Issuer:    "mi-proyecto",
})

accessToken, _ := token.GenerateAccessToken(claims)
refreshToken, _ := token.GenerateRefreshToken(claims)
claims, err := token.ValidateToken(accessToken)
newToken, err := token.RefreshAccessToken(refreshToken)
manager := token.GetDefault()
```

> ⚠️ Si no llamas a `token.Init`, el manager global usa una clave de desarrollo embebida (`gokit-default-super-secret-key-32bytes!!`) solo para que la app no falle al arrancar. **Nunca la uses en producción** — siempre llama a `token.Init` con tu propio secreto.

### Sesiones — crear un manager

```go
sessionManager, err := token.NewSessionManager(token.SessionConfig{
    SecurityLevel: security.LevelHigh, // 8h timeout, 15min idle, máx 2 sesiones
})

// Con configuración manual y un store propio (Redis, BD, etc.)
sessionManager, err = token.NewSessionManager(token.SessionConfig{
    SessionTimeout:        8 * time.Hour,
    IdleTimeout:           15 * time.Minute,
    MaxConcurrentSessions: 2,
    Store:                 myRedisStore, // implementa token.SessionStore
})
```

> Sin `Store`, se usa `MemorySessionStore` — válido solo para desarrollo/testing, no persiste ni es distribuido.

### Sesiones — ciclo de vida

```go
sessionID, err := sessionManager.CreateSession(token.SessionInfo{
    UserID:    "user-123",
    Username:  "john_doe",
    IPAddress: "192.168.1.100",
    UserAgent: "Mozilla/5.0...",
})
// si el usuario ya tiene el máximo de sesiones concurrentes, revoca la más antigua automáticamente

session, err := sessionManager.ValidateSession(sessionID) // también actualiza LastActivityAt
// llamar en CADA request autenticado

err = sessionManager.RevokeSession(sessionID, "user_logout")               // logout individual
err = sessionManager.RevokeAllUserSessions("user-123", "password_changed") // logout global

sessions, err := sessionManager.GetUserSessions("user-123") // "dónde estás conectado"
cleaned, err := sessionManager.CleanExpiredSessions()        // tarea periódica de mantenimiento
```

### `token.SessionStore` — implementar tu propio backend

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

Implementa esta interfaz con Redis/Postgres/lo que uses y pásala en `SessionConfig.Store`.

### Ejemplo conjunto del módulo (login completo: JWT + sesión enlazados)

```go
sessionID, _ := sessionManager.CreateSession(token.SessionInfo{
    UserID: "user-123", Username: "john_doe", IPAddress: r.RemoteAddr,
})

accessToken, _ := manager.GenerateAccessToken(token.Claims{
    UserID: "user-123", Role: "admin", SessionID: sessionID,
})
refreshToken, _ := manager.GenerateRefreshToken(token.Claims{
    UserID: "user-123", SessionID: sessionID,
})

// En cada request protegido:
claims, err := manager.ValidateToken(accessToken)
if err == nil {
    _, err = sessionManager.ValidateSession(claims.SessionID) // detecta logout en otro dispositivo
}
```

---

## 🌐 Módulo `security/middleware`

Middlewares HTTP reutilizables. El núcleo (`Middleware`, `Chain`, `RequireAuth`, `RequireRole`, `RequireActiveSession`, `RateLimit`, `CORS`, `RequestLogger`) sigue la firma estándar `func(http.Handler) http.Handler` y funciona con `net/http`, `chi`, `gorilla/mux`, etc. Además hay adaptadores nativos para **Gin** y **Fiber**, y un helper para registrar rutas con logging automático.

```go
import "github.com/AndresGT/GoKit/security/middleware"
```

### Núcleo net/http — autenticación y autorización

```go
authed := middleware.RequireAuth(jwtManager) // valida Bearer token, inyecta claims en el contexto
mux.Handle("/perfil", authed(http.HandlerFunc(perfilHandler)))

adminOnly := middleware.RequireRole("admin", "superadmin") // debe ir DESPUÉS de RequireAuth
mux.Handle("/admin", authed(adminOnly(http.HandlerFunc(adminHandler))))

activeSession := middleware.RequireActiveSession(sessionManager) // revocación instantánea
mux.Handle("/perfil", authed(activeSession(http.HandlerFunc(perfilHandler))))

// Dentro de un handler protegido:
claims, ok := middleware.ClaimsFromContext(r.Context())
```

### `middleware.Chain` — componer varios middlewares

```go
handler := middleware.Chain(mux,
    middleware.RequestLogger(log), // se ejecuta primero
    middleware.CORS(corsConfig),
    middleware.RequireAuth(jwtManager), // se ejecuta justo antes del handler
)
http.ListenAndServe(":8080", handler)
```

### `middleware.RateLimit` — limitar peticiones por clave

```go
limiter := middleware.NewMemoryRateLimiter(60, time.Minute) // 60 req/min por clave
handler := middleware.RateLimit(limiter, nil)(mux) // nil => usa RemoteIPKeyFunc

// Limitar por usuario autenticado en vez de por IP:
byUser := func(r *http.Request) string {
    if claims, ok := middleware.ClaimsFromContext(r.Context()); ok {
        return claims.UserID
    }
    return middleware.RemoteIPKeyFunc(r)
}
handler = middleware.RequireAuth(jwtManager)(middleware.RateLimit(limiter, byUser)(mux))

// Limpieza periódica obligatoria (el mapa interno no se reduce solo)
go func() {
    ticker := time.NewTicker(5 * time.Minute)
    for range ticker.C {
        limiter.Cleanup()
    }
}()
```

Para límites compartidos entre varias instancias/réplicas, implementa tu propio `middleware.RateLimiter` (interfaz de un solo método `Allow(key string) bool`) respaldado por Redis.

### `middleware.CORS`

```go
handler := middleware.CORS(middleware.CORSConfig{
    AllowedOrigins:   []string{"https://app.example.com"},
    AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE"}, // opcional, hay default
    AllowedHeaders:   []string{"Authorization", "Content-Type"}, // opcional, hay default
    AllowCredentials: true,
    MaxAge:           3600,
})(mux)
```

> `AllowedOrigins: ["*"]` se ignora automáticamente si `AllowCredentials` es `true` (la spec CORS lo prohíbe).

### `middleware.RequestLogger`

```go
log := logger.New()
handler := middleware.RequestLogger(log)(mux) // acepta cualquier tipo con método Info(string)
```

### Gin — middlewares nativos

```go
r := gin.New()
r.Use(middleware.GinRecovery(), middleware.GinLogger())

authed := r.Group("/perfil", middleware.GinAuth())
```

| Función           | Qué hace                                                         |
|--------------------|---------------------------------------------------------------------|
| `middleware.GinAuth()`     | Valida Bearer token contra el manager JWT global, inyecta `user_id`/`user_claims` en `c`. |
| `middleware.GinLogger()`   | Loguea cada request (method, path, status, duración, IP) con el logger global.            |
| `middleware.GinRecovery()` | Captura panics en handlers Gin y responde 500 sin tumbar el proceso.                      |

### Fiber — middlewares nativos

```go
app := fiber.New()
app.Use(middleware.FiberRecovery(), middleware.FiberLogger())

app.Get("/perfil", middleware.FiberAuth(), perfilHandler)
```

| Función              | Qué hace                                                     |
|-----------------------|-----------------------------------------------------------------|
| `middleware.FiberAuth()`     | Igual que `GinAuth()` pero para Fiber (usa `c.Locals`).   |
| `middleware.FiberLogger()`   | Igual que `GinLogger()` pero para Fiber.                  |
| `middleware.FiberRecovery()` | Igual que `GinRecovery()` pero para Fiber.                |

### Registro de rutas con logging automático (`Route[H]`)

Registra un grupo de rutas y deja constancia de cada endpoint en el logger global al arrancar — indicando método, path y si está protegida.

```go
type Route[H any] struct {
    Method    string // "GET", "POST", ...
    Path      string
    Handler   H      // gin.HandlerFunc o fiber.Handler
    Protected bool   // solo informativo, salvo que uses WithAuthManager
}
```

**Gin:**

```go
authGroup := r.Group("/auth")
middleware.RegisterGinRoutes(authGroup, []middleware.Route[gin.HandlerFunc]{
    {Method: "POST", Path: "/signup", Handler: handler.SignUp, Protected: false},
    {Method: "POST", Path: "/signin", Handler: handler.SignIn, Protected: false},
}, middleware.WithGroupName("auth"))

// Con auth automática en las rutas protegidas:
adminGroup := r.Group("/admin")
middleware.RegisterGinRoutes(adminGroup, []middleware.Route[gin.HandlerFunc]{
    {Method: "GET", Path: "/dashboard", Handler: handler.Dashboard, Protected: true},
}, middleware.WithAuthManager(jwtManager), middleware.WithGroupName("admin"))
```

**Fiber:**

```go
authGroup := app.Group("/auth")
middleware.RegisterFiberRoutes(authGroup, []middleware.Route[fiber.Handler]{
    {Method: "POST", Path: "/signup", Handler: handler.SignUp, Protected: false},
    {Method: "POST", Path: "/signin", Handler: handler.SignIn, Protected: false},
}, middleware.WithGroupName("auth"))
```

> ℹ️ A diferencia de Gin, `fiber.Router` no expone un `BasePath()` equivalente, así que en el log de Fiber `path` muestra la ruta relativa al grupo (`/signup`), no la ruta completa (`/auth/signup`). Usa `WithGroupName` para saber a qué grupo pertenece cada línea.

| Opción                              | Qué hace                                                                          |
|---------------------------------------|--------------------------------------------------------------------------------------|
| `middleware.WithAuthManager(manager)` | Las rutas `Protected: true` reciben auth automática validada contra ese manager.    |
| `middleware.WithGroupName(name)`      | Etiqueta el grupo en el log de arranque (`group=auth`).                             |

Salida en consola al arrancar (ejemplo):

```
2026-08-02 10:00:00 [INFO] 🔓 ruta registrada | method=POST, path=/auth/signup, protected=false, group=auth
2026-08-02 10:00:00 [INFO] 🔒 ruta registrada | method=GET, path=/admin/dashboard, protected=true, auth=aplicado, group=admin
```

### Ejemplo conjunto del módulo (net/http puro)

```go
mux := http.NewServeMux()
mux.HandleFunc("/health", healthHandler)

limiter := middleware.NewMemoryRateLimiter(100, time.Minute)
authed := middleware.RequireAuth(jwtManager)
adminOnly := middleware.RequireRole("admin")

mux.Handle("/perfil", authed(http.HandlerFunc(perfilHandler)))
mux.Handle("/admin", authed(adminOnly(http.HandlerFunc(adminHandler))))

handler := middleware.Chain(mux,
    middleware.RequestLogger(log),
    middleware.CORS(middleware.CORSConfig{AllowedOrigins: []string{"https://app.example.com"}}),
    middleware.RateLimit(limiter, nil),
)

http.ListenAndServe(":8080", handler)
```

---

## 🧩 Ejemplo completo de integración

Une los cinco módulos: hashing en el signup, JWT + sesión en el login, y un router Gin con auth automática en las rutas protegidas.

```go
package main

import (
    "net/http"
    "time"

    "github.com/AndresGT/GoKit/logger"
    "github.com/AndresGT/GoKit/security"
    "github.com/AndresGT/GoKit/security/crypto"
    "github.com/AndresGT/GoKit/security/middleware"
    "github.com/AndresGT/GoKit/security/token"
    "github.com/gin-gonic/gin"
)

func main() {
    log := logger.New(logger.WithLevel(logger.InfoLevel))
    logger.SetDefault(log)

    jwtManager, _ := token.NewJWTManager(token.JWTConfig{
        SecretKey:     []byte("clave-secreta-de-produccion-32-bytes!!"),
        Issuer:        "mi-api",
        SecurityLevel: security.LevelHigh,
    })
    sessionManager, _ := token.NewSessionManager(token.SessionConfig{
        SecurityLevel: security.LevelHigh,
    })

    r := gin.New()
    r.Use(middleware.GinRecovery(), middleware.GinLogger())

    authGroup := r.Group("/auth")
    middleware.RegisterGinRoutes(authGroup, []middleware.Route[gin.HandlerFunc]{
        {Method: "POST", Path: "/signup", Protected: false, Handler: func(c *gin.Context) {
            var body struct{ Password, Email string }
            _ = c.BindJSON(&body)

            hash, err := crypto.HashPassword(body.Password)
            if err != nil {
                c.JSON(http.StatusBadRequest, gin.H{"error": security.ErrWeakPassword.Error()})
                return
            }
            // ... guardar hash en la base de datos ...
            c.JSON(http.StatusCreated, gin.H{"hash_preview": hash[:20] + "..."})
        }},
        {Method: "POST", Path: "/signin", Protected: false, Handler: func(c *gin.Context) {
            userID := "user-123" // tras verificar crypto.VerifyPassword contra el hash guardado

            sessionID, _ := sessionManager.CreateSession(token.SessionInfo{
                UserID: userID, IPAddress: c.ClientIP(),
            })
            accessToken, _ := jwtManager.GenerateAccessToken(token.Claims{
                UserID: userID, Role: "user", SessionID: sessionID,
            })
            refreshToken, _ := jwtManager.GenerateRefreshToken(token.Claims{
                UserID: userID, SessionID: sessionID,
            })
            c.JSON(http.StatusOK, gin.H{"access_token": accessToken, "refresh_token": refreshToken})
        }},
    }, middleware.WithGroupName("auth"))

    adminGroup := r.Group("/admin")
    middleware.RegisterGinRoutes(adminGroup, []middleware.Route[gin.HandlerFunc]{
        {Method: "GET", Path: "/dashboard", Protected: true, Handler: func(c *gin.Context) {
            c.JSON(http.StatusOK, gin.H{"claims": c.MustGet("user_claims")})
        }},
    }, middleware.WithAuthManager(jwtManager), middleware.WithGroupName("admin"))

    log.Info("🚀 Servidor escuchando en :8080")
    _ = r.Run(":8080")
    _ = time.Second // placeholder si agregas timeouts propios
}
```

---

## ❗ Manejo de errores

Cada paquete expone sus propios `error` como variables comparables con `errors.Is`:

| Paquete                          | Errores principales                                                                 |
|------------------------------------|-----------------------------------------------------------------------------------------|
| `logger`                           | `ErrInvalidLevel`, `ErrWriteFailed`, `ErrInvalidFilePath`                               |
| `security`                         | `ErrAuthenticationFailed`, `ErrPermissionDenied`, `ErrTokenInvalid`, `ErrSessionExpired`, `ErrRateLimitExceeded`, `ErrAccountLocked`, `ErrWeakPassword`, y más (ver [módulo `security`](#-módulo-security-raíz)) |
| `security/crypto`                  | `ErrInvalidHash`, `ErrUnsupportedAlgorithm`, `ErrPasswordTooShort`, `ErrPasswordTooLong`, `ErrInvalidKeyLength`, `ErrEncryptionFailed`, `ErrDecryptionFailed`, `ErrInvalidCiphertext`, `ErrInvalidLength`, `ErrRandomGenerationFailed`, `ErrInvalidPrefix` |
| `security/token`                   | `ErrJWTInvalid`, `ErrJWTExpired`, `ErrJWTSigningMethodInvalid`, `ErrSessionNotFound`, `ErrSessionStoreFailed` |
| `security/middleware`              | `ErrMissingAuthHeader`, `ErrInvalidAuthHeader`                                          |

```go
if errors.Is(err, token.ErrJWTExpired) {
    // pedir refresh
} else if errors.Is(err, security.ErrSessionExpired) {
    // pedir re-login
}
```

## 📜 Licencia

MIT
