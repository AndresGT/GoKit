# GoKit - Documentación

> Toolkit de Go con utilidades listas para producción: logging, niveles de seguridad, hashing de contraseñas, cifrado AES-256-GCM, generación de datos aleatorios seguros, JWT, sesiones, middlewares HTTP (net/http, Gin y Fiber) y auditoría forense con IA.

[![Go Version](https://img.shields.io/badge/Go-1.25+-00ADD8?style=flat&logo=go)](https://golang.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

---

## Índice

1. [Instalación](#instalación)
2. [Estructura del proyecto](#estructura-del-proyecto)
3. [logger](#logger)
4. [security (raíz)](#security-raíz)
5. [security/crypto](#securitycrypto)
6. [security/token](#securitytoken)
7. [security/middleware](#securitymiddleware)
8. [security/audit](#securityaudit)
9. [Pruebas y cobertura](#pruebas-y-cobertura)
10. [Licencia](#licencia)

---

## Instalación

```bash
go get github.com/AndresGT/GoKit
```

Cada módulo es un paquete independiente; importa solo lo que necesites:

```go
import (
    "github.com/AndresGT/GoKit/logger"
    "github.com/AndresGT/GoKit/security"
    "github.com/AndresGT/GoKit/security/crypto"
    "github.com/AndresGT/GoKit/security/token"
    "github.com/AndresGT/GoKit/security/middleware"
    "github.com/AndresGT/GoKit/security/audit"
)
```

Requiere Go 1.25 o superior.

## Estructura del proyecto

```
GoKit/
├── logger/                    # Logging con 8 niveles, colores y salidas flexibles
├── security/
│   ├── levels.go              # Niveles de seguridad (Low/Medium/High/Critical) y sus defaults
│   ├── errors.go              # Errores transversales del dominio "security"
│   ├── crypto/                # Hashing de contraseñas, cifrado AES-256-GCM, random seguro
│   ├── token/                 # JWT (access/refresh) y gestión de sesiones
│   ├── middleware/            # Middlewares HTTP: net/http, Gin, Fiber + registro de rutas
│   └── audit/                 # Auditoría forense con IA y storages memory/sqlite/postgres
└── main.go                    # Ejemplo de humo (smoke test) de todos los módulos
```

---

## logger

Logging thread-safe con 8 niveles, colores ANSI configurables y salida a consola/archivo/ambas.

### Niveles

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

### Uso global (sin configuración)

```go
logger.Info("Servidor iniciado en el puerto 8080")
logger.Warn("Uso de memoria por encima del 80%")
logger.Error("No se pudo conectar a la API externa")
logger.Success("Usuario autenticado correctamente")

logger.InfoWithFields("usuario_creado", map[string]interface{}{
    "user_id": "usr_123",
    "email":   "ana@example.com",
})
```

### Instancia propia con Functional Options

```go
log := logger.New(
    logger.WithLevel(logger.DebugLevel),
    logger.WithColor(true),
)
log.Debug("Instancia propia, no la global")

// Escribir a consola + archivo:
fileWriter, err := logger.NewFileWriter("logs/app.log") // crea directorios si faltan
cfg := logger.NewConfig()
cfg.Writer = logger.NewMultiWriter(logger.NewConsoleWriter(), fileWriter)
log2 := logger.New(logger.WithWriter(cfg.Writer))
```

### Opciones disponibles

| Opción                                    | Qué hace                                                                 |
|--------------------------------------------|---------------------------------------------------------------------------|
| `logger.WithLevel(level Level)`             | Nivel mínimo de severidad (se ignora si no es válido).                    |
| `logger.WithWriter(w io.Writer)`            | Destino de salida (se ignora si `w` es `nil`).                            |
| `logger.WithColor(enable bool)`             | Activa/desactiva colores ANSI.                                            |
| `logger.WithDateTime(showDate, showTime bool)` | Incluye/oculta fecha y hora.                                            |
| `logger.WithFileOutput(filePath string)`    | Escribe a archivo (append) y desactiva color automáticamente.             |

### SetDefault / GetDefault

```go
custom := logger.New(logger.WithFileOutput("logs/app.log"))
logger.SetDefault(custom) // logger.Info(...) pasa a usar custom
current := logger.GetDefault()
```

### Temas y errores

```go
logger.SetTheme(logger.Theme{Info: "\033[36m", /* ... */})
logger.ResetTheme()
```

Errores comparables con `errors.Is`: `logger.ErrInvalidLevel`, `logger.ErrWriteFailed`, `logger.ErrInvalidFilePath`.

---

## security (raíz)

Define niveles de seguridad (`security.Level`) con defaults por nivel y los errores transversales de todo el ecosistema.

### Niveles

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

`Level` se pasa a `token.JWTConfig.SecurityLevel` y `token.SessionConfig.SecurityLevel` para heredar sus defaults.

### Errores transversales

`security.ErrAuthenticationFailed`, `ErrPermissionDenied`, `ErrInsufficientSecurityLevel`, `ErrTokenInvalid`, `ErrTokenRevoked`, `ErrSessionExpired`, `ErrRateLimitExceeded`, `ErrAccountLocked`, `ErrIPBlocked`, `ErrInvalidInput`, `ErrWeakPassword`, `ErrOperationNotAllowed`, `ErrPasswordChangeRequired`, `ErrInvalidHash`, `ErrIncompatibleVersion`, `ErrInvalidCiphertext`, `ErrInvalidKeyLength`.

```go
if errors.Is(err, security.ErrSessionExpired) {
    // pedir re-login
}
```

---

## security/crypto

Tres capacidades: hashing de contraseñas (4 algoritmos), cifrado AES-256-GCM y generación de datos aleatorios seguros.

### Hashing (Argon2id por defecto, estándar OWASP)

```go
hash, err := crypto.HashPassword("MiContraseñaSuperSegura123!") // valida 8–72 chars
ok, err := crypto.VerifyPassword("MiContraseñaSuperSegura123!", hash)
needsUpgrade := crypto.NeedsUpgrade(hash)
```

`VerifyPassword` detecta el algoritmo del hash (`DetectAlgorithm`), así que puedes migrar de algoritmo sin invalidar contraseñas existentes.

### Hasher específico vía interfaz

```go
type Hasher interface {
    Hash(password string) (string, error)
    Verify(password, hash string) (bool, error)
    NeedsUpgrade(hash string) bool
}

hasher, _ := crypto.NewHasher(crypto.HasherConfig{
    Algorithm:         crypto.AlgorithmArgon2id,
    Argon2Memory:      64 * 1024, // 64 MB
    Argon2Iterations:  3,
    Argon2Parallelism: 4,
    Argon2KeyLength:   32,
    Argon2SaltLength:  16,
})

hasher, _ = crypto.NewHasher(crypto.HasherConfig{
    Algorithm:  crypto.AlgorithmBcrypt,
    BcryptCost: 12, // 10 dev, 12 producción, 14 alta seguridad, 15+ crítico
})

hasher, _ = crypto.NewHasher(crypto.HasherConfig{
    Algorithm: crypto.AlgorithmScrypt,
    ScryptN:   16384, ScryptR: 8, ScryptP: 1, ScryptKeyLen: 32, ScryptSaltLen: 16,
})

hasher, _ = crypto.NewHasher(crypto.HasherConfig{
    Algorithm:        crypto.AlgorithmPBKDF2,
    PBKDF2Iterations: 600000, // recomendación OWASP 2023
})
```

Los parámetros numéricos son opcionales: en cero, cada algoritmo aplica valores seguros por defecto.

### Cifrado AES-256-GCM

```go
key, _ := crypto.GenerateEncryptionKey()        // []byte, 32 bytes
keyB64, _ := crypto.GenerateEncryptionKeyBase64() // string base64 para .env

encrypter, err := crypto.NewAESEncrypter(key)
ciphertext, _ := encrypter.Encrypt([]byte("dato sensible"))
plaintext, _ := encrypter.Decrypt(ciphertext)

encryptedStr, _ := encrypter.EncryptString("Número de tarjeta: 4111-1111-1111-1111")
decryptedStr, _ := encrypter.DecryptString(encryptedStr)
```

GCM incluye autenticación integrada: ciphertext manipulado → `ErrDecryptionFailed`.

### Datos aleatorios seguros

```go
bytes, _  := crypto.RandomBytes(32)        // []byte aleatorios
str, _    := crypto.RandomString(32)       // alfanumérico URL-safe — session IDs, CSRF
hex, _    := crypto.RandomHex(32)          // hexadecimal (64 chars) — refresh tokens, API keys
uuid, _   := crypto.GenerateUUID()         // UUID v4 (RFC 4122)
apiKey, _ := crypto.GenerateAPIKey("usr")  // "usr_a1b2c3..." — prefix "" usa "gk_" por defecto
otp, _    := crypto.GenerateNumericCode(6) // "482913" — OTPs, 2FA, PINs
```

---

## security/token

JWT (access/refresh) y gestión de sesiones revocables.

### JWT — manager propio

```go
manager, err := token.NewJWTManager(token.JWTConfig{
    SecretKey:     []byte("mi-clave-secreta-de-al-menos-32-bytes!"), // mínimo 32 bytes
    Issuer:        "mi-api",
    SecurityLevel: security.LevelHigh, // 15min access, 24h refresh
})

// O duraciones explícitas (prioridad sobre SecurityLevel):
manager, err = token.NewJWTManager(token.JWTConfig{
    SecretKey:            []byte("mi-clave-secreta-de-al-menos-32-bytes!"),
    AccessTokenDuration:  15 * time.Minute,
    RefreshTokenDuration: 7 * 24 * time.Hour,
})
```

### JWT — generar y validar

```go
claims := token.Claims{
    UserID:    "user-123",
    Username:  "john_doe",
    Role:      "admin",
    Email:     "john@example.com",
    SessionID: "session-abc-123", // enlaza el JWT con una sesión revocable
}

accessToken, _ := manager.GenerateAccessToken(claims)
refreshToken, _ := manager.GenerateRefreshToken(claims)

validClaims, err := manager.ValidateToken(accessToken)
if errors.Is(err, token.ErrJWTExpired) {
    // requerir refresh
}

newAccessToken, _ := manager.RefreshAccessToken(refreshToken)
cfg := manager.GetConfig()
```

`ValidateToken` rechaza tokens con método de firma distinto a HS256 y verifica el `Issuer` si fue configurado.

### JWT — API global

```go
err := token.Init(token.JWTConfig{
    SecretKey: []byte(os.Getenv("JWT_SECRET")),
    Issuer:    "mi-proyecto",
})

accessToken, _ := token.GenerateAccessToken(claims)
claims, err := token.ValidateToken(accessToken)
manager := token.GetDefault()
```

> ⚠️ Sin `token.Init`, el manager global usa una clave de desarrollo embebida. **Nunca la uses en producción.**

### Sesiones

```go
sessionManager := token.NewSessionManager(token.SessionConfig{
    SecurityLevel: security.LevelHigh, // 8h timeout, 15min idle, máx 2 sesiones
})

// Con store propio (Redis, BD, etc.):
sessionManager = token.NewSessionManager(token.SessionConfig{
    SessionTimeout:        8 * time.Hour,
    IdleTimeout:           15 * time.Minute,
    MaxConcurrentSessions: 2,
    Store:                 myRedisStore, // implementa token.SessionStore
})

sessionID, _ := sessionManager.CreateSession(token.SessionInfo{
    UserID:    "user-123",
    Username:  "john_doe",
    IPAddress: "192.168.1.100",
    UserAgent: "Mozilla/5.0...",
})

session, err := sessionManager.ValidateSession(sessionID) // también actualiza LastActivityAt
err = sessionManager.RevokeSession(sessionID, "user_logout")
err = sessionManager.RevokeAllUserSessions("user-123", "password_changed")
sessions, _ := sessionManager.GetUserSessions("user-123")
cleaned, _ := sessionManager.CleanExpiredSessions()
```

Sin `Store` se usa `MemorySessionStore` (solo desarrollo/testing).

---

## security/middleware

Middlewares con firma estándar `func(http.Handler) http.Handler` (net/http, chi, gorilla/mux) y adaptadores nativos para Gin y Fiber.

### Núcleo net/http

```go
authed := middleware.RequireAuth(jwtManager) // valida Bearer token, inyecta claims en el contexto
mux.Handle("/perfil", authed(http.HandlerFunc(perfilHandler)))

adminOnly := middleware.RequireRole("admin", "superadmin") // DESPUÉS de RequireAuth
mux.Handle("/admin", authed(adminOnly(http.HandlerFunc(adminHandler))))

activeSession := middleware.RequireActiveSession(sessionManager) // revocación instantánea

// Dentro de un handler protegido:
claims, ok := middleware.ClaimsFromContext(r.Context())
```

### Chain, RateLimit, CORS, RequestLogger

```go
handler := middleware.Chain(mux,
    middleware.RequestLogger(log),
    middleware.CORS(middleware.CORSConfig{
        AllowedOrigins:   []string{"https://app.example.com"},
        AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE"}, // hay default
        AllowedHeaders:   []string{"Authorization", "Content-Type"}, // hay default
        AllowCredentials: true,
        MaxAge:           3600,
    }),
    middleware.RateLimit(limiter, nil), // nil => usa RemoteIPKeyFunc
)
http.ListenAndServe(":8080", handler)
```

```go
limiter := middleware.NewMemoryRateLimiter(60, time.Minute) // 60 req/min por clave
handler := middleware.RateLimit(limiter, nil)(mux)

// Limpieza periódica obligatoria:
go func() {
    ticker := time.NewTicker(5 * time.Minute)
    for range ticker.C {
        limiter.Cleanup()
    }
}()
```

> `AllowedOrigins: ["*"]` se ignora si `AllowCredentials` es `true` (la spec CORS lo prohíbe).

### Gin y Fiber

```go
r := gin.New()
r.Use(middleware.GinRecovery(), middleware.GinLogger())
authed := r.Group("/perfil", middleware.GinAuth()) // valida contra el manager global

app := fiber.New()
app.Use(middleware.FiberRecovery(), middleware.FiberLogger())
app.Get("/perfil", middleware.FiberAuth(), perfilHandler)
```

### Registro de rutas con logging automático

```go
authGroup := r.Group("/auth")
middleware.RegisterGinRoutes(authGroup, []middleware.Route[gin.HandlerFunc]{
    {Method: "POST", Path: "/signup", Handler: handler.SignUp, Protected: false},
    {Method: "POST", Path: "/signin", Handler: handler.SignIn, Protected: false},
}, middleware.WithGroupName("auth"))

adminGroup := r.Group("/admin")
middleware.RegisterGinRoutes(adminGroup, []middleware.Route[gin.HandlerFunc]{
    {Method: "GET", Path: "/dashboard", Handler: handler.Dashboard, Protected: true},
}, middleware.WithAuthManager(jwtManager), middleware.WithGroupName("admin"))
```

| Opción                              | Qué hace                                                                          |
|---------------------------------------|--------------------------------------------------------------------------------------|
| `middleware.WithAuthManager(manager)` | Las rutas `Protected: true` reciben auth automática contra ese manager.             |
| `middleware.WithGroupName(name)`      | Etiqueta el grupo en el log de arranque (`group=auth`).                             |

---

## security/audit

Auditoría forense con detección de amenazas mediante IA: fuerza bruta, SQLi/XSS, scraping, viaje imposible, DDoS, anomalías comportamentales e IPs maliciosas. Storages: memoria (tests), SQLite (dev, sin CGO) y PostgreSQL (producción).

### Configuración

```go
auditor, err := audit.NewAuditor(audit.Config{
    StorageType:  "sqlite",
    StorageConfig: audit.SQLiteConfig{DSN: "audit.db"},
    EnableIA:     true,
    IAMinRiskThreshold: 0.6, // solo alertar con score de riesgo alto
    EnableAsync:  true,      // procesamiento asíncrono
    AsyncBufferSize: 1000,
    Retention: audit.RetentionPolicy{
        MaxAgeDays:       90,
        EnableAutoDelete: true, // goroutine de mantenimiento automático
    },
    LogLevel: "info",
})
```

PostgreSQL:

```go
auditor, err := audit.NewAuditor(audit.Config{
    StorageType:  "postgres",
    StorageConfig: audit.PostgresConfig{
        DSN:          "postgres://user:pass@localhost/audit?sslmode=disable",
        MaxOpenConns: 20,
        MaxIdleConns: 5,
    },
    EnableIA: true,
})
```

`RetentionPolicy` también admite `MaxEvents`, `CompressAfterDays` y `ArchiveAfterDays`. Cifrado en reposo con `EnableEncryption` + `EncryptionKey`; la huella digital (`DigitalFingerprint`) se calcula por evento automáticamente.

Instancia global (activa los helpers `*Quick` y `GetDefault`):

```go
err = audit.Init(audit.Config{StorageType: "memory", EnableIA: true})
```

### Registro de eventos

```go
ev := &audit.Event{
    Actor: audit.ActorInfo{
        ID: "user_123", Email: "ana@example.com", Role: "admin", Type: "user",
        SessionID: "sess-abc123",
    },
    Action: audit.ActionInfo{
        Type: "PASSWORD_CHANGE", Category: "SECURITY",
        Method: "POST", Path: "/api/v1/auth/password",
    },
    Resource: audit.ResourceInfo{Type: "user_account", ID: "user_123"},
    Result:   audit.ResultInfo{Status: "SUCCESS", StatusCode: 200},
    Context:  audit.ContextInfo{
        IPAddress: "192.168.1.50",
        UserAgent: "Mozilla/5.0...",
        RequestID: "req-xyz",
    },
    Metadata: map[string]interface{}{"mfa_enabled": true},
}

err := auditor.Record(ev)     // síncrono (ejecuta IA y calcula fingerprint)
err = auditor.RecordAsync(ev) // asíncrono
err = audit.RecordQuick(ev)   // con el auditor global
```

### Consultas forenses

```go
events, err := auditor.Query(context.Background(), audit.QueryFilter{
    ActorIDs:     []string{"user_123"},
    Statuses:     []string{"FAILURE"},
    ThreatTypes:  []string{"BRUTE_FORCE"},
    StartTime:    time.Now().Add(-24 * time.Hour),
    SortBy:       "risk_score",
    SortOrder:    "desc",
    Limit:        100,
})

event, _ := auditor.GetByID(ctx, "uuid-del-evento")
total, _ := auditor.Count(ctx, audit.QueryFilter{ActorIDs: []string{"user_123"}})
stats := auditor.GetStats() // Stats: TotalEvents, ThreatsDetected, AverageRiskScore, ...
```

### Motor de IA

Reglas por defecto (`LoadDefaultRules`): `BRUTE_FORCE_001` (>5 logins fallidos por IP en 5 min), `SQL_INJECTION_001`, `XSS_001`, `SCRAPING_001` (>30 req/min), `IMPOSSIBLE_TRAVEL_001` (logins en ubicaciones distantes en <1h), `DDOS_001` (>200 req en 10s), `ANOMALY_001` (desviación del perfil de comportamiento) y `MALICIOUS_IP_001`.

```go
threats, riskScore := iaEngine.Analyze(ev)
iaEngine.AddRule(audit.DetectionRule{
    ID: "CUSTOM_001", Name: "Regla personalizada", Severity: "HIGH",
    Condition: func(e *audit.Event) bool { return e.Result.Status == "FAILURE" },
    Action: func(e *audit.Event) *audit.ThreatDetection {
        return &audit.ThreatDetection{Type: "CUSTOM", Severity: "HIGH", Confidence: 0.9}
    },
    Enabled: true,
})
iaEngine.RemoveRule("CUSTOM_001")
iaEngine.Disable() / iaEngine.Enable()
iaStats := iaEngine.GetStats() // IAStats: TotalEvaluations, ThreatsDetected, DetectionByType, ...
```

`ThreatDetection` expone `Type`, `Severity`, `Confidence` (0–1), `Description`, `Evidence`, `RuleID`, `Pattern` y `Recommendation`. Las amenazas HIGH/CRITICAL se loguean automáticamente con el logger global.

### Exportación

```go
var buf bytes.Buffer
err := auditor.Export(ctx, audit.QueryFilter{StartTime: time.Now().AddDate(0, -1, 0)},
    audit.ExportFormatJSON, &buf)    // JSON
err = auditor.Export(ctx, filter, audit.ExportFormatCSV, &buf)     // CSV
err = auditor.Export(ctx, filter, audit.ExportFormatNDJSON, &buf)  // NDJSON para ELK/Splunk

err = audit.ExportQuick(ctx, filter, audit.ExportFormatJSON, &buf) // con el auditor global
```

### Storage directo

```go
mem := audit.NewMemoryStorage() // en memoria, útil para tests
sq, _ := audit.NewSQLiteStorage(audit.SQLiteConfig{DSN: "audit.db"})
pg, _ := audit.NewPostgresStorage(audit.PostgresConfig{DSN: "postgres://user:pass@localhost/audit?sslmode=disable"})

sq.Save(context.Background(), ev)
n, _ := sq.DeleteOlderThan(context.Background(), time.Now().Add(-30*24*time.Hour))
```

---

## Pruebas y cobertura

```bash
go test -race -count=1 ./...
go test -covermode=atomic -coverprofile=coverage.out ./...
```

Todos los paquetes del gate de CI (`logger`, `security`, `security/crypto`, `security/token`, `security/middleware` y `security/audit`) tienen **100% de cobertura**. El pipeline de CI (`.github/workflows/ci.yml`) exige ≥99.99% por paquete y ejecuta los tests con `-race`.

Tests clave del módulo `security/audit`:

| Test | Qué cubre |
|------|-----------|
| `TestBruteForceDetection` / `TestBruteForceEndToEnd` | Fuerza bruta por IP y flujo completo |
| `TestSQLInjectionDetection` / `TestDetectSQLInjectionAndXSS` | Patrones SQLi y XSS |
| `TestImpossibleTravelDetection` | Viaje imposible entre ubicaciones |
| `TestDetectScraping` / `TestDetectDDoS` | Scraping y DDoS |
| `TestDetectAnomaly` / `TestDetectMaliciousIP` | Anomalías e IPs maliciosas |
| `TestConcurrentAccess` | Thread-safety con acceso concurrente |
| `TestSQLiteStorageErrors` / `TestNewPostgresStorageBranches` | Errores de storage (sqlmock) |
| `TestMemorySortAllBranches` / `TestMemoryStorageBranches` | Storage en memoria y ordenamiento |
| `TestExportEvents` / `TestSQLiteExportHelpers` | Exportación JSON/CSV/NDJSON |
| `TestRetentionDeletion` / `TestRetentionMaintenance` | Retención y borrado automático |
| `TestPIISanitization` | Sanitización de datos personales |

## Licencia

MIT
