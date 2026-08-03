# 🚀 GoKit - Documentación Completa

> **Toolkit interno de Go con utilidades listas para producción**

[![Go Version](https://img.shields.io/badge/Go-1.26.4-blue.svg)](https://golang.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/Tests-Passing-brightgreen.svg)]()

---

## 📑 Tabla de Contenidos

1. [Introducción](#introducción)
2. [Instalación](#instalación)
3. [Módulos Disponibles](#módulos-disponibles)
4. [Logger](#logger)
5. [Crypto](#crypto)
6. [Token](#token)
7. [Middleware](#middleware)
8. [Audit](#audit)
9. [Ejemplos Reales](#ejemplos-reales)
10. [Mejores Prácticas](#mejores-prácticas)

---

## Introducción

**GoKit** es un toolkit interno desarrollado en Go que proporciona utilidades listas para producción, diseñadas para acelerar el desarrollo de aplicaciones seguras y escalables.

### ✨ Características Principales

- **🔒 Seguridad por defecto**: Todos los módulos siguen las mejores prácticas de seguridad
- **⚡ Uso rápido**: Funciones globales para prototipado veloz
- **⚙️ Configuración completa**: Control total para entornos de producción
- **🧪 Tests exhaustivos**: Cobertura >80% en todos los módulos
- **📚 Documentación detallada**: Ejemplos reales y casos de uso
- **🔗 Integración total**: Módulos diseñados para trabajar juntos

### 🎯 Casos de Uso

- APIs RESTful con autenticación JWT
- Sistemas de gestión de usuarios y sesiones
- Auditoría forense y cumplimiento normativo (GDPR, SOC2)
- Cifrado de datos sensibles
- Logging estructurado para monitoreo
- Protección contra ataques comunes

---

## Instalación

```bash
go get github.com/juanmdev/gokit
```

### Requisitos

- Go 1.26.4 o superior
- Conexión a internet para descargar dependencias

### Dependencias

```go
require (
    github.com/golang-jwt/jwt/v5 v5.2.0
    golang.org/x/crypto v0.31.0
    github.com/gin-gonic/gin v1.9.1
    github.com/gofiber/fiber/v2 v2.52.0
)
```

---

## Módulos Disponibles

| Módulo | Descripción | Estado | Cobertura Tests |
|--------|-------------|--------|-----------------|
| **logger** | Logging estructurado con 8 niveles | ✅ Stable | 62.8% |
| **crypto** | Hashing y cifrado (4 algoritmos) | ✅ Stable | 75.9% |
| **token** | JWT y gestión de sesiones | ✅ Stable | 87.7% |
| **middleware** | Middlewares HTTP (net/http, Gin, Fiber) | ✅ Stable | 82.4% |
| **audit** | Auditoría forense con IA | ✅ New | 84.2% |

---

## Logger

Sistema de logging thread-safe con 8 niveles, colores ANSI y salidas múltiples.

### 🚀 Inicio Rápido

```go
package main

import "github.com/juanmdev/gokit/logger"

func main() {
    // Uso global (más simple)
    logger.Info("Aplicación iniciada")
    logger.Success("Conexión exitosa a DB")
    logger.Error("Error crítico", "error", err)
    
    // Con campos contextuales
    logger.WithFields("user_id", "123", "action", "login").
        Info("Usuario autenticado")
}
```

### ⚙️ Configuración Avanzada

```go
cfg := logger.Config{
    Level:      logger.InfoLevel,
    Format:     logger.JSONFormat,
    Output:     logger.OutputBoth, // Consola + Archivo
    FilePath:   "/var/log/app.log",
    Theme:      logger.DarkTheme,
    Timestamp:  true,
    CallerInfo: true,
}

log := logger.New(cfg)
log.Warn("Advertencia personalizada")
```

### 📊 Niveles Disponibles

| Nivel | Método | Uso | Color |
|-------|--------|-----|-------|
| Trace | `Trace()` | Debug muy detallado | Gris |
| Debug | `Debug()` | Información de debug | Cyan |
| Info | `Info()` | Información general | Azul |
| Success | `Success()` | Operaciones exitosas | Verde |
| Warn | `Warn()` | Advertencias | Amarillo |
| Error | `Error()` | Errores no críticos | Rojo |
| Fatal | `Fatal()` | Errores críticos (termina) | Rojo intenso |
| Panic | `Panic()` | Errores críticos (panic) | Rojo intenso |

### 📝 Ejemplo Completo

```go
package main

import (
    "github.com/juanmdev/gokit/logger"
    "time"
)

func main() {
    // Configurar logger
    cfg := logger.Config{
        Level:      logger.DebugLevel,
        Format:     logger.ConsoleFormat,
        Theme:      logger.DarkTheme,
        Timestamp:  true,
    }
    
    log := logger.New(cfg)
    
    // Simular proceso
    log.Info("Iniciando procesamiento", "batch_id", "BATCH-001")
    
    for i := 0; i < 5; i++ {
        log.WithFields("item", i, "total", 5).
            Debug("Procesando item")
        time.Sleep(100 * time.Millisecond)
    }
    
    log.Success("Procesamiento completado", "items", 5)
    
    // Logger con errores
    if err := someOperation(); err != nil {
        log.Error("Operación fallida", 
            "error", err,
            "retry_count", 3)
    }
}

func someOperation() error {
    return nil
}
```

### 🔗 Referencia Rápida

```go
// Funciones globales
logger.Trace(msg, fields...)
logger.Debug(msg, fields...)
logger.Info(msg, fields...)
logger.Success(msg, fields...)
logger.Warn(msg, fields...)
logger.Error(msg, fields...)
logger.Fatal(msg, fields...)
logger.Panic(msg, fields...)

// Con campos
logger.WithFields(keyValues...).Info(msg)
logger.WithFields(keyValues...).Error(msg, fields...)

// Obtener/setear default
defaultLog := logger.GetDefault()
logger.SetDefault(customLog)
```

**📖 Ver documentación completa:** [`logger/README_LOGGER.md`](logger/README_LOGGER.md)

---

## Crypto

Herramientas criptográficas para hashing de contraseñas, cifrado AES y generación segura de datos aleatorios.

### 🚀 Inicio Rápido

```go
package main

import "github.com/juanmdev/gokit/security/crypto"

func main() {
    // Hashing de contraseñas (Argon2id por defecto)
    hash, _ := crypto.HashPassword("mi_contraseña_segura")
    
    // Verificar contraseña
    valid, _ := crypto.VerifyPassword("mi_contraseña_segura", hash)
    
    // Cifrar texto
    encrypted, _ := crypto.EncryptString("datos sensibles")
    decrypted, _ := crypto.DecryptString(encrypted)
    
    // Generar UUID
    uuid := crypto.GenerateUUIDv4()
    
    // Generar API Key
    apiKey := crypto.GenerateAPIKey("prod")
    
    // Generar OTP (6 dígitos)
    otp := crypto.GenerateOTP(6)
}
```

### 🔐 Algoritmos de Hashing Soportados

| Algoritmo | Función | Uso Recomendado | Velocidad |
|-----------|---------|-----------------|-----------|
| **Argon2id** | `HashWithArgon2id()` | Por defecto, más seguro | Lento |
| **Bcrypt** | `HashWithBcrypt()` | Compatibilidad legacy | Medio |
| **Scrypt** | `HashWithScrypt()` | Alto security budget | Lento |
| **PBKDF2** | `HashWithPBKDF2()` | FIPS compliance | Rápido |

### ⚙️ Configuración Avanzada

```go
// Crear hasher personalizado
config := crypto.HashConfig{
    Algorithm:  crypto.Argon2id,
    Memory:     64 * 1024, // 64 MB
    Iterations: 3,
    Parallelism: 4,
    SaltLength: 16,
    KeyLength:  32,
}

hasher := crypto.NewHasher(config)
hash, _ := hasher.Hash("password")

// Verificar y actualizar si es necesario
valid, needsUpgrade, _ := hasher.VerifyAndUpdate("password", hash)
if needsUpgrade {
    newHash, _ := hasher.Hash("password")
    // Guardar newHash en DB
}
```

### 🔒 Cifrado AES-256-GCM

```go
// Configurar clave maestra (32 bytes)
key := crypto.GenerateRandomBytes(32)
crypto.SetEncryptionKey(key)

// Cifrar/descifrar
encrypted, _ := crypto.EncryptString("datos secretos")
decrypted, _ := crypto.DecryptString(encrypted)

// Usar clave específica
customKey := []byte("clave_personalizada_32_bytes!!")
encrypted2, _ := crypto.EncryptWithKey("datos", customKey)
decrypted2, _ := crypto.DecryptWithKey(encrypted2, customKey)
```

### 🎲 Generación Aleatoria Segura

```go
// Bytes aleatorios
bytes := crypto.GenerateRandomBytes(32)

// String aleatorio
str := crypto.GenerateRandomString(32)

// UUID v4
uuid := crypto.GenerateUUIDv4()

// API Key con prefijo
apiKey := crypto.GenerateAPIKeyWithPrefix("sk_live", 32)

// Código OTP
otp := crypto.GenerateOTP(6) // "123456"

// Token seguro
token := crypto.GenerateSecureToken()
```

### 📝 Ejemplo: Sistema de Autenticación

```go
package auth

import (
    "github.com/juanmdev/gokit/security/crypto"
    "errors"
)

type UserService struct {
    // ...
}

func (s *UserService) Register(email, password string) error {
    // Validar fortaleza de contraseña
    if len(password) < 8 {
        return errors.New("password too weak")
    }
    
    // Hashear contraseña
    hash, err := crypto.HashPassword(password)
    if err != nil {
        return err
    }
    
    // Guardar usuario con hash en DB
    // db.SaveUser(email, hash)
    
    return nil
}

func (s *UserService) Login(email, password string) (bool, error) {
    // Obtener hash de DB
    storedHash, err := s.getUserHash(email)
    if err != nil {
        return false, err
    }
    
    // Verificar contraseña
    valid, err := crypto.VerifyPassword(password, storedHash)
    if err != nil {
        return false, err
    }
    
    return valid, nil
}

func (s *UserService) ChangePassword(userID, oldPwd, newPwd string) error {
    // Verificar contraseña actual
    // ...
    
    // Hashear nueva contraseña
    newHash, err := crypto.HashPassword(newPwd)
    if err != nil {
        return err
    }
    
    // Actualizar en DB
    // db.UpdatePassword(userID, newHash)
    
    return nil
}
```

**📖 Ver documentación completa:** [`security/crypto/README_CRYPTO.md`](security/crypto/README_CRYPTO.md)

---

## Token

Gestión de JWT (Access/Refresh tokens) y sistema de sesiones con revocación.

### 🚀 Inicio Rápido

```go
package main

import "github.com/juanmdev/gokit/security/token"

func main() {
    // Generar token rápido
    accessToken, refreshToken, _ := token.GenerateQuickToken("user-123", "admin")
    
    // Validar token
    valid := token.ValidateQuickToken(accessToken)
    
    // Extraer información
    userID := token.ExtractUserID(accessToken)
    claims := token.ExtractClaims(accessToken)
    
    // Gestionar sesiones
    sessionID, _ := token.CreateQuickSession("user-123")
    exists := token.QuickSessionExists(sessionID)
    
    // Revocar sesión
    token.RevokeQuickSession(sessionID)
}
```

### ⚙️ Configuración Avanzada

```go
// Configurar JWT
jwtConfig := token.JWTConfig{
    SecretKey:       "super-secret-key-32-bytes-long!",
    AccessDuration:  15 * time.Minute,
    RefreshDuration: 7 * 24 * time.Hour,
    Issuer:          "myapp.com",
    Audience:        "myapp-users",
}

jwtManager := token.NewJWTManager(jwtConfig)

// Configurar sesiones
sessionConfig := token.SessionConfig{
    StoreType:     "redis",
    SessionTimeout: 24 * time.Hour,
    MaxSessionsPerUser: 5,
}

sessionManager := token.NewSessionManager(sessionConfig)
```

### 🎫 Tipos de Tokens

```go
// Access Token (corta duración)
type AccessToken struct {
    UserID   string   `json:"user_id"`
    Email    string   `json:"email"`
    Role     string   `json:"role"`
    Permissions []string `json:"permissions"`
}

// Refresh Token (larga duración)
type RefreshToken struct {
    UserID    string    `json:"user_id"`
    SessionID string    `json:"session_id"`
    ExpiresAt time.Time `json:"expires_at"`
}
```

### 📝 Ejemplo: Flujo de Autenticación Completo

```go
package handlers

import (
    "github.com/juanmdev/gokit/security/token"
    "github.com/juanmdev/gokit/security/crypto"
    "net/http"
)

type AuthHandler struct {
    jwtManager     *token.JWTManager
    sessionManager *token.SessionManager
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
    var req struct {
        Email    string `json:"email"`
        Password string `json:"password"`
    }
    
    // Parsear request
    // json.NewDecoder(r.Body).Decode(&req)
    
    // Verificar credenciales
    user, err := h.authenticate(req.Email, req.Password)
    if err != nil {
        http.Error(w, "Invalid credentials", http.StatusUnauthorized)
        return
    }
    
    // Generar tokens
    accessToken, refreshToken, err := h.jwtManager.GenerateTokens(
        user.ID,
        token.Claims{
            Email: user.Email,
            Role:  user.Role,
        },
    )
    if err != nil {
        http.Error(w, "Token generation failed", http.StatusInternalServerError)
        return
    }
    
    // Crear sesión
    sessionID, err := h.sessionManager.CreateSession(user.ID, r.RemoteAddr)
    if err != nil {
        http.Error(w, "Session creation failed", http.StatusInternalServerError)
        return
    }
    
    // Responder
    response := map[string]interface{}{
        "access_token":  accessToken,
        "refresh_token": refreshToken,
        "session_id":    sessionID,
        "expires_in":    900, // 15 minutos
    }
    
    json.NewEncoder(w).Encode(response)
}

func (h *AuthHandler) RefreshToken(w http.ResponseWriter, r *http.Request) {
    var req struct {
        RefreshToken string `json:"refresh_token"`
    }
    
    // Validar refresh token
    claims, err := h.jwtManager.ValidateRefreshToken(req.RefreshToken)
    if err != nil {
        http.Error(w, "Invalid refresh token", http.StatusUnauthorized)
        return
    }
    
    // Verificar sesión activa
    if !h.sessionManager.ValidateSession(claims.SessionID) {
        http.Error(w, "Session revoked", http.StatusUnauthorized)
        return
    }
    
    // Generar nuevos tokens
    newAccessToken, newRefreshToken, err := h.jwtManager.GenerateTokens(
        claims.UserID,
        claims.Claims,
    )
    
    // Responder
    // ...
}

func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
    sessionID := r.Header.Get("X-Session-ID")
    
    // Revocar sesión
    h.sessionManager.RevokeSession(sessionID)
    
    // Opcional: Revocar todos los tokens del usuario
    // h.sessionManager.RevokeAllUserSessions(userID)
    
    w.WriteHeader(http.StatusNoContent)
}
```

### 🔐 Middleware de Autenticación

```go
// Middleware para proteger rutas
func AuthMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        authHeader := r.Header.Get("Authorization")
        if authHeader == "" {
            http.Error(w, "Missing authorization header", http.StatusUnauthorized)
            return
        }
        
        tokenString := strings.TrimPrefix(authHeader, "Bearer ")
        
        claims, err := token.ValidateQuickToken(tokenString)
        if err != nil {
            http.Error(w, "Invalid token", http.StatusUnauthorized)
            return
        }
        
        // Agregar claims al contexto
        ctx := context.WithValue(r.Context(), "user_claims", claims)
        next.ServeHTTP(w, r.WithContext(ctx))
    })
}
```

**📖 Ver documentación completa:** [`security/token/README_TOKEN.md`](security/token/README_TOKEN.md)

---

## Middleware

Middlewares HTTP para autenticación, CORS, logging, rate limiting y más. Compatible con net/http, Gin y Fiber.

### 🚀 Inicio Rápido

```go
package main

import (
    "github.com/juanmdev/gokit/security/middleware"
    "github.com/gin-gonic/gin"
)

func main() {
    // Inicializar middlewares
    middleware.Init(middleware.Config{
        EnableAuth:      true,
        EnableCORS:      true,
        EnableLogging:   true,
        EnableRateLimit: true,
        RateLimit:       100, // requests/minuto
    })
    
    // Usar con Gin
    r := gin.Default()
    
    // Aplicar middlewares globales
    r.Use(middleware.Logger())
    r.Use(middleware.CORS())
    r.Use(middleware.RateLimit(100))
    
    // Rutas protegidas
    protected := r.Group("/")
    protected.Use(middleware.Auth())
    {
        protected.GET("/users", getUsers)
        protected.POST("/users", createUser)
    }
    
    r.Run(":8080")
}
```

### 🛡️ Middlewares Disponibles

| Middleware | Función | Frameworks |
|------------|---------|------------|
| **Auth** | Validación JWT | net/http, Gin, Fiber |
| **CORS** | Control de origen cruzado | net/http, Gin, Fiber |
| **Logging** | Log de peticiones | net/http, Gin, Fiber |
| **RateLimit** | Limitación de tasa | net/http, Gin, Fiber |
| **Chain** | Combinar múltiples | Todos |

### ⚙️ Configuración Detallada

```go
// Configurar autenticación
authConfig := middleware.AuthConfig{
    SecretKey:      "jwt-secret-key",
    TokenLocation:  "header", // header, cookie, query
    CookieName:     "auth_token",
    QueryParam:     "token",
    SkipPaths:      []string{"/health", "/public"},
    ErrorHandler: func(c middleware.Context, err error) {
        c.JSON(401, map[string]string{"error": "Unauthorized"})
    },
}

authMW := middleware.NewAuthMiddleware(authConfig)

// Configurar CORS
corsConfig := middleware.CORSConfig{
    AllowOrigins:     []string{"https://example.com"},
    AllowMethods:     []string{"GET", "POST", "PUT", "DELETE"},
    AllowHeaders:     []string{"Authorization", "Content-Type"},
    AllowCredentials: true,
    MaxAge:           3600,
}

corsMW := middleware.NewCORS(corsConfig)

// Configurar Rate Limiting
rateConfig := middleware.RateLimitConfig{
    RequestsPerMinute: 100,
    BurstSize:         20,
    ByIP:              true,
    ByUser:            true,
    SkipPaths:         []string{"/health"},
}

rateMW := middleware.NewRateLimit(rateConfig)
```

### 📝 Ejemplo: API REST Completa

```go
package main

import (
    "github.com/juanmdev/gokit/security/middleware"
    "github.com/gin-gonic/gin"
    "net/http"
)

func main() {
    r := gin.New()
    
    // Middlewares globales
    r.Use(middleware.Logger())
    r.Use(middleware.Recovery())
    r.Use(middleware.CORS())
    
    // Health check (público)
    r.GET("/health", func(c *gin.Context) {
        c.JSON(200, gin.H{"status": "ok"})
    })
    
    // Grupo público
    public := r.Group("/api/v1")
    {
        public.POST("/auth/login", loginHandler)
        public.POST("/auth/register", registerHandler)
    }
    
    // Grupo protegido
    protected := r.Group("/api/v1")
    protected.Use(middleware.Auth())
    {
        // Usuarios
        protected.GET("/users", getUsers)
        protected.GET("/users/:id", getUserByID)
        protected.POST("/users", createUser)
        protected.PUT("/users/:id", updateUser)
        protected.DELETE("/users/:id", deleteUser)
        
        // Productos (con rate limit adicional)
        products := protected.Group("/products")
        products.Use(middleware.RateLimit(50))
        {
            products.GET("", getProducts)
            products.POST("", createProduct)
        }
    }
    
    // Admin (solo roles específicos)
    admin := r.Group("/admin")
    admin.Use(middleware.Auth())
    admin.Use(middleware.RequireRole("admin"))
    {
        admin.GET("/stats", getStats)
        admin.GET("/audit", getAuditLogs)
    }
    
    r.Run(":8080")
}

// Handlers
func loginHandler(c *gin.Context) {
    // Implementar login
    c.JSON(http.StatusOK, gin.H{"token": "..."})
}

func getUsers(c *gin.Context) {
    // Extraer usuario del contexto
    userID := middleware.GetUserID(c)
    role := middleware.GetUserRole(c)
    
    c.JSON(http.StatusOK, gin.H{
        "users": []string{},
        "requested_by": userID,
    })
}
```

### 🔗 Chain Middleware

```go
// Combinar múltiples middlewares
chain := middleware.NewChain(
    middleware.Logger(),
    middleware.CORS(),
    middleware.RateLimit(100),
    middleware.Auth(),
)

// Usar chain
r := gin.New()
r.Use(chain.Then())

// O para rutas específicas
r.GET("/protected", chain.ThenFunc(protectedHandler))
```

### 🎯 Context Helpers

```go
// Extraer información del contexto
userID := middleware.GetUserID(c)           // string
userRole := middleware.GetUserRole(c)       // string
userEmail := middleware.GetUserEmail(c)     // string
claims := middleware.GetClaims(c)           // token.Claims
sessionID := middleware.GetSessionID(c)     // string

// Verificar permisos
if middleware.HasRole(c, "admin") {
    // Es admin
}

if middleware.HasPermission(c, "users:write") {
    // Tiene permiso de escritura
}
```

**📖 Ver documentación completa:** [`security/middleware/README_MIDDLEWARE.md`](security/middleware/README_MIDDLEWARE.md)

---

## Audit

Sistema de auditoría forense con IA para detección de amenazas, registro completo de eventos y cumplimiento normativo.

### 🚀 Inicio Rápido

```go
package main

import "github.com/juanmdev/gokit/security/audit"

func main() {
    // Inicializar auditoría
    audit.Init(audit.Config{
        StorageType: "memory", // memory, sqlite, postgres
        EnableIA:    true,
        RetentionDays: 90,
    })
    
    // Registrar evento manualmente
    event := audit.CreateEvent(
        audit.EventTypeAuth,
        "user-123",
        "LOGIN",
        "auth_system",
    ).WithIP("192.168.1.100").
      WithUserAgent("Mozilla/5.0...").
      WithSession("sess-abc123").
      WithRole("admin").
      WithEmail("admin@example.com")
    
    audit.RecordQuick(event)
    
    // La IA detecta automáticamente amenazas
    
    // Consultar eventos
    events, _ := audit.QueryQuick(audit.QueryFilter{
        EventTypes: []audit.EventType{audit.EventTypeAuth},
        StartTime:  time.Now().Add(-24 * time.Hour),
        Limit:      100,
    })
    
    // Exportar logs
    data, _ := audit.ExportQuick(audit.ExportJSON, audit.QueryFilter{})
}
```

### 🤖 Detección de Amenazas con IA

El motor de IA detecta automáticamente:

| Amenaza | Descripción | Score Típico |
|---------|-------------|--------------|
| **Fuerza Bruta** | 5+ intentos fallidos en 5 min | 0.7-0.9 |
| **SQL Injection** | Patrones SQLi en payload | 0.8-1.0 |
| **XSS** | Scripts maliciosos | 0.7-0.9 |
| **Scraping** | 100+ req/min desde misma IP | 0.5-0.7 |
| **Viaje Imposible** | Logins desde países diferentes en poco tiempo | 0.8-1.0 |
| **DDoS** | 1000+ req/seg | 0.9-1.0 |
| **Anomalías** | Comportamiento fuera de patrón | 0.4-0.6 |
| **IPs Maliciosas** | Tor, Proxy, VPN conocidas | 0.6-0.8 |

### ⚙️ Configuración Avanzada

```go
// Configuración completa para producción
config := audit.Config{
    StorageType:      "postgres",
    ConnectionString: "postgres://user:pass@localhost:5432/audit?sslmode=require",
    EnableIA:         true,
    AsyncProcessing:  true,
    BufferSize:       1000,
    RetentionDays:    365,
    EnableEncryption: true,
    LogLevel:         "info",
}

auditor, err := audit.NewAuditor(config)
if err != nil {
    log.Fatal(err)
}

// Registrar evento completo
event := &audit.Event{
    Type: audit.EventTypeSecurity,
    Actor: audit.ActorInfo{
        ID:        "user-456",
        Type:      "user",
        Email:     "user@example.com",
        Role:      "admin",
        SessionID: "sess-xyz789",
        Metadata: map[string]string{
            "department": "IT",
            "location":   "HQ",
        },
    },
    Action: audit.ActionInfo{
        Type:       "PASSWORD_CHANGE",
        Category:   "SECURITY",
        Resource:   "user_account",
        ResourceID: "user-456",
        Method:     "POST",
        Path:       "/api/v1/auth/password",
        Metadata: map[string]string{
            "old_hash": "xxx...",
            "new_hash": "yyy...",
        },
    },
    Context: audit.ContextInfo{
        IPAddress: "203.0.113.50",
        UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64)...",
        GeoLocation: &audit.GeoLocation{
            Country:   "US",
            City:      "New York",
            Latitude:  40.7128,
            Longitude: -74.0060,
            Timezone:  "America/New_York",
        },
        DeviceID:   "device-abc123",
        Timestamp:  time.Now().UTC(),
        Duration:   250 * time.Millisecond,
        StatusCode: 200,
        Headers: map[string]string{
            "X-Forwarded-For": "203.0.113.50",
            "X-Real-IP":       "203.0.113.50",
        },
        Payload:   `{"old_password":"***","new_password":"***"}`,
        RequestID: "req-unique-id",
    },
}

err = auditor.Record(event)
```

### 🔍 Consultas Forenses

```go
// Filtrar por múltiples criterios
filter := audit.QueryFilter{
    EventTypes:  []audit.EventType{audit.EventTypeSecurity, audit.EventTypeAuth},
    ActorIDs:    []string{"user-123", "user-456"},
    IPAddresses: []string{"192.168.1.100"},
    StartTime:   time.Now().Add(-7 * 24 * time.Hour),
    EndTime:     time.Now(),
    RiskLevels:  []audit.RiskLevel{audit.RiskHigh, audit.RiskCritical},
    Limit:       1000,
    OrderBy:     "timestamp",
    OrderDesc:   true,
}

events, err := auditor.Query(filter)

// Buscar eventos con amenazas detectadas
threatFilter := audit.QueryFilter{
    ThreatDetected: boolPtr(true),
    StartTime:      time.Now().Add(-24 * time.Hour),
}

threats, _ := auditor.Query(threatFilter)

// Estadísticas en tiempo real
stats := auditor.GetStats()
fmt.Printf("Total eventos: %d\n", stats.TotalEvents)
fmt.Printf("Amenazas detectadas: %d\n", stats.ThreatsDetected)
```

### 📤 Exportación de Logs

```go
// Exportar a JSON
jsonData, _ := auditor.Export(audit.ExportJSON, filter)

// Exportar a CSV (para Excel)
csvData, _ := auditor.Export(audit.ExportCSV, filter)

// Exportar a NDJSON (para Elasticsearch/Logstash)
ndjsonData, _ := auditor.Export(audit.ExportNDJSON, filter)

// Guardar en archivo
os.WriteFile("audit_export.json", jsonData, 0644)
```

### 📝 Ejemplo: Middleware de Auditoría Automática

```go
// Middleware que audita todas las peticiones HTTP
func AuditMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        start := time.Now()
        
        // Capturar respuesta
        rw := &responseWriter{ResponseWriter: w, statusCode: 200}
        
        // Llamar al siguiente handler
        next.ServeHTTP(rw, r)
        
        duration := time.Since(start)
        
        // Extraer información del contexto
        userID := middleware.GetUserID(r.Context())
        sessionID := middleware.GetSessionID(r.Context())
        
        // Crear evento de auditoría
        event := audit.CreateEvent(
            audit.EventTypeAccess,
            userID,
            r.Method,
            r.URL.Path,
        ).WithIP(getRealIP(r)).
          WithUserAgent(r.UserAgent()).
          WithSession(sessionID).
          WithStatusCode(rw.statusCode).
          WithDuration(duration).
          WithMetadata("request_id", getRequestID(r))
        
        // Registrar asíncronamente
        audit.RecordQuick(event)
    })
}

// Uso en router
r := gin.New()
r.Use(AuditMiddleware)
```

### 🎯 Casos de Uso Reales

#### 1. Investigación de Incidente de Seguridad

```go
// Investigar intento de acceso no autorizado
func investigateIncident(suspiciousIP string) {
    filter := audit.QueryFilter{
        IPAddresses: []string{suspiciousIP},
        StartTime:   time.Now().Add(-24 * time.Hour),
        EventTypes:  []audit.EventType{audit.EventTypeAuth, audit.EventTypeSecurity},
        Limit:       10000,
    }
    
    events, _ := audit.GetDefaultAuditor().Query(filter)
    
    // Analizar patrón de ataque
    var failedLogins int
    var targetedUsers []string
    
    for _, event := range events {
        if event.Context.StatusCode == 401 {
            failedLogins++
            targetedUsers = append(targetedUsers, event.Actor.ID)
        }
    }
    
    if failedLogins > 5 {
        logger.Warn("Possible brute force attack detected",
            "ip", suspiciousIP,
            "failed_attempts", failedLogins,
            "targeted_users", len(targetedUsers))
        
        // Bloquear IP temporalmente
        // blockIP(suspiciousIP)
    }
}
```

#### 2. Cumplimiento GDPR

```go
// Exportar todos los datos de un usuario para GDPR
func exportUserData(userID string) ([]byte, error) {
    filter := audit.QueryFilter{
        ActorIDs: []string{userID},
        StartTime: time.Now().AddDate(-1, 0, 0), // Último año
        Limit:     100000,
    }
    
    return audit.GetDefaultAuditor().Export(audit.ExportJSON, filter)
}

// Eliminar datos de usuario (Right to be Forgotten)
func deleteUserData(userID string) error {
    // Nota: En producción, esto debería ser soft-delete para mantener integridad forense
    filter := audit.QueryFilter{
        ActorIDs: []string{userID},
        Limit:    100000,
    }
    
    events, err := audit.GetDefaultAuditor().Query(filter)
    if err != nil {
        return err
    }
    
    // Anonimizar datos personales
    for _, event := range events {
        event.Actor.Email = "[REDACTED]"
        event.Actor.Metadata["ip_sanitized"] = true
        // Actualizar evento anonimizado
        // auditor.Update(event)
    }
    
    return nil
}
```

#### 3. Dashboard de Monitoreo en Tiempo Real

```go
// Obtener métricas para dashboard
func getDashboardMetrics() map[string]interface{} {
    stats := audit.GetStatsQuick()
    
    // Eventos por hora (últimas 24h)
    hourlyEvents := make(map[string]int64)
    for i := 0; i < 24; i++ {
        hour := time.Now().Add(time.Duration(-i) * time.Hour).Format("2006-01-02 15:00")
        filter := audit.QueryFilter{
            StartTime: time.Now().Add(time.Duration(-(i+1)) * time.Hour),
            EndTime:   time.Now().Add(time.Duration(-i) * time.Hour),
            Limit:     10000,
        }
        events, _ := audit.QueryQuick(filter)
        hourlyEvents[hour] = int64(len(events))
    }
    
    return map[string]interface{}{
        "total_events":      stats.TotalEvents,
        "threats_detected":  stats.ThreatsDetected,
        "events_by_type":    stats.EventsByType,
        "risk_distribution": stats.RiskDistribution,
        "hourly_events":     hourlyEvents,
        "last_updated":      stats.LastUpdated,
    }
}
```

### 🔐 Mejores Prácticas

1. **Almacenamiento**: Usar PostgreSQL en producción con particionamiento por fecha
2. **Retención**: Configurar políticas automáticas (90 días mínimo, 7 años para compliance)
3. **Cifrado**: Habilitar cifrado en reposo para datos sensibles
4. **Acceso**: Restringir acceso a logs de auditoría solo a administradores
5. **Backup**: Realizar backups diarios con retención a largo plazo
6. **Monitoreo**: Alertar automáticamente sobre eventos de riesgo crítico
7. **Inmutabilidad**: Los registros nunca deben modificarse, solo anonimizarse si es requerido

**📖 Ver documentación completa:** [`security/audit/README_AUDIT.md`](security/audit/README_AUDIT.md)

---

## Ejemplos Reales

### 🏗️ Arquitectura de Microservicios

```go
// main.go - Servicio de Usuarios
package main

import (
    "github.com/juanmdev/gokit/logger"
    "github.com/juanmdev/gokit/security/crypto"
    "github.com/juanmdev/gokit/security/token"
    "github.com/juanmdev/gokit/security/middleware"
    "github.com/juanmdev/gokit/security/audit"
    "github.com/gin-gonic/gin"
)

func main() {
    // Inicializar logger
    logger.Init(logger.Config{
        Level:   logger.InfoLevel,
        Format:  logger.JSONFormat,
        Output:  logger.OutputBoth,
    })
    
    // Inicializar auditoría
    audit.Init(audit.Config{
        StorageType:     "postgres",
        ConnectionString: getEnv("DATABASE_URL"),
        EnableIA:        true,
        RetentionDays:   365,
    })
    
    // Configurar JWT
    token.Init(token.JWTConfig{
        SecretKey:       getEnv("JWT_SECRET"),
        AccessDuration:  15 * time.Minute,
        RefreshDuration: 7 * 24 * time.Hour,
    })
    
    // Inicializar middlewares
    middleware.Init(middleware.Config{
        EnableAuth:      true,
        EnableCORS:      true,
        EnableLogging:   true,
        EnableRateLimit: true,
        RateLimit:       100,
    })
    
    // Crear router
    r := gin.New()
    
    // Middlewares globales
    r.Use(middleware.Logger())
    r.Use(middleware.CORS())
    r.Use(middleware.RateLimit(100))
    
    // Health check
    r.GET("/health", healthHandler)
    
    // Rutas públicas
    public := r.Group("/api/v1")
    {
        public.POST("/auth/register", registerHandler)
        public.POST("/auth/login", loginHandler)
        public.POST("/auth/refresh", refreshHandler)
    }
    
    // Rutas protegidas
    protected := r.Group("/api/v1")
    protected.Use(middleware.Auth())
    {
        protected.GET("/users/me", getMeHandler)
        protected.PUT("/users/me", updateMeHandler)
        protected.POST("/users/change-password", changePasswordHandler)
    }
    
    // Admin
    admin := r.Group("/admin")
    admin.Use(middleware.Auth())
    admin.Use(middleware.RequireRole("admin"))
    {
        admin.GET("/users", listUsersHandler)
        admin.GET("/audit/logs", auditLogsHandler)
        admin.GET("/stats", statsHandler)
    }
    
    logger.Info("Server starting on :8080")
    r.Run(":8080")
}

// Handlers
func registerHandler(c *gin.Context) {
    var req struct {
        Email    string `json:"email"`
        Password string `json:"password"`
    }
    
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(400, gin.H{"error": "Invalid request"})
        return
    }
    
    // Hashear contraseña
    hash, err := crypto.HashPassword(req.Password)
    if err != nil {
        logger.Error("Failed to hash password", "error", err)
        c.JSON(500, gin.H{"error": "Internal error"})
        return
    }
    
    // Guardar usuario en DB
    // user := db.CreateUser(req.Email, hash)
    
    // Auditar registro
    event := audit.CreateEvent(
        audit.EventTypeAuth,
        "user-new",
        "REGISTER",
        "auth_system",
    ).WithIP(c.ClientIP()).
      WithUserAgent(c.Request.UserAgent()).
      WithEmail(req.Email).
      WithStatusCode(201)
    
    audit.RecordQuick(event)
    
    c.JSON(201, gin.H{"message": "User created"})
}

func loginHandler(c *gin.Context) {
    var req struct {
        Email    string `json:"email"`
        Password string `json:"password"`
    }
    
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(400, gin.H{"error": "Invalid request"})
        return
    }
    
    // Obtener usuario de DB
    // user := db.GetUserByEmail(req.Email)
    
    // Verificar contraseña
    // valid := crypto.VerifyPassword(req.Password, user.PasswordHash)
    
    // Generar tokens
    accessToken, refreshToken, _ := token.GenerateQuickToken(
        "user-id",
        "user",
    )
    
    // Crear sesión
    sessionID, _ := token.CreateQuickSession("user-id")
    
    // Auditar login
    event := audit.CreateEvent(
        audit.EventTypeAuth,
        "user-id",
        "LOGIN",
        "auth_system",
    ).WithIP(c.ClientIP()).
      WithUserAgent(c.Request.UserAgent()).
      WithSession(sessionID).
      WithStatusCode(200)
    
    audit.RecordQuick(event)
    
    c.JSON(200, gin.H{
        "access_token":  accessToken,
        "refresh_token": refreshToken,
        "session_id":    sessionID,
    })
}
```

---

## Mejores Prácticas

### 🔒 Seguridad

1. **Contraseñas**: Usar Argon2id con parámetros adecuados (memory: 64MB, iterations: 3)
2. **JWT**: Secrets de al menos 32 bytes, rotación cada 90 días
3. **HTTPS**: Siempre usar TLS en producción
4. **Rate Limiting**: Proteger endpoints sensibles (login, registro)
5. **Auditoría**: Habilitar logging de todos los eventos críticos

### ⚡ Performance

1. **Async Processing**: Usar procesamiento asíncrono para auditoría
2. **Buffering**: Configurar buffers adecuados según carga esperada
3. **Connection Pooling**: Usar pools de conexiones para DB
4. **Caching**: Cachear tokens validados recientemente

### 🧪 Testing

1. **Unit Tests**: Cobertura mínima del 80%
2. **Integration Tests**: Probar flujos completos
3. **Load Tests**: Validar bajo carga esperada
4. **Security Tests**: Penetration testing regular

### 📊 Monitoreo

1. **Metrics**: Exportar métricas a Prometheus
2. **Alerts**: Configurar alertas para eventos críticos
3. **Dashboards**: Visualizar KPIs de seguridad
4. **Logs**: Centralizar logs en ELK/Loki

---

## 🤝 Contribución

Las contribuciones son bienvenidas. Por favor:

1. Fork el repositorio
2. Crear rama de feature (`git checkout -b feature/amazing-feature`)
3. Commit cambios (`git commit -m 'Add amazing feature'`)
4. Push a la rama (`git push origin feature/amazing-feature`)
5. Abrir Pull Request

## 📄 Licencia

Distribuido bajo la licencia MIT. Ver `LICENSE` para más información.

## 👨‍💻 Autor

**Juan Manuel Dev** - [GitHub](https://github.com/juanmdev)

---

**Hecho con ❤️ usando Go**
