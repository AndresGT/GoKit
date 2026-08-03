# Módulo de Auditoría con IA - GoKit

## 📋 Descripción

El módulo de auditoría es un sistema completo y profesional para registro, monitoreo y análisis forense de eventos en aplicaciones Go. Incorpora inteligencia artificial para detección automática de amenazas y comportamientos anómalos.

### Características Principales

✅ **Recolección Completa de Datos**
- Información completa del actor (ID, email, rol, sesión)
- Contexto detallado (IP, geolocalización, User-Agent, dispositivo)
- Metadatos de la acción (método HTTP, ruta, payload)
- Huella digital inmutable para cada evento
- Soporte para distributed tracing (TraceID, SpanID)

✅ **Motor de IA Integrado**
- Detección de fuerza bruta
- SQL Injection detection
- Cross-Site Scripting (XSS)
- Web Scraping detection
- Viajes imposibles (Impossible Travel)
- Ataques DDoS
- Anomalías de comportamiento
- IPs maliciosas (Tor, Proxy, VPN)

✅ **Almacenamiento Flexible**
- Memoria RAM (ideal para tests)
- SQLite (desarrollo/producción ligera)
- PostgreSQL (producción enterprise)

✅ **Seguridad Forense**
- Cifrado en reposo opcional
- Inmutabilidad de registros
- Huellas digitales criptográficas
- Sanitización de PII (Información Personal Identificable)
- Cadena de custodia

✅ **Búsqueda y Análisis**
- Filtros avanzados multi-campo
- Búsqueda full-text
- Paginación eficiente
- Exportación a JSON, CSV, NDJSON
- Compresión GZIP opcional

✅ **Integración Completa**
- Middleware automático para HTTP
- Integración con logger existente
- Conexión con módulos de token y crypto
- API dual (rápida y configurable)

---

## 🚀 Inicio Rápido

### Instalación

```bash
go get github.com/AndresGT/GoKit/security/audit
```

### Uso Básico (Quick Start)

```go
package main

import (
    "context"
    "github.com/AndresGT/GoKit/security/audit"
)

func main() {
    // Inicializar con configuración por defecto
    err := audit.Init(audit.Config{
        StorageType: "memory", // o "sqlite", "postgres"
        EnableIA:    true,
    })
    if err != nil {
        panic(err)
    }

    // Registrar evento rápidamente
    event := &audit.Event{
        Actor: audit.ActorInfo{
            ID:   "user-123",
            Type: "user",
        },
        Action: audit.ActionInfo{
            Type:     "LOGIN",
            Category: "AUTH",
        },
        Result: audit.ResultInfo{
            Status: "SUCCESS",
        },
        Context: audit.ContextInfo{
            IPAddress: "192.168.1.100",
        },
    }

    err = audit.RecordQuick(event)
    if err != nil {
        panic(err)
    }

    // Consultar eventos
    ctx := context.Background()
    events, _ := audit.QueryQuick(ctx, audit.QueryFilter{
        ActorIDs: []string{"user-123"},
        Limit:    10,
    })

    println("Eventos encontrados:", len(events))
}
```

---

## ⚙️ Configuración Avanzada

### Configuración Completa

```go
config := audit.Config{
    // Tipo de almacenamiento
    StorageType: "postgres",
    StorageConfig: audit.PostgresConfig{
        DSN:          "postgres://user:pass@localhost:5432/auditdb?sslmode=disable",
        MaxOpenConns: 25,
        MaxIdleConns: 5,
        MaxLifetime:  300,
    },
    
    // Motor de IA
    EnableIA:           true,
    IAMinRiskThreshold: 0.7, // Threshold para alertas (0-1)
    
    // Procesamiento asíncrono
    EnableAsync:     true,
    AsyncBufferSize: 1000,
    
    // Política de retención
    Retention: audit.RetentionPolicy{
        MaxAgeDays:        90,  // Retener por 90 días
        MaxEvents:         1000000, // Máximo 1M de eventos
        CompressAfterDays: 7,   // Comprimir después de 7 días
        EnableAutoDelete:  true,
    },
    
    // Seguridad
    EnableEncryption: true,
    EncryptionKey:    "your-secret-key-here",
    SanitizePII:      true, // Enmascarar emails e IPs
    
    // Payloads
    IncludePayload: true,
    MaxPayloadSize: 1024 * 1024, // 1MB máximo
    
    LogLevel: "info",
}

auditor, err := audit.NewAuditor(config)
if err != nil {
    log.Fatal(err)
}
defer auditor.Close()
```

### Configuración para SQLite

```go
config := audit.Config{
    StorageType: "sqlite",
    StorageConfig: audit.SQLiteConfig{
        DSN:          "./data/audit.db",
        MaxOpenConns: 1, // SQLite no soporta múltiples writers
        MaxIdleConns: 1,
    },
    EnableIA: true,
}
```

---

## 📖 API Reference

### Estructura de Evento

```go
type Event struct {
    ID                 string                 `json:"id"`
    Timestamp          time.Time              `json:"timestamp"`
    Actor              ActorInfo              `json:"actor"`
    Action             ActionInfo             `json:"action"`
    Resource           ResourceInfo           `json:"resource"`
    Result             ResultInfo             `json:"result"`
    Context            ContextInfo            `json:"context"`
    Metadata           map[string]interface{} `json:"metadata,omitempty"`
    RiskScore          float64                `json:"risk_score"`
    Threats            []ThreatDetection      `json:"threats,omitempty"`
    DigitalFingerprint string                 `json:"digital_fingerprint"`
}
```

### ActorInfo - Información del Actor

```go
type ActorInfo struct {
    ID        string `json:"id,omitempty"`         // ID único del usuario
    Email     string `json:"email,omitempty"`      // Email (sanitizado si está habilitado)
    Username  string `json:"username,omitempty"`   // Nombre de usuario
    Role      string `json:"role,omitempty"`       // Rol/Permiso
    SessionID string `json:"session_id,omitempty"` // ID de sesión activa
    Type      string `json:"type"`                 // user, system, api, anonymous
}
```

### ContextInfo - Contexto Completo

```go
type ContextInfo struct {
    IPAddress      string            `json:"ip_address"`
    IPGeoLocation  GeoLocation       `json:"ip_geo_location"`
    UserAgent      string            `json:"user_agent"`
    ClientInfo     ClientInfo        `json:"client_info"`
    Referer        string            `json:"referer,omitempty"`
    ForwardedFor   string            `json:"forwarded_for,omitempty"`
    RequestID      string            `json:"request_id"`
    TraceID        string            `json:"trace_id,omitempty"`
    SpanID         string            `json:"span_id,omitempty"`
    Headers        map[string]string `json:"headers,omitempty"`
    PayloadSize    int64             `json:"payload_size,omitempty"`
    PayloadHash    string            `json:"payload_hash,omitempty"`
    TLSVersion     string            `json:"tls_version,omitempty"`
    ServerPort     int               `json:"server_port,omitempty"`
}
```

### ThreatDetection - Amenazas Detectadas

```go
type ThreatDetection struct {
    Type         string   `json:"type"`                // BRUTE_FORCE, SQL_INJECTION, etc.
    Severity     string   `json:"severity"`            // LOW, MEDIUM, HIGH, CRITICAL
    Confidence   float64  `json:"confidence"`          // 0-1
    Description  string   `json:"description"`
    Evidence     []string `json:"evidence"`
    RuleID       string   `json:"rule_id"`
    Pattern      string   `json:"pattern,omitempty"`
    Recommendation string `json:"recommendation"`
}
```

---

## 🔍 Tipos de Amenazas Detectadas

| Tipo | Severidad | Descripción | Ejemplo |
|------|-----------|-------------|---------|
| `BRUTE_FORCE` | HIGH | Múltiples intentos fallidos consecutivos | 5+ logins fallidos en 5 min |
| `SQL_INJECTION` | CRITICAL | Patrones de inyección SQL detectados | `' OR '1'='1` |
| `XSS` | HIGH | Scripts maliciosos en payloads | `<script>alert(1)</script>` |
| `SCRAPING` | MEDIUM | Comportamiento automatizado de extracción | 100+ requests/min |
| `IMPOSSIBLE_TRAVEL` | CRITICAL | Logins desde ubicaciones imposibles | NYC → Tokyo en 10 min |
| `DDOS` | CRITICAL | Volumen anormal de peticiones | 1000+ req/seg desde misma IP |
| `ANOMALY` | MEDIUM | Comportamiento fuera del patrón normal | Acción nunca antes realizada |
| `MALICIOUS_IP` | HIGH | IP con reputación negativa | Tor exit node, proxy conocido |

---

## 💡 Ejemplos de Uso

### Ejemplo 1: Auditoría de Autenticación

```go
// Registrar intento de login
loginEvent := &audit.Event{
    Actor: audit.ActorInfo{
        ID:       userID,
        Email:    userEmail,
        Username: username,
        Type:     "user",
    },
    Action: audit.ActionInfo{
        Type:        "LOGIN",
        Category:    "AUTH",
        Description: "User login attempt",
        Method:      "POST",
        Path:        "/api/v1/auth/login",
    },
    Resource: audit.ResourceInfo{
        Type: "auth",
    },
    Result: audit.ResultInfo{
        Status:     status, // SUCCESS or FAILURE
        StatusCode: httpStatus,
        Message:    message,
        Duration:   duration.Milliseconds(),
    },
    Context: audit.ContextInfo{
        IPAddress:   clientIP,
        UserAgent:   userAgent,
        RequestID:   requestID,
    },
    Metadata: map[string]interface{}{
        "mfa_used":      mfaEnabled,
        "login_method":  "password", // o "oauth", "sso"
        "device_trusted": isTrustedDevice,
    },
}

err := audit.RecordQuick(loginEvent)
```

### Ejemplo 2: Auditoría de Cambios de Datos

```go
// Registrar actualización de perfil
updateEvent := &audit.Event{
    Actor: audit.ActorInfo{
        ID:   currentUser.ID,
        Role: currentUser.Role,
        Type: "user",
    },
    Action: audit.ActionInfo{
        Type:        "UPDATE",
        Category:    "DATA",
        Description: "User profile updated",
        Method:      "PUT",
        Path:        "/api/v1/users/profile",
    },
    Resource: audit.ResourceInfo{
        Type:       "user",
        ID:         currentUser.ID,
        Name:       currentUser.Username,
        Collection: "users",
    },
    Result: audit.ResultInfo{
        Status:       "SUCCESS",
        StatusCode:   200,
        ChangesCount: changesCount,
        Duration:     duration.Milliseconds(),
    },
    Context: audit.ContextInfo{
        IPAddress: clientIP,
        RequestID: requestID,
    },
    Metadata: map[string]interface{}{
        "changed_fields": []string{"email", "phone"},
        "old_values":     oldValues,
        "new_values":     newValues,
        "ip_changed":     ipChanged,
    },
}

err := auditor.Record(updateEvent)
```

### Ejemplo 3: Consulta Forense Avanzada

```go
ctx := context.Background()

// Buscar todos los intentos fallidos de un usuario en las últimas 24 horas
filter := audit.QueryFilter{
    ActorIDs:    []string{"user-123"},
    ActionTypes: []string{"LOGIN"},
    Statuses:    []string{"FAILURE"},
    StartTime:   time.Now().Add(-24 * time.Hour),
    EndTime:     time.Now(),
    MinRiskScore: 0.5,
    Limit:       100,
    SortBy:      "timestamp",
    SortOrder:   "desc",
}

events, err := auditor.Query(ctx, filter)
if err != nil {
    log.Fatal(err)
}

// Analizar patrones
for _, event := range events {
    if len(event.Threats) > 0 {
        for _, threat := range event.Threats {
            log.Printf("Amenaza detectada: %s (Severidad: %s)", 
                threat.Type, threat.Severity)
        }
    }
}
```

### Ejemplo 4: Exportación de Logs para Auditoría Externa

```go
// Exportar logs del último mes para compliance
filter := audit.QueryFilter{
    StartTime: time.Now().AddDate(0, -1, 0),
    EndTime:   time.Now(),
    Limit:     10000,
}

// Exportar a JSON
var jsonBuf bytes.Buffer
err := auditor.Export(ctx, filter, audit.ExportFormatJSON, &jsonBuf)

// Exportar a CSV para Excel
var csvBuf bytes.Buffer
err := auditor.Export(ctx, filter, audit.ExportFormatCSV, &csvBuf)

// Guardar en archivo
os.WriteFile("audit_logs_2024_01.json", jsonBuf.Bytes(), 0644)
os.WriteFile("audit_logs_2024_01.csv", csvBuf.Bytes(), 0644)
```

### Ejemplo 5: Integración con Middleware HTTP

```go
// Middleware que audita automáticamente todas las peticiones
func AuditMiddleware(auditor *audit.Auditor) gin.HandlerFunc {
    return func(c *gin.Context) {
        start := time.Now()
        
        // Procesar petición
        c.Next()
        
        duration := time.Since(start)
        
        // Crear evento de auditoría
        event := &audit.Event{
            Timestamp: start,
            Actor: audit.ActorInfo{
                ID:   getUserID(c),
                Type: getActorType(c),
            },
            Action: audit.ActionInfo{
                Type:     c.Request.Method,
                Category: "HTTP",
                Method:   c.Request.Method,
                Path:     c.Request.URL.Path,
            },
            Result: audit.ResultInfo{
                Status:     getStatus(c.Writer.Status()),
                StatusCode: c.Writer.Status(),
                Duration:   duration.Milliseconds(),
            },
            Context: audit.ContextInfo{
                IPAddress: c.ClientIP(),
                UserAgent: c.Request.UserAgent(),
                RequestID: c.GetString("request_id"),
                Headers:   extractHeaders(c.Request),
            },
        }
        
        // Registrar asíncronamente para no bloquear
        auditor.RecordAsync(event)
    }
}
```

---

## 🧪 Pruebas Unitarias

### Ejecutar Tests

```bash
cd security/audit
go test -v -coverprofile=coverage.out ./...
go tool cover -html=coverage.out -o coverage.html
```

### Test de Detección de Fuerza Bruta

```go
func TestBruteForceDetection(t *testing.T) {
    auditor, _ := audit.NewAuditor(audit.Config{
        StorageType: "memory",
        EnableIA:    true,
    })
    defer auditor.Close()

    // Simular 5 intentos fallidos
    for i := 0; i < 5; i++ {
        event := &audit.Event{
            Actor: audit.ActorInfo{ID: "attacker", Type: "user"},
            Action: audit.ActionInfo{Type: "LOGIN", Category: "AUTH"},
            Result: audit.ResultInfo{Status: "FAILURE"},
            Context: audit.ContextInfo{IPAddress: "10.0.0.50"},
            Metadata: map[string]interface{}{
                "failed_attempts": i + 1,
            },
        }
        auditor.Record(event)
    }

    stats := auditor.GetStats()
    t.Logf("Amenazas detectadas: %d", stats.ThreatsDetected)
}
```

### Test de Viaje Imposible

```go
func TestImpossibleTravelDetection(t *testing.T) {
    auditor, _ := audit.NewAuditor(audit.Config{
        StorageType: "memory",
        EnableIA:    true,
    })
    defer auditor.Close()

    // Login desde USA
    auditor.Record(&audit.Event{
        Actor: audit.ActorInfo{ID: "traveler", Type: "user"},
        Action: audit.ActionInfo{Type: "LOGIN", Category: "AUTH"},
        Result: audit.ResultInfo{Status: "SUCCESS"},
        Context: audit.ContextInfo{
            IPAddress: "8.8.8.8",
            IPGeoLocation: audit.GeoLocation{
                Country:     "United States",
                CountryCode: "US",
            },
        },
    })

    // Login desde Japón 10 minutos después
    auditor.Record(&audit.Event{
        Actor: audit.ActorInfo{ID: "traveler", Type: "user"},
        Action: audit.ActionInfo{Type: "LOGIN", Category: "AUTH"},
        Result: audit.ResultInfo{Status: "SUCCESS"},
        Context: audit.ContextInfo{
            IPAddress: "1.1.1.1",
            IPGeoLocation: audit.GeoLocation{
                Country:     "Japan",
                CountryCode: "JP",
            },
        },
    })

    stats := auditor.GetStats()
    t.Logf("Viaje imposible detectado: %d amenazas", stats.ThreatsDetected)
}
```

### Test de SQL Injection

```go
func TestSQLInjectionDetection(t *testing.T) {
    auditor, _ := audit.NewAuditor(audit.Config{
        StorageType: "memory",
        EnableIA:    true,
    })
    defer auditor.Close()

    maliciousPayload := "admin' OR '1'='1' --"
    
    event := &audit.Event{
        Actor: audit.ActorInfo{ID: "attacker", Type: "user"},
        Action: audit.ActionInfo{Type: "QUERY", Category: "DATA"},
        Result: audit.ResultInfo{Status: "FAILURE"},
        Context: audit.ContextInfo{IPAddress: "203.0.113.50"},
        Metadata: map[string]interface{}{
            "payload": maliciousPayload,
        },
    }

    auditor.Record(event)
    
    stats := auditor.GetStats()
    t.Logf("SQL Injection detectado: %d amenazas", stats.ThreatsDetected)
}
```

### Test de Concurrencia

```go
func TestConcurrentAccess(t *testing.T) {
    auditor, _ := audit.NewAuditor(audit.Config{
        StorageType: "memory",
        EnableIA:    false,
    })
    defer auditor.Close()

    const goroutines = 10
    const eventsPerGoroutine = 100
    done := make(chan bool)

    for g := 0; g < goroutines; g++ {
        go func(id int) {
            for i := 0; i < eventsPerGoroutine; i++ {
                event := &audit.Event{
                    Actor: audit.ActorInfo{ID: fmt.Sprintf("user-%d", id), Type: "user"},
                    Action: audit.ActionInfo{Type: "UPDATE", Category: "DATA"},
                    Result: audit.ResultInfo{Status: "SUCCESS"},
                    Context: audit.ContextInfo{IPAddress: fmt.Sprintf("192.168.1.%d", id)},
                }
                auditor.Record(event)
            }
            done <- true
        }(g)
    }

    for g := 0; g < goroutines; g++ {
        <-done
    }

    stats := auditor.GetStats()
    expected := goroutines * eventsPerGoroutine
    if stats.TotalEvents != int64(expected) {
        t.Errorf("Esperado %d eventos, obtenido %d", expected, stats.TotalEvents)
    }
    t.Logf("✓ %d eventos concurrentes registrados exitosamente", stats.TotalEvents)
}
```

---

## 📊 Casos de Uso Reales

### Caso 1: Cumplimiento GDPR/SOX

```go
// Auditoría completa para compliance
complianceFilter := audit.QueryFilter{
    StartTime: time.Now().AddDate(-1, 0, 0), // Último año
    EndTime:   time.Now(),
    ActionCategories: []string{"AUTH", "DATA", "SECURITY"},
    Limit: 100000,
}

// Exportar para auditor externo
var exportBuf bytes.Buffer
err := auditor.Export(ctx, complianceFilter, audit.ExportFormatJSON, &exportBuf)

// Generar reporte de acceso a datos personales
personalDataFilter := audit.QueryFilter{
    ResourceTypes: []string{"user", "customer", "personal_data"},
    ActionTypes:   []string{"VIEW", "EXPORT", "DELETE"},
    StartTime:     time.Now().AddDate(0, -1, 0),
}
```

### Caso 2: Investigación de Incidente de Seguridad

```go
// Investigar posible brecha de seguridad
suspectIP := "203.0.113.50"

// Todas las actividades desde esa IP
ipFilter := audit.QueryFilter{
    IPAddresses: []string{suspectIP},
    StartTime:   time.Now().Add(-7 * 24 * time.Hour),
    Limit:       1000,
    SortBy:      "risk_score",
    SortOrder:   "desc",
}

suspiciousEvents, _ := auditor.Query(ctx, ipFilter)

// Filtrar solo eventos de alto riesgo
highRiskEvents := []*audit.Event{}
for _, event := range suspiciousEvents {
    if event.RiskScore > 0.7 || len(event.Threats) > 0 {
        highRiskEvents = append(highRiskEvents, event)
    }
}

// Reconstruir línea de tiempo del atacante
fmt.Println("=== Línea de Tiempo del Atacante ===")
for _, event := range highRiskEvents {
    fmt.Printf("[%s] %s - %s (Riesgo: %.2f)\n",
        event.Timestamp.Format(time.RFC3339),
        event.Action.Type,
        event.Action.Path,
        event.RiskScore,
    )
    
    for _, threat := range event.Threats {
        fmt.Printf("  ⚠️  AMENAZA: %s (%s)\n", threat.Type, threat.Severity)
    }
}
```

### Caso 3: Monitoreo de Usuarios Privilegiados

```go
// Auditar todas las acciones de administradores
adminFilter := audit.QueryFilter{
    ActorTypes: []string{"admin", "superadmin"},
    ActionCategories: []string{"SYSTEM", "CONFIG", "USER_MANAGEMENT"},
    StartTime:   time.Now().Add(-24 * time.Hour),
    Limit:       500,
}

adminActivities, _ := auditor.Query(ctx, adminFilter)

// Alertar sobre configuraciones críticas cambiadas
for _, event := range adminActivities {
    if event.Resource.Type == "config" && event.Action.Type == "UPDATE" {
        log.Warnf("⚠️  Configuración modificada por %s: %s",
            event.Actor.ID,
            event.Resource.Name,
        )
    }
}
```

---

## 🔒 Mejores Prácticas

### 1. Inicialización Temprana

```go
func main() {
    // Inicializar auditoría al inicio de la aplicación
    err := audit.Init(audit.Config{
        StorageType: "postgres",
        EnableIA:    true,
        EnableAsync: true,
    })
    if err != nil {
        log.Fatal("Failed to init audit system:", err)
    }
    
    // Resto de la aplicación...
}
```

### 2. Usar Procesamiento Asíncrono

```go
// Para no bloquear el flujo principal
err := auditor.RecordAsync(event)
if err != nil {
    // Fallback a síncrono si el buffer está lleno
    auditor.Record(event)
}
```

### 3. Sanitizar PII en Producción

```go
config := audit.Config{
    SanitizePII: true, // Enmascara emails e IPs automáticamente
    // ...
}
```

### 4. Implementar Retención Apropiada

```go
// Ajustar según requerimientos legales
config.Retention = audit.RetentionPolicy{
    MaxAgeDays:       365, // 1 año para compliance
    EnableAutoDelete: true,
}
```

### 5. Monitorear el Sistema de Auditoría

```go
// Chequear estadísticas periódicamente
ticker := time.NewTicker(1 * time.Minute)
go func() {
    for range ticker.C {
        stats := auditor.GetStats()
        log.Infof("Audit Stats: Events=%d, Threats=%d, AvgRisk=%.2f",
            stats.TotalEvents,
            stats.ThreatsDetected,
            stats.AverageRiskScore,
        )
    }
}()
```

---

## 📈 Métricas y Estadísticas

### Stats Disponibles

```go
type Stats struct {
    TotalEvents      int64     // Total de eventos registrados
    EventsLastHour   int64     // Eventos en la última hora
    EventsLastDay    int64     // Eventos en el último día
    ThreatsDetected  int64     // Total de amenazas detectadas
    AverageRiskScore float64   // Score promedio de riesgo
    LastEventTime    time.Time // Timestamp del último evento
    StorageSize      int64     // Tamaño en bytes del storage
    Uptime           time.Duration // Tiempo activo del sistema
}
```

### Uso

```go
stats := auditor.GetStats()
fmt.Printf("📊 Auditoría Activa\n")
fmt.Printf("   Total Eventos: %d\n", stats.TotalEvents)
fmt.Printf("   Amenazas Detectadas: %d\n", stats.ThreatsDetected)
fmt.Printf("   Riesgo Promedio: %.2f\n", stats.AverageRiskScore)
fmt.Printf("   Uptime: %v\n", stats.Uptime)
```

---

## 🎯 Checklist de Producción

- [ ] Configurar almacenamiento persistente (PostgreSQL recomendado)
- [ ] Habilitar procesamiento asíncrono con buffer adecuado
- [ ] Ajustar políticas de retención según compliance
- [ ] Configurar thresholds de IA según tu entorno
- [ ] Habilitar sanitización de PII
- [ ] Implementar backup del storage de auditoría
- [ ] Configurar alertas para amenazas CRITICAL/HIGH
- [ ] Establecer monitoreo de estadísticas del auditor
- [ ] Documentar procedimientos de investigación forense
- [ ] Realizar pruebas de carga del sistema de auditoría

---

## 📝 Licencia

Este módulo es parte de GoKit y está disponible bajo la misma licencia del proyecto principal.

---

## 🤝 Contribución

Para contribuir con nuevas reglas de detección de IA o mejoras al sistema de auditoría, por favor revisar las guías de contribución del proyecto GoKit.
