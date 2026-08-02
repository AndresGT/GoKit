# GoKit Logger

[![Go Version](https://img.shields.io/badge/Go-1.26+-00ADD8?style=flat&logo=go)](https://golang.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

Un sistema de logging modular, concurrente y personalizable para aplicaciones Go, diseñado como parte del ecosistema GoKit.

## 🌟 Características

- **8 niveles de log**: Trace, Debug, Info, Success, Warn, Error, Fatal, Panic
- **Colores personalizables**: temas configurables con códigos ANSI
- **Salida flexible**: consola, archivo, o ambos simultáneamente (`io.MultiWriter`)
- **Concurrencia segura**: thread-safe gracias a `sync.Mutex`
- **API moderna**: patrón Functional Options para una configuración limpia
- **Alto rendimiento**: uso de `strings.Builder` para minimizar asignaciones en el formateo
- **Zero dependencies**: solo usa la biblioteca estándar de Go
- **Campos contextuales**: añade metadata estructurada a tus logs con `*WithFields()`
- **Logger global**: instancia por defecto lista para usar con funciones package-level

## 📦 Instalación

```bash
go get github.com/AndresGT/GoKit/logger
```

## 🚀 Inicio rápido

### Uso básico con logger por defecto

```go
package main

import "github.com/AndresGT/GoKit/logger"

func main() {
    // Usar el logger global directamente (configuración por defecto)
    logger.Info("Servidor iniciado en puerto 8080")
    logger.Debug("Conectando a la base de datos...")
    logger.Error("No se pudo conectar a la API externa")
    logger.Success("Usuario autenticado correctamente")
}
```

### Crear instancia personalizada

```go
package main

import "github.com/AndresGT/GoKit/logger"

func main() {
    // Crear logger con configuración personalizada
    log := logger.New(
        logger.WithLevel(logger.DebugLevel),
        logger.WithColor(true),
    )

    log.Info("Servidor iniciado en puerto 8080")
    log.Debug("Conectando a la base de datos...")
    log.Error("No se pudo conectar a la API externa")
}
```

### Salida en consola

```log
2026-07-17 14:32:15 [INFO] Servidor iniciado en puerto 8080
2026-07-17 14:32:15 [DEBUG] Conectando a la base de datos...
2026-07-17 14:32:15 [ERROR] No se pudo conectar a la API externa
2026-07-17 14:32:15 [SUCCESS] Usuario autenticado correctamente
```

> Nota: por defecto `EnableColor` está en `true`, así que en una terminal compatible con ANSI cada nivel se mostrará en un color distinto (ver [Temas y colores](#-temas-y-colores)).

## 📖 Niveles de log

| Nivel   | Método (instancia)     | Método (global)           | Descripción              | Cuándo usarlo                                   |
|---------|------------------------|---------------------------|--------------------------|--------------------------------------------------|
| Trace   | `log.Trace()`          | `logger.Trace()`          | Diagnóstico profundo     | Flujos internos, debugging muy detallado          |
| Debug   | `log.Debug()`          | `logger.Debug()`          | Información de depuración| Desarrollo y troubleshooting                      |
| Info    | `log.Info()`           | `logger.Info()`           | Información general      | Eventos normales de la aplicación                 |
| Success | `log.Success()`        | `logger.Success()`        | Operación exitosa        | Confirmación de tareas completadas                |
| Warn    | `log.Warn()`           | `logger.Warn()`           | Advertencia               | Situaciones potencialmente problemáticas          |
| Error   | `log.Error()`          | `logger.Error()`          | Error no crítico          | Fallos en operaciones que no detienen la app      |
| Fatal   | `log.Fatal()`          | `logger.Fatal()`          | Error crítico             | Termina el programa inmediatamente (`os.Exit(1)`) |
| Panic   | `log.Panic()`          | `logger.Panic()`          | Condición de pánico       | Dispara un `panic()` con el mensaje de log        |

⚠️ **Importante:** `Fatal` y `Panic` no solo registran el mensaje, también alteran el flujo del programa:
- `Fatal` escribe el log y llama a `os.Exit(1)`, terminando el proceso al instante.
- `Panic` escribe el log y luego ejecuta `panic(message)`.

Solo los niveles iguales o más severos que `Config.Level` se registran. Por ejemplo, si `Level = InfoLevel`, los mensajes `Trace` y `Debug` se descartan silenciosamente.

### Métodos con campos contextuales

Para añadir metadata estructurada a tus logs, usa los métodos `*WithFields()`:

```go
// Con instancia personalizada
log.InfoWithFields("Usuario conectado", map[string]interface{}{
    "user_id": 12345,
    "email": "usuario@example.com",
    "ip": "192.168.1.100",
})

log.ErrorWithFields("Error en base de datos", map[string]interface{}{
    "query": "SELECT * FROM users",
    "error": err.Error(),
    "duration_ms": 1500,
})

// Con logger global
logger.DebugWithFields("Procesando request", map[string]interface{}{
    "method": "POST",
    "path": "/api/users",
    "request_id": "abc-123-xyz",
})
```

**Salida de ejemplo:**
```log
2026-07-17 14:32:15 [INFO] Usuario conectado | user_id=12345, email=usuario@example.com, ip=192.168.1.100
2026-07-17 14:32:15 [ERROR] Error en base de datos | query=SELECT * FROM users, error=connection timeout, duration_ms=1500
```

Métodos disponibles con campos:
- `InfoWithFields(message string, fields map[string]interface{})`
- `DebugWithFields(message string, fields map[string]interface{})`
- `WarnWithFields(message string, fields map[string]interface{})`
- `ErrorWithFields(message string, fields map[string]interface{})`
- `SuccessWithFields(message string, fields map[string]interface{})`

## ⚙️ Configuración

El logger se configura mediante la estructura `Config` o, de forma más idiomática, con **Functional Options** pasadas a `logger.New(...)`.

### Estructura Config

```go
type Config struct {
    Writer      io.Writer // Destino de salida (por defecto os.Stdout)
    Level       Level     // Nivel mínimo a registrar (por defecto InfoLevel)
    EnableColor bool      // Colores ANSI en la salida (por defecto true)
    ShowDate    bool      // Incluir fecha YYYY-MM-DD (por defecto true)
    ShowTime    bool      // Incluir hora HH:MM:SS (por defecto true)
}
```

### Crear configuración por defecto

```go
cfg := logger.NewConfig()
cfg.Level = logger.DebugLevel
cfg.EnableColor = false
```

### Opciones disponibles (Functional Options)

| Opción                              | Descripción                                                                 | Ejemplo                                      |
|--------------------------------------|------------------------------------------------------------------------------|----------------------------------------------|
| `WithLevel(level Level)`             | Establece el nivel mínimo de severidad. Se ignora si el nivel no es válido.  | `logger.WithLevel(logger.DebugLevel)`        |
| `WithWriter(w io.Writer)`            | Define el destino de salida. Se ignora si `w` es `nil`.                     | `logger.WithWriter(fileWriter)`              |
| `WithColor(enable bool)`             | Activa o desactiva los códigos de color ANSI.                              | `logger.WithColor(false)`                    |
| `WithDateTime(showDate, showTime bool)` | Controla si se incluyen fecha y/u hora en cada línea.                    | `logger.WithDateTime(true, false)`           |
| `WithFileOutput(filePath string)`    | Escribe en un archivo (modo append) y desactiva el color automáticamente.   | `logger.WithFileOutput("logs/app.log")`      |

### Ejemplos de configuración

```go
// Configuración mínima con opciones
log := logger.New(
    logger.WithLevel(logger.DebugLevel),
    logger.WithColor(false),
)

// Configuración con salida a archivo
log := logger.New(
    logger.WithLevel(logger.InfoLevel),
    logger.WithFileOutput("logs/app.log"),
)

// Configuración completa con múltiples opciones
log := logger.New(
    logger.WithLevel(logger.TraceLevel),
    logger.WithDateTime(true, true),
    logger.WithColor(true),
)
```

> `WithFileOutput` falla en silencio si no puede crear el archivo (mantiene el writer anterior). Para manejo de errores estricto, usa `NewFileWriter` directamente junto con `WithWriter`.

## 📤 Destinos de salida (Outputs)

El logger soporta múltiples destinos de salida que pueden combinarse según sea necesario.

### Consola (stdout)

```go
// Solo consola (comportamiento por defecto)
writer := logger.NewConsoleWriter()

log := logger.New(logger.WithWriter(writer))
```

### Archivo

```go
// Solo archivo (crea directorios intermedios si no existen)
fileWriter, err := logger.NewFileWriter("logs/app.log")
if err != nil {
    // manejar error
    log.Fatal(err.Error())
}

log := logger.New(logger.WithWriter(fileWriter))
```

### Múltiples destinos simultáneos

```go
// Consola + archivo al mismo tiempo
consoleWriter := logger.NewConsoleWriter()
fileWriter, err := logger.NewFileWriter("logs/app.log")
if err != nil {
    log.Fatal(err.Error())
}

combined := logger.NewMultiWriter(consoleWriter, fileWriter)
log := logger.New(logger.WithWriter(combined))
```

> `NewMultiWriter` acepta cualquier número de `io.Writer` y escribe cada mensaje en todos ellos simultáneamente.

## 🎨 Temas y colores

Cada nivel tiene un color ANSI asignado a través de un `Theme`. Puedes definir tu propio esquema con `SetTheme` y volver al original con `ResetTheme`.

### Tema por defecto

El tema predeterminado usa los siguientes colores ANSI:

| Nivel   | Color              | Código ANSI           |
|---------|--------------------|-----------------------|
| Trace   | Gris               | `\033[90m`            |
| Debug   | Azul               | `\033[34m`            |
| Info    | Cyan               | `\033[36m`            |
| Success | Verde              | `\033[32m`            |
| Warn    | Amarillo           | `\033[33m`            |
| Error   | Rojo               | `\033[31m`            |
| Fatal   | Magenta            | `\033[35m`            |
| Panic   | Fondo rojo + Blanco| `\033[41m\033[97m`    |

### Personalizar tema

```go
customTheme := logger.Theme{
    Trace:   "\033[90m",      // Gris
    Debug:   "\033[34m",      // Azul
    Info:    "\033[36m",      // Cyan
    Success: "\033[32m",      // Verde
    Warn:    "\033[33m",      // Amarillo
    Error:   "\033[31m",      // Rojo
    Fatal:   "\033[35m",      // Magenta
    Panic:   "\033[41m\033[97m", // Fondo rojo + texto blanco
    Reset:   "\033[0m",       // Resetear color
}

logger.SetTheme(customTheme)
// ... uso del logger ...
logger.ResetTheme() // restaura el tema por defecto de GoKit
```

⚠️ **Importante:** `SetTheme`/`ResetTheme` modifican una variable global compartida por todos los loggers del proceso, no un tema por instancia.

### Desactivar colores

Si tu entorno no soporta colores ANSI o prefieres salida en texto plano:

```go
log := logger.New(logger.WithColor(false))
```

## ❗ Errores del paquete

El paquete expone variables de error para casos conocidos que puedes usar para manejo explícito de errores:

```go
var (
    ErrInvalidLevel    = errors.New("nivel de log inválido")
    ErrWriteFailed     = errors.New("fallo al escribir el mensaje de log")
    ErrInvalidFilePath = errors.New("ruta de archivo de log inválida o inaccesible")
)
```

### Uso con `errors.Is`

```go
fileWriter, err := logger.NewFileWriter("/ruta/inaccesible/app.log")
if err != nil {
    if errors.Is(err, logger.ErrInvalidFilePath) {
        // Manejar error específico de ruta inválida
        log.Println("No se pudo crear el archivo de log:", err)
    }
}
```

Puedes compararlos con `errors.Is` en tu propio código si necesitas distinguir estos casos.

## 🧵 Concurrencia

`Logger` usa un `sync.Mutex` interno, por lo que una misma instancia puede compartirse de forma segura entre múltiples goroutines sin necesidad de sincronización adicional por parte del usuario.

```go
log := logger.New(logger.WithLevel(logger.DebugLevel))

// Compartir log entre múltiples goroutines es seguro
var wg sync.WaitGroup
for i := 0; i < 10; i++ {
    wg.Add(1)
    go func(id int) {
        defer wg.Done()
        log.Info(fmt.Sprintf("Goroutine %d completada", id))
    }(i)
}
wg.Wait()
```

## 🔧 Funciones utilitarias del paquete

Además de los métodos de instancia, el paquete provee funciones a nivel de package para uso rápido:

### Logger global

El paquete inicializa un logger por defecto que puedes usar directamente:

```go
// Usar funciones package-level sin crear instancia
logger.Info("Mensaje informativo")
logger.Error("Algo salió mal")
logger.Success("Operación completada")
```

### Personalizar el logger global

Puedes reemplazar el logger por defecto con tu propia configuración:

```go
customLog := logger.New(
    logger.WithLevel(logger.TraceLevel),
    logger.WithFileOutput("app.log"),
)

// Establecer como logger global
logger.SetDefault(customLog)

// Ahora todas las funciones package-level usan tu configuración
logger.Trace("Este mensaje se escribirá en app.log")
```

### Obtener el logger global

```go
defaultLog := logger.GetDefault()
defaultLog.Info("Usando el logger global obtenido explícitamente")
```

## 📄 Ejemplo avanzado

Un ejemplo completo que combina múltiples características del logger:

```go
package main

import (
    "fmt"
    "github.com/AndresGT/GoKit/logger"
)

func main() {
    // Configurar logger con salida múltiple (consola + archivo)
    consoleWriter := logger.NewConsoleWriter()
    fileWriter, err := logger.NewFileWriter("logs/app.log")
    if err != nil {
        panic(err)
    }
    
    combinedWriter := logger.NewMultiWriter(consoleWriter, fileWriter)
    
    log := logger.New(
        logger.WithLevel(logger.DebugLevel),
        logger.WithWriter(combinedWriter),
        logger.WithDateTime(true, true),
        logger.WithColor(true),
    )
    
    // Logs básicos
    log.Debug("Conectando a la base de datos...")
    log.Info("Aplicación iniciada correctamente")
    log.Warn("Uso de memoria por encima del 80%")
    log.Error("No se pudo conectar a la base de datos")
    
    // Logs con campos contextuales
    log.InfoWithFields("Usuario conectado", map[string]interface{}{
        "user_id": 12345,
        "email": "usuario@example.com",
        "ip": "192.168.1.100",
    })
    
    log.ErrorWithFields("Error en query", map[string]interface{}{
        "query": "SELECT * FROM users",
        "error": "connection timeout",
        "duration_ms": 1500,
    })
    
    // Usar logger global también configurado
    logger.SetDefault(log)
    logger.Success("Configuración completada")
}
```

### Salida esperada

```log
2026-07-17 14:32:15 [DEBUG] Conectando a la base de datos...
2026-07-17 14:32:15 [INFO] Aplicación iniciada correctamente
2026-07-17 14:32:15 [WARN] Uso de memoria por encima del 80%
2026-07-17 14:32:15 [ERROR] No se pudo conectar a la base de datos
2026-07-17 14:32:15 [INFO] Usuario conectado | user_id=12345, email=usuario@example.com, ip=192.168.1.100
2026-07-17 14:32:15 [ERROR] Error en query | query=SELECT * FROM users, error=connection timeout, duration_ms=1500
2026-07-17 14:32:15 [SUCCESS] Configuración completada
```

## 📋 API Reference Rápida

### Funciones de logging (package-level)
| Función | Descripción |
|---------|-------------|
| `logger.Trace(msg string)` | Log nivel TRACE |
| `logger.Debug(msg string)` | Log nivel DEBUG |
| `logger.Info(msg string)` | Log nivel INFO |
| `logger.Success(msg string)` | Log nivel SUCCESS |
| `logger.Warn(msg string)` | Log nivel WARN |
| `logger.Error(msg string)` | Log nivel ERROR |
| `logger.Fatal(msg string)` | Log nivel FATAL + `os.Exit(1)` |
| `logger.Panic(msg string)` | Log nivel PANIC + `panic()` |

### Funciones con campos (package-level)
| Función | Descripción |
|---------|-------------|
| `logger.DebugWithFields(msg string, fields map[string]interface{})` | DEBUG con metadata |
| `logger.InfoWithFields(msg string, fields map[string]interface{})` | INFO con metadata |
| `logger.SuccessWithFields(msg string, fields map[string]interface{})` | SUCCESS con metadata |
| `logger.WarnWithFields(msg string, fields map[string]interface{})` | WARN con metadata |
| `logger.ErrorWithFields(msg string, fields map[string]interface{})` | ERROR con metadata |

### Métodos de instancia
| Método | Descripción |
|--------|-------------|
| `logger.New(opts ...Option) *Logger` | Crear nueva instancia |
| `log.Trace/Debug/Info/Success/Warn/Error/Fatal/Panic(msg string)` | Logs por nivel |
| `log.*WithFields(msg string, fields map[string]interface{})` | Logs con campos |

### Functional Options
| Opción | Descripción |
|--------|-------------|
| `WithLevel(level Level)` | Nivel mínimo de logging |
| `WithWriter(w io.Writer)` | Destino de salida |
| `WithColor(enable bool)` | Activar/desactivar colores |
| `WithDateTime(showDate, showTime bool)` | Controlar fecha/hora |
| `WithFileOutput(filePath string)` | Salida a archivo |

### Gestión de outputs
| Función | Descripción |
|---------|-------------|
| `NewConsoleWriter() io.Writer` | Writer para stdout |
| `NewFileWriter(path string) (io.Writer, error)` | Writer para archivo |
| `NewMultiWriter(writers ...io.Writer) io.Writer` | Combinar múltiples writers |

### Tema y configuración global
| Función | Descripción |
|---------|-------------|
| `SetTheme(t Theme)` | Establecer tema global |
| `ResetTheme()` | Restaurar tema por defecto |
| `SetDefault(l *Logger)` | Establecer logger global |
| `GetDefault() *Logger` | Obtener logger global |
| `NewConfig() Config` | Obtener configuración por defecto |

## 📜 Licencia

MIT