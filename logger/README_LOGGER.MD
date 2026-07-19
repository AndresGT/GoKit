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

## 📦 Instalación

```bash
go get github.com/AndresGT/GoKit/logger
```

## 🚀 Inicio rápido

```go
package main

import "github.com/AndresGT/GoKit/logger"

func main() {
    // Crear logger con configuración por defecto
    log := logger.New()

    // Usar los diferentes niveles
    log.Info("Servidor iniciado en puerto 8080")
    log.Debug("Conectando a la base de datos...")
    log.Error("No se pudo conectar a la API externa")
    log.Success("Usuario autenticado correctamente")
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

| Nivel   | Método         | Descripción              | Cuándo usarlo                                   |
|---------|----------------|--------------------------|--------------------------------------------------|
| Trace   | `log.Trace()`  | Diagnóstico profundo     | Flujos internos, debugging muy detallado          |
| Debug   | `log.Debug()`  | Información de depuración| Desarrollo y troubleshooting                      |
| Info    | `log.Info()`   | Información general      | Eventos normales de la aplicación                 |
| Success | `log.Success()`| Operación exitosa        | Confirmación de tareas completadas                |
| Warn    | `log.Warn()`   | Advertencia               | Situaciones potencialmente problemáticas          |
| Error   | `log.Error()`  | Error no crítico          | Fallos en operaciones que no detienen la app      |
| Fatal   | `log.Fatal()`  | Error crítico             | Termina el programa inmediatamente (`os.Exit(1)`) |
| Panic   | `log.Panic()`  | Condición de pánico       | Dispara un `panic()` con el mensaje de log        |

⚠️ **Importante:** `Fatal` y `Panic` no solo registran el mensaje, también alteran el flujo del programa:
- `Fatal` escribe el log y llama a `os.Exit(1)`, terminando el proceso al instante.
- `Panic` escribe el log y luego ejecuta `panic(message)`.

Solo los niveles iguales o más severos que `Config.Level` se registran. Por ejemplo, si `Level = InfoLevel`, los mensajes `Trace` y `Debug` se descartan silenciosamente.

## ⚙️ Configuración

El logger se configura mediante la estructura `Config` o, de forma más idiomática, con **Functional Options** pasadas a `logger.New(...)`.

```go
type Config struct {
    Writer      io.Writer // Destino de salida (por defecto os.Stdout)
    Level       Level     // Nivel mínimo a registrar (por defecto InfoLevel)
    EnableColor bool      // Colores ANSI en la salida (por defecto true)
    ShowDate    bool      // Incluir fecha YYYY-MM-DD (por defecto true)
    ShowTime    bool      // Incluir hora HH:MM:SS (por defecto true)
}
```

```go
cfg := logger.NewConfig()
cfg.Level = logger.DebugLevel
cfg.EnableColor = false
```

### Opciones disponibles (Functional Options)

| Opción                              | Descripción                                                                 |
|--------------------------------------|------------------------------------------------------------------------------|
| `WithLevel(level Level)`             | Establece el nivel mínimo de severidad. Se ignora si el nivel no es válido.  |
| `WithWriter(w io.Writer)`            | Define el destino de salida. Se ignora si `w` es `nil`.                     |
| `WithColor(enable bool)`             | Activa o desactiva los códigos de color ANSI.                              |
| `WithDateTime(showDate, showTime bool)` | Controla si se incluyen fecha y/u hora en cada línea.                    |
| `WithFileOutput(filePath string)`    | Escribe en un archivo (modo append) y desactiva el color automáticamente.   |

```go
log := logger.New(
    logger.WithLevel(logger.DebugLevel),
    logger.WithColor(false),
    logger.WithFileOutput("logs/app.log"),
)
```

> `WithFileOutput` falla en silencio si no puede crear el archivo (mantiene el writer anterior). Para manejo de errores estricto, usa `NewFileWriter` directamente junto con `WithWriter`.

## 📤 Destinos de salida (Outputs)

```go
// Solo consola (comportamiento por defecto)
writer := logger.NewConsoleWriter()

// Solo archivo (crea directorios intermedios si no existen)
fileWriter, err := logger.NewFileWriter("logs/app.log")
if err != nil {
    // manejar error
}

// Consola + archivo al mismo tiempo
combined := logger.NewMultiWriter(logger.NewConsoleWriter(), fileWriter)

log := logger.New(logger.WithWriter(combined))
```

## 🎨 Temas y colores

Cada nivel tiene un color ANSI asignado a través de un `Theme`. Puedes definir tu propio esquema con `SetTheme` y volver al original con `ResetTheme`.

```go
customTheme := logger.Theme{
    Trace:   "\033[90m",
    Debug:   "\033[34m",
    Info:    "\033[36m",
    Success: "\033[32m",
    Warn:    "\033[33m",
    Error:   "\033[31m",
    Fatal:   "\033[35m",
    Panic:   "\033[41m\033[97m",
    Reset:   "\033[0m",
}

logger.SetTheme(customTheme)
// ...
logger.ResetTheme() // restaura el tema por defecto de GoKit
```

⚠️ `SetTheme`/`ResetTheme` modifican una variable global compartida por todos los loggers del proceso, no un tema por instancia.

## ❗ Errores del paquete

El paquete expone variables de error para casos conocidos:

```go
var (
    ErrInvalidLevel     = errors.New("nivel de log inválido")
    ErrWriteFailed      = errors.New("fallo al escribir el mensaje de log")
    ErrInvalidFilePath  = errors.New("ruta de archivo de log inválida o inaccesible")
)
```

Puedes compararlos con `errors.Is` en tu propio código si necesitas distinguir estos casos.

## 🧵 Concurrencia

`Logger` usa un `sync.Mutex` interno, por lo que una misma instancia puede compartirse de forma segura entre múltiples goroutines sin necesidad de sincronización adicional por parte del usuario.

## 📄 Ejemplo avanzado

```go
package main

import "github.com/AndresGT/GoKit/logger"

func main() {
    cfg := logger.NewConfig()
    cfg.Level = logger.DebugLevel

    fileWriter, err := logger.NewFileWriter("logs/app.log")
    if err != nil {
        panic(err)
    }
    cfg.Writer = logger.NewMultiWriter(logger.NewConsoleWriter(), fileWriter)

    log := logger.New(
        logger.WithLevel(cfg.Level),
        logger.WithWriter(cfg.Writer),
    )

    log.Debug("Conectando a la base de datos...")
    log.Info("Aplicación iniciada correctamente")
    log.Warn("Uso de memoria por encima del 80%")
    log.Error("No se pudo conectar a la base de datos")
}
```

## 📜 Licencia

MIT