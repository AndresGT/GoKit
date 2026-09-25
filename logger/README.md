# GoKit Logger

[![Go Version](https://img.shields.io/badge/Go-1.26+-00ADD8?style=flat&logo=go)](https://go.dev/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

Logger modular, concurrente y personalizable para aplicaciones Go, desarrollado como parte del ecosistema **GoKit**.

Está construido únicamente con la biblioteca estándar de Go y ofrece diferentes niveles de logging, campos estructurados, colores ANSI, múltiples destinos de salida y un logger global listo para utilizar.

---

## 🌟 Características

- **8 niveles de log:** `Trace`, `Debug`, `Info`, `Success`, `Warn`, `Error`, `Fatal` y `Panic`.
- **Thread-safe:** las escrituras de cada instancia están protegidas mediante `sync.Mutex`.
- **Logger global:** funciones package-level listas para usar sin crear una instancia manualmente.
- **Campos estructurados:** agrega información adicional mediante `WithFields()`.
- **Functional Options:** configuración sencilla y flexible mediante opciones.
- **Colores ANSI:** temas personalizables por nivel.
- **Temas thread-safe:** el tema global utiliza `sync.RWMutex`.
- **Múltiples destinos:** consola, archivo o varios destinos simultáneamente.
- **Salida a archivos:** crea automáticamente los directorios necesarios y utiliza modo `append`.
- **Formateo configurable:** fecha, hora y nivel pueden mostrarse u ocultarse.
- **Zero dependencies:** utiliza exclusivamente la biblioteca estándar de Go.

---

## 📦 Instalación

```bash
go get github.com/AndresGT/GoKit/logger
```

Importa el paquete:

```go
import "github.com/AndresGT/GoKit/logger"
```

---

## 🚀 Inicio rápido

### Logger global

Puedes utilizar el logger global directamente:

```go
package main

import "github.com/AndresGT/GoKit/logger"

func main() {
    logger.Trace("Mensaje de trazabilidad")
    logger.Debug("Conectando a la base de datos...")
    logger.Info("Servidor iniciado en el puerto 8080")
    logger.Success("Proceso completado correctamente")
    logger.Warn("Conexión lenta detectada")
    logger.Error("No se pudo conectar con la API externa")
}
```

Una salida típica puede verse así:

```text
2026-09-24 18:00:00 [INFO] Servidor iniciado en el puerto 8080
2026-09-24 18:00:00 [SUCCESS] Proceso completado correctamente
2026-09-24 18:00:00 [WARN] Conexión lenta detectada
2026-09-24 18:00:00 [ERROR] No se pudo conectar con la API externa
```

> Los colores ANSI están habilitados por defecto.

---

## 🧩 Crear un Logger personalizado

La configuración se realiza mediante **Functional Options**:

```go
package main

import "github.com/AndresGT/GoKit/logger"

func main() {
    log := logger.New(
        logger.WithLevel(logger.DebugLevel),
        logger.WithColor(true),
        logger.WithShowDate(true),
        logger.WithShowTime(true),
    )

    log.Info("Logger personalizado inicializado")

    log.Debug("Ejecutando consulta a la base de datos...")
}
```

También puedes controlar fecha y hora mediante una sola opción:

```go
log := logger.New(
    logger.WithLevel(logger.DebugLevel),
    logger.WithDateTime(true, true),
)
```

---

## 📖 Niveles de Log

| Nivel | Instancia | Global | Descripción |
|---|---|---|---|
| `Trace` | `log.Trace()` | `logger.Trace()` | Diagnóstico muy detallado |
| `Debug` | `log.Debug()` | `logger.Debug()` | Información para depuración |
| `Info` | `log.Info()` | `logger.Info()` | Información general |
| `Success` | `log.Success()` | `logger.Success()` | Operación completada correctamente |
| `Warn` | `log.Warn()` | `logger.Warn()` | Advertencia |
| `Error` | `log.Error()` | `logger.Error()` | Error de ejecución |
| `Fatal` | `log.Fatal()` | `logger.Fatal()` | Registra el mensaje y termina el proceso |
| `Panic` | `log.Panic()` | `logger.Panic()` | Registra el mensaje y ejecuta `panic()` |

### Filtrado por nivel

El logger registra únicamente los mensajes cuyo nivel sea igual o superior al nivel configurado.

Por ejemplo:

```go
log := logger.New(
    logger.WithLevel(logger.InfoLevel),
)
```

Con esta configuración:

- `Trace` → ignorado
- `Debug` → ignorado
- `Info` → registrado
- `Success` → registrado
- `Warn` → registrado
- `Error` → registrado
- `Fatal` → registrado
- `Panic` → registrado

---

## ⚠️ `Fatal` y `Panic`

Estos dos niveles tienen un comportamiento especial.

### Fatal

`Fatal` escribe el mensaje y posteriormente ejecuta:

```go
os.Exit(1)
```

Ejemplo:

```go
logger.Fatal("No se pudo iniciar el servidor")
```

El proceso termina inmediatamente.

### Panic

`Panic` escribe el mensaje y posteriormente ejecuta:

```go
panic(message)
```

Ejemplo:

```go
logger.Panic("Estado interno inválido")
```

---

## 🏷️ Campos estructurados

Los métodos `WithFields()` permiten adjuntar información contextual utilizando:

```go
map[string]any
```

Ejemplo:

```go
log.InfoWithFields("Usuario autenticado", map[string]any{
    "user_id": 42,
    "role":    "admin",
    "ip":      "127.0.0.1",
})
```

Salida:

```text
2026-09-24 18:00:00 [INFO] Usuario autenticado | user_id=42, role=admin, ip=127.0.0.1
```

### Métodos disponibles

Actualmente existen métodos con campos para:

```text
DebugWithFields()
InfoWithFields()
SuccessWithFields()
WarnWithFields()
ErrorWithFields()
```

También están disponibles en el logger global:

```go
logger.DebugWithFields(...)
logger.InfoWithFields(...)
logger.SuccessWithFields(...)
logger.WarnWithFields(...)
logger.ErrorWithFields(...)
```

### Ejemplo práctico

```go
log.ErrorWithFields("Error en la base de datos", map[string]any{
    "query":       "SELECT * FROM users",
    "error":       err.Error(),
    "duration_ms": 1500,
})
```

Salida:

```text
2026-09-24 18:00:00 [ERROR] Error en la base de datos | query=SELECT * FROM users, error=connection timeout, duration_ms=1500
```

> El orden de los campos provenientes de un `map` no está garantizado por Go.

---

## ⚙️ Configuración

La configuración interna utiliza la siguiente estructura:

```go
type Config struct {
    Writer      io.Writer
    Level       Level
    EnableColor bool
    ShowDate    bool
    ShowTime    bool
    ShowLevel   bool
}
```

### Valores predeterminados

El logger utiliza:

```text
Level       = InfoLevel
Writer      = os.Stdout
EnableColor = true
ShowDate    = true
ShowTime    = true
ShowLevel   = true
```

Puedes obtener una copia de la configuración predeterminada con:

```go
cfg := logger.NewConfig()
```

---

## 🛠️ Functional Options

### `WithLevel`

Establece el nivel mínimo de logging:

```go
log := logger.New(
    logger.WithLevel(logger.DebugLevel),
)
```

Si se proporciona un nivel inválido, la opción no modifica la configuración.

---

### `WithWriter`

Permite definir un destino personalizado:

```go
log := logger.New(
    logger.WithWriter(os.Stdout),
)
```

También puedes utilizar cualquier implementación de:

```go
io.Writer
```

Por ejemplo:

```go
var buffer bytes.Buffer

log := logger.New(
    logger.WithWriter(&buffer),
)
```

---

### `WithColor`

Activa o desactiva los colores ANSI:

```go
log := logger.New(
    logger.WithColor(false),
)
```

---

### `WithShowDate`

Controla la fecha:

```go
log := logger.New(
    logger.WithShowDate(false),
)
```

---

### `WithShowTime`

Controla la hora:

```go
log := logger.New(
    logger.WithShowTime(false),
)
```

---

### `WithDateTime`

Permite controlar fecha y hora simultáneamente:

```go
log := logger.New(
    logger.WithDateTime(true, false),
)
```

En este ejemplo se muestra únicamente la fecha.

---

### `WithFileOutput`

Configura directamente la salida hacia un archivo:

```go
log := logger.New(
    logger.WithFileOutput("logs/app.log"),
)
```

El archivo se abre en modo `append`.

Además, cuando se utiliza `WithFileOutput`, los colores ANSI se desactivan automáticamente.

Si no es posible abrir o crear el archivo, la opción conserva el writer anterior y escribe el error en `stderr`.

---

## 📤 Destinos de salida

El paquete proporciona varias funciones para trabajar con diferentes destinos.

### Consola

```go
writer := logger.NewConsoleWriter()

log := logger.New(
    logger.WithWriter(writer),
)
```

`NewConsoleWriter()` devuelve `os.Stdout`.

---

### Archivo

```go
fileWriter, err := logger.NewFileWriter("logs/app.log")
if err != nil {
    panic(err)
}

log := logger.New(
    logger.WithWriter(fileWriter),
)
```

`NewFileWriter()`:

- Crea los directorios intermedios si no existen.
- Crea el archivo si no existe.
- Abre el archivo en modo `append`.
- Devuelve un `io.Writer`.
- Devuelve un error si no puede crear o abrir el archivo.

---

### Consola + archivo

Puedes escribir simultáneamente en varios destinos:

```go
consoleWriter := logger.NewConsoleWriter()

fileWriter, err := logger.NewFileWriter("logs/app.log")
if err != nil {
    panic(err)
}

combinedWriter := logger.NewMultiWriter(
    consoleWriter,
    fileWriter,
)

log := logger.New(
    logger.WithWriter(combinedWriter),
)
```

`NewMultiWriter()` utiliza internamente:

```go
io.MultiWriter
```

y acepta cualquier cantidad de `io.Writer`.

---

## 🎨 Temas y colores

Los colores de los niveles se administran mediante `Theme`.

La estructura es:

```go
type Theme struct {
    Trace   string
    Debug   string
    Info    string
    Success string
    Warn    string
    Error   string
    Fatal   string
    Panic   string
    Reset   string
}
```

### Tema predeterminado

| Nivel | Color |
|---|---|
| `Trace` | Gris |
| `Debug` | Azul |
| `Info` | Cyan |
| `Success` | Verde |
| `Warn` | Amarillo |
| `Error` | Rojo |
| `Fatal` | Magenta |
| `Panic` | Fondo rojo + texto blanco |

### Crear un tema personalizado

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
```

### Restaurar el tema

```go
logger.ResetTheme()
```

### Obtener el tema actual

```go
theme := logger.GetTheme()
```

> La lectura y modificación del tema global están protegidas mediante `sync.RWMutex`.

---

## 🌐 Logger global

GoKit Logger incluye una instancia global creada automáticamente.

Esto permite escribir:

```go
logger.Info("Aplicación iniciada")
```

sin necesidad de crear manualmente:

```go
log := logger.New(...)
```

### Cambiar el logger global

Puedes establecer una instancia personalizada como logger predeterminado:

```go
customLogger := logger.New(
    logger.WithLevel(logger.DebugLevel),
    logger.WithColor(false),
)

logger.SetDefault(customLogger)
```

A partir de ese momento:

```go
logger.Debug("Mensaje de debug")
logger.Info("Mensaje informativo")
logger.Error("Ocurrió un error")
```

utilizarán la instancia configurada.

### Obtener el logger global

```go
log := logger.GetDefault()

log.Info("Usando el logger global")
```

`SetDefault()` y `GetDefault()` utilizan `sync.RWMutex` para proteger el acceso concurrente al logger global.

---

## 🧵 Concurrencia y Thread-Safety

El logger está diseñado para utilizarse desde múltiples goroutines.

Cada instancia de `Logger` contiene un mutex interno:

```go
type Logger struct {
    mu        sync.Mutex
    config    Config
    formatter *Formatter
}
```

Las escrituras se sincronizan para evitar que varios mensajes se mezclen cuando diferentes goroutines escriben simultáneamente.

Ejemplo:

```go
package main

import (
    "sync"

    "github.com/AndresGT/GoKit/logger"
)

func main() {
    var wg sync.WaitGroup

    for i := 0; i < 100; i++ {
        wg.Add(1)

        go func(id int) {
            defer wg.Done()

            logger.InfoWithFields(
                "Procesando worker",
                map[string]any{
                    "worker": id,
                },
            )
        }(i)
    }

    wg.Wait()
}
```

El acceso al logger global también está protegido:

```text
defaultLoggerMu sync.RWMutex
```

y el tema global utiliza:

```text
themeMu sync.RWMutex
```

---

## 📝 Formateo

El formateador utiliza `strings.Builder` para construir cada línea.

El formato depende de las opciones configuradas.

### Fecha + hora + nivel

Configuración:

```go
logger.New(
    logger.WithDateTime(true, true),
)
```

Salida:

```text
2026-09-24 18:00:00 [INFO] Servidor iniciado
```

### Solo fecha

```go
logger.New(
    logger.WithDateTime(true, false),
)
```

Salida:

```text
2026-09-24 [INFO] Servidor iniciado
```

### Solo hora

```go
logger.New(
    logger.WithDateTime(false, true),
)
```

Salida:

```text
18:00:00 [INFO] Servidor iniciado
```

### Sin fecha ni hora

```go
logger.New(
    logger.WithDateTime(false, false),
)
```

Salida:

```text
[INFO] Servidor iniciado
```

### Ocultar el nivel

La configuración también permite controlar `ShowLevel` directamente:

```go
cfg := logger.NewConfig()
cfg.ShowLevel = false
```

---

## 🔌 Uso con `io.Writer`

Una de las ventajas del logger es que no está limitado a `os.Stdout`.

Puedes utilizar cualquier tipo que implemente:

```go
io.Writer
```

Por ejemplo:

```go
var buffer bytes.Buffer

log := logger.New(
    logger.WithWriter(&buffer),
)

log.Info("Mensaje de prueba")

fmt.Println(buffer.String())
```

Esto también facilita la integración con otros sistemas de logging, buffers, archivos o componentes de una aplicación.

---

## 🧪 Pruebas

Para ejecutar las pruebas:

```bash
go test ./...
```

Para ejecutarlas con el detector de condiciones de carrera:

```bash
go test -race ./...
```

También puedes utilizar:

```bash
go test -v -race ./...
```

El uso de `-race` es especialmente recomendable cuando se realizan cambios relacionados con concurrencia, logger global, temas o escritura simultánea.

---

## 📁 Estructura del paquete

La implementación está organizada por responsabilidades:

```text
logger/
├── config.go
├── doc.go
├── errors.go
├── formatter.go
├── levels.go
├── logger.go
├── options.go
├── output.go
├── theme.go
└── README.md
```

### `config.go`

Define:

- `Config`
- configuración predeterminada
- `NewConfig()`

### `levels.go`

Define:

- `Level`
- niveles disponibles
- validación
- nombres
- prefijos
- colores

### `logger.go`

Contiene:

- `Logger`
- creación de instancias
- métodos de logging
- campos estructurados
- logger global
- control de concurrencia

### `options.go`

Contiene las opciones de configuración:

- `WithLevel`
- `WithWriter`
- `WithColor`
- `WithDateTime`
- `WithShowDate`
- `WithShowTime`
- `WithFileOutput`

### `formatter.go`

Se encarga de construir el texto final del log.

### `output.go`

Proporciona:

- `NewConsoleWriter`
- `NewFileWriter`
- `NewMultiWriter`

### `theme.go`

Gestiona:

- `Theme`
- `SetTheme`
- `GetTheme`
- `ResetTheme`
- colores ANSI
- sincronización del tema global

### `errors.go`

Define errores relacionados con el paquete:

```go
var (
    ErrInvalidLevel    = errors.New("nivel de log inválido")
    ErrWriteFailed     = errors.New("fallo al escribir el mensaje de log")
    ErrInvalidFilePath = errors.New("ruta de archivo de log inválida o inaccesible")
)
```

---

## 📚 API principal

### Creación

```go
logger.New(...)
logger.NewConfig()
```

### Logger global

```go
logger.SetDefault(...)
logger.GetDefault()
```

### Logging

```go
logger.Trace(...)
logger.Debug(...)
logger.Info(...)
logger.Success(...)
logger.Warn(...)
logger.Error(...)
logger.Fatal(...)
logger.Panic(...)
```

### Campos

```go
logger.DebugWithFields(...)
logger.InfoWithFields(...)
logger.SuccessWithFields(...)
logger.WarnWithFields(...)
logger.ErrorWithFields(...)
```

### Configuración

```go
logger.WithLevel(...)
logger.WithWriter(...)
logger.WithColor(...)
logger.WithDateTime(...)
logger.WithShowDate(...)
logger.WithShowTime(...)
logger.WithFileOutput(...)
```

### Outputs

```go
logger.NewConsoleWriter()
logger.NewFileWriter(...)
logger.NewMultiWriter(...)
```

### Temas

```go
logger.SetTheme(...)
logger.GetTheme()
logger.ResetTheme()
```

---

## 💡 Ejemplo completo

```go
package main

import (
    "sync"

    "github.com/AndresGT/GoKit/logger"
)

func main() {
    log := logger.New(
        logger.WithLevel(logger.DebugLevel),
        logger.WithColor(true),
        logger.WithDateTime(true, true),
    )

    log.Info("Aplicación iniciada")

    log.DebugWithFields("Configuración cargada", map[string]any{
        "environment": "development",
        "port":        8080,
    })

    log.SuccessWithFields("Usuario autenticado", map[string]any{
        "user_id": 42,
        "role":    "admin",
    })

    log.Warn("La conexión está tardando más de lo esperado")

    log.ErrorWithFields("Error al consultar la base de datos", map[string]any{
        "query": "SELECT * FROM users",
    })

    var wg sync.WaitGroup

    for i := 0; i < 10; i++ {
        wg.Add(1)

        go func(id int) {
            defer wg.Done()

            log.InfoWithFields(
                "Worker ejecutándose",
                map[string]any{
                    "worker": id,
                },
            )
        }(i)
    }

    wg.Wait()

    log.Info("Aplicación finalizada")
}
```

---

## 📄 Licencia

Este proyecto se distribuye bajo la licencia **MIT**.

Consulta el archivo [`LICENSE`](LICENSE) para obtener los términos completos de la licencia.
