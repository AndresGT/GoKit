package logger

import (
	"io"
	"os"
)

// =============================================================================
// Configuración del Logger
// =============================================================================

// Config define los parámetros de comportamiento del logger.
// Controla aspectos como el destino de salida, el nivel mínimo de log,
// la apariencia visual y la información temporal incluida en cada mensaje.
type Config struct {
	// Writer es el destino donde se escribirán los mensajes de log.
	// Por defecto es os.Stdout, pero puede configurarse para escribir
	// en archivos, buffers o múltiples destinos usando io.MultiWriter.
	Writer io.Writer

	// Level establece el nivel mínimo de severidad que se registrará.
	// Los mensajes con un nivel inferior a este serán ignorados.
	// Por defecto es InfoLevel.
	Level Level

	// EnableColor controla si los mensajes de salida incluirán códigos
	// de color ANSI para resaltar los niveles en la terminal.
	// Se recomienda desactivarlo cuando la salida no sea una TTY
	// (por ejemplo, al redirigir a un archivo).
	EnableColor bool

	// ShowDate indica si se debe incluir la fecha (YYYY-MM-DD) en cada línea de log.
	ShowDate bool

	// ShowTime indica si se debe incluir la hora (HH:MM:SS) en cada línea de log.
	ShowTime bool
}

// =============================================================================
// Configuración Predeterminada
// =============================================================================

// defaultConfig contiene los valores iniciales recomendados para el logger.
// Proporciona una configuración sensible y lista para usar en la mayoría
// de las aplicaciones: salida a consola con colores, fecha y hora activas,
// y nivel de severidad Info.
var defaultConfig = Config{
	Level:       InfoLevel,
	Writer:      os.Stdout,
	EnableColor: true,
	ShowDate:    true,
	ShowTime:    true,
}

// =============================================================================
// Constructor
// =============================================================================

// NewConfig devuelve una copia de la configuración predeterminada.
// El usuario puede modificar los campos del Config devuelto antes de
// pasarlo al constructor del logger para personalizar su comportamiento.
//
// Ejemplo de uso:
//
//	cfg := logger.NewConfig()
//	cfg.Level = logger.DebugLevel
//	cfg.EnableColor = false
func NewConfig() Config {
	return defaultConfig
}