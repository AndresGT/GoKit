package logger

import (
	"io"
)

// =============================================================================
// Opciones Funcionales (Functional Options Pattern)
// =============================================================================

// Option es una función que modifica la configuración del logger.
// Este patrón permite una configuración flexible, legible y extensible
// al crear una nueva instancia del logger, sin necesidad de múltiples
// constructores o estructuras de configuración mutables.
type Option func(*Config)

// WithLevel establece el nivel mínimo de severidad para el logging.
// Los mensajes con un nivel inferior a este serán ignorados.
// Si se proporciona un nivel no válido, se ignora el cambio.
func WithLevel(level Level) Option {
	return func(c *Config) {
		if level.IsValid() {
			c.Level = level
		}
	}
}

// WithWriter establece el destino de salida (io.Writer) para los mensajes de log.
// Por defecto es os.Stdout. Se puede combinar con logger.NewMultiWriter 
// para escribir en consola y archivo simultáneamente.
func WithWriter(w io.Writer) Option {
	return func(c *Config) {
		if w != nil {
			c.Writer = w
		}
	}
}

// WithColor habilita o deshabilita el uso de códigos de color ANSI en la salida.
// Se recomienda establecerlo en 'false' si la salida se redirige a un archivo
// para evitar caracteres extraños en el archivo de texto.
func WithColor(enable bool) Option {
	return func(c *Config) {
		c.EnableColor = enable
	}
}

// WithDateTime controla la inclusión de la fecha y la hora en los mensajes de log.
func WithDateTime(showDate, showTime bool) Option {
	return func(c *Config) {
		c.ShowDate = showDate
		c.ShowTime = showTime
	}
}

// WithFileOutput es una opción de conveniencia que configura el logger
// para escribir directamente en un archivo específico en modo append.
// Nota: Si ocurre un error al crear el archivo, esta opción falla en silencio
// y mantiene el writer anterior. Para un manejo de errores estricto, se 
// recomienda crear el writer con NewFileWriter() y pasarlo con WithWriter().
func WithFileOutput(filePath string) Option {
	return func(c *Config) {
		if filePath == "" {
			return
		}
		if w, err := NewFileWriter(filePath); err == nil {
			c.Writer = w
			c.EnableColor = false // Desactivar colores por defecto en archivos
		}
	}
}