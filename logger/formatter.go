package logger

import (
	"strings"
	"time"
)

// =============================================================================
// Formateador de Logs
// =============================================================================

// Formatter se encarga de dar estructura, formato y estilo a los mensajes de log.
// Utiliza la configuración proporcionada (Config) para decidir qué elementos
// incluir (fecha, hora, colores) y cómo representarlos.
type Formatter struct {
	config Config
}

// NewFormatter crea y devuelve una nueva instancia de Formatter inicializada
// con la configuración especificada.
func NewFormatter(cfg Config) *Formatter {
	return &Formatter{
		config: cfg,
	}
}

// Format construye la cadena final del log combinando de manera eficiente
// la fecha, la hora, el nivel de severidad y el mensaje del usuario.
// Utiliza strings.Builder para optimizar el rendimiento y minimizar
// las asignaciones de memoria durante la concatenación.
func (f *Formatter) Format(level Level, message string) string {
	var sb strings.Builder

	// 1. Fecha (si está habilitada en la configuración)
	if f.config.ShowDate {
		sb.WriteString(f.formatDate())
		sb.WriteString(" ")
	}

	// 2. Hora (si está habilitada en la configuración)
	if f.config.ShowTime {
		sb.WriteString(f.formatTime())
		sb.WriteString(" ")
	}

	// 3. Nivel formateado (con o sin color, según la configuración)
	sb.WriteString(f.formatLevel(level))
	sb.WriteString(" ")

	// 4. Mensaje proporcionado por el usuario
	sb.WriteString(message)

	return sb.String()
}

// =============================================================================
// Métodos Internos de Formato
// =============================================================================

// formatDate devuelve la fecha actual formateada como YYYY-MM-DD.
// Utiliza el layout estándar de Go "2006-01-02".
func (f *Formatter) formatDate() string {
	return time.Now().Format("2006-01-02")
}

// formatTime devuelve la hora actual formateada como HH:MM:SS.
// Utiliza el layout estándar de Go "15:04:05".
// Nota: Se puede cambiar a "15:04:05.000" si se requiere precisión de milisegundos.
func (f *Formatter) formatTime() string {
	return time.Now().Format("15:04:05")
}

// formatLevel obtiene el prefijo textual del nivel (ej. "[INFO]") y,
// si los colores están habilitados en la configuración, lo envuelve
// con los códigos ANSI correspondientes usando la función colorize.
func (f *Formatter) formatLevel(level Level) string {
	prefix := level.Prefix()
	
	if f.config.EnableColor {
		return colorize(level.Color(), prefix)
	}
	
	return prefix
}

// join es una función de utilidad interna para concatenar múltiples
// cadenas de texto separadas por un espacio.
// Nota: El método principal Format ya utiliza strings.Builder para mayor
// eficiencia, pero esta función se mantiene disponible para usos específicos.
func (f *Formatter) join(parts ...string) string {
	return strings.Join(parts, " ")
}