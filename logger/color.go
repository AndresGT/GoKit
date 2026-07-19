package logger

// =============================================================================
// Constantes de Colores ANSI
// =============================================================================

const (
	// colorReset restablece el formato de texto de la terminal a su estado predeterminado.
	colorReset = "\033[0m"

	// Colores de texto estándar para los diferentes niveles de log.
	colorGray    = "\033[90m"
	colorBlue    = "\033[34m"
	colorCyan    = "\033[36m"
	colorGreen   = "\033[32m"
	colorYellow  = "\033[33m"
	colorRed     = "\033[31m"
	colorMagenta = "\033[35m"

	// Colores de fondo y combinaciones para niveles críticos.
	colorBgRed = "\033[41m"
	colorWhite = "\033[97m"
)

// =============================================================================
// Tipos y Variables de Tema
// =============================================================================

// Theme define el esquema de colores para cada nivel de log.
// Permite a los usuarios personalizar la apariencia visual de la salida del logger.
type Theme struct {
	Trace   string // Color para el nivel TRACE
	Debug   string // Color para el nivel DEBUG
	Info    string // Color para el nivel INFO
	Success string // Color para el nivel SUCCESS
	Warn    string // Color para el nivel WARN
	Error   string // Color para el nivel ERROR
	Fatal   string // Color para el nivel FATAL
	Panic   string // Color para el nivel PANIC
	Reset   string // Código para restablecer el color al final de cada mensaje
}

// theme es la variable global que mantiene el esquema de colores activo actualmente.
var theme = defaultTheme

// defaultTheme contiene la configuración de colores predeterminada de GoKit Logger.
var defaultTheme = Theme{
	Trace:   colorGray,
	Debug:   colorBlue,
	Info:    colorCyan,
	Success: colorGreen,
	Warn:    colorYellow,
	Error:   colorRed,
	Fatal:   colorMagenta,
	Panic:   colorBgRed + colorWhite, // Fondo rojo con texto blanco para máxima visibilidad
	Reset:   colorReset,
}

// =============================================================================
// Funciones de Gestión de Tema
// =============================================================================

// SetTheme permite establecer un esquema de colores personalizado globalmente.
// Es útil si la aplicación requiere una identidad visual específica o para mejorar
// la legibilidad en terminales con fondos claros/oscuros.
func SetTheme(t Theme) {
	theme = t
}

// ResetTheme restaura el esquema de colores a la configuración predeterminada de GoKit.
func ResetTheme() {
	theme = defaultTheme
}

// =============================================================================
// Funciones Internas de Utilidad
// =============================================================================

// colorize envuelve un texto con el código de color especificado y el código de restablecimiento.
// Si el color está vacío, devuelve el texto sin modificar.
func colorize(color, text string) string {
	if color == "" {
		return text
	}
	return color + text + theme.Reset
}