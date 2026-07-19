package logger

// =============================================================================
// Niveles de Log
// =============================================================================

// Level representa la severidad o importancia de un mensaje de log.
// Se define como uint8 para un uso eficiente de memoria y permite
// comparaciones rápidas y seguras entre niveles.
type Level uint8

const (
	// TraceLevel es el nivel más detallado, usado para diagnóstico profundo y flujos internos.
	TraceLevel Level = iota
	// DebugLevel se usa para información de depuración durante el desarrollo.
	DebugLevel
	// InfoLevel es el nivel predeterminado para mensajes informativos generales.
	InfoLevel
	// SuccessLevel indica una operación completada exitosamente (útil para flujos de usuario).
	SuccessLevel
	// WarnLevel indica una situación potencialmente problemática, pero no crítica.
	WarnLevel
	// ErrorLevel indica un fallo en una operación que no detiene la ejecución del programa.
	ErrorLevel
	// FatalLevel indica un error crítico que provocará la terminación inmediata del programa.
	FatalLevel
	// PanicLevel indica una condición de pánico (recoverable o no) en la aplicación.
	PanicLevel
)
	
// levelNames es un array que mapea cada nivel a su representación en cadena de texto.
// El índice del array corresponde directamente al valor uint8 del Level, lo que
// permite una búsqueda de O(1) extremadamente rápida.
var levelNames = [...]string{
	"TRACE",
	"DEBUG",
	"INFO",
	"SUCCESS",
	"WARN",
	"ERROR",
	"FATAL",
	"PANIC",
}

// =============================================================================
// Métodos del Nivel de Log
// =============================================================================

// String devuelve la representación en cadena de texto del nivel de log.
// Si el nivel no es válido, devuelve "UNKNOWN".
// Este método permite que Level implemente automáticamente la interfaz fmt.Stringer.
func (l Level) String() string {
	if !l.IsValid() {
		return "UNKNOWN"
	}
	return levelNames[l]
}

// Enabled determina si un nivel de log específico debe ser registrado,
// comparándolo con el nivel mínimo configurado (min).
// Devuelve true si el nivel actual (l) es igual o más severo que el nivel mínimo.
// 
// Ejemplo: 
//   - DebugLevel.Enabled(InfoLevel) devuelve false (1 >= 2 es falso).
//   - ErrorLevel.Enabled(InfoLevel) devuelve true (5 >= 2 es verdadero).
func (l Level) Enabled(min Level) bool {
	return l >= min
}

// Prefix devuelve el nivel formateado entre corchetes (ej. "[INFO]").
// Es útil para construir el mensaje final del log de manera consistente.
func (l Level) Prefix() string {
	return "[" + l.String() + "]"
}

// IsValid verifica si el valor del nivel se encuentra dentro del rango
// definido de niveles válidos (desde TraceLevel hasta PanicLevel).
func (l Level) IsValid() bool {
	return l >= TraceLevel && l <= PanicLevel
}

// Color devuelve el código de color ANSI asociado a este nivel de log,
// según el tema (Theme) configurado actualmente en el paquete.
// Si el nivel no es válido, devuelve una cadena vacía para evitar artefactos.
func (l Level) Color() string {
	if !l.IsValid() {
		return ""
	}

	switch l {
	case TraceLevel:
		return theme.Trace
	case DebugLevel:
		return theme.Debug
	case InfoLevel:
		return theme.Info
	case SuccessLevel:
		return theme.Success
	case WarnLevel:
		return theme.Warn
	case ErrorLevel:
		return theme.Error
	case FatalLevel:
		return theme.Fatal
	case PanicLevel:
		return theme.Panic
	default:
		return ""
	}
}