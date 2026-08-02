package logger

import (
	"fmt"
	"os"
	"strings"
	"sync"
)

// =============================================================================
// Instancia Global y API a Nivel de Paquete (Evita inyección de dependencias)
// =============================================================================

var defaultLogger *Logger

func init() {
	// Inicialización por defecto para que funcione out-of-the-box
	defaultLogger = New()
}

// SetDefault permite reconfigurar la instancia global desde main.go.
func SetDefault(l *Logger) {
	if l != nil {
		defaultLogger = l
	}
}

// GetDefault devuelve la instancia global actual del logger.
func GetDefault() *Logger {
	return defaultLogger
}

// --- Métodos globales (Texto Plano) ---

func Trace(message string)   { defaultLogger.Trace(message) }
func Debug(message string)   { defaultLogger.Debug(message) }
func Info(message string)    { defaultLogger.Info(message) }
func Success(message string) { defaultLogger.Success(message) }
func Warn(message string)    { defaultLogger.Warn(message) }
func Error(message string)   { defaultLogger.Error(message) }
func Fatal(message string)   { defaultLogger.Fatal(message) }
func Panic(message string)   { defaultLogger.Panic(message) }

// --- Métodos globales (Campos Contextuales) ---

func InfoWithFields(msg string, fields map[string]interface{}) {
	defaultLogger.InfoWithFields(msg, fields)
}
func ErrorWithFields(msg string, fields map[string]interface{}) {
	defaultLogger.ErrorWithFields(msg, fields)
}
func DebugWithFields(msg string, fields map[string]interface{}) {
	defaultLogger.DebugWithFields(msg, fields)
}
func WarnWithFields(msg string, fields map[string]interface{}) {
	defaultLogger.WarnWithFields(msg, fields)
}
func SuccessWithFields(msg string, fields map[string]interface{}) {
	defaultLogger.SuccessWithFields(msg, fields)
}

// =============================================================================
// Núcleo del Logger
// =============================================================================

// Logger representa la instancia principal del sistema de logging.
// Es seguro para su uso concurrente (goroutine-safe).
type Logger struct {
	mu        sync.Mutex
	config    Config
	formatter *Formatter
}

// New crea y devuelve una nueva instancia de Logger.
func New(opts ...Option) *Logger {
	cfg := NewConfig()

	for _, opt := range opts {
		opt(&cfg)
	}

	if cfg.Writer == nil {
		cfg.Writer = os.Stdout
	}

	return &Logger{
		config:    cfg,
		formatter: NewFormatter(cfg),
	}
}

// =============================================================================
// Métodos Internos de Escritura (Corregidos con defer y liberación de lock)
// =============================================================================

// log maneja el filtrado por nivel, concurrencia y escritura final.
func (l *Logger) log(level Level, message string) {
	if !level.Enabled(l.config.Level) {
		return
	}

	// Función anónima autoejecutada para acotar la duración del Lock
	// y asegurar que se libere EL MUTEX antes de os.Exit o panic.
	func() {
		l.mu.Lock()
		defer l.mu.Unlock()

		formattedMessage := l.formatter.Format(level, message) + "\n"

		_, err := fmt.Fprint(l.config.Writer, formattedMessage)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR DE LOGGING: %v\n", err)
		}
	}()

	// Manejo de comportamientos terminales fuera del bloqueo del mutex
	if level == FatalLevel {
		os.Exit(1)
	}

	if level == PanicLevel {
		panic(message)
	}
}

// logWithFields maneja mensajes enriquecidos con mapas de contexto.
func (l *Logger) logWithFields(level Level, message string, fields map[string]interface{}) {
	if !level.Enabled(l.config.Level) {
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	formattedMessage := l.formatter.Format(level, message)

	if len(fields) > 0 {
		formattedMessage += " | " + formatFields(fields)
	}

	formattedMessage += "\n"

	_, err := fmt.Fprint(l.config.Writer, formattedMessage)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR DE LOGGING: %v\n", err)
	}
}

// formatFields convierte campos en clave=valor usando strings.Builder de alto rendimiento.
func formatFields(fields map[string]interface{}) string {
	var sb strings.Builder
	first := true
	for k, v := range fields {
		if !first {
			sb.WriteString(", ")
		}
		sb.WriteString(fmt.Sprintf("%s=%v", k, v))
		first = false
	}
	return sb.String()
}

// =============================================================================
// Métodos Públicos de Instancia (Texto Plano)
// =============================================================================

func (l *Logger) Trace(message string)   { l.log(TraceLevel, message) }
func (l *Logger) Debug(message string)   { l.log(DebugLevel, message) }
func (l *Logger) Info(message string)    { l.log(InfoLevel, message) }
func (l *Logger) Success(message string) { l.log(SuccessLevel, message) }
func (l *Logger) Warn(message string)    { l.log(WarnLevel, message) }
func (l *Logger) Error(message string)   { l.log(ErrorLevel, message) }
func (l *Logger) Fatal(message string)   { l.log(FatalLevel, message) }
func (l *Logger) Panic(message string)   { l.log(PanicLevel, message) }

// =============================================================================
// Métodos Públicos de Instancia (Campos Contextuales)
// =============================================================================

func (l *Logger) InfoWithFields(message string, fields map[string]interface{}) {
	l.logWithFields(InfoLevel, message, fields)
}

func (l *Logger) ErrorWithFields(message string, fields map[string]interface{}) {
	l.logWithFields(ErrorLevel, message, fields)
}

func (l *Logger) DebugWithFields(message string, fields map[string]interface{}) {
	l.logWithFields(DebugLevel, message, fields)
}

func (l *Logger) WarnWithFields(message string, fields map[string]interface{}) {
	l.logWithFields(WarnLevel, message, fields)
}

func (l *Logger) SuccessWithFields(message string, fields map[string]interface{}) {
	l.logWithFields(SuccessLevel, message, fields)
}
