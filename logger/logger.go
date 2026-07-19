package logger

import (
	"fmt"
	"os"
	"strings"
	"sync"
)

// =============================================================================
// Núcleo del Logger
// =============================================================================

// Logger representa la instancia principal del sistema de logging.
// Es seguro para su uso concurrente (goroutine-safe) gracias al mutex interno,
// lo que permite que múltiples goroutines escriban logs simultáneamente sin
// condiciones de carrera ni corrupción de la salida.
type Logger struct {
	mu        sync.Mutex
	config    Config
	formatter *Formatter
}

// New crea y devuelve una nueva instancia de Logger.
// Acepta un número variable de opciones (Option) para configurar
// el logger de manera flexible, legible y segura.
//
// Ejemplo de uso:
//
//	log := logger.New(
//	    logger.WithLevel(logger.DebugLevel),
//	    logger.WithColor(false),
//	    logger.WithFileOutput("app.log"),
//	)
func New(opts ...Option) *Logger {
	// 1. Partimos de la configuración por defecto
	cfg := NewConfig()

	// 2. Aplicamos cada opción proporcionada por el usuario
	for _, opt := range opts {
		opt(&cfg)
	}

	// 3. Fallback de seguridad: si el writer sigue siendo nil, usamos Stdout
	if cfg.Writer == nil {
		cfg.Writer = os.Stdout
	}

	return &Logger{
		config:    cfg,
		formatter: NewFormatter(cfg),
	}
}

// =============================================================================
// Métodos Internos de Escritura
// =============================================================================

// log es el método central que maneja la concurrencia, el filtrado por nivel,
// el formateo y la escritura final del mensaje de texto plano.
func (l *Logger) log(level Level, message string) {
	// 1. Verificar si este nivel debe ser registrado según la configuración
	if !level.Enabled(l.config.Level) {
		return
	}

	// 2. Bloquear el mutex para garantizar seguridad en concurrencia
	l.mu.Lock()
	defer l.mu.Unlock()

	// 3. Formatear el mensaje
	formattedMessage := l.formatter.Format(level, message) + "\n"

	// 4. Escribir en el destino configurado
	_, err := fmt.Fprint(l.config.Writer, formattedMessage)
	if err != nil {
		// Si falla la escritura, intentamos reportarlo a stderr como último recurso
		fmt.Fprintf(os.Stderr, "ERROR DE LOGGING: %v\n", err)
	}

	// 5. Manejar comportamientos especiales para niveles críticos
	if level == FatalLevel {
		l.mu.Unlock() // Desbloquear antes de salir para evitar deadlocks
		os.Exit(1)
	}

	if level == PanicLevel {
		l.mu.Unlock()
		panic(message)
	}
}

// logWithFields es el método interno que maneja el registro de mensajes
// enriquecidos con campos contextuales (pares clave-valor). Aplica las mismas
// reglas de concurrencia y filtrado por nivel que el método log estándar,
// pero añade los metadatos al final del mensaje formateado.
func (l *Logger) logWithFields(level Level, message string, fields map[string]interface{}) {
	if !level.Enabled(l.config.Level) {
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	// Formatear mensaje base
	formattedMessage := l.formatter.Format(level, message)

	// Agregar campos contextuales si existen
	if len(fields) > 0 {
		formattedMessage += " | " + formatFields(fields)
	}

	formattedMessage += "\n"

	_, err := fmt.Fprint(l.config.Writer, formattedMessage)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR DE LOGGING: %v\n", err)
	}
}

// formatFields convierte un mapa de campos contextuales en una cadena
// de texto formateada como "key1=value1, key2=value2".
// Utiliza strings.Builder para garantizar un rendimiento óptimo y
// minimizar las asignaciones de memoria.
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
// Métodos Públicos de Logging (Texto Plano)
// =============================================================================

// Trace registra un mensaje de nivel TRACE (diagnóstico profundo).
func (l *Logger) Trace(message string) {
	l.log(TraceLevel, message)
}

// Debug registra un mensaje de nivel DEBUG (depuración).
func (l *Logger) Debug(message string) {
	l.log(DebugLevel, message)
}

// Info registra un mensaje de nivel INFO (información general).
func (l *Logger) Info(message string) {
	l.log(InfoLevel, message)
}

// Success registra un mensaje de nivel SUCCESS (operación exitosa).
func (l *Logger) Success(message string) {
	l.log(SuccessLevel, message)
}

// Warn registra un mensaje de nivel WARN (advertencia).
func (l *Logger) Warn(message string) {
	l.log(WarnLevel, message)
}

// Error registra un mensaje de nivel ERROR (fallo no crítico).
func (l *Logger) Error(message string) {
	l.log(ErrorLevel, message)
}

// Fatal registra un mensaje de nivel FATAL y termina la ejecución
// del programa con código de salida 1.
func (l *Logger) Fatal(message string) {
	l.log(FatalLevel, message)
}

// Panic registra un mensaje de nivel PANIC y dispara un panic
// en la aplicación después de registrar el mensaje.
func (l *Logger) Panic(message string) {
	l.log(PanicLevel, message)
}

// =============================================================================
// Métodos Públicos de Logging (Con Campos Contextuales)
// =============================================================================

// InfoWithFields registra un mensaje de nivel INFO junto con un mapa
// de campos contextuales adicionales. Es ideal para auditoría y debugging,
// permitiendo adjuntar metadatos como IP, User-Agent o IDs de transacción.
//
// Ejemplo:
//
//	log.InfoWithFields("usuario_autenticado", map[string]interface{}{
//	    "user_id": 123,
//	    "ip": "192.168.1.1",
//	})
func (l *Logger) InfoWithFields(message string, fields map[string]interface{}) {
	l.logWithFields(InfoLevel, message, fields)
}

// ErrorWithFields registra un mensaje de nivel ERROR con campos contextuales.
// Útil para registrar fallos junto con el estado del sistema en ese momento.
func (l *Logger) ErrorWithFields(message string, fields map[string]interface{}) {
	l.logWithFields(ErrorLevel, message, fields)
}

// DebugWithFields registra un mensaje de nivel DEBUG con campos contextuales.
func (l *Logger) DebugWithFields(message string, fields map[string]interface{}) {
	l.logWithFields(DebugLevel, message, fields)
}

// WarnWithFields registra un mensaje de nivel WARN con campos contextuales.
func (l *Logger) WarnWithFields(message string, fields map[string]interface{}) {
	l.logWithFields(WarnLevel, message, fields)
}

// SuccessWithFields registra un mensaje de nivel SUCCESS con campos contextuales.
func (l *Logger) SuccessWithFields(message string, fields map[string]interface{}) {
	l.logWithFields(SuccessLevel, message, fields)
}
