package logger

import (
	"fmt"
	"os"
	"strings"
	"sync"
)

var defaultLogger *Logger

// exitProcess permite redirigir os.Exit en pruebas
var exitProcess = os.Exit

func init() {
	defaultLogger = New()
}

func SetDefault(l *Logger) {
	if l != nil {
		defaultLogger = l
	}
}

func GetDefault() *Logger {
	return defaultLogger
}

func Trace(message string)   { defaultLogger.Trace(message) }
func Debug(message string)   { defaultLogger.Debug(message) }
func Info(message string)    { defaultLogger.Info(message) }
func Success(message string) { defaultLogger.Success(message) }
func Warn(message string)    { defaultLogger.Warn(message) }
func Error(message string)   { defaultLogger.Error(message) }
func Fatal(message string)   { defaultLogger.Fatal(message) }
func Panic(message string)   { defaultLogger.Panic(message) }

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

type Logger struct {
	mu        sync.Mutex
	config    Config
	formatter *Formatter
}

func New(opts ...Option) *Logger {
	cfg := NewConfig()

	for _, opt := range opts {
		opt(&cfg)
	}

	return &Logger{
		config:    cfg,
		formatter: NewFormatter(cfg),
	}
}

func (l *Logger) log(level Level, message string) {
	if !level.Enabled(l.config.Level) {
		return
	}

	func() {
		l.mu.Lock()
		defer l.mu.Unlock()

		formattedMessage := l.formatter.Format(level, message) + "\n"

		_, err := fmt.Fprint(l.config.Writer, formattedMessage)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR DE LOGGING: %v\n", err)
		}
	}()

	if level == FatalLevel {
		exitProcess(1)
	}

	if level == PanicLevel {
		panic(message)
	}
}

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

func formatFields(fields map[string]any) string {
	var sb strings.Builder
	first := true
	for k, v := range fields {
		if !first {
			sb.WriteString(", ")
		}
		fmt.Fprintf(&sb, "%s=%v", k, v)
		first = false
	}
	return sb.String()
}

func (l *Logger) Trace(message string)   { l.log(TraceLevel, message) }
func (l *Logger) Debug(message string)   { l.log(DebugLevel, message) }
func (l *Logger) Info(message string)    { l.log(InfoLevel, message) }
func (l *Logger) Success(message string) { l.log(SuccessLevel, message) }
func (l *Logger) Warn(message string)    { l.log(WarnLevel, message) }
func (l *Logger) Error(message string)   { l.log(ErrorLevel, message) }
func (l *Logger) Fatal(message string)   { l.log(FatalLevel, message) }
func (l *Logger) Panic(message string)   { l.log(PanicLevel, message) }

func (l *Logger) InfoWithFields(message string, fields map[string]any) {
	l.logWithFields(InfoLevel, message, fields)
}

func (l *Logger) ErrorWithFields(message string, fields map[string]any) {
	l.logWithFields(ErrorLevel, message, fields)
}

func (l *Logger) DebugWithFields(message string, fields map[string]any) {
	l.logWithFields(DebugLevel, message, fields)
}

func (l *Logger) WarnWithFields(message string, fields map[string]any) {
	l.logWithFields(WarnLevel, message, fields)
}

func (l *Logger) SuccessWithFields(message string, fields map[string]any) {
	l.logWithFields(SuccessLevel, message, fields)
}
