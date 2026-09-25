package logger

import (
	"fmt"
	"os"
	"strings"
	"sync"
)

var (
	defaultLoggerMu sync.RWMutex
	defaultLogger   *Logger
)

var exitProcess = os.Exit

func init() {
	defaultLogger = New()
}

func SetDefault(l *Logger) {
	if l == nil {
		return
	}
	defaultLoggerMu.Lock()
	defer defaultLoggerMu.Unlock()
	defaultLogger = l
}

func GetDefault() *Logger {
	defaultLoggerMu.RLock()
	defer defaultLoggerMu.RUnlock()
	return defaultLogger
}

func Trace(message string)   { GetDefault().Trace(message) }
func Debug(message string)   { GetDefault().Debug(message) }
func Info(message string)    { GetDefault().Info(message) }
func Success(message string) { GetDefault().Success(message) }
func Warn(message string)    { GetDefault().Warn(message) }
func Error(message string)   { GetDefault().Error(message) }
func Fatal(message string)   { GetDefault().Fatal(message) }
func Panic(message string)   { GetDefault().Panic(message) }

func InfoWithFields(msg string, fields map[string]any)  { GetDefault().InfoWithFields(msg, fields) }
func ErrorWithFields(msg string, fields map[string]any) { GetDefault().ErrorWithFields(msg, fields) }
func DebugWithFields(msg string, fields map[string]any) { GetDefault().DebugWithFields(msg, fields) }
func WarnWithFields(msg string, fields map[string]any)  { GetDefault().WarnWithFields(msg, fields) }
func SuccessWithFields(msg string, fields map[string]any) {
	GetDefault().SuccessWithFields(msg, fields)
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

func (l *Logger) log(level Level, message string, fields map[string]any) {
	if !level.Enabled(l.config.Level) {
		return
	}

	finalMsg := message
	if len(fields) > 0 {
		finalMsg = fmt.Sprintf("%s | %s", message, formatFields(fields))
	}

	l.mu.Lock()
	formattedMessage := l.formatter.Format(level, finalMsg)
	_, err := fmt.Fprint(l.config.Writer, formattedMessage)
	l.mu.Unlock()

	if err != nil {
		fmt.Fprintf(os.Stderr, "logger: error writing log: %v\n", err)
	}

	if level == FatalLevel {
		exitProcess(1)
	}

	if level == PanicLevel {
		panic(message)
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

func (l *Logger) Trace(message string)   { l.log(TraceLevel, message, nil) }
func (l *Logger) Debug(message string)   { l.log(DebugLevel, message, nil) }
func (l *Logger) Info(message string)    { l.log(InfoLevel, message, nil) }
func (l *Logger) Success(message string) { l.log(SuccessLevel, message, nil) }
func (l *Logger) Warn(message string)    { l.log(WarnLevel, message, nil) }
func (l *Logger) Error(message string)   { l.log(ErrorLevel, message, nil) }
func (l *Logger) Fatal(message string)   { l.log(FatalLevel, message, nil) }
func (l *Logger) Panic(message string)   { l.log(PanicLevel, message, nil) }

func (l *Logger) InfoWithFields(message string, fields map[string]any) {
	l.log(InfoLevel, message, fields)
}

func (l *Logger) ErrorWithFields(message string, fields map[string]any) {
	l.log(ErrorLevel, message, fields)
}

func (l *Logger) DebugWithFields(message string, fields map[string]any) {
	l.log(DebugLevel, message, fields)
}

func (l *Logger) WarnWithFields(message string, fields map[string]any) {
	l.log(WarnLevel, message, fields)
}

func (l *Logger) SuccessWithFields(message string, fields map[string]any) {
	l.log(SuccessLevel, message, fields)
}
