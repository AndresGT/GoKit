package logger

import (
	"bytes"
	"strings"
	"sync"
	"testing"
)

// TestNewLogger prueba la creación básica del logger
func TestNewLogger(t *testing.T) {
	logger := New()
	if logger == nil {
		t.Fatal("Expected non-nil logger")
	}
	if logger.config.Level != InfoLevel {
		t.Errorf("Expected default level InfoLevel, got %v", logger.config.Level)
	}
	if logger.config.EnableColor != true {
		t.Error("Expected color enabled by default")
	}
	if logger.config.ShowDate != true {
		t.Error("Expected ShowDate enabled by default")
	}
	if logger.config.ShowTime != true {
		t.Error("Expected ShowTime enabled by default")
	}
}

// TestLoggerWithOptions prueba la configuración con opciones
func TestLoggerWithOptions(t *testing.T) {
	var buf bytes.Buffer
	logger := New(
		WithWriter(&buf),
		WithLevel(DebugLevel),
		WithColor(false),
		WithDateTime(true, false),
	)

	if logger.config.Level != DebugLevel {
		t.Errorf("Expected DebugLevel, got %v", logger.config.Level)
	}
	if logger.config.EnableColor != false {
		t.Error("Expected color disabled")
	}
	if logger.config.ShowDate != true {
		t.Error("Expected ShowDate enabled")
	}
	if logger.config.ShowTime != false {
		t.Error("Expected ShowTime disabled")
	}
}

// TestLoggerAllLevels prueba todos los niveles de log
func TestLoggerAllLevels(t *testing.T) {
	tests := []struct {
		name   string
		level  Level
		method func(*Logger, string)
		prefix string
	}{
		{"Trace", TraceLevel, func(l *Logger, m string) { l.Trace(m) }, "[TRACE]"},
		{"Debug", DebugLevel, func(l *Logger, m string) { l.Debug(m) }, "[DEBUG]"},
		{"Info", InfoLevel, func(l *Logger, m string) { l.Info(m) }, "[INFO]"},
		{"Success", SuccessLevel, func(l *Logger, m string) { l.Success(m) }, "[SUCCESS]"},
		{"Warn", WarnLevel, func(l *Logger, m string) { l.Warn(m) }, "[WARN]"},
		{"Error", ErrorLevel, func(l *Logger, m string) { l.Error(m) }, "[ERROR]"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			logger := New(
				WithWriter(&buf),
				WithLevel(TraceLevel),
				WithColor(false),
				WithDateTime(false, false),
			)

			tt.method(logger, "test message")

			output := buf.String()
			if !strings.Contains(output, tt.prefix) {
				t.Errorf("Expected prefix %s in output, got: %s", tt.prefix, output)
			}
			if !strings.Contains(output, "test message") {
				t.Errorf("Expected 'test message' in output, got: %s", output)
			}
		})
	}
}

// TestLoggerLevelFiltering prueba el filtrado por niveles
func TestLoggerLevelFiltering(t *testing.T) {
	tests := []struct {
		name       string
		minLevel   Level
		logLevel   Level
		shouldLog  bool
		logMessage string
	}{
		{"Info logs when min is Info", InfoLevel, InfoLevel, true, "info msg"},
		{"Info does not log when min is Warn", WarnLevel, InfoLevel, false, "info msg"},
		{"Error logs when min is Warn", WarnLevel, ErrorLevel, true, "error msg"},
		{"Debug does not log when min is Info", InfoLevel, DebugLevel, false, "debug msg"},
		{"Warn logs when min is Warn", WarnLevel, WarnLevel, true, "warn msg"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			logger := New(
				WithWriter(&buf),
				WithLevel(tt.minLevel),
				WithColor(false),
				WithDateTime(false, false),
			)

			switch tt.logLevel {
			case TraceLevel:
				logger.Trace(tt.logMessage)
			case DebugLevel:
				logger.Debug(tt.logMessage)
			case InfoLevel:
				logger.Info(tt.logMessage)
			case SuccessLevel:
				logger.Success(tt.logMessage)
			case WarnLevel:
				logger.Warn(tt.logMessage)
			case ErrorLevel:
				logger.Error(tt.logMessage)
			}

			output := buf.String()
			if tt.shouldLog && output == "" {
				t.Errorf("Expected output for level %v with min level %v, got empty", tt.logLevel, tt.minLevel)
			}
			if !tt.shouldLog && output != "" {
				t.Errorf("Expected no output for level %v with min level %v, got: %s", tt.logLevel, tt.minLevel, output)
			}
		})
	}
}

// TestInfoWithFields prueba InfoWithFields
func TestInfoWithFields(t *testing.T) {
	var buf bytes.Buffer
	logger := New(
		WithWriter(&buf),
		WithLevel(InfoLevel),
		WithColor(false),
		WithDateTime(false, false),
	)

	fields := map[string]interface{}{
		"user_id":   123,
		"username":  "john_doe",
		"active":    true,
		"score":     95.5,
	}

	logger.InfoWithFields("User logged in", fields)

	output := buf.String()
	if !strings.Contains(output, "[INFO]") {
		t.Errorf("Expected [INFO] in output, got: %s", output)
	}
	if !strings.Contains(output, "User logged in") {
		t.Errorf("Expected 'User logged in' in output, got: %s", output)
	}
	if !strings.Contains(output, "user_id=123") {
		t.Errorf("Expected 'user_id=123' in output, got: %s", output)
	}
	if !strings.Contains(output, "username=john_doe") {
		t.Errorf("Expected 'username=john_doe' in output, got: %s", output)
	}
	if !strings.Contains(output, "active=true") {
		t.Errorf("Expected 'active=true' in output, got: %s", output)
	}
	if !strings.Contains(output, "score=95.5") {
		t.Errorf("Expected 'score=95.5' in output, got: %s", output)
	}
}

// TestErrorWithFields prueba ErrorWithFields
func TestErrorWithFields(t *testing.T) {
	var buf bytes.Buffer
	logger := New(
		WithWriter(&buf),
		WithLevel(ErrorLevel),
		WithColor(false),
		WithDateTime(false, false),
	)

	fields := map[string]interface{}{
		"error_code": 500,
		"message":    "internal server error",
		"path":       "/api/users",
	}

	logger.ErrorWithFields("Database connection failed", fields)

	output := buf.String()
	if !strings.Contains(output, "[ERROR]") {
		t.Errorf("Expected [ERROR] in output, got: %s", output)
	}
	if !strings.Contains(output, "Database connection failed") {
		t.Errorf("Expected 'Database connection failed' in output, got: %s", output)
	}
	if !strings.Contains(output, "error_code=500") {
		t.Errorf("Expected 'error_code=500' in output, got: %s", output)
	}
	if !strings.Contains(output, "path=/api/users") {
		t.Errorf("Expected 'path=/api/users' in output, got: %s", output)
	}
}

// TestDebugWithFields prueba DebugWithFields
func TestDebugWithFields(t *testing.T) {
	var buf bytes.Buffer
	logger := New(
		WithWriter(&buf),
		WithLevel(DebugLevel),
		WithColor(false),
		WithDateTime(false, false),
	)

	fields := map[string]interface{}{
		"query":    "SELECT * FROM users",
		"duration": "45ms",
		"rows":     10,
	}

	logger.DebugWithFields("Query executed", fields)

	output := buf.String()
	if !strings.Contains(output, "[DEBUG]") {
		t.Errorf("Expected [DEBUG] in output, got: %s", output)
	}
	if !strings.Contains(output, "Query executed") {
		t.Errorf("Expected 'Query executed' in output, got: %s", output)
	}
	if !strings.Contains(output, "query=SELECT * FROM users") {
		t.Errorf("Expected 'query=SELECT * FROM users' in output, got: %s", output)
	}
	if !strings.Contains(output, "duration=45ms") {
		t.Errorf("Expected 'duration=45ms' in output, got: %s", output)
	}
	if !strings.Contains(output, "rows=10") {
		t.Errorf("Expected 'rows=10' in output, got: %s", output)
	}
}

// TestWarnWithFields prueba WarnWithFields
func TestWarnWithFields(t *testing.T) {
	var buf bytes.Buffer
	logger := New(
		WithWriter(&buf),
		WithLevel(WarnLevel),
		WithColor(false),
		WithDateTime(false, false),
	)

	fields := map[string]interface{}{
		"retry_count": 3,
		"max_retries": 5,
		"service":     "payment_gateway",
	}

	logger.WarnWithFields("Service degraded", fields)

	output := buf.String()
	if !strings.Contains(output, "[WARN]") {
		t.Errorf("Expected [WARN] in output, got: %s", output)
	}
	if !strings.Contains(output, "Service degraded") {
		t.Errorf("Expected 'Service degraded' in output, got: %s", output)
	}
	if !strings.Contains(output, "retry_count=3") {
		t.Errorf("Expected 'retry_count=3' in output, got: %s", output)
	}
	if !strings.Contains(output, "service=payment_gateway") {
		t.Errorf("Expected 'service=payment_gateway' in output, got: %s", output)
	}
}

// TestSuccessWithFields prueba SuccessWithFields
func TestSuccessWithFields(t *testing.T) {
	var buf bytes.Buffer
	logger := New(
		WithWriter(&buf),
		WithLevel(SuccessLevel),
		WithColor(false),
		WithDateTime(false, false),
	)

	fields := map[string]interface{}{
		"transaction_id": "txn_123456",
		"amount":         150.00,
		"currency":       "USD",
	}

	logger.SuccessWithFields("Payment processed", fields)

	output := buf.String()
	if !strings.Contains(output, "[SUCCESS]") {
		t.Errorf("Expected [SUCCESS] in output, got: %s", output)
	}
	if !strings.Contains(output, "Payment processed") {
		t.Errorf("Expected 'Payment processed' in output, got: %s", output)
	}
	if !strings.Contains(output, "transaction_id=txn_123456") {
		t.Errorf("Expected 'transaction_id=txn_123456' in output, got: %s", output)
	}
	if !strings.Contains(output, "amount=150") {
		t.Errorf("Expected 'amount=150' in output, got: %s", output)
	}
}

// TestWithFieldsEmptyFields prueba campos vacíos
func TestWithFieldsEmptyFields(t *testing.T) {
	var buf bytes.Buffer
	logger := New(
		WithWriter(&buf),
		WithLevel(InfoLevel),
		WithColor(false),
		WithDateTime(false, false),
	)

	logger.InfoWithFields("Simple message", map[string]interface{}{})

	output := buf.String()
	if !strings.Contains(output, "[INFO]") {
		t.Errorf("Expected [INFO] in output, got: %s", output)
	}
	if !strings.Contains(output, "Simple message") {
		t.Errorf("Expected 'Simple message' in output, got: %s", output)
	}
	// No debería tener separador de campos si está vacío
	if strings.Contains(output, " | ") {
		t.Errorf("Expected no field separator for empty fields, got: %s", output)
	}
}

// TestWithFieldsNilFields prueba campos nil
func TestWithFieldsNilFields(t *testing.T) {
	var buf bytes.Buffer
	logger := New(
		WithWriter(&buf),
		WithLevel(InfoLevel),
		WithColor(false),
		WithDateTime(false, false),
	)

	logger.InfoWithFields("Simple message", nil)

	output := buf.String()
	if !strings.Contains(output, "[INFO]") {
		t.Errorf("Expected [INFO] in output, got: %s", output)
	}
	if !strings.Contains(output, "Simple message") {
		t.Errorf("Expected 'Simple message' in output, got: %s", output)
	}
	// No debería tener separador de campos si es nil
	if strings.Contains(output, " | ") {
		t.Errorf("Expected no field separator for nil fields, got: %s", output)
	}
}

// TestWithFieldsLevelFiltering prueba que WithFields respeta el nivel de log
func TestWithFieldsLevelFiltering(t *testing.T) {
	var buf bytes.Buffer
	logger := New(
		WithWriter(&buf),
		WithLevel(WarnLevel),
		WithColor(false),
		WithDateTime(false, false),
	)

	fields := map[string]interface{}{"key": "value"}

	// Info no debería loguearse cuando el nivel mínimo es Warn
	logger.InfoWithFields("Info message", fields)

	output := buf.String()
	if output != "" {
		t.Errorf("Expected no output for Info when min level is Warn, got: %s", output)
	}

	// Warn sí debería loguearse
	buf.Reset()
	logger.WarnWithFields("Warn message", fields)

	output = buf.String()
	if output == "" {
		t.Error("Expected output for Warn when min level is Warn")
	}
	if !strings.Contains(output, "[WARN]") {
		t.Errorf("Expected [WARN] in output, got: %s", output)
	}
}

// TestGlobalLoggerFunctions prueba las funciones globales del logger
func TestGlobalLoggerFunctions(t *testing.T) {
	var buf bytes.Buffer
	oldLogger := GetDefault()

	globalLogger := New(
		WithWriter(&buf),
		WithLevel(InfoLevel),
		WithColor(false),
		WithDateTime(false, false),
	)
	SetDefault(globalLogger)
	defer SetDefault(oldLogger)

	Info("Global info message")

	output := buf.String()
	if !strings.Contains(output, "[INFO]") {
		t.Errorf("Expected [INFO] in global output, got: %s", output)
	}
	if !strings.Contains(output, "Global info message") {
		t.Errorf("Expected 'Global info message' in global output, got: %s", output)
	}
}

// TestGlobalWithFieldsFunctions prueba las funciones globales con campos
func TestGlobalWithFieldsFunctions(t *testing.T) {
	var buf bytes.Buffer
	oldLogger := GetDefault()

	globalLogger := New(
		WithWriter(&buf),
		WithLevel(InfoLevel),
		WithColor(false),
		WithDateTime(false, false),
	)
	SetDefault(globalLogger)
	defer SetDefault(oldLogger)

	fields := map[string]interface{}{
		"request_id": "req_789",
		"method":     "POST",
	}

	InfoWithFields("Global request", fields)

	output := buf.String()
	if !strings.Contains(output, "[INFO]") {
		t.Errorf("Expected [INFO] in global output, got: %s", output)
	}
	if !strings.Contains(output, "Global request") {
		t.Errorf("Expected 'Global request' in global output, got: %s", output)
	}
	if !strings.Contains(output, "request_id=req_789") {
		t.Errorf("Expected 'request_id=req_789' in output, got: %s", output)
	}
	if !strings.Contains(output, "method=POST") {
		t.Errorf("Expected 'method=POST' in output, got: %s", output)
	}
}

// TestLoggerConcurrency prueba la concurrencia del logger
func TestLoggerConcurrency(t *testing.T) {
	var buf bytes.Buffer
	logger := New(
		WithWriter(&buf),
		WithLevel(InfoLevel),
		WithColor(false),
		WithDateTime(false, false),
	)

	var wg sync.WaitGroup
	numGoroutines := 100
	msgsPerGoroutine := 10

	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < msgsPerGoroutine; j++ {
				logger.InfoWithFields("Concurrent message", map[string]interface{}{
					"goroutine": id,
					"msg_num":   j,
				})
			}
		}(i)
	}

	wg.Wait()

	expectedMessages := numGoroutines * msgsPerGoroutine
	output := buf.String()
	lines := strings.Split(strings.TrimSpace(output), "\n")

	if len(lines) != expectedMessages {
		t.Errorf("Expected %d log lines, got %d", expectedMessages, len(lines))
	}
}

// TestFormatterWithDateTime prueba el formateo con fecha y hora
func TestFormatterWithDateTime(t *testing.T) {
	var buf bytes.Buffer
	logger := New(
		WithWriter(&buf),
		WithLevel(InfoLevel),
		WithColor(false),
		WithDateTime(true, true),
	)

	logger.Info("DateTime test")

	output := buf.String()
	// Debería contener fecha (YYYY-MM-DD) y hora (HH:MM:SS)
	if !strings.Contains(output, "[INFO]") {
		t.Errorf("Expected [INFO] in output, got: %s", output)
	}
	// Verificar formato básico de fecha y hora
	parts := strings.Fields(output)
	if len(parts) < 4 {
		t.Errorf("Expected at least 4 parts (date time level message), got: %v", parts)
	}
}

// TestFormatterWithoutDateTime prueba el formateo sin fecha y hora
func TestFormatterWithoutDateTime(t *testing.T) {
	var buf bytes.Buffer
	logger := New(
		WithWriter(&buf),
		WithLevel(InfoLevel),
		WithColor(false),
		WithDateTime(false, false),
	)

	logger.Info("No DateTime test")

	output := buf.String()
	if !strings.Contains(output, "[INFO]") {
		t.Errorf("Expected [INFO] in output, got: %s", output)
	}
	if !strings.Contains(output, "No DateTime test") {
		t.Errorf("Expected 'No DateTime test' in output, got: %s", output)
	}
	// Verificar que NO contiene fecha ni hora (formato YYYY-MM-DD o HH:MM:SS)
	if strings.Contains(output, "-") && len(strings.Split(output, "-")) >= 3 {
		// Podría contener guiones del formato de fecha
		parts := strings.Split(output, "-")
		if len(parts) >= 3 && len(parts[0]) == 4 {
			t.Errorf("Expected no date in output, but found date-like format: %s", output)
		}
	}
}

// TestFormatFields prueba la función formatFields
func TestFormatFields(t *testing.T) {
	fields := map[string]interface{}{
		"key1": "value1",
		"key2": 42,
		"key3": true,
	}

	result := formatFields(fields)

	// Verificar que contiene todos los campos
	if !strings.Contains(result, "key1=value1") {
		t.Errorf("Expected 'key1=value1' in result, got: %s", result)
	}
	if !strings.Contains(result, "key2=42") {
		t.Errorf("Expected 'key2=42' in result, got: %s", result)
	}
	if !strings.Contains(result, "key3=true") {
		t.Errorf("Expected 'key3=true' in result, got: %s", result)
	}

	// Verificar separador
	if !strings.Contains(result, ", ") {
		t.Errorf("Expected ', ' separator in result, got: %s", result)
	}
}

// TestFormatFieldsEmpty prueba formatFields con mapa vacío
func TestFormatFieldsEmpty(t *testing.T) {
	fields := map[string]interface{}{}

	result := formatFields(fields)

	if result != "" {
		t.Errorf("Expected empty string for empty fields, got: %s", result)
	}
}

// TestLevelMethods prueba los métodos del tipo Level
func TestLevelMethods(t *testing.T) {
	tests := []struct {
		level          Level
		expectedStr    string
		expectedPrefix string
		isValid        bool
	}{
		{TraceLevel, "TRACE", "[TRACE]", true},
		{DebugLevel, "DEBUG", "[DEBUG]", true},
		{InfoLevel, "INFO", "[INFO]", true},
		{SuccessLevel, "SUCCESS", "[SUCCESS]", true},
		{WarnLevel, "WARN", "[WARN]", true},
		{ErrorLevel, "ERROR", "[ERROR]", true},
		{FatalLevel, "FATAL", "[FATAL]", true},
		{PanicLevel, "PANIC", "[PANIC]", true},
		{Level(99), "UNKNOWN", "[UNKNOWN]", false},
	}

	for _, tt := range tests {
		t.Run(tt.level.String(), func(t *testing.T) {
			if tt.level.String() != tt.expectedStr {
				t.Errorf("Expected String()=%s, got %s", tt.expectedStr, tt.level.String())
			}
			if tt.level.Prefix() != tt.expectedPrefix {
				t.Errorf("Expected Prefix()=%s, got %s", tt.expectedPrefix, tt.level.Prefix())
			}
			if tt.level.IsValid() != tt.isValid {
				t.Errorf("Expected IsValid()=%v, got %v", tt.isValid, tt.level.IsValid())
			}
		})
	}
}

// TestLevelEnabled prueba el método Enabled del tipo Level
func TestLevelEnabled(t *testing.T) {
	tests := []struct {
		level    Level
		minLevel Level
		expected bool
	}{
		{InfoLevel, InfoLevel, true},
		{InfoLevel, DebugLevel, true},  // Info >= Debug, así que está habilitado
		{InfoLevel, WarnLevel, false},  // Info < Warn, así que NO está habilitado
		{ErrorLevel, WarnLevel, true},  // Error >= Warn, así que está habilitado
		{DebugLevel, InfoLevel, false}, // Debug < Info, así que NO está habilitado
		{WarnLevel, TraceLevel, true},  // Warn >= Trace, así que está habilitado
	}

	for _, tt := range tests {
		name := tt.level.String() + "_vs_" + tt.minLevel.String()
		t.Run(name, func(t *testing.T) {
			result := tt.level.Enabled(tt.minLevel)
			if result != tt.expected {
				t.Errorf("Expected %v.Enabled(%v)=%v, got %v",
					tt.level, tt.minLevel, tt.expected, result)
			}
		})
	}
}

// TestGetDefault prueba la función GetDefault
func TestGetDefault(t *testing.T) {
	logger := GetDefault()
	if logger == nil {
		t.Fatal("Expected non-nil default logger")
	}
	// El logger por defecto debería tener nivel Info
	if logger.config.Level != InfoLevel {
		t.Errorf("Expected default logger level InfoLevel, got %v", logger.config.Level)
	}
}

// TestSetDefault prueba la función SetDefault
func TestSetDefault(t *testing.T) {
	oldLogger := GetDefault()
	defer SetDefault(oldLogger)

	var buf bytes.Buffer
	newLogger := New(
		WithWriter(&buf),
		WithLevel(DebugLevel),
		WithColor(false),
	)

	SetDefault(newLogger)

	// Usar funciones globales que deberían usar el nuevo logger
	Debug("Test debug message")

	output := buf.String()
	if !strings.Contains(output, "[DEBUG]") {
		t.Errorf("Expected [DEBUG] in output after SetDefault, got: %s", output)
	}
}

// TestSetDefaultNil prueba SetDefault con nil
func TestSetDefaultNil(t *testing.T) {
	oldLogger := GetDefault()

	// No debería causar panic
	SetDefault(nil)

	// El logger por defecto debería seguir siendo el mismo
	currentLogger := GetDefault()
	if currentLogger != oldLogger {
		t.Error("Expected default logger to remain unchanged when setting nil")
	}
}
