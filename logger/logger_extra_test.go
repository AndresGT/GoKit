package logger

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// failWriter falla siempre al escribir
type failWriter struct{}

func (failWriter) Write(p []byte) (int, error) {
	return 0, errors.New("write failed")
}

// TestGlobalLoggerAllLevels cubre las funciones globales de todos los niveles
func TestGlobalLoggerAllLevels(t *testing.T) {
	old := GetDefault()
	defer SetDefault(old)

	tests := []struct {
		name   string
		level  Level
		method func(string)
	}{
		{"Trace", TraceLevel, Trace},
		{"Debug", DebugLevel, Debug},
		{"Info", InfoLevel, Info},
		{"Success", SuccessLevel, Success},
		{"Warn", WarnLevel, Warn},
		{"Error", ErrorLevel, Error},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			SetDefault(New(WithWriter(&buf), WithLevel(tt.level), WithColor(false), WithDateTime(false, false)))
			tt.method("global " + tt.name)
			if !strings.Contains(buf.String(), "[INFO]") && !strings.Contains(buf.String(), strings.ToUpper(tt.name)) {
				t.Errorf("expected output for global %s", tt.name)
			}
			if buf.String() == "" {
				t.Errorf("expected non-empty output for global %s", tt.name)
			}
		})
	}
}

// TestGlobalWithFieldsAllLevels cubre las funciones globales *WithFields
func TestGlobalWithFieldsAllLevels(t *testing.T) {
	old := GetDefault()
	defer SetDefault(old)

	tests := []struct {
		name   string
		level  Level
		method func(string, map[string]interface{})
	}{
		{"Debug", DebugLevel, DebugWithFields},
		{"Info", InfoLevel, InfoWithFields},
		{"Success", SuccessLevel, SuccessWithFields},
		{"Warn", WarnLevel, WarnWithFields},
		{"Error", ErrorLevel, ErrorWithFields},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			SetDefault(New(WithWriter(&buf), WithLevel(tt.level), WithColor(false), WithDateTime(false, false)))
			tt.method("global fields", map[string]interface{}{"k": "v"})
			if buf.String() == "" {
				t.Errorf("expected non-empty output for global %s", tt.name)
			}
			if !strings.Contains(buf.String(), "k=v") {
				t.Errorf("expected fields in output for global %s", tt.name)
			}
		})
	}
}

// TestFatalLog prueba el nivel Fatal sin salir del proceso
func TestFatalLog(t *testing.T) {
	var buf bytes.Buffer
	logger := New(WithWriter(&buf), WithLevel(FatalLevel), WithColor(false), WithDateTime(false, false))

	oldExit := exitProcess
	exited := false
	exitProcess = func(code int) { exited = true }
	defer func() { exitProcess = oldExit }()

	logger.Fatal("fatal message")

	if !exited {
		t.Error("expected exitProcess to be called")
	}
	if !strings.Contains(buf.String(), "[FATAL]") {
		t.Errorf("expected [FATAL] in output, got: %s", buf.String())
	}
}

// TestPanicLog prueba el nivel Panic y recupera el panic
func TestPanicLog(t *testing.T) {
	var buf bytes.Buffer
	logger := New(WithWriter(&buf), WithLevel(PanicLevel), WithColor(false), WithDateTime(false, false))

	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic to be raised")
		}
	}()
	logger.Panic("panic message")
}

// TestGlobalFatal prueba la función global Fatal
func TestGlobalFatal(t *testing.T) {
	old := GetDefault()
	defer SetDefault(old)
	oldExit := exitProcess
	exitProcess = func(code int) {}
	defer func() { exitProcess = oldExit }()

	var buf bytes.Buffer
	SetDefault(New(WithWriter(&buf), WithLevel(FatalLevel), WithColor(false), WithDateTime(false, false)))
	Fatal("global fatal")
	if buf.String() == "" {
		t.Error("expected output for global Fatal")
	}
}

// TestGlobalPanic prueba la función global Panic
func TestGlobalPanic(t *testing.T) {
	old := GetDefault()
	defer SetDefault(old)

	var buf bytes.Buffer
	SetDefault(New(WithWriter(&buf), WithLevel(PanicLevel), WithColor(false), WithDateTime(false, false)))

	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic from global Panic")
		}
	}()
	Panic("global panic")
}

// TestLogWriterError cubre el error al escribir en el writer
func TestLogWriterError(t *testing.T) {
	logger := New(WithWriter(failWriter{}), WithLevel(InfoLevel), WithColor(false), WithDateTime(false, false))
	logger.Info("this write will fail")
}

// TestLogWithFieldsWriterError cubre el error al escribir con campos
func TestLogWithFieldsWriterError(t *testing.T) {
	logger := New(WithWriter(failWriter{}), WithLevel(InfoLevel), WithColor(false), WithDateTime(false, false))
	logger.InfoWithFields("this write will fail", map[string]interface{}{"k": "v"})
}

// TestLevelColor cubre el método Color para todos los niveles
func TestLevelColor(t *testing.T) {
	levels := []Level{TraceLevel, DebugLevel, InfoLevel, SuccessLevel, WarnLevel, ErrorLevel, FatalLevel, PanicLevel}
	for _, l := range levels {
		if l.Color() == "" {
			t.Errorf("expected color for level %v", l)
		}
	}
	if Level(200).Color() != "" {
		t.Error("expected empty color for invalid level")
	}
}

// TestFormatterColorEnabled cubre formatLevel con color habilitado
func TestFormatterColorEnabled(t *testing.T) {
	formatter := NewFormatter(Config{EnableColor: true, ShowDate: false, ShowTime: false})
	out := formatter.Format(InfoLevel, "colored")
	if !strings.Contains(out, "\033[") {
		t.Errorf("expected ANSI color codes, got: %q", out)
	}
	if !strings.Contains(out, "colored") {
		t.Errorf("expected message in output, got: %q", out)
	}
}

// TestSetAndResetTheme cubre SetTheme y ResetTheme
func TestSetAndResetTheme(t *testing.T) {
	old := theme
	defer ResetTheme()

	SetTheme(Theme{
		Trace: "1", Debug: "2", Info: "3", Success: "4",
		Warn: "5", Error: "6", Fatal: "7", Panic: "8", Reset: "0",
	})

	if theme.Info != "3" {
		t.Error("expected theme to be replaced")
	}

	ResetTheme()
	if theme != defaultTheme {
		t.Error("expected theme to be reset")
	}

	_ = old
}

// TestColorizeNoColor cubre colorize sin color
func TestColorizeNoColor(t *testing.T) {
	if got := colorize("", "text"); got != "text" {
		t.Errorf("expected 'text', got %q", got)
	}
	if got := colorize("red", "text"); got != "red"+"text"+theme.Reset {
		t.Errorf("unexpected colorized output: %q", got)
	}
}

// TestConsoleWriter cubre NewConsoleWriter
func TestConsoleWriter(t *testing.T) {
	if NewConsoleWriter() != os.Stdout {
		t.Error("expected console writer to be os.Stdout")
	}
}

// TestFileWriterSuccess cubre NewFileWriter exitoso
func TestFileWriterSuccess(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "app.log")

	w, err := NewFileWriter(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, err := io.WriteString(w, "line1\n"); err != nil {
		t.Fatalf("write failed: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}
	if string(data) != "line1\n" {
		t.Errorf("unexpected content: %q", string(data))
	}

	w.(io.Closer).Close()
}

// TestFileWriterDirError cubre NewFileWriter con ruta que no se puede crear
func TestFileWriterDirError(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(tmp, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	// El directorio no puede crearse porque "blocker" es un archivo
	_, err := NewFileWriter(filepath.Join(tmp, "nested", "app.log"))
	if err == nil {
		t.Error("expected error creating writer under a file")
	}
}

// TestFileWriterOpenError cubre NewFileWriter abriendo un directorio
func TestFileWriterOpenError(t *testing.T) {
	dir := t.TempDir()
	_, err := NewFileWriter(dir)
	if err == nil {
		t.Error("expected error opening a directory as file")
	}
}

// TestMultiWriter cubre NewMultiWriter
func TestMultiWriter(t *testing.T) {
	var a, b bytes.Buffer
	w := NewMultiWriter(&a, &b)
	_, err := io.WriteString(w, "hello")
	if err != nil {
		t.Fatal(err)
	}
	if a.String() != "hello" || b.String() != "hello" {
		t.Error("expected both writers to receive content")
	}
}

// TestWithFileOutputEmpty cubre WithFileOutput con ruta vacía
func TestWithFileOutputEmpty(t *testing.T) {
	logger := New(WithFileOutput(""))
	if logger.config.Writer != os.Stdout {
		t.Error("expected default writer when path is empty")
	}
}

// TestWithFileOutputSuccess cubre WithFileOutput exitoso
func TestWithFileOutputSuccess(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.log")
	logger := New(WithFileOutput(path))
	if logger.config.Writer == os.Stdout {
		t.Error("expected file writer to be set")
	}
	if logger.config.EnableColor {
		t.Error("expected color to be disabled for file output")
	}
}

// TestWithFileOutputError cubre WithFileOutput con error
func TestWithFileOutputError(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(tmp, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	logger := New(WithFileOutput(filepath.Join(tmp, "nested", "app.log")))
	if logger.config.Writer != os.Stdout {
		t.Error("expected writer to remain default on error")
	}
}

// TestWithLevelInvalid cubre WithLevel con nivel inválido
func TestWithLevelInvalid(t *testing.T) {
	logger := New(WithLevel(Level(200)))
	if logger.config.Level != InfoLevel {
		t.Error("expected level to remain default when invalid")
	}
}

// TestWithWriterNil cubre WithWriter con nil
func TestWithWriterNil(t *testing.T) {
	logger := New(WithWriter(nil))
	if logger.config.Writer == nil {
		t.Error("expected writer to default to stdout when nil")
	}
}
