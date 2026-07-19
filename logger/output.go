package logger

import (
	"io"
	"os"
	"path/filepath"
)

// =============================================================================
// Gestión de Salidas (Outputs)
// =============================================================================

// NewConsoleWriter devuelve un io.Writer que escribe en la salida estándar (consola).
// Es el comportamiento predeterminado, pero se expone explícitamente por claridad.
func NewConsoleWriter() io.Writer {
	return os.Stdout
}

// NewFileWriter crea y devuelve un io.Writer que escribe en el archivo especificado.
// Si el archivo no existe, intenta crearlo. Si los directorios intermedios no existen,
// intenta crearlos también. El archivo se abre en modo append (añadir al final).
//
// Ejemplo de uso:
//
//	writer, err := logger.NewFileWriter("logs/app.log")
//	if err != nil {
//	    log.Fatal(err)
//	}
func NewFileWriter(filePath string) (io.Writer, error) {
	// Asegurar que el directorio donde se guardará el archivo exista
	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, err
	}

	// Abrir el archivo en modo: crear si no existe, añadir al final, permisos 0644
	file, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}

	return file, nil
}

// NewMultiWriter combina múltiples destinos de escritura (por ejemplo, consola y archivo)
// en un único io.Writer. Cada mensaje de log se escribirá en todos los destinos proporcionados.
//
// Ejemplo de uso (Consola + Archivo):
//
//	fileWriter, _ := logger.NewFileWriter("logs/app.log")
//	combinedWriter := logger.NewMultiWriter(logger.NewConsoleWriter(), fileWriter)
func NewMultiWriter(writers ...io.Writer) io.Writer {
	return io.MultiWriter(writers...)
}