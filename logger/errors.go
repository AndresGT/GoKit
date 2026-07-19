package logger

import "errors"

// =============================================================================
// Errores del Paquete
// =============================================================================

var (
	// ErrInvalidLevel se retorna cuando se intenta usar o configurar un nivel 
	// de log que está fuera del rango válido (TraceLevel a PanicLevel).
	ErrInvalidLevel = errors.New("nivel de log inválido")

	// ErrWriteFailed se retorna cuando el logger no puede escribir el mensaje 
	// en el destino (Writer) configurado (ej. disco lleno, permisos denegados).
	ErrWriteFailed = errors.New("fallo al escribir el mensaje de log")

	// ErrInvalidFilePath se retorna cuando la ruta proporcionada para el archivo 
	// de log no es válida, no se puede crear o no tiene permisos de escritura.
	ErrInvalidFilePath = errors.New("ruta de archivo de log inválida o inaccesible")
)