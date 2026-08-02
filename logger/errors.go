package logger

import "errors"

var (
	ErrInvalidLevel = errors.New("nivel de log inválido")
	ErrWriteFailed = errors.New("fallo al escribir el mensaje de log")
	ErrInvalidFilePath = errors.New("ruta de archivo de log inválida o inaccesible")
)
