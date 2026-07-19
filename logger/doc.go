// Package logger provides a modular, concurrent-safe, and colorful logging utility for GoKit applications.
//
// It supports multiple log levels (Trace, Debug, Info, Success, Warn, Error, Fatal, Panic),
// customizable themes, and flexible output destinations (console, file, or both via io.MultiWriter).
//
// Basic usage:
//
//	log := logger.New(logger.NewConfig())
//	log.Info("Aplicación iniciada correctamente")
//	log.Error("No se pudo conectar a la base de datos")
//
// Advanced usage with file output and custom level:
//
//	cfg := logger.NewConfig()
//	cfg.Level = logger.DebugLevel
//	cfg.Writer = logger.NewMultiWriter(logger.NewConsoleWriter(), fileWriter)
//	log := logger.New(cfg)
//	log.Debug("Conectando a la base de datos...")
package logger