package logger

import (
	"io"
	"os"
)

type Config struct {
	Writer      io.Writer
	Level       Level
	EnableColor bool
	ShowDate    bool
	ShowTime    bool
}

var defaultConfig = Config{
	Level:       InfoLevel,
	Writer:      os.Stdout,
	EnableColor: true,
	ShowDate:    true,
	ShowTime:    true,
}

func NewConfig() Config {
	return defaultConfig
}
