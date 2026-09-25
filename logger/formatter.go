package logger

import (
	"strings"
	"time"
)

type Formatter struct {
	config Config
}

func NewFormatter(cfg Config) *Formatter {
	return &Formatter{
		config: cfg,
	}
}

func (f *Formatter) Format(level Level, message string) string {
	var sb strings.Builder
	now := time.Now()

	if f.config.ShowDate && f.config.ShowTime {
		sb.WriteString(now.Format("2006-01-02 15:04:05"))
		sb.WriteString(" ")
	} else if f.config.ShowDate {
		sb.WriteString(now.Format("2006-01-02"))
		sb.WriteString(" ")
	} else if f.config.ShowTime {
		sb.WriteString(now.Format("15:04:05"))
		sb.WriteString(" ")
	}

	if f.config.ShowLevel {
		sb.WriteString(f.formatLevel(level))
		sb.WriteString(" ")
	}

	sb.WriteString(message)

	sb.WriteString("\n")

	return sb.String()
}

func (f *Formatter) formatLevel(level Level) string {
	prefix := level.Prefix()

	if f.config.EnableColor {
		return colorize(level.Color(), prefix)
	}

	return prefix
}
