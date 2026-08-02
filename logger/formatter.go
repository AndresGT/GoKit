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

	if f.config.ShowDate {
		sb.WriteString(f.formatDate())
		sb.WriteString(" ")
	}

	if f.config.ShowTime {
		sb.WriteString(f.formatTime())
		sb.WriteString(" ")
	}

	sb.WriteString(f.formatLevel(level))
	sb.WriteString(" ")

	sb.WriteString(message)

	return sb.String()
}

func (f *Formatter) formatDate() string {
	return time.Now().Format("2006-01-02")
}

func (f *Formatter) formatTime() string {
	return time.Now().Format("15:04:05")
}

func (f *Formatter) formatLevel(level Level) string {
	prefix := level.Prefix()
	
	if f.config.EnableColor {
		return colorize(level.Color(), prefix)
	}
	
	return prefix
}

func (f *Formatter) join(parts ...string) string {
	return strings.Join(parts, " ")
}