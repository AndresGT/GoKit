package logger

import (
	"io"
)

type Option func(*Config)

func WithLevel(level Level) Option {
	return func(c *Config) {
		if level.IsValid() {
			c.Level = level
		}
	}
}

func WithWriter(w io.Writer) Option {
	return func(c *Config) {
		if w != nil {
			c.Writer = w
		}
	}
}

func WithColor(enable bool) Option {
	return func(c *Config) {
		c.EnableColor = enable
	}
}

func WithDateTime(showDate, showTime bool) Option {
	return func(c *Config) {
		c.ShowDate = showDate
		c.ShowTime = showTime
	}
}

func WithFileOutput(filePath string) Option {
	return func(c *Config) {
		if filePath == "" {
			return
		}
		if w, err := NewFileWriter(filePath); err == nil {
			c.Writer = w
			c.EnableColor = false 
		}
	}
}
