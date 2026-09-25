package logger

import (
	"fmt"
	"io"
	"os"
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

func WithShowDate(showDate bool) Option {
	return func(c *Config) {
		c.ShowDate = showDate
	}
}

func WithShowTime(showTime bool) Option {
	return func(c *Config) {
		c.ShowTime = showTime
	}
}

func WithFileOutput(filePath string) Option {
	return func(c *Config) {
		if filePath == "" {
			return
		}
		w, err := NewFileWriter(filePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "logger: failed to open %s: %v\n", filePath, err)
			return
		}
		c.Writer = w
		c.EnableColor = false
	}
}
