package logger

import "sync"

const (
	colorReset = "\033[0m"

	colorGray    = "\033[90m"
	colorBlue    = "\033[34m"
	colorCyan    = "\033[36m"
	colorGreen   = "\033[32m"
	colorYellow  = "\033[33m"
	colorRed     = "\033[31m"
	colorMagenta = "\033[35m"

	colorBgRed = "\033[41m"
	colorWhite = "\033[97m"
)

type Theme struct {
	Trace   string
	Debug   string
	Info    string
	Success string
	Warn    string
	Error   string
	Fatal   string
	Panic   string
	Reset   string
}

var defaultTheme = Theme{
	Trace:   colorGray,
	Debug:   colorBlue,
	Info:    colorCyan,
	Success: colorGreen,
	Warn:    colorYellow,
	Error:   colorRed,
	Fatal:   colorMagenta,
	Panic:   colorBgRed + colorWhite,
	Reset:   colorReset,
}

var (
	themeMu sync.RWMutex
	theme   = defaultTheme
)

func SetTheme(t Theme) {
	themeMu.Lock()
	defer themeMu.Unlock()
	theme = t
}

func ResetTheme() {
	themeMu.Lock()
	defer themeMu.Unlock()
	theme = defaultTheme
}

func GetTheme() Theme {
	themeMu.RLock()
	defer themeMu.RUnlock()
	return theme
}

func colorize(color, text string) string {
	if color == "" {
		return text
	}
	return color + text + colorReset
}
