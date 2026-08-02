package logger

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
	Trace   string // Color para el nivel TRACE
	Debug   string // Color para el nivel DEBUG
	Info    string // Color para el nivel INFO
	Success string // Color para el nivel SUCCESS
	Warn    string // Color para el nivel WARN
	Error   string // Color para el nivel ERROR
	Fatal   string // Color para el nivel FATAL
	Panic   string // Color para el nivel PANIC
	Reset   string // Código para restablecer el color al final de cada mensaje
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

var theme = defaultTheme

func SetTheme(t Theme) {
	theme = t
}

func ResetTheme() {
	theme = defaultTheme
}
func colorize(color, text string) string {
	if color == "" {
		return text
	}
	return color + text + theme.Reset
}
