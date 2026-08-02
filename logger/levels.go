package logger

type Level uint8

const (
	TraceLevel Level = iota
	DebugLevel
	InfoLevel
	SuccessLevel
	WarnLevel
	ErrorLevel
	FatalLevel
	PanicLevel
)
	

var levelNames = [...]string{
	"TRACE",
	"DEBUG",
	"INFO",
	"SUCCESS",
	"WARN",
	"ERROR",
	"FATAL",
	"PANIC",
}

func (l Level) String() string {
	if !l.IsValid() {
		return "UNKNOWN"
	}
	return levelNames[l]
}


func (l Level) Enabled(min Level) bool {
	return l >= min
}

func (l Level) Prefix() string {
	return "[" + l.String() + "]"
}

func (l Level) IsValid() bool {
	return l >= TraceLevel && l <= PanicLevel
}

func (l Level) Color() string {
	if !l.IsValid() {
		return ""
	}

	switch l {
	case TraceLevel:
		return theme.Trace
	case DebugLevel:
		return theme.Debug
	case InfoLevel:
		return theme.Info
	case SuccessLevel:
		return theme.Success
	case WarnLevel:
		return theme.Warn
	case ErrorLevel:
		return theme.Error
	case FatalLevel:
		return theme.Fatal
	case PanicLevel:
		return theme.Panic
	default:
		return ""
	}
}