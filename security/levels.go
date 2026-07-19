package security

import "time"

// =============================================================================
// Niveles de Seguridad
// =============================================================================

// Level representa el nivel de rigor en las políticas de seguridad aplicadas.
// Cada nivel ajusta automáticamente los valores predeterminados de hashing,
// expiración de tokens, límites de intentos y restricciones de sesión.
//
// PRINCIPIO DE DISEÑO: "Seguridad por defecto". Si el usuario no configura
// nada, LevelMedium se aplica automáticamente, garantizando un baseline seguro.
type Level uint8

const (
	// LevelLow: Para entornos de desarrollo o aplicaciones internas de bajo riesgo.
	// Hashing rápido (bcrypt cost 10), tokens de larga duración (24h),
	// límites permisivos. NO usar en producción con datos sensibles.
	LevelLow Level = iota

	// LevelMedium: Para aplicaciones estándar de producción (recomendado por defecto).
	// Equilibrio entre seguridad y rendimiento. Bcrypt cost 12, JWT 1h,
	// 5 intentos de login antes de bloqueo.
	LevelMedium

	// LevelHigh: Para aplicaciones que manejan datos sensibles (PII, finanzas, salud).
	// Hashing robusto (bcrypt cost 14), tokens de corta duración (15min),
	// rotación obligatoria de refresh tokens, 3 intentos antes de bloqueo.
	LevelHigh

	// LevelCritical: Para infraestructura crítica, banca, gobierno o sistemas
	// con requerimientos regulatorios estrictos. Bcrypt cost 15 (o Argon2),
	// JWT de 5min, 2FA obligatorio, bloqueo de 24h tras 3 intentos.
	LevelCritical
)

// SecurityDefaults define los parámetros base para cada nivel de seguridad.
// Estos valores son el resultado de auditorías de seguridad y recomendaciones
// de OWASP, NIST y otros estándares de la industria.
type SecurityDefaults struct {
	// Hashing de contraseñas
	BcryptCost int // Costo computacional (10-15). Mayor = más seguro pero más lento.

	// Tokens
	AccessTokenDuration  time.Duration // Validez del token de acceso principal
	RefreshTokenDuration time.Duration // Validez del token de renovación

	// Rate limiting y protección contra fuerza bruta
	MaxLoginAttempts        int           // Intentos máximos antes de bloqueo
	LockoutDuration         time.Duration // Tiempo de bloqueo tras superar intentos
	PasswordResetMaxPerHour int           // Máximo de resets de contraseña por hora

	// Sesiones
	MaxConcurrentSessions int           // Máximo de sesiones activas por usuario
	SessionTimeout        time.Duration // Tiempo máximo absoluto de sesión
	IdleTimeout           time.Duration // Tiempo de inactividad antes de cerrar sesión

	// 2FA / MFA
	Require2FA bool // Si true, 2FA es obligatorio para todos los usuarios
}

// GetDefaults devuelve la configuración segura predeterminada para un nivel dado.
// Si el nivel no es válido, retorna LevelMedium como fallback seguro.
//
// Ejemplo de uso:
//
//	defaults := security.LevelHigh.GetDefaults()
//	fmt.Println(defaults.BcryptCost)          // 14
//	fmt.Println(defaults.AccessTokenDuration) // 15m0s
func (l Level) GetDefaults() SecurityDefaults {
	switch l {
	case LevelLow:
		return SecurityDefaults{
			BcryptCost:              10,
			AccessTokenDuration:     24 * time.Hour,
			RefreshTokenDuration:    30 * 24 * time.Hour,
			MaxLoginAttempts:        10,
			LockoutDuration:         5 * time.Minute,
			PasswordResetMaxPerHour: 5,
			MaxConcurrentSessions:   5,
			SessionTimeout:          7 * 24 * time.Hour,
			IdleTimeout:             24 * time.Hour,
			Require2FA:              false,
		}

	case LevelMedium:
		return SecurityDefaults{
			BcryptCost:              12,
			AccessTokenDuration:     1 * time.Hour,
			RefreshTokenDuration:    7 * 24 * time.Hour,
			MaxLoginAttempts:        5,
			LockoutDuration:         15 * time.Minute,
			PasswordResetMaxPerHour: 3,
			MaxConcurrentSessions:   3,
			SessionTimeout:          24 * time.Hour,
			IdleTimeout:             30 * time.Minute,
			Require2FA:              false,
		}

	case LevelHigh:
		return SecurityDefaults{
			BcryptCost:              14,
			AccessTokenDuration:     15 * time.Minute,
			RefreshTokenDuration:    24 * time.Hour,
			MaxLoginAttempts:        3,
			LockoutDuration:         1 * time.Hour,
			PasswordResetMaxPerHour: 2,
			MaxConcurrentSessions:   2,
			SessionTimeout:          8 * time.Hour,
			IdleTimeout:             15 * time.Minute,
			Require2FA:              true,
		}

	case LevelCritical:
		return SecurityDefaults{
			BcryptCost:              15,
			AccessTokenDuration:     5 * time.Minute,
			RefreshTokenDuration:    12 * time.Hour,
			MaxLoginAttempts:        3,
			LockoutDuration:         24 * time.Hour,
			PasswordResetMaxPerHour: 1,
			MaxConcurrentSessions:   1,
			SessionTimeout:          2 * time.Hour,
			IdleTimeout:             5 * time.Minute,
			Require2FA:              true,
		}

	default:
		// Fallback seguro: siempre usar al menos LevelMedium
		return LevelMedium.GetDefaults()
	}
}

// String devuelve la representación en texto del nivel de seguridad.
// Útil para logging y mensajes de auditoría.
func (l Level) String() string {
	switch l {
	case LevelLow:
		return "LOW"
	case LevelMedium:
		return "MEDIUM"
	case LevelHigh:
		return "HIGH"
	case LevelCritical:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}

// IsValid verifica si el nivel está dentro del rango válido.
func (l Level) IsValid() bool {
	return l >= LevelLow && l <= LevelCritical
}
