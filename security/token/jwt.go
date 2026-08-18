package token

import (
	"errors"
	"time"

	"github.com/AndresGT/GoKit/security"
	"github.com/AndresGT/GoKit/security/crypto"
	"github.com/golang-jwt/jwt/v5"
)

// =============================================================================
// Errores de JWT
// =============================================================================

var (
	// ErrJWTInvalid se retorna cuando el token JWT está mal formado o es inválido.
	// Es un error genérico que no revela detalles internos.
	ErrJWTInvalid = errors.New("token JWT inválido")

	// ErrJWTExpired se retorna cuando el token JWT ha expirado.
	ErrJWTExpired = errors.New("token JWT expirado")

	// ErrJWTSigningMethodInvalid se retorna cuando el método de firma del token
	// no es el esperado (previene ataques de confusión de algoritmos).
	ErrJWTSigningMethodInvalid = errors.New("método de firma JWT inválido")
)

// =============================================================================
// Claims Personalizados
// =============================================================================

// Claims representa los claims personalizados del JWT.
// Incluye los claims estándar de JWT (RegisteredClaims) más campos
// específicos de la aplicación.
type Claims struct {
	jwt.RegisteredClaims

	// UserID es el identificador único del usuario autenticado.
	UserID string `json:"user_id"`

	// Username es el nombre de usuario (opcional, para logging/auditoría).
	Username string `json:"username,omitempty"`

	// Role es el rol del usuario (ej. "admin", "user", "moderator").
	Role string `json:"role,omitempty"`

	// Email es el email del usuario (opcional).
	Email string `json:"email,omitempty"`

	// SessionID es el identificador único de la sesión asociada.
	// Permite revocar sesiones específicas sin invalidar todos los tokens.
	SessionID string `json:"session_id,omitempty"`

	// DeviceInfo contiene información del dispositivo (opcional).
	DeviceInfo string `json:"device_info,omitempty"`

	// IPAddress es la IP desde donde se generó el token (opcional, para auditoría).
	IPAddress string `json:"ip_address,omitempty"`

	// TokenType indica si el token es de acceso ("access") o de renovación
	// ("refresh"). Permite rechazar un access token si se usa donde se
	// espera un refresh token, y viceversa.
	TokenType string `json:"token_type,omitempty"`
}

// Tipos de token soportados, usados en el claim TokenType.
const (
	// TokenTypeAccess identifica un access token.
	TokenTypeAccess = "access"

	// TokenTypeRefresh identifica un refresh token.
	TokenTypeRefresh = "refresh"
)

// =============================================================================
// Configuración del Manager de JWT
// =============================================================================

// JWTConfig define la configuración para el manager de JWT.
type JWTConfig struct {
	// SecretKey es la clave secreta para firmar los tokens.
	// Debe tener al menos 32 bytes para HMAC-SHA256.
	SecretKey []byte

	// Issuer es el emisor del token (ej. "gokit-auth", "api.example.com").
	Issuer string

	// AccessTokenDuration es la duración del token de acceso.
	// Si es 0, se usa el valor predeterminado del nivel de seguridad.
	AccessTokenDuration time.Duration

	// RefreshTokenDuration es la duración del token de renovación.
	// Si es 0, se usa el valor predeterminado del nivel de seguridad.
	RefreshTokenDuration time.Duration

	// SecurityLevel define el nivel de seguridad para usar valores predeterminados.
	// Si no se especifica, se usa LevelMedium.
	SecurityLevel security.Level
}

// =============================================================================
// Manager de JWT
// =============================================================================

// JWTManager maneja la generación y validación de tokens JWT.
type JWTManager struct {
	config JWTConfig
}

// NewJWTManager crea un nuevo manager de JWT con la configuración proporcionada.
// Si no se especifican duraciones, se usan los valores predeterminados del nivel
// de seguridad configurado.
//
// Ejemplo de uso:
//
//	// Con configuración manual
//	manager, err := token.NewJWTManager(token.JWTConfig{
//	    SecretKey:             []byte("mi-clave-secreta-de-32-bytes!!"),
//	    Issuer:                "gokit-auth",
//	    AccessTokenDuration:   15 * time.Minute,
//	    RefreshTokenDuration:  7 * 24 * time.Hour,
//	})
//
//	// Con nivel de seguridad (usa valores predeterminados)
//	manager, err := token.NewJWTManager(token.JWTConfig{
//	    SecretKey:     []byte("mi-clave-secreta-de-32-bytes!!"),
//	    Issuer:        "gokit-auth",
//	    SecurityLevel: security.LevelHigh,
//	})
func NewJWTManager(config JWTConfig) (*JWTManager, error) {
	// Validar clave secreta
	if len(config.SecretKey) < 32 {
		return nil, errors.New("la clave secreta debe tener al menos 32 bytes")
	}

	// Aplicar valores predeterminados del nivel de seguridad si no se especificaron
	defaults := config.SecurityLevel.GetDefaults()

	if config.AccessTokenDuration == 0 {
		config.AccessTokenDuration = defaults.AccessTokenDuration
	}

	if config.RefreshTokenDuration == 0 {
		config.RefreshTokenDuration = defaults.RefreshTokenDuration
	}

	return &JWTManager{
		config: config,
	}, nil
}

// GenerateAccessToken genera un token de acceso (access token) con los claims proporcionados.
// El token tendrá la duración configurada en AccessTokenDuration.
//
// Ejemplo de uso:
//
//	claims := token.Claims{
//	    UserID:    "user-123",
//	    Username:  "john_doe",
//	    Role:      "admin",
//	    SessionID: "session-abc-123",
//	}
//
//	accessToken, err := jwtManager.GenerateAccessToken(claims)
//	if err != nil {
//	    // Manejar error
//	}
func (m *JWTManager) GenerateAccessToken(claims Claims) (string, error) {
	claims.TokenType = TokenTypeAccess
	return m.generateToken(claims, m.config.AccessTokenDuration)
}

// GenerateRefreshToken genera un token de renovación (refresh token) con los claims proporcionados.
// El token tendrá la duración configurada en RefreshTokenDuration.
//
// Los refresh tokens deben almacenarse de forma segura en la base de datos
// y usarse para generar nuevos access tokens cuando el actual expire.
//
// Ejemplo de uso:
//
//	claims := token.Claims{
//	    UserID:    "user-123",
//	    SessionID: "session-abc-123",
//	}
//
//	refreshToken, err := jwtManager.GenerateRefreshToken(claims)
//	if err != nil {
//	    // Manejar error
//	}
func (m *JWTManager) GenerateRefreshToken(claims Claims) (string, error) {
	claims.TokenType = TokenTypeRefresh
	return m.generateToken(claims, m.config.RefreshTokenDuration)
}

// generateUUID es inyectable para poder probar el camino de error.
var generateUUID = crypto.GenerateUUID

// generateToken es el método interno que genera tokens JWT.
func (m *JWTManager) generateToken(claims Claims, duration time.Duration) (string, error) {
	// Establecer claims estándar
	now := time.Now()
	claims.IssuedAt = jwt.NewNumericDate(now)
	claims.ExpiresAt = jwt.NewNumericDate(now.Add(duration))
	claims.Issuer = m.config.Issuer

	// Generar ID único para el token (jti)
	tokenID, err := generateUUID()
	if err != nil {
		return "", ErrJWTInvalid
	}
	claims.ID = tokenID

	// Crear el token con HMAC-SHA256
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Firmar el token
	return token.SignedString(m.config.SecretKey)
}

// ValidateToken valida un token JWT y retorna los claims si es válido.
// Verifica:
//   - Firma del token
//   - Expiración
//   - Emisor
//   - Método de firma (previene ataques de confusión de algoritmos)
//
// Ejemplo de uso:
//
//	claims, err := jwtManager.ValidateToken(tokenString)
//	if err != nil {
//	    if errors.Is(err, token.ErrJWTExpired) {
//	        // Token expirado, requerir refresh
//	    }
//	    // Token inválido
//	}
//
//	// Usar los claims
//	fmt.Println(claims.UserID)
//	fmt.Println(claims.Role)
func (m *JWTManager) ValidateToken(tokenString string) (*Claims, error) {
	parser := jwt.NewParser(jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}))

	token, err := parser.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return m.config.SecretKey, nil
	})

	if err != nil {
		// Diferenciar entre token expirado y otros errores
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrJWTExpired
		}
		return nil, ErrJWTInvalid
	}

	// Extraer claims
	claims := token.Claims.(*Claims)

	if m.config.Issuer != "" && claims.Issuer != m.config.Issuer {
		return nil, ErrJWTInvalid
	}

	return claims, nil
}

// RefreshAccessToken genera un nuevo access token usando un refresh token válido.
// Esto permite renovar la sesión sin requerir que el usuario vuelva a autenticarse.
//
// IMPORTANTE: Después de usar un refresh token, debe ser invalidado y reemplazado
// por uno nuevo (rotación de tokens) para prevenir ataques de replay.
//
// Ejemplo de uso:
//
//	newAccessToken, err := jwtManager.RefreshAccessToken(refreshTokenString)
//	if err != nil {
//	    // Refresh token inválido o expirado, requerir re-autenticación
//	}
func (m *JWTManager) RefreshAccessToken(refreshTokenString string) (string, error) {
	// Validar el refresh token
	claims, err := m.ValidateToken(refreshTokenString)
	if err != nil {
		return "", err
	}

	// Rechazar el token si no es un refresh token (evita que un access
	// token robado o filtrado se use para generar nuevos access tokens).
	if claims.TokenType != TokenTypeRefresh {
		return "", ErrJWTInvalid
	}

	// Generar nuevo access token con los mismos datos del usuario
	// pero sin copiar el SessionID (se mantiene el mismo)
	newClaims := Claims{
		UserID:     claims.UserID,
		Username:   claims.Username,
		Role:       claims.Role,
		Email:      claims.Email,
		SessionID:  claims.SessionID,
		DeviceInfo: claims.DeviceInfo,
		IPAddress:  claims.IPAddress,
	}

	return m.GenerateAccessToken(newClaims)
}

// GetConfig retorna la configuración actual del manager.
// Útil para debugging o para verificar los valores configurados.
func (m *JWTManager) GetConfig() JWTConfig {
	return m.config
}

// =============================================================================
// API Global a Nivel de Paquete (Fachada Simplificada)
// =============================================================================

var defaultManager *JWTManager

func init() {
	// Instancia global inicializada por defecto con credenciales dev/locales.
	// Esto asegura que la app funcione out-of-the-box sin romper al arrancar.
	defaultManager, _ = NewJWTManager(JWTConfig{
		SecretKey:            []byte("gokit-default-super-secret-key-32bytes!!"),
		Issuer:               "gokit-api",
		AccessTokenDuration:  15 * time.Minute,
		RefreshTokenDuration: 7 * 24 * time.Hour,
	})
}

// Init permite reconfigurar el manager global al iniciar la app desde main.go.
//
// Ejemplo:
//
//	token.Init(token.JWTConfig{
//	    SecretKey: []byte(os.Getenv("JWT_SECRET")),
//	    Issuer:    "mi-proyecto",
//	})
func Init(config JWTConfig) error {
	manager, err := NewJWTManager(config)
	if err != nil {
		return err
	}
	defaultManager = manager
	return nil
}

// GetDefault devuelve la instancia global actual del JWTManager.
func GetDefault() *JWTManager {
	return defaultManager
}

// --- Funciones globales de uso directo a nivel de paquete ---

// GenerateAccessToken crea un access token utilizando el manager global.
func GenerateAccessToken(claims Claims) (string, error) {
	return defaultManager.GenerateAccessToken(claims)
}

// GenerateRefreshToken crea un refresh token utilizando el manager global.
func GenerateRefreshToken(claims Claims) (string, error) {
	return defaultManager.GenerateRefreshToken(claims)
}

// ValidateToken valida un token JWT utilizando el manager global.
func ValidateToken(tokenString string) (*Claims, error) {
	return defaultManager.ValidateToken(tokenString)
}

// RefreshAccessToken renueva un access token usando el manager global.
func RefreshAccessToken(refreshTokenString string) (string, error) {
	return defaultManager.RefreshAccessToken(refreshTokenString)
}

// =============================================================================
// Funciones Helper de Uso Rápido (Uso Directo sin Configurar Manager)
// =============================================================================

// GenerateQuickToken genera un access token rápido con configuración por defecto.
// Ideal para prototipado o pruebas rápidas. No recomendado para producción.
//
// Ejemplo:
//
//	tokenStr, err := token.GenerateQuickToken("user-123", "admin")
func GenerateQuickToken(userID, role string) (string, error) {
	claims := Claims{
		UserID: userID,
		Role:   role,
	}
	return defaultManager.GenerateAccessToken(claims)
}

// GenerateQuickTokenWithEmail genera un access token rápido incluyendo email.
// Ideal para prototipado o pruebas rápidas.
//
// Ejemplo:
//
//	tokenStr, err := token.GenerateQuickTokenWithEmail("user-123", "john@example.com", "user")
func GenerateQuickTokenWithEmail(userID, email, role string) (string, error) {
	claims := Claims{
		UserID: userID,
		Email:  email,
		Role:   role,
	}
	return defaultManager.GenerateAccessToken(claims)
}

// ValidateQuickToken valida un token usando la configuración global.
// Retorna true si el token es válido, false en caso contrario.
//
// Ejemplo:
//
//	if token.ValidateQuickToken(tokenStr) {
//	    // Token válido
//	}
func ValidateQuickToken(tokenString string) bool {
	_, err := defaultManager.ValidateToken(tokenString)
	return err == nil
}

// ExtractUserID extrae el UserID de un token sin validar completamente.
// Útil para logging o auditoría antes de la validación formal.
//
// Ejemplo:
//
//	userID := token.ExtractUserID(tokenStr)
func ExtractUserID(tokenString string) string {
	claims, err := defaultManager.ValidateToken(tokenString)
	if err != nil {
		return ""
	}
	return claims.UserID
}

// ExtractClaims extrae todos los claims de un token validado.
// Retorna nil si el token es inválido.
//
// Ejemplo:
//
//	claims := token.ExtractClaims(tokenStr)
//	if claims != nil {
//	    fmt.Println(claims.Role)
//	}
func ExtractClaims(tokenString string) *Claims {
	claims, err := defaultManager.ValidateToken(tokenString)
	if err != nil {
		return nil
	}
	return claims
}