package token

import (
	"errors"
	"time"

	"github.com/AndresGT/GoKit/security"
	"github.com/AndresGT/GoKit/security/crypto"
	"github.com/golang-jwt/jwt/v5"
)

var (
	ErrJWTInvalid              = errors.New("token JWT inválido")
	ErrJWTExpired              = errors.New("token JWT expirado")
	ErrJWTSigningMethodInvalid = errors.New("método de firma JWT inválido")
)

type Claims struct {
	jwt.RegisteredClaims

	UserID     string                 `json:"user_id"`
	Username   string                 `json:"username,omitempty"`
	Role       string                 `json:"role,omitempty"`
	Email      string                 `json:"email,omitempty"`
	SessionID  string                 `json:"session_id,omitempty"`
	DeviceInfo string                 `json:"device_info,omitempty"`
	IPAddress  string                 `json:"ip_address,omitempty"`
	TokenType  string                 `json:"token_type,omitempty"`
	CustomData map[string]interface{} `json:"custom_data,omitempty"`
}

const (
	TokenTypeAccess  = "access"
	TokenTypeRefresh = "refresh"
)

type JWTConfig struct {
	SecretKey            []byte
	Issuer               string
	AccessTokenDuration  time.Duration
	RefreshTokenDuration time.Duration
	SecurityLevel        security.Level
}

type JWTManager struct {
	config JWTConfig
}

func NewJWTManager(config JWTConfig) (*JWTManager, error) {
	if len(config.SecretKey) < 32 {
		return nil, errors.New("la clave secreta debe tener al menos 32 bytes")
	}

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

func (m *JWTManager) GenerateAccessToken(claims Claims) (string, error) {
	claims.TokenType = TokenTypeAccess
	return m.generateToken(claims, m.config.AccessTokenDuration)
}

func (m *JWTManager) GenerateRefreshToken(claims Claims) (string, error) {
	claims.TokenType = TokenTypeRefresh
	return m.generateToken(claims, m.config.RefreshTokenDuration)
}

var generateUUID = crypto.GenerateUUID

func (m *JWTManager) generateToken(claims Claims, duration time.Duration) (string, error) {
	now := time.Now()
	claims.IssuedAt = jwt.NewNumericDate(now)
	claims.ExpiresAt = jwt.NewNumericDate(now.Add(duration))
	claims.Issuer = m.config.Issuer

	tokenID, err := generateUUID()
	if err != nil {
		return "", ErrJWTInvalid
	}
	claims.ID = tokenID

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	return token.SignedString(m.config.SecretKey)
}

func (m *JWTManager) ValidateToken(tokenString string) (*Claims, error) {
	parser := jwt.NewParser(jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}))

	token, err := parser.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return m.config.SecretKey, nil
	})

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrJWTExpired
		}
		return nil, ErrJWTInvalid
	}

	claims := token.Claims.(*Claims)

	if m.config.Issuer != "" && claims.Issuer != m.config.Issuer {
		return nil, ErrJWTInvalid
	}

	return claims, nil
}

func (m *JWTManager) RefreshAccessToken(refreshTokenString string) (string, error) {
	claims, err := m.ValidateToken(refreshTokenString)
	if err != nil {
		return "", err
	}

	if claims.TokenType != TokenTypeRefresh {
		return "", ErrJWTInvalid
	}

	newClaims := Claims{
		UserID:     claims.UserID,
		Username:   claims.Username,
		Role:       claims.Role,
		Email:      claims.Email,
		SessionID:  claims.SessionID,
		DeviceInfo: claims.DeviceInfo,
		IPAddress:  claims.IPAddress,
		CustomData: claims.CustomData,
	}

	return m.GenerateAccessToken(newClaims)
}

func (m *JWTManager) GetConfig() JWTConfig {
	return m.config
}

var defaultManager *JWTManager

func init() {
	defaultManager, _ = NewJWTManager(JWTConfig{
		SecretKey:            []byte("gokit-default-super-secret-key-32bytes!!"),
		Issuer:               "gokit-api",
		AccessTokenDuration:  15 * time.Minute,
		RefreshTokenDuration: 7 * 24 * time.Hour,
	})
}

func Init(config JWTConfig) error {
	manager, err := NewJWTManager(config)
	if err != nil {
		return err
	}
	defaultManager = manager
	return nil
}

func GetDefault() *JWTManager {
	return defaultManager
}

func GenerateAccessToken(claims Claims) (string, error) {
	return defaultManager.GenerateAccessToken(claims)
}

func GenerateRefreshToken(claims Claims) (string, error) {
	return defaultManager.GenerateRefreshToken(claims)
}

func ValidateToken(tokenString string) (*Claims, error) {
	return defaultManager.ValidateToken(tokenString)
}

func RefreshAccessToken(refreshTokenString string) (string, error) {
	return defaultManager.RefreshAccessToken(refreshTokenString)
}

func GenerateQuickToken(userID, role string) (string, error) {
	claims := Claims{
		UserID: userID,
		Role:   role,
	}
	return defaultManager.GenerateAccessToken(claims)
}

func GenerateQuickTokenWithEmail(userID, email, role string) (string, error) {
	claims := Claims{
		UserID: userID,
		Email:  email,
		Role:   role,
	}
	return defaultManager.GenerateAccessToken(claims)
}

func ValidateQuickToken(tokenString string) bool {
	_, err := defaultManager.ValidateToken(tokenString)
	return err == nil
}

func ExtractUserID(tokenString string) string {
	claims, err := defaultManager.ValidateToken(tokenString)
	if err != nil {
		return ""
	}
	return claims.UserID
}

func ExtractClaims(tokenString string) *Claims {
	claims, err := defaultManager.ValidateToken(tokenString)
	if err != nil {
		return nil
	}
	return claims
}
