package crypto

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// =============================================================================
// Errores de Generación Aleatoria
// =============================================================================

var (
	// ErrInvalidLength se retorna cuando se solicita una longitud inválida
	// (negativa o cero) para la generación de datos aleatorios.
	ErrInvalidLength = errors.New("la longitud debe ser mayor que cero")

	// ErrRandomGenerationFailed se retorna cuando el generador criptográfico
	// del sistema no puede producir datos aleatorios (fallo muy raro pero posible).
	// Es un error genérico que no revela detalles internos del sistema.
	ErrRandomGenerationFailed = errors.New("fallo al generar datos aleatorios seguros")

	// ErrInvalidPrefix se retorna cuando el prefijo proporcionado a GenerateAPIKey
	// contiene caracteres no alfanuméricos.
	ErrInvalidPrefix = errors.New("el prefijo debe ser alfanumérico")
)

// =============================================================================
// Constantes Internas
// =============================================================================

// charsetURLSafe contiene caracteres alfanuméricos URL-safe (sin +, /, =).
// Se usa para generar tokens, session IDs y otros identificadores que puedan
// viajar en URLs o headers HTTP sin necesidad de codificación adicional.
const charsetURLSafe = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

// charsetNumeric contiene solo dígitos, usado para generar códigos OTP
// que se envían por SMS o email y deben ser fáciles de leer/dictar.
const charsetNumeric = "0123456789"

// defaultAPIKeyPrefix es el prefijo estándar para API keys generadas.
// No revela información sobre la herramienta usada internamente.
const defaultAPIKeyPrefix = "gk"

// =============================================================================
// Generación de Bytes Aleatorios (Base Criptográfica)
// =============================================================================

// RandomBytes genera n bytes criptográficamente seguros usando crypto/rand.
// Esta es la función base sobre la que se construyen todas las demás.
//
// Usa el generador de números aleatorios del sistema operativo, que está
// diseñado para ser impredecible y resistente a ataques.
//
// Ejemplo de uso:
//
//	bytes, err := crypto.RandomBytes(32)
//	if err != nil {
//	    // Manejar error (fallo del sistema, muy raro)
//	}
//	// bytes contiene 32 bytes aleatorios seguros
func RandomBytes(n int) ([]byte, error) {
	if n <= 0 {
		return nil, ErrInvalidLength
	}

	bytes := make([]byte, n)
	if _, err := rand.Read(bytes); err != nil {
		return nil, ErrRandomGenerationFailed
	}

	return bytes, nil
}

// =============================================================================
// Generación de Strings Aleatorios
// =============================================================================

// RandomString genera una cadena de n caracteres alfanuméricos URL-safe
// criptográficamente seguros. Usa el charset "A-Za-z0-9" (62 caracteres).
//
// Ideal para:
//   - Session IDs
//   - Tokens CSRF
//   - Identificadores únicos en URLs
//   - Nonces criptográficos
//
// Ejemplo de uso:
//
//	sessionID := crypto.RandomString(32)
//	// Resultado: "aB3xK9mP2qL5nR8wT1yU4zV6cF0hJ7d"
func RandomString(n int) (string, error) {
	if n <= 0 {
		return "", ErrInvalidLength
	}

	result := make([]byte, n)
	charsetLen := big.NewInt(int64(len(charsetURLSafe)))

	for i := 0; i < n; i++ {
		// crypto/rand.Int genera un número aleatorio seguro en el rango [0, max)
		idx, err := rand.Int(rand.Reader, charsetLen)
		if err != nil {
			return "", ErrRandomGenerationFailed
		}
		result[i] = charsetURLSafe[idx.Int64()]
	}

	return string(result), nil
}

// RandomHex genera una cadena hexadecimal de n bytes (2*n caracteres).
// Cada byte se representa con 2 caracteres hexadecimales (0-9, a-f).
//
// Ideal para:
//   - Refresh tokens
//   - API keys
//   - Identificadores de transacción
//   - Tokens de verificación por email
//
// Ejemplo de uso:
//
//	token := crypto.RandomHex(32)
//	// Resultado: "a1b2c3d4e5f6..." (64 caracteres hex)
func RandomHex(n int) (string, error) {
	bytes, err := RandomBytes(n)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// =============================================================================
// Generación de UUIDs
// =============================================================================

// GenerateUUID genera un UUID versión 4 (aleatorio) según RFC 4122.
// Los UUID v4 son ideales para identificadores únicos distribuidos donde
// no se requiere centralización ni secuencialidad.
//
// Formato: xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx
// Donde:
//   - El dígito '4' indica versión 4
//   - 'y' es uno de [8, 9, a, b] (variante RFC 4122)
//
// Ejemplo de uso:
//
//	id := crypto.GenerateUUID()
//	// Resultado: "550e8400-e29b-41d4-a716-446655440000"
func GenerateUUID() (string, error) {
	uuid := make([]byte, 16)
	if _, err := rand.Read(uuid); err != nil {
		return "", ErrRandomGenerationFailed
	}

	// Establecer versión 4 (bits 12-15 del time_hi_and_version)
	uuid[6] = (uuid[6] & 0x0f) | 0x40

	// Establecer variante RFC 4122 (bits 6-7 del clock_seq_hi_and_reserved)
	uuid[8] = (uuid[8] & 0x3f) | 0x80

	// Formatear como string estándar UUID
	return fmt.Sprintf("%x-%x-%x-%x-%x",
		uuid[0:4],
		uuid[4:6],
		uuid[6:8],
		uuid[8:10],
		uuid[10:16],
	), nil
}

// =============================================================================
// Generación de API Keys
// =============================================================================

// GenerateAPIKey genera una API key con el formato: "prefijo_stringHex".
// El prefijo ayuda a identificar el tipo de clave sin revelar información
// sensible, y el string hexadecimal proporciona la entropía necesaria.
//
// Si prefix está vacío, se usa el prefijo por defecto "gk".
// La longitud del string hexadecimal es de 32 bytes (64 caracteres).
//
// Ejemplo de uso:
//
//	apiKey := crypto.GenerateAPIKey("usr")
//	// Resultado: "usr_a1b2c3d4e5f6..."
//
//	apiKey := crypto.GenerateAPIKey("")
//	// Resultado: "gk_a1b2c3d4e5f6..." (prefijo por defecto)
func GenerateAPIKey(prefix string) (string, error) {
	if prefix == "" {
		prefix = defaultAPIKeyPrefix
	}

	// Validar que el prefijo sea alfanumérico para evitar inyección
	for _, c := range prefix {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
			return "", ErrInvalidPrefix
		}
	}

	randomPart, err := RandomHex(32)
	if err != nil {
		return "", err
	}

	return strings.ToLower(prefix) + "_" + randomPart, nil
}

// =============================================================================
// Generación de Códigos Numéricos (OTPs)
// =============================================================================

// GenerateNumericCode genera un código numérico de la longitud especificada.
// Usa crypto/rand para garantizar que el código sea impredecible.
//
// Ideal para:
//   - OTPs enviados por SMS o email
//   - Códigos de verificación de 2FA
//   - PINs temporales
//   - Códigos de recuperación
//
// Ejemplo de uso:
//
//	code, err := crypto.GenerateNumericCode(6)
//	if err != nil {
//	    // Manejar error
//	}
//	// Resultado: "482913" (6 dígitos)
//
//	// Para códigos más largos (ej. recuperación):
//	code, _ := crypto.GenerateNumericCode(8)
//	// Resultado: "94827163"
func GenerateNumericCode(length int) (string, error) {
	if length <= 0 {
		return "", ErrInvalidLength
	}

	result := make([]byte, length)
	charsetLen := big.NewInt(int64(len(charsetNumeric)))

	for i := 0; i < length; i++ {
		idx, err := rand.Int(rand.Reader, charsetLen)
		if err != nil {
			return "", ErrRandomGenerationFailed
		}
		result[i] = charsetNumeric[idx.Int64()]
	}

	return string(result), nil
}
