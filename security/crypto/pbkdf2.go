package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

// =============================================================================
// Implementación de PBKDF2
// =============================================================================

// PBKDF2Hasher implementa la interfaz Hasher usando el algoritmo PBKDF2
// (Password-Based Key Derivation Function 2) con SHA-256.
// PBKDF2 es el estándar recomendado por NIST (NIST SP 800-132) y es ampliamante
// usado en aplicaciones enterprise y sistemas legacy.
//
// Aunque no es tan resistente a ataques GPU como argon2 o scrypt, sigue siendo
// una opción segura y ampliamente aceptada cuando se usa con suficientes iteraciones.
type PBKDF2Hasher struct {
	iterations int
	keyLen     int
	saltLen    int
}

// NewPBKDF2Hasher crea un nuevo hasher PBKDF2 con la configuración especificada.
// Si no se proporcionan valores válidos, se usan parámetros seguros por defecto.
//
// Parámetros recomendados (según NIST SP 800-132):
//   - Iteraciones: 600,000 mínimo (recomendación OWASP 2023 para SHA-256)
//   - keyLen: 32 bytes (256 bits)
//   - saltLen: 16 bytes mínimo
//
// Nota: OWASP recomienda aumentar las iteraciones con el tiempo a medida
// que el hardware se vuelve más potente.
func NewPBKDF2Hasher(cfg HasherConfig) (*PBKDF2Hasher, error) {
	iterations := cfg.PBKDF2Iterations
	if iterations < 600000 {
		iterations = 600000 // Recomendación OWASP 2023
	}

	keyLen := cfg.PBKDF2KeyLen
	if keyLen < 32 {
		keyLen = 32
	}

	saltLen := cfg.PBKDF2SaltLen
	if saltLen < 16 {
		saltLen = 16
	}

	return &PBKDF2Hasher{
		iterations: iterations,
		keyLen:     keyLen,
		saltLen:    saltLen,
	}, nil
}

// Hash genera un hash PBKDF2-SHA256 de la contraseña proporcionada.
// El resultado tiene el formato:
// $pbkdf2-sha256$i=600000$salt$hash
//
// Este formato incluye todos los parámetros necesarios para verificar
// el hash en el futuro, permitiendo migración transparente entre
// diferentes configuraciones.
func (h *PBKDF2Hasher) Hash(password string) (string, error) {
	// Generar salt criptográficamente seguro
	salt := make([]byte, h.saltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", err
	}

	// Generar clave derivada usando PBKDF2 con SHA-256
	key := pbkdf2.Key([]byte(password), salt, h.iterations, h.keyLen, sha256.New)

	// Codificar salt y hash en base64
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Key := base64.RawStdEncoding.EncodeToString(key)

	// Construir el string final con todos los parámetros
	encodedHash := fmt.Sprintf("$pbkdf2-sha256$i=%d$%s$%s",
		h.iterations, b64Salt, b64Key)

	return encodedHash, nil
}

// Verify compara una contraseña en texto plano con un hash PBKDF2.
// Extrae los parámetros del hash para garantizar que se usa la misma
// configuración que cuando se generó. Usa comparación de tiempo constante.
func (h *PBKDF2Hasher) Verify(password, hash string) (bool, error) {
	// Parsear el hash para extraer parámetros
	parts := strings.Split(hash, "$")
	if len(parts) != 5 {
		return false, ErrInvalidHash
	}

	// Verificar que sea PBKDF2-SHA256
	if parts[1] != "pbkdf2-sha256" {
		return false, ErrInvalidHash
	}

	// Extraer número de iteraciones
	var iterations int
	_, err := fmt.Sscanf(parts[2], "i=%d", &iterations)
	if err != nil {
		return false, ErrInvalidHash
	}

	// Decodificar salt y hash esperado
	salt, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil {
		return false, ErrInvalidHash
	}

	expectedKey, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, ErrInvalidHash
	}

	// Generar clave con los mismos parámetros
	actualKey := pbkdf2.Key([]byte(password), salt, iterations, len(expectedKey), sha256.New)

	// Comparación de tiempo constante
	return subtle.ConstantTimeCompare(actualKey, expectedKey) == 1, nil
}

// NeedsUpgrade determina si un hash PBKDF2 debe ser regenerado porque
// el número de iteraciones configurado actualmente es mayor que el usado
// para generar el hash.
func (h *PBKDF2Hasher) NeedsUpgrade(hash string) bool {
	parts := strings.Split(hash, "$")
	if len(parts) != 5 {
		return true
	}

	var iterations int
	_, err := fmt.Sscanf(parts[2], "i=%d", &iterations)
	if err != nil {
		return true
	}

	return iterations < h.iterations
}