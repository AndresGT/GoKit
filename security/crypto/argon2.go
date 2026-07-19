package crypto

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// =============================================================================
// Implementación de Argon2id
// =============================================================================

// Argon2Hasher implementa la interfaz Hasher usando el algoritmo argon2id.
// Argon2id es el ganador del Password Hashing Competition (2015) y es
// resistente a ataques GPU/ASIC gracias a su uso intensivo de memoria.
// Es la opción más segura actualmente disponible.
type Argon2Hasher struct {
	memory      uint32 // KB
	iterations  uint32
	parallelism uint8
	keyLength   uint32
	saltLength  uint32
}

// NewArgon2Hasher crea un nuevo hasher argon2id con la configuración especificada.
// Si no se proporcionan valores válidos, se usan parámetros seguros por defecto.
//
// Parámetros recomendados (según RFC 9106):
//   - Memoria: 64 MB mínimo, 256 MB para alta seguridad
//   - Iteraciones: 3 mínimo
//   - Paralelismo: Número de CPUs disponibles (1-8)
//   - Longitud de clave: 32 bytes (256 bits)
//   - Longitud de salt: 16 bytes mínimo
func NewArgon2Hasher(cfg HasherConfig) (*Argon2Hasher, error) {
	memory := cfg.Argon2Memory
	if memory < 64*1024 { // 64 MB mínimo
		memory = 64 * 1024
	}

	iterations := cfg.Argon2Iterations
	if iterations < 3 {
		iterations = 3
	}

	parallelism := cfg.Argon2Parallelism
	if parallelism < 1 {
		parallelism = 4
	}

	keyLength := cfg.Argon2KeyLength
	if keyLength < 32 {
		keyLength = 32
	}

	saltLength := cfg.Argon2SaltLength
	if saltLength < 16 {
		saltLength = 16
	}

	return &Argon2Hasher{
		memory:      memory,
		iterations:  iterations,
		parallelism: parallelism,
		keyLength:   keyLength,
		saltLength:  saltLength,
	}, nil
}

// Hash genera un hash argon2id de la contraseña proporcionada.
// El resultado tiene el formato:
// $argon2id$v=19$m=65536,t=3,p=4$salt$hash
//
// Este formato incluye todos los parámetros necesarios para verificar
// el hash en el futuro, incluso si los parámetros por defecto cambian.
func (h *Argon2Hasher) Hash(password string) (string, error) {
	// Generar salt criptográficamente seguro
	salt := make([]byte, h.saltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	// Generar hash usando argon2id
	hash := argon2.IDKey([]byte(password), salt, h.iterations, h.memory, h.parallelism, h.keyLength)

	// Codificar salt y hash en base64
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	// Construir el string final con todos los parámetros
	encodedHash := fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		h.memory, h.iterations, h.parallelism, b64Salt, b64Hash)

	return encodedHash, nil
}

// Verify compara una contraseña en texto plano con un hash argon2id.
// Extrae los parámetros del hash para garantizar que se usa la misma
// configuración que cuando se generó. Usa comparación de tiempo constante.
func (h *Argon2Hasher) Verify(password, hash string) (bool, error) {
	// Parsear el hash para extraer parámetros
	parts := strings.Split(hash, "$")
	if len(parts) != 6 {
		return false, ErrInvalidHash
	}

	// Extraer parámetros del hash
	var memory, iterations uint32
	var parallelism uint8
	_, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &iterations, &parallelism)
	if err != nil {
		return false, ErrInvalidHash
	}

	// Decodificar salt y hash
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, ErrInvalidHash
	}

	expectedHash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, ErrInvalidHash
	}

	// Generar hash con los mismos parámetros
	actualHash := argon2.IDKey([]byte(password), salt, iterations, memory, parallelism, uint32(len(expectedHash)))

	// Comparación de tiempo constante
	return subtle.ConstantTimeCompare(actualHash, expectedHash) == 1, nil
}

// NeedsUpgrade determina si un hash argon2id debe ser regenerado porque
// los parámetros configurados actualmente son más estrictos que los usados
// para generar el hash.
func (h *Argon2Hasher) NeedsUpgrade(hash string) bool {
	parts := strings.Split(hash, "$")
	if len(parts) != 6 {
		return true
	}

	var memory, iterations uint32
	var parallelism uint8
	_, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &iterations, &parallelism)
	if err != nil {
		return true
	}

	// Si cualquiera de los parámetros actuales es más estricto, necesita upgrade
	return memory < h.memory || iterations < h.iterations || parallelism < h.parallelism
}