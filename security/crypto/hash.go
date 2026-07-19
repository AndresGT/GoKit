package crypto

import (
	"errors"
	"strings"
)

// =============================================================================
// Interfaz de Hashing
// =============================================================================

// Hasher define el contrato que deben cumplir todos los proveedores de hashing
// de contraseñas. Esta abstracción permite cambiar el algoritmo sin modificar
// el código que lo utiliza (principio Open/Closed).
type Hasher interface {
	// Hash genera un hash seguro de la contraseña proporcionada.
	// La contraseña debe ser validada antes de llamar a este método.
	Hash(password string) (string, error)

	// Verify compara una contraseña en texto plano con un hash almacenado.
	// Devuelve true si coinciden, false en caso contrario.
	// IMPORTANTE: Usa comparación de tiempo constante para prevenir ataques
	// de timing.
	Verify(password, hash string) (bool, error)

	// NeedsUpgrade determina si un hash existente debe ser regenerado
	// (por ejemplo, si los parámetros de seguridad han aumentado).
	NeedsUpgrade(hash string) bool
}

// =============================================================================
// Tipos de Algoritmos
// =============================================================================

// Algorithm representa el tipo de algoritmo de hashing disponible.
type Algorithm string

const (
	// AlgorithmBcrypt es el estándar de la industria, ampliamente soportado.
	// Recomendado para la mayoría de aplicaciones.
	AlgorithmBcrypt Algorithm = "bcrypt"

	// AlgorithmArgon2id es el ganador del Password Hashing Competition (2015).
	// Resistente a ataques GPU/ASIC. Recomendado para máxima seguridad.
	AlgorithmArgon2id Algorithm = "argon2id"

	// AlgorithmScrypt es una alternativa a bcrypt con uso intensivo de memoria.
	// Bueno para sistemas legacy o requisitos específicos.
	AlgorithmScrypt Algorithm = "scrypt"

	// AlgorithmPBKDF2 es el estándar NIST, usado en muchas aplicaciones enterprise.
	// Compatible con sistemas legacy que lo requieran.
	AlgorithmPBKDF2 Algorithm = "pbkdf2"
)

// =============================================================================
// Errores
// =============================================================================

var (
	// ErrInvalidHash se retorna cuando el formato del hash no es válido
	// o no puede ser parseado.
	ErrInvalidHash = errors.New("formato de hash inválido")

	// ErrUnsupportedAlgorithm se retorna cuando se intenta usar un algoritmo
	// que no está disponible o no es soportado.
	ErrUnsupportedAlgorithm = errors.New("algoritmo de hashing no soportado")

	// ErrPasswordTooShort se retorna cuando la contraseña no cumple con
	// la longitud mínima requerida.
	ErrPasswordTooShort = errors.New("la contraseña es demasiado corta")

	// ErrPasswordTooLong se retorna cuando la contraseña excede la longitud
	// máxima permitida (previene ataques DoS en algunos algoritmos).
	ErrPasswordTooLong = errors.New("la contraseña es demasiado larga")
)

// =============================================================================
// Fábrica de Proveedores
// =============================================================================

// HasherConfig contiene los parámetros de configuración para crear un Hasher.
type HasherConfig struct {
	// Algorithm es el algoritmo de hashing a utilizar.
	Algorithm Algorithm

	// Parámetros específicos de cada algoritmo (se usan según corresponda)

	// Bcrypt
	BcryptCost int

	// Argon2id
	Argon2Memory      uint32 // KB
	Argon2Iterations  uint32
	Argon2Parallelism uint8
	Argon2KeyLength   uint32
	Argon2SaltLength  uint32

	// Scrypt
	ScryptN       int
	ScryptR       int
	ScryptP       int
	ScryptKeyLen  int
	ScryptSaltLen int

	// PBKDF2
	PBKDF2Iterations int
	PBKDF2KeyLen     int
	PBKDF2SaltLen    int
}

// NewHasher crea y devuelve un Hasher configurado según el algoritmo especificado.
// Si la configuración es inválida o incompleta, se aplican valores predeterminados
// seguros para el algoritmo seleccionado.
//
// Ejemplo de uso:
//
//	// Usar bcrypt con configuración por defecto
//	hasher, err := crypto.NewHasher(crypto.HasherConfig{
//	    Algorithm: crypto.AlgorithmBcrypt,
//	})
//
//	// Usar argon2id con parámetros personalizados
//	hasher, err := crypto.NewHasher(crypto.HasherConfig{
//	    Algorithm:         crypto.AlgorithmArgon2id,
//	    Argon2Memory:      64 * 1024, // 64 MB
//	    Argon2Iterations:  3,
//	    Argon2Parallelism: 4,
//	})
func NewHasher(cfg HasherConfig) (Hasher, error) {
	switch cfg.Algorithm {
	case AlgorithmBcrypt:
		return NewBcryptHasher(cfg)
	case AlgorithmArgon2id:
		return NewArgon2Hasher(cfg)
	case AlgorithmScrypt:
		return NewScryptHasher(cfg)
	case AlgorithmPBKDF2:
		return NewPBKDF2Hasher(cfg)
	default:
		return nil, ErrUnsupportedAlgorithm
	}
}

// DetectAlgorithm examina un hash y determina qué algoritmo fue usado
// para generarlo. Esto es útil para sistemas que necesitan soportar
// múltiples algoritmos simultáneamente (migración gradual).
//
// El formato esperado es: $algorithm$params$salt$hash
func DetectAlgorithm(hash string) (Algorithm, error) {
	if !strings.HasPrefix(hash, "$") {
		return "", ErrInvalidHash
	}

	parts := strings.Split(hash, "$")
	if len(parts) < 3 {
		return "", ErrInvalidHash
	}

	algorithm := parts[1]
	switch algorithm {
	case "2a", "2b", "2y":
		return AlgorithmBcrypt, nil
	case "argon2id":
		return AlgorithmArgon2id, nil
	case "scrypt":
		return AlgorithmScrypt, nil
	case "pbkdf2-sha256":
		return AlgorithmPBKDF2, nil
	default:
		return "", ErrUnsupportedAlgorithm
	}
}