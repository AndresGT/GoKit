package crypto

import (
	"errors"
	"strings"
)

// =============================================================================
// Interfaz de Hashing
// =============================================================================

// Hasher define el contrato que deben cumplir todos los proveedores de hashing
// de contraseñas. Esta abstracción permite cambiar el algoritmo subyacente sin
// modificar el código consumidor (principio Open/Closed).
type Hasher interface {
	// Hash genera un hash seguro de la contraseña proporcionada.
	Hash(password string) (string, error)

	// Verify compara una contraseña en texto plano con un hash almacenado.
	// Devuelve true si coinciden, false en caso contrario.
	// Nota: Debe implementarse usando comparación en tiempo constante (subtle.ConstantTimeCompare)
	// para prevenir ataques de temporización (timing attacks).
	Verify(password, hash string) (bool, error)

	// NeedsUpgrade determina si un hash existente debe ser regenerado
	// (ej. si el algoritmo por defecto cambió o si los parámetros de seguridad han aumentado).
	NeedsUpgrade(hash string) bool
}

// =============================================================================
// Tipos de Algoritmos
// =============================================================================

// Algorithm representa el identificador del algoritmo de hashing de contraseñas.
type Algorithm string

const (
	// AlgorithmBcrypt es el estándar clásico ampliamente soportado.
	AlgorithmBcrypt Algorithm = "bcrypt"

	// AlgorithmArgon2id es el ganador del Password Hashing Competition (PHC).
	// Es el estándar recomendado actualmente por OWASP por su resistencia a GPUs/ASICs.
	AlgorithmArgon2id Algorithm = "argon2id"

	// AlgorithmScrypt es una alternativa con uso intensivo de memoria, útil para sistemas legacy.
	AlgorithmScrypt Algorithm = "scrypt"

	// AlgorithmPBKDF2 es el estándar NIST tradicional para entornos corporativos o legacy.
	AlgorithmPBKDF2 Algorithm = "pbkdf2"
)

// =============================================================================
// Errores Específicos del Módulo de Hashing
// =============================================================================

var (
	// ErrInvalidHash se retorna cuando el formato del hash no cumple con la especificación PHC
	// o no puede ser interpretado por ningún parser.
	ErrInvalidHash = errors.New("formato de hash inválido")

	// ErrUnsupportedAlgorithm se retorna al solicitar un algoritmo no registrado o no disponible.
	ErrUnsupportedAlgorithm = errors.New("algoritmo de hashing no soportado")

	// ErrPasswordTooShort se retorna si la contraseña no cumple el tamaño mínimo seguro.
	ErrPasswordTooShort = errors.New("la contraseña es demasiado corta")

	// ErrPasswordTooLong se retorna si la contraseña excede el tamaño máximo permitido (mitiga DoS).
	ErrPasswordTooLong = errors.New("la contraseña es demasiado larga")
)

// =============================================================================
// Configuración y Fábrica (Factory)
// =============================================================================

// HasherConfig contiene los parámetros necesarios para instanciar cualquier proveedor Hasher.
type HasherConfig struct {
	// Algorithm especifica qué algoritmo se instanciará.
	Algorithm Algorithm

	// --- Parámetros específicos de Bcrypt ---
	BcryptCost int

	// --- Parámetros específicos de Argon2id ---
	Argon2Memory      uint32 // Memoria en KB (ej. 65536 = 64MB)
	Argon2Iterations  uint32 // Número de pasadas
	Argon2Parallelism uint8  // Goroutines en paralelo
	Argon2KeyLength   uint32 // Longitud de la clave generada
	Argon2SaltLength  uint32 // Longitud del salt

	// --- Parámetros específicos de Scrypt ---
	ScryptN       int
	ScryptR       int
	ScryptP       int
	ScryptKeyLen  int
	ScryptSaltLen int

	// --- Parámetros específicos de PBKDF2 ---
	PBKDF2Iterations int
	PBKDF2KeyLen     int
	PBKDF2SaltLen    int
}

// NewHasher crea y devuelve un proveedor que implementa la interfaz Hasher.
// Si los parámetros numéricos de la configuración son 0, la implementación concreta
// asignará defaults seguros automáticamente.
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

// DetectAlgorithm analiza la cabecera de la cadena de hash (formato PHC)
// y determina el algoritmo utilizado para su generación.
//
// Formato general esperado: $identificador$parametros...
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