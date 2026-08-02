package crypto

// =============================================================================
// API Global a Nivel de Paquete (Fachada Simplificada)
// =============================================================================

var defaultHasher Hasher

func init() {
	// Inicialización por defecto usando Argon2id (OWASP Standard)
	var err error
	defaultHasher, err = NewHasher(HasherConfig{
		Algorithm:         AlgorithmArgon2id,
		Argon2Memory:      64 * 1024, // 64 MB
		Argon2Iterations:  3,
		Argon2Parallelism: 2,
		Argon2KeyLength:   32,
		Argon2SaltLength:  16,
	})
	if err != nil {
		panic("crypto: fallo al inicializar el Hasher por defecto: " + err.Error())
	}
}

// SetDefaultHasher permite reconfigurar la estrategia global de hashing desde main.go.
func SetDefaultHasher(hasher Hasher) {
	if hasher != nil {
		defaultHasher = hasher
	}
}

// HashPassword genera un hash seguro utilizando el proveedor global por defecto.
// Aplica validaciones básicas de tamaño antes de ejecutar el algoritmo.
func HashPassword(password string) (string, error) {
	if len(password) < 8 {
		return "", ErrPasswordTooShort // Usa directamente el error de hash.go
	}
	if len(password) > 72 {
		return "", ErrPasswordTooLong // Usa directamente el error de hash.go
	}

	return defaultHasher.Hash(password)
}

// VerifyPassword valida una contraseña plana contra un hash guardado.
// Identifica automáticamente el algoritmo usado en el hash original para permitir
// verificaciones cruzadas y migraciones sin afectar a los usuarios existentes.
func VerifyPassword(password, storedHash string) (bool, error) {
	algo, err := DetectAlgorithm(storedHash)
	if err != nil {
		return false, ErrInvalidHash // Usa directamente el error de hash.go
	}

	// Si el hash fue creado con otro algoritmo, instanciamos ese algoritmo al vuelo para verificar
	hasherToUse := defaultHasher
	if algo != AlgorithmArgon2id {
		tempHasher, err := NewHasher(HasherConfig{Algorithm: algo})
		if err != nil {
			return false, err
		}
		hasherToUse = tempHasher
	}

	return hasherToUse.Verify(password, storedHash)
}

// NeedsUpgrade verifica si el hash almacenado requiere ser re-hasheado
// (por ejemplo, si el sistema migró de Bcrypt a Argon2id).
func NeedsUpgrade(storedHash string) bool {
	return defaultHasher.NeedsUpgrade(storedHash)
}