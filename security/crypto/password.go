package crypto

// =============================================================================
// Variables Globales y Configuración por Defecto
// =============================================================================

var (
	// defaultHasher es la instancia global usada por las funciones de conveniencia.
	// Se inicializa con Argon2id (recomendado por OWASP) en init().
	defaultHasher Hasher

	// defaultEncrypter es la instancia global para cifrado AES-256-GCM.
	// Se inicializa con una clave segura generada automáticamente.
	// NOTA: En producción, debes configurar tu propia clave con SetEncryptionKey().
	defaultEncrypter Encrypter

	// Constructores inyectables para poder probar los caminos de error de init().
	newDefaultHasher = func() (Hasher, error) {
		return NewHasher(HasherConfig{
			Algorithm:         AlgorithmArgon2id,
			Argon2Memory:      64 * 1024, // 64 MB
			Argon2Iterations:  3,
			Argon2Parallelism: 2,
			Argon2KeyLength:   32,
			Argon2SaltLength:  16,
		})
	}
	generateDefaultKey  = GenerateEncryptionKey
	newDefaultEncrypter = NewAESEncrypter
)

// =============================================================================
// Inicialización
// =============================================================================

func init() {
	initGlobalState()
}

// initGlobalState inicializa las instancias globales por defecto.
// Está separado de init() para poder probar los caminos de error.
func initGlobalState() {
	var err error
	defaultHasher, err = newDefaultHasher()
	if err != nil {
		panic("crypto: fallo al inicializar el Hasher por defecto: " + err.Error())
	}

	// ADVERTENCIA: Esta clave NO es segura para producción
	key, err := generateDefaultKey()
	if err != nil {
		panic("crypto: fallo al generar la clave por defecto: " + err.Error())
	}

	defaultEncrypter, err = newDefaultEncrypter(key)
	if err != nil {
		panic("crypto: fallo al inicializar el Encrypter por defecto: " + err.Error())
	}
}

// =============================================================================
// Funciones de Conveniencia para Hashing (Uso Rápido)
// =============================================================================

// HashPassword genera un hash seguro de contraseña usando Argon2id (por defecto).
// Es la forma más rápida de hashear contraseñas sin configuración.
//
// Ejemplo:
//
//	hash, err := crypto.HashPassword("mi-contraseña")
func HashPassword(password string) (string, error) {
	return defaultHasher.Hash(password)
}

// VerifyPassword verifica una contraseña contra un hash almacenado.
// Detecta automáticamente el algoritmo usado y lo verifica correctamente.
//
// Ejemplo:
//
//	valid, err := crypto.VerifyPassword("mi-contraseña", "$argon2id$...")
func VerifyPassword(password, storedHash string) (bool, error) {
	algo, err := DetectAlgorithm(storedHash)
	if err != nil {
		return false, ErrInvalidHash
	}

	hasherToUse := defaultHasher
	if algo != AlgorithmArgon2id {
		// NewHasher nunca falla para algoritmos devueltos por DetectAlgorithm
		tempHasher, _ := NewHasher(HasherConfig{Algorithm: algo})
		hasherToUse = tempHasher
	}

	return hasherToUse.Verify(password, storedHash)
}

// NeedsUpgrade determina si un hash debe regenerarse con parámetros más seguros.
// Útil para migración gradual de hashes antiguos.
//
// Ejemplo:
//
//	if crypto.NeedsUpgrade(hash) {
//	    nuevoHash, _ := crypto.HashPassword(password)
//	    // Guardar nuevoHash en BD
//	}
func NeedsUpgrade(storedHash string) bool {
	return defaultHasher.NeedsUpgrade(storedHash)
}

// SetDefaultHasher cambia el hasher global por defecto.
// Útil cuando quieres usar otro algoritmo como predeterminado.
//
// Ejemplo:
//
//	crypto.SetDefaultHasher(crypto.NewBcryptHasher(crypto.HasherConfig{BcryptCost: 12}))
func SetDefaultHasher(hasher Hasher) {
	if hasher != nil {
		defaultHasher = hasher
	}
}

// =============================================================================
// Funciones de Conveniencia para Cifrado (Uso Rápido)
// =============================================================================

// EncryptString cifra un string usando AES-256-GCM con la clave por defecto.
// ADVERTENCIA: La clave por defecto NO es segura para producción.
// Usa SetEncryptionKey() o NewAESEncrypter() para producción.
//
// Ejemplo:
//
//	ciphertext, err := crypto.EncryptString("dato-secreto")
func EncryptString(plaintext string) (string, error) {
	return defaultEncrypter.EncryptString(plaintext)
}

// DecryptString descifra un string usando AES-256-GCM con la clave por defecto.
//
// Ejemplo:
//
//	plaintext, err := crypto.DecryptString(ciphertext)
func DecryptString(ciphertext string) (string, error) {
	return defaultEncrypter.DecryptString(ciphertext)
}

// EncryptBytes cifra bytes usando AES-256-GCM con la clave por defecto.
//
// Ejemplo:
//
//	ciphertext, err := crypto.EncryptBytes([]byte("datos-binarios"))
func EncryptBytes(plaintext []byte) (string, error) {
	return defaultEncrypter.Encrypt(plaintext)
}

// DecryptBytes descifra bytes usando AES-256-GCM con la clave por defecto.
//
// Ejemplo:
//
//	plaintext, err := crypto.DecryptBytes(ciphertext)
func DecryptBytes(ciphertext string) ([]byte, error) {
	return defaultEncrypter.Decrypt(ciphertext)
}

// SetEncryptionKey configura la clave global para cifrado/descifrado.
// DEBE llamarse antes de usar las funciones de cifrado en producción.
// La clave debe tener exactamente 32 bytes.
//
// Ejemplo:
//
//	key, _ := crypto.GenerateEncryptionKey()
//	crypto.SetEncryptionKey(key)
//	// O desde variable de entorno:
//	// keyBytes, _ := base64.StdEncoding.DecodeString(os.Getenv("ENCRYPTION_KEY"))
//	// crypto.SetEncryptionKey(keyBytes)
func SetEncryptionKey(key []byte) error {
	encrypter, err := NewAESEncrypter(key)
	if err != nil {
		return err
	}
	defaultEncrypter = encrypter
	return nil
}

// =============================================================================
// Funciones de Utilidad Directa (Herramientas Funcionales)
// =============================================================================

// --- Hashing directo con algoritmos específicos ---

// HashWithArgon2id genera un hash usando Argon2id con configuración óptima.
// Recomendado para la mayoría de casos (OWASP).
func HashWithArgon2id(password string) (string, error) {
	hasher, _ := NewArgon2Hasher(HasherConfig{})
	return hasher.Hash(password)
}

// HashWithBcrypt genera un hash usando Bcrypt con costo 12.
// Bueno para compatibilidad con sistemas legacy.
func HashWithBcrypt(password string) (string, error) {
	hasher, _ := NewBcryptHasher(HasherConfig{BcryptCost: 12})
	return hasher.Hash(password)
}

// HashWithScrypt genera un hash usando Scrypt con configuración estándar.
func HashWithScrypt(password string) (string, error) {
	hasher, _ := NewScryptHasher(HasherConfig{})
	return hasher.Hash(password)
}

// HashWithPBKDF2 genera un hash usando PBKDF2-SHA256 con 600k iteraciones.
// Estándar NIST para entornos enterprise.
func HashWithPBKDF2(password string) (string, error) {
	hasher, _ := NewPBKDF2Hasher(HasherConfig{})
	return hasher.Hash(password)
}

// --- Generación aleatoria directa ---

// GenerateRandomBytes genera n bytes criptográficamente seguros.
func GenerateRandomBytes(n int) ([]byte, error) {
	return RandomBytes(n)
}

// GenerateRandomString genera un string aleatorio URL-safe de n caracteres.
func GenerateRandomString(n int) (string, error) {
	return RandomString(n)
}

// GenerateSecureToken genera un token hexadecimal de 32 bytes (64 chars).
func GenerateSecureToken() (string, error) {
	return RandomHex(32)
}

// GenerateUUIDv4 genera un UUID versión 4 aleatorio.
func GenerateUUIDv4() (string, error) {
	return GenerateUUID()
}

// GenerateAPIKey genera una API key con formato "prefijo_hex".
func GenerateAPIKeyWithPrefix(prefix string) (string, error) {
	return GenerateAPIKey(prefix)
}

// GenerateOTP genera un código numérico OTP de longitud especificada.
func GenerateOTP(length int) (string, error) {
	return GenerateNumericCode(length)
}

// --- Cifrado directo ---

// EncryptWithKey cifra datos usando una clave específica (sin usar global).
func EncryptWithKey(plaintext string, key []byte) (string, error) {
	encrypter, err := NewAESEncrypter(key)
	if err != nil {
		return "", err
	}
	return encrypter.EncryptString(plaintext)
}

// DecryptWithKey descifra datos usando una clave específica (sin usar global).
func DecryptWithKey(ciphertext string, key []byte) (string, error) {
	encrypter, err := NewAESEncrypter(key)
	if err != nil {
		return "", err
	}
	return encrypter.DecryptString(ciphertext)
}
