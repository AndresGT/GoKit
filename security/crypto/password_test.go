package crypto

import (
	"strings"
	"testing"
)

// =============================================================================
// Tests para HashPassword, VerifyPassword y NeedsUpgrade (Funciones Globales)
// =============================================================================

func TestHashPassword(t *testing.T) {
	password := "test-password-123"
	
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	
	if hash == "" {
		t.Error("HashPassword() returned empty hash")
	}
	
	// Verificar formato PHC
	if !strings.HasPrefix(hash, "$") {
		t.Error("HashPassword() hash should start with $ for PHC format")
	}
	
	// Verificar que es Argon2id por defecto
	if !strings.HasPrefix(hash, "$argon2id$") {
		t.Errorf("HashPassword() should use Argon2id by default, got: %s", hash)
	}
}

func TestVerifyPassword_Argon2id(t *testing.T) {
	password := "secure-password-456"
	
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	
	valid, err := VerifyPassword(password, hash)
	if err != nil {
		t.Fatalf("VerifyPassword() error = %v", err)
	}
	
	if !valid {
		t.Error("VerifyPassword() should return true for correct password")
	}
}

func TestVerifyPassword_WrongPassword(t *testing.T) {
	password := "correct-password"
	wrongPassword := "wrong-password"
	
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	
	valid, err := VerifyPassword(wrongPassword, hash)
	if err != nil {
		t.Fatalf("VerifyPassword() error = %v", err)
	}
	
	if valid {
		t.Error("VerifyPassword() should return false for wrong password")
	}
}

func TestVerifyPassword_Bcrypt(t *testing.T) {
	password := "bcrypt-test-password"
	
	// Crear hash con bcrypt directamente
	hasher, err := NewBcryptHasher(HasherConfig{BcryptCost: 10})
	if err != nil {
		t.Fatalf("NewBcryptHasher() error = %v", err)
	}
	
	hash, err := hasher.Hash(password)
	if err != nil {
		t.Fatalf("Bcrypt Hash() error = %v", err)
	}
	
	// VerifyPassword debe detectar automáticamente el algoritmo
	valid, err := VerifyPassword(password, hash)
	if err != nil {
		t.Fatalf("VerifyPassword() error = %v", err)
	}
	
	if !valid {
		t.Error("VerifyPassword() should verify bcrypt hash correctly")
	}
}

func TestVerifyPassword_Scrypt(t *testing.T) {
	password := "scrypt-test-password"
	
	hasher, err := NewScryptHasher(HasherConfig{})
	if err != nil {
		t.Fatalf("NewScryptHasher() error = %v", err)
	}
	
	hash, err := hasher.Hash(password)
	if err != nil {
		t.Fatalf("Scrypt Hash() error = %v", err)
	}
	
	valid, err := VerifyPassword(password, hash)
	if err != nil {
		t.Fatalf("VerifyPassword() error = %v", err)
	}
	
	if !valid {
		t.Error("VerifyPassword() should verify scrypt hash correctly")
	}
}

func TestVerifyPassword_PBKDF2(t *testing.T) {
	password := "pbkdf2-test-password"
	
	hasher, err := NewPBKDF2Hasher(HasherConfig{})
	if err != nil {
		t.Fatalf("NewPBKDF2Hasher() error = %v", err)
	}
	
	hash, err := hasher.Hash(password)
	if err != nil {
		t.Fatalf("PBKDF2 Hash() error = %v", err)
	}
	
	valid, err := VerifyPassword(password, hash)
	if err != nil {
		t.Fatalf("VerifyPassword() error = %v", err)
	}
	
	if !valid {
		t.Error("VerifyPassword() should verify PBKDF2 hash correctly")
	}
}

func TestVerifyPassword_InvalidHash(t *testing.T) {
	invalidHash := "not-a-valid-hash"
	
	valid, err := VerifyPassword("password", invalidHash)
	if err == nil {
		t.Error("VerifyPassword() should return error for invalid hash")
	}
	
	if valid {
		t.Error("VerifyPassword() should return false for invalid hash")
	}
}

func TestNeedsUpgrade(t *testing.T) {
	password := "upgrade-test-password"
	
	// Hash con parámetros bajos
	hasher, err := NewArgon2Hasher(HasherConfig{
		Argon2Memory:      64 * 1024, // 64 MB
		Argon2Iterations:  1,         // Muy bajo
		Argon2Parallelism: 1,
		Argon2KeyLength:   32,
		Argon2SaltLength:  16,
	})
	if err != nil {
		t.Fatalf("NewArgon2Hasher() error = %v", err)
	}
	
	hash, err := hasher.Hash(password)
	if err != nil {
		t.Fatalf("Hash() error = %v", err)
	}
	
	// Debería necesitar upgrade porque las iteraciones son más bajas que el default
	if !NeedsUpgrade(hash) {
		t.Error("NeedsUpgrade() should return true for hash with low iterations")
	}
}

func TestSetDefaultHasher(t *testing.T) {
	// Guardar hasher original
	originalHasher := defaultHasher
	
	// Cambiar a Bcrypt
	bcryptHasher, err := NewBcryptHasher(HasherConfig{BcryptCost: 10})
	if err != nil {
		t.Fatalf("NewBcryptHasher() error = %v", err)
	}
	
	SetDefaultHasher(bcryptHasher)
	
	password := "test-with-bcrypt"
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	
	// Verificar que ahora usa Bcrypt
	if !strings.HasPrefix(hash, "$2") {
		t.Errorf("After SetDefaultHasher(Bcrypt), hash should start with $2, got: %s", hash)
	}
	
	// Restaurar hasher original
	defaultHasher = originalHasher
}

// =============================================================================
// Tests para Funciones de Cifrado Globales
// =============================================================================

func TestEncryptString_DecryptString(t *testing.T) {
	plaintext := "secret-message-to-encrypt"
	
	encrypted, err := EncryptString(plaintext)
	if err != nil {
		t.Fatalf("EncryptString() error = %v", err)
	}
	
	if encrypted == "" {
		t.Error("EncryptString() returned empty ciphertext")
	}
	
	decrypted, err := DecryptString(encrypted)
	if err != nil {
		t.Fatalf("DecryptString() error = %v", err)
	}
	
	if decrypted != plaintext {
		t.Errorf("DecryptString() = %v, want %v", decrypted, plaintext)
	}
}

func TestEncryptBytes_DecryptBytes(t *testing.T) {
	plaintext := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	
	encrypted, err := EncryptBytes(plaintext)
	if err != nil {
		t.Fatalf("EncryptBytes() error = %v", err)
	}
	
	decrypted, err := DecryptBytes(encrypted)
	if err != nil {
		t.Fatalf("DecryptBytes() error = %v", err)
	}
	
	for i, b := range decrypted {
		if b != plaintext[i] {
			t.Errorf("DecryptBytes() index %d = %v, want %v", i, b, plaintext[i])
		}
	}
}

func TestSetEncryptionKey(t *testing.T) {
	// Generar nueva clave
	newKey, err := GenerateEncryptionKey()
	if err != nil {
		t.Fatalf("GenerateEncryptionKey() error = %v", err)
	}
	
	err = SetEncryptionKey(newKey)
	if err != nil {
		t.Fatalf("SetEncryptionKey() error = %v", err)
	}
	
	// Probar cifrado con nueva clave
	plaintext := "test-with-new-key"
	encrypted, err := EncryptString(plaintext)
	if err != nil {
		t.Fatalf("EncryptString() error = %v", err)
	}
	
	decrypted, err := DecryptString(encrypted)
	if err != nil {
		t.Fatalf("DecryptString() error = %v", err)
	}
	
	if decrypted != plaintext {
		t.Errorf("DecryptString() after SetEncryptionKey = %v, want %v", decrypted, plaintext)
	}
}

func TestEncryptWithKey_DecryptWithKey(t *testing.T) {
	key, err := GenerateEncryptionKey()
	if err != nil {
		t.Fatalf("GenerateEncryptionKey() error = %v", err)
	}
	
	plaintext := "encrypt-with-specific-key"
	
	encrypted, err := EncryptWithKey(plaintext, key)
	if err != nil {
		t.Fatalf("EncryptWithKey() error = %v", err)
	}
	
	decrypted, err := DecryptWithKey(encrypted, key)
	if err != nil {
		t.Fatalf("DecryptWithKey() error = %v", err)
	}
	
	if decrypted != plaintext {
		t.Errorf("DecryptWithKey() = %v, want %v", decrypted, plaintext)
	}
}

func TestEncryptWithKey_WrongKey(t *testing.T) {
	key1, _ := GenerateEncryptionKey()
	key2, _ := GenerateEncryptionKey()
	
	plaintext := "wrong-key-test"
	
	encrypted, _ := EncryptWithKey(plaintext, key1)
	
	// Intentar descifrar con clave incorrecta
	_, err := DecryptWithKey(encrypted, key2)
	if err == nil {
		t.Error("DecryptWithKey() should return error with wrong key")
	}
}

// =============================================================================
// Tests para Funciones de Hashing Directas
// =============================================================================

func TestHashWithArgon2id(t *testing.T) {
	password := "argon2id-direct-test"
	
	hash, err := HashWithArgon2id(password)
	if err != nil {
		t.Fatalf("HashWithArgon2id() error = %v", err)
	}
	
	if !strings.HasPrefix(hash, "$argon2id$") {
		t.Errorf("HashWithArgon2id() should produce argon2id hash, got: %s", hash)
	}
	
	valid, err := VerifyPassword(password, hash)
	if err != nil || !valid {
		t.Error("HashWithArgon2id() produced invalid hash")
	}
}

func TestHashWithBcrypt(t *testing.T) {
	password := "bcrypt-direct-test"
	
	hash, err := HashWithBcrypt(password)
	if err != nil {
		t.Fatalf("HashWithBcrypt() error = %v", err)
	}
	
	if !strings.HasPrefix(hash, "$2") {
		t.Errorf("HashWithBcrypt() should produce bcrypt hash, got: %s", hash)
	}
	
	valid, err := VerifyPassword(password, hash)
	if err != nil || !valid {
		t.Error("HashWithBcrypt() produced invalid hash")
	}
}

func TestHashWithScrypt(t *testing.T) {
	password := "scrypt-direct-test"
	
	hash, err := HashWithScrypt(password)
	if err != nil {
		t.Fatalf("HashWithScrypt() error = %v", err)
	}
	
	if !strings.HasPrefix(hash, "$scrypt$") {
		t.Errorf("HashWithScrypt() should produce scrypt hash, got: %s", hash)
	}
	
	valid, err := VerifyPassword(password, hash)
	if err != nil || !valid {
		t.Error("HashWithScrypt() produced invalid hash")
	}
}

func TestHashWithPBKDF2(t *testing.T) {
	password := "pbkdf2-direct-test"
	
	hash, err := HashWithPBKDF2(password)
	if err != nil {
		t.Fatalf("HashWithPBKDF2() error = %v", err)
	}
	
	if !strings.HasPrefix(hash, "$pbkdf2-sha256$") {
		t.Errorf("HashWithPBKDF2() should produce pbkdf2 hash, got: %s", hash)
	}
	
	valid, err := VerifyPassword(password, hash)
	if err != nil || !valid {
		t.Error("HashWithPBKDF2() produced invalid hash")
	}
}

// =============================================================================
// Tests para Funciones de Generación Aleatoria
// =============================================================================

func TestGenerateRandomBytes(t *testing.T) {
	bytes, err := GenerateRandomBytes(32)
	if err != nil {
		t.Fatalf("GenerateRandomBytes() error = %v", err)
	}
	
	if len(bytes) != 32 {
		t.Errorf("GenerateRandomBytes(32) returned %d bytes, want 32", len(bytes))
	}
	
	// Verificar que no sean todos ceros
	allZeros := true
	for _, b := range bytes {
		if b != 0 {
			allZeros = false
			break
		}
	}
	if allZeros {
		t.Error("GenerateRandomBytes() returned all zeros")
	}
}

func TestGenerateRandomBytes_InvalidLength(t *testing.T) {
	_, err := GenerateRandomBytes(0)
	if err == nil {
		t.Error("GenerateRandomBytes(0) should return error")
	}
	
	_, err = GenerateRandomBytes(-1)
	if err == nil {
		t.Error("GenerateRandomBytes(-1) should return error")
	}
}

func TestGenerateRandomString(t *testing.T) {
	str, err := GenerateRandomString(32)
	if err != nil {
		t.Fatalf("GenerateRandomString() error = %v", err)
	}
	
	if len(str) != 32 {
		t.Errorf("GenerateRandomString(32) returned string of length %d, want 32", len(str))
	}
	
	// Verificar que solo contiene caracteres URL-safe
	for _, c := range str {
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) {
			t.Errorf("GenerateRandomString() contains non-URL-safe character: %c", c)
		}
	}
}

func TestGenerateSecureToken(t *testing.T) {
	token, err := GenerateSecureToken()
	if err != nil {
		t.Fatalf("GenerateSecureToken() error = %v", err)
	}
	
	// 32 bytes = 64 caracteres hex
	if len(token) != 64 {
		t.Errorf("GenerateSecureToken() returned token of length %d, want 64", len(token))
	}
}

func TestGenerateUUIDv4(t *testing.T) {
	uuid, err := GenerateUUIDv4()
	if err != nil {
		t.Fatalf("GenerateUUIDv4() error = %v", err)
	}
	
	// UUID formato: xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx (36 chars)
	if len(uuid) != 36 {
		t.Errorf("GenerateUUIDv4() returned UUID of length %d, want 36", len(uuid))
	}
	
	// Verificar versión 4 (posición 14 debe ser '4')
	if uuid[14] != '4' {
		t.Errorf("GenerateUUIDv4() version should be 4, got: %c", uuid[14])
	}
	
	// Verificar variante RFC 4122 (posición 19 debe ser 8, 9, a, o b)
	variant := uuid[19]
	if !((variant >= '8' && variant <= '9') || (variant >= 'a' && variant <= 'b')) {
		t.Errorf("GenerateUUIDv4() variant should be 8,9,a,b, got: %c", variant)
	}
}

func TestGenerateAPIKeyWithPrefix(t *testing.T) {
	apiKey, err := GenerateAPIKeyWithPrefix("usr")
	if err != nil {
		t.Fatalf("GenerateAPIKeyWithPrefix() error = %v", err)
	}
	
	// Formato: "usr_<hex>"
	if !strings.HasPrefix(apiKey, "usr_") {
		t.Errorf("GenerateAPIKeyWithPrefix('usr') should start with 'usr_', got: %s", apiKey)
	}
}

func TestGenerateAPIKeyWithPrefix_Empty(t *testing.T) {
	apiKey, err := GenerateAPIKeyWithPrefix("")
	if err != nil {
		t.Fatalf("GenerateAPIKeyWithPrefix() error = %v", err)
	}
	
	// Prefijo por defecto es "gk"
	if !strings.HasPrefix(apiKey, "gk_") {
		t.Errorf("GenerateAPIKeyWithPrefix('') should start with 'gk_', got: %s", apiKey)
	}
}

func TestGenerateAPIKeyWithPrefix_Invalid(t *testing.T) {
	_, err := GenerateAPIKeyWithPrefix("us@r")
	if err == nil {
		t.Error("GenerateAPIKeyWithPrefix() should return error for invalid prefix")
	}
}

func TestGenerateOTP(t *testing.T) {
	otp, err := GenerateOTP(6)
	if err != nil {
		t.Fatalf("GenerateOTP() error = %v", err)
	}
	
	if len(otp) != 6 {
		t.Errorf("GenerateOTP(6) returned code of length %d, want 6", len(otp))
	}
	
	// Verificar que solo contiene dígitos
	for _, c := range otp {
		if c < '0' || c > '9' {
			t.Errorf("GenerateOTP() contains non-digit character: %c", c)
		}
	}
}

func TestGenerateOTP_InvalidLength(t *testing.T) {
	_, err := GenerateOTP(0)
	if err == nil {
		t.Error("GenerateOTP(0) should return error")
	}
}
