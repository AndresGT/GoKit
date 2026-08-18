package crypto

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

// failReader falla siempre al leer
type failReader struct{}

func (failReader) Read(p []byte) (int, error) {
	return 0, errors.New("read failed")
}

// swapRandReader reemplaza crypto/rand.Reader durante el test
func swapRandReader(t *testing.T, r interface{ Read([]byte) (int, error) }) {
	t.Helper()
	old := rand.Reader
	rand.Reader = r
	t.Cleanup(func() { rand.Reader = old })
}

// =============================================================================
// Init / estado global
// =============================================================================

func TestInitGlobalStateHasherError(t *testing.T) {
	old := newDefaultHasher
	newDefaultHasher = func() (Hasher, error) { return nil, errors.New("boom") }
	defer func() { newDefaultHasher = old; initGlobalState() }()

	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic when hasher construction fails")
		}
	}()
	initGlobalState()
}

func TestInitGlobalStateKeyError(t *testing.T) {
	old := generateDefaultKey
	generateDefaultKey = func() ([]byte, error) { return nil, errors.New("boom") }
	defer func() { generateDefaultKey = old; initGlobalState() }()

	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic when key generation fails")
		}
	}()
	initGlobalState()
}

func TestInitGlobalStateEncrypterError(t *testing.T) {
	old := newDefaultEncrypter
	newDefaultEncrypter = func(key []byte) (*AESEncrypter, error) {
		return nil, errors.New("boom")
	}
	defer func() { newDefaultEncrypter = old; initGlobalState() }()

	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic when encrypter construction fails")
		}
	}()
	initGlobalState()
}

// =============================================================================
// Argon2
// =============================================================================

func TestArgon2NewDefaults(t *testing.T) {
	h, err := NewArgon2Hasher(HasherConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if h.memory != 64*1024 || h.iterations != 3 || h.parallelism != 4 ||
		h.keyLength != 32 || h.saltLength != 16 {
		t.Errorf("unexpected defaults: %+v", h)
	}
}

func TestArgon2HashRandError(t *testing.T) {
	swapRandReader(t, failReader{})
	h, _ := NewArgon2Hasher(HasherConfig{})
	if _, err := h.Hash("pw"); err == nil {
		t.Error("expected error when rand fails")
	}
}

func TestArgon2VerifyErrors(t *testing.T) {
	h, _ := NewArgon2Hasher(HasherConfig{})

	cases := []string{
		"$argon2id$v=19$m=65536,t=3,p=4",                    // pocas partes
		"$argon2id$v=19$malformatted$c2FsdA==$aGFzaA==",      // Sscanf falla
		"$argon2id$v=19$m=65536,t=3,p=4$!!!$aGFzaA==",        // salt base64 inválido
		"$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$!!!",          // hash base64 inválido
	}
	for _, c := range cases {
		if _, err := h.Verify("pw", c); err == nil {
			t.Errorf("expected error for hash %q", c)
		}
	}
}

func TestArgon2VerifyRoundTrip(t *testing.T) {
	h, _ := NewArgon2Hasher(HasherConfig{})
	hash, _ := h.Hash("secret")
	if ok, err := h.Verify("secret", hash); err != nil || !ok {
		t.Errorf("expected valid verification, ok=%v err=%v", ok, err)
	}
	if ok, err := h.Verify("wrong", hash); err != nil || ok {
		t.Errorf("expected invalid verification, ok=%v err=%v", ok, err)
	}
}

func TestArgon2NeedsUpgrade(t *testing.T) {
	h, _ := NewArgon2Hasher(HasherConfig{Argon2Iterations: 10})

	if !h.NeedsUpgrade("not a valid hash") {
		t.Error("expected upgrade for malformed hash")
	}
	if !h.NeedsUpgrade("$argon2id$v=19$bad$c2FsdA==$aGFzaA==") {
		t.Error("expected upgrade for unparsable hash")
	}

	weak, _ := NewArgon2Hasher(HasherConfig{Argon2Memory: 64 * 1024, Argon2Iterations: 3, Argon2Parallelism: 1, Argon2KeyLength: 32, Argon2SaltLength: 16})
	weakHash, _ := weak.Hash("pw")
	if !h.NeedsUpgrade(weakHash) {
		t.Error("expected upgrade for weaker hash")
	}

	strong, _ := NewArgon2Hasher(HasherConfig{Argon2Memory: 128 * 1024, Argon2Iterations: 20, Argon2Parallelism: 8, Argon2KeyLength: 32, Argon2SaltLength: 16})
	strongHash, _ := strong.Hash("pw")
	if h.NeedsUpgrade(strongHash) {
		t.Error("expected no upgrade for stronger hash")
	}
}

// =============================================================================
// Bcrypt
// =============================================================================

func TestBcryptNewDefaults(t *testing.T) {
	h, err := NewBcryptHasher(HasherConfig{BcryptCost: 2})
	if err != nil {
		t.Fatal(err)
	}
	if h.cost != 12 {
		t.Errorf("expected default cost 12, got %d", h.cost)
	}

	h2, _ := NewBcryptHasher(HasherConfig{BcryptCost: 40})
	if h2.cost != 31 {
		t.Errorf("expected cost clamped to 31, got %d", h2.cost)
	}
}

func TestBcryptPreprocessLongPassword(t *testing.T) {
	long := strings.Repeat("a", 100)
	pre := preprocessPassword(long)
	if len(pre) == 0 {
		t.Error("expected preprocessed password")
	}

	h, _ := NewBcryptHasher(HasherConfig{BcryptCost: 4})
	hash, err := h.Hash(long)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := h.Verify(long, hash); err != nil || !ok {
		t.Errorf("long password round trip failed: ok=%v err=%v", ok, err)
	}
}

func TestBcryptHashCostError(t *testing.T) {
	h := &BcryptHasher{cost: 99}
	if _, err := h.Hash("pw"); err == nil {
		t.Error("expected error for invalid cost")
	}
}

func TestBcryptVerifyErrors(t *testing.T) {
	h, _ := NewBcryptHasher(HasherConfig{BcryptCost: 4})
	if ok, err := h.Verify("pw", "not-a-hash"); err == nil || ok {
		t.Errorf("expected error for invalid hash, ok=%v", ok)
	}
	if ok, err := h.Verify("pw", "garbage$$$"); err == nil || ok {
		t.Errorf("expected error for garbage hash, ok=%v", ok)
	}
}

func TestBcryptVerifyMismatch(t *testing.T) {
	h, _ := NewBcryptHasher(HasherConfig{BcryptCost: 4})
	hash, _ := h.Hash("correct")
	if ok, err := h.Verify("wrong", hash); err != nil || ok {
		t.Errorf("expected mismatch (false,nil), got ok=%v err=%v", ok, err)
	}
}

func TestBcryptNeedsUpgrade(t *testing.T) {
	h, _ := NewBcryptHasher(HasherConfig{BcryptCost: 12})

	if !h.NeedsUpgrade("invalid") {
		t.Error("expected upgrade for invalid hash")
	}

	weak, _ := NewBcryptHasher(HasherConfig{BcryptCost: 4})
	weakHash, _ := weak.Hash("pw")
	if !h.NeedsUpgrade(weakHash) {
		t.Error("expected upgrade for weaker cost")
	}

	strong, _ := NewBcryptHasher(HasherConfig{BcryptCost: 14})
	strongHash, _ := strong.Hash("pw")
	if h.NeedsUpgrade(strongHash) {
		t.Error("expected no upgrade for stronger cost")
	}
}

// =============================================================================
// AES / cifrado
// =============================================================================

func TestNewAESEncrypterInvalidKey(t *testing.T) {
	if _, err := NewAESEncrypter([]byte("short")); err == nil {
		t.Error("expected error for invalid key length")
	}
	if _, err := NewAESEncrypter(nil); err == nil {
		t.Error("expected error for nil key")
	}
}

func TestEncryptRandError(t *testing.T) {
	swapRandReader(t, failReader{})
	key, _ := GenerateEncryptionKey()
	e, _ := NewAESEncrypter(key)
	if _, err := e.Encrypt([]byte("data")); err == nil {
		t.Error("expected error when rand fails")
	}
}

func TestDecryptErrors(t *testing.T) {
	key, _ := GenerateEncryptionKey()
	e, _ := NewAESEncrypter(key)

	// Base64 inválido
	if _, err := e.Decrypt("!!!not-base64!!!"); err == nil {
		t.Error("expected error for invalid base64")
	}
	// Muy corto (nonce + 1 byte)
	if _, err := e.Decrypt("c2hvcnQ="); err == nil {
		t.Error("expected error for too-short ciphertext")
	}
	// Datos manipulados
	encrypted, _ := e.Encrypt([]byte("data"))
	raw, _ := base64.StdEncoding.DecodeString(encrypted)
	raw[len(raw)-1] ^= 0xFF
	if _, err := e.Decrypt(base64.StdEncoding.EncodeToString(raw)); err == nil {
		t.Error("expected error for tampered ciphertext")
	}
}

func TestGenerateEncryptionKeyRandError(t *testing.T) {
	swapRandReader(t, failReader{})
	if _, err := GenerateEncryptionKey(); err == nil {
		t.Error("expected error when rand fails")
	}
}

func TestGenerateEncryptionKeyBase64(t *testing.T) {
	key, err := GenerateEncryptionKeyBase64()
	if err != nil {
		t.Fatal(err)
	}
	if len(key) == 0 {
		t.Error("expected non-empty base64 key")
	}

	swapRandReader(t, failReader{})
	if _, err := GenerateEncryptionKeyBase64(); err == nil {
		t.Error("expected error when rand fails")
	}
}

// =============================================================================
// Factory y detección de algoritmo
// =============================================================================

func TestNewHasherUnsupported(t *testing.T) {
	if _, err := NewHasher(HasherConfig{Algorithm: Algorithm("nope")}); err == nil {
		t.Error("expected unsupported algorithm error")
	}
}

func TestDetectAlgorithmErrors(t *testing.T) {
	if _, err := DetectAlgorithm("no-dollar-prefix"); err == nil {
		t.Error("expected error for missing $ prefix")
	}
	if _, err := DetectAlgorithm("$only"); err == nil {
		t.Error("expected error for too few parts")
	}
	if _, err := DetectAlgorithm("$md5$salt$hash"); err == nil {
		t.Error("expected error for unsupported algorithm")
	}
}

func TestDetectAlgorithmSupported(t *testing.T) {
	cases := []struct {
		hash  string
		algo  Algorithm
	}{
		{"$2a$10$abcdefghijklmnopqrstuv", AlgorithmBcrypt},
		{"$2b$10$abcdefghijklmnopqrstuv", AlgorithmBcrypt},
		{"$2y$10$abcdefghijklmnopqrstuv", AlgorithmBcrypt},
		{"$argon2id$v=19$m=65536,t=3,p=4$c2FsdA==$aGFzaA==", AlgorithmArgon2id},
		{"$scrypt$ln=14,r=8,p=1$c2FsdA==$aGFzaA==", AlgorithmScrypt},
		{"$pbkdf2-sha256$i=600000$c2FsdA==$aGFzaA==", AlgorithmPBKDF2},
	}
	for _, c := range cases {
		algo, err := DetectAlgorithm(c.hash)
		if err != nil {
			t.Errorf("unexpected error for %q: %v", c.hash, err)
		}
		if algo != c.algo {
			t.Errorf("expected %v, got %v", c.algo, algo)
		}
	}
}

// =============================================================================
// Funciones globales de cifrado con clave
// =============================================================================

func TestSetEncryptionKeyInvalid(t *testing.T) {
	if err := SetEncryptionKey([]byte("short")); err == nil {
		t.Error("expected error for invalid key")
	}
}

func TestEncryptWithKeyInvalidKey(t *testing.T) {
	if _, err := EncryptWithKey("data", []byte("short")); err == nil {
		t.Error("expected error for invalid key")
	}
}

func TestDecryptWithKeyInvalidKey(t *testing.T) {
	if _, err := DecryptWithKey("data", []byte("short")); err == nil {
		t.Error("expected error for invalid key")
	}
}

// =============================================================================
// Random
// =============================================================================

func TestRandomBytesRandError(t *testing.T) {
	swapRandReader(t, failReader{})
	if _, err := RandomBytes(16); err == nil {
		t.Error("expected error when rand fails")
	}
}

func TestRandomStringInvalidLength(t *testing.T) {
	if _, err := RandomString(0); err == nil {
		t.Error("expected error for invalid length")
	}
}

func TestRandomStringRandError(t *testing.T) {
	swapRandReader(t, failReader{})
	if _, err := RandomString(16); err == nil {
		t.Error("expected error when rand fails")
	}
}

func TestRandomHexRandError(t *testing.T) {
	swapRandReader(t, failReader{})
	if _, err := RandomHex(16); err == nil {
		t.Error("expected error when rand fails")
	}
}

func TestGenerateUUIDRandError(t *testing.T) {
	swapRandReader(t, failReader{})
	if _, err := GenerateUUID(); err == nil {
		t.Error("expected error when rand fails")
	}
}

func TestGenerateNumericCodeRandError(t *testing.T) {
	swapRandReader(t, failReader{})
	if _, err := GenerateNumericCode(6); err == nil {
		t.Error("expected error when rand fails")
	}
}

func TestGenerateAPIKeyDefaultPrefix(t *testing.T) {
	key, err := GenerateAPIKey("")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(key, "gk_") {
		t.Errorf("expected default prefix gk_, got %s", key)
	}
}

func TestGenerateAPIKeyNonAlnum(t *testing.T) {
	if _, err := GenerateAPIKey("us-r"); err == nil {
		t.Error("expected error for non-alphanumeric prefix")
	}
}

func TestGenerateAPIKeyRandError(t *testing.T) {
	swapRandReader(t, failReader{})
	if _, err := GenerateAPIKey("usr"); err == nil {
		t.Error("expected error when rand fails")
	}
}

// =============================================================================
// Scrypt
// =============================================================================

func TestScryptNewDefaults(t *testing.T) {
	h, err := NewScryptHasher(HasherConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if h.n != 16384 || h.r != 8 || h.p != 1 || h.keyLen != 32 || h.saltLen != 16 {
		t.Errorf("unexpected defaults: %+v", h)
	}
}

func TestScryptHashKeyError(t *testing.T) {
	// Params inválidos forzados a través de la construcción directa
	h := &ScryptHasher{n: 3, r: 8, p: 1, keyLen: 32, saltLen: 16}
	if _, err := h.Hash("pw"); err == nil {
		t.Error("expected error for invalid scrypt params")
	}
}

func TestScryptHashRandError(t *testing.T) {
	swapRandReader(t, failReader{})
	h, _ := NewScryptHasher(HasherConfig{})
	if _, err := h.Hash("pw"); err == nil {
		t.Error("expected error when rand fails")
	}
}

func TestScryptVerifyErrors(t *testing.T) {
	h, _ := NewScryptHasher(HasherConfig{})

	cases := []string{
		"$scrypt$ln=14,r=8,p=1",                          // pocas partes
		"$scrypt$bad$c2FsdA==$aGFzaA==",                  // Sscanf falla
		"$scrypt$ln=14,r=8,p=1$!!!$aGFzaA==",             // salt inválido
		"$scrypt$ln=14,r=8,p=1$c2FsdA$!!!",                   // key inválido
		"$scrypt$ln=0,r=8,p=1$c2FsdA$c2FsdA",              // N=1 inválido en scrypt.Key
	}
	for _, c := range cases {
		if _, err := h.Verify("pw", c); err == nil {
			t.Errorf("expected error for hash %q", c)
		}
	}
}

func TestScryptNeedsUpgrade(t *testing.T) {
	h, _ := NewScryptHasher(HasherConfig{})

	if !h.NeedsUpgrade("bad") {
		t.Error("expected upgrade for malformed hash")
	}
	if !h.NeedsUpgrade("$scrypt$bad$c2FsdA==$aGFzaA==") {
		t.Error("expected upgrade for unparsable hash")
	}

	weak := &ScryptHasher{n: 16384, r: 4, p: 1, keyLen: 32, saltLen: 16}
	weakHash, _ := weak.Hash("pw")
	if !h.NeedsUpgrade(weakHash) {
		t.Error("expected upgrade for weaker hash")
	}

	strong := &ScryptHasher{n: 32768, r: 8, p: 1, keyLen: 32, saltLen: 16}
	strongHash, _ := strong.Hash("pw")
	if h.NeedsUpgrade(strongHash) {
		t.Error("expected no upgrade for stronger hash")
	}
}

// =============================================================================
// PBKDF2
// =============================================================================

func TestPBKDF2NewDefaults(t *testing.T) {
	h, err := NewPBKDF2Hasher(HasherConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if h.iterations != 600000 || h.keyLen != 32 || h.saltLen != 16 {
		t.Errorf("unexpected defaults: %+v", h)
	}
}

func TestPBKDF2HashRandError(t *testing.T) {
	swapRandReader(t, failReader{})
	h := &PBKDF2Hasher{iterations: 1000, keyLen: 32, saltLen: 16}
	if _, err := h.Hash("pw"); err == nil {
		t.Error("expected error when rand fails")
	}
}

func TestPBKDF2VerifyErrors(t *testing.T) {
	h := &PBKDF2Hasher{iterations: 1000, keyLen: 32, saltLen: 16}

	cases := []string{
		"$pbkdf2-sha256$i=1000$c2FsdA==",                     // pocas partes
		"$scrypt$i=1000$c2FsdA==$aGFzaA==",                   // algoritmo incorrecto
		"$pbkdf2-sha256$bad$c2FsdA==$aGFzaA==",               // Sscanf falla
		"$pbkdf2-sha256$i=1000$!!!$aGFzaA==",                 // salt inválido
		"$pbkdf2-sha256$i=1000$c2FsdA$!!!",                   // key inválido
	}
	for _, c := range cases {
		if _, err := h.Verify("pw", c); err == nil {
			t.Errorf("expected error for hash %q", c)
		}
	}
}

func TestPBKDF2NeedsUpgrade(t *testing.T) {
	h := &PBKDF2Hasher{iterations: 1000, keyLen: 32, saltLen: 16}

	if !h.NeedsUpgrade("bad") {
		t.Error("expected upgrade for malformed hash")
	}
	if !h.NeedsUpgrade("$pbkdf2-sha256$bad$c2FsdA==$aGFzaA==") {
		t.Error("expected upgrade for unparsable hash")
	}

	weak := &PBKDF2Hasher{iterations: 500, keyLen: 32, saltLen: 16}
	weakHash, _ := weak.Hash("pw")
	if !h.NeedsUpgrade(weakHash) {
		t.Error("expected upgrade for weaker hash")
	}

	strong := &PBKDF2Hasher{iterations: 2000, keyLen: 32, saltLen: 16}
	strongHash, _ := strong.Hash("pw")
	if h.NeedsUpgrade(strongHash) {
		t.Error("expected no upgrade for stronger hash")
	}
}

// =============================================================================
// Convenience: funciones globales de generación
// =============================================================================

func TestConvenienceRandom(t *testing.T) {
	if _, err := GenerateSecureToken(); err != nil {
		t.Fatal(err)
	}
	if _, err := GenerateUUIDv4(); err != nil {
		t.Fatal(err)
	}
	if _, err := GenerateOTP(6); err != nil {
		t.Fatal(err)
	}
	if _, err := GenerateRandomBytes(8); err != nil {
		t.Fatal(err)
	}
	if _, err := GenerateRandomString(8); err != nil {
		t.Fatal(err)
	}
}
