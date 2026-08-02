package crypto

import "unicode/utf8"

var defaultHasher Hasher

func init() {
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

func SetDefaultHasher(hasher Hasher) {
	if hasher != nil {
		defaultHasher = hasher
	}
}

func HashPassword(password string) (string, error) {
	return defaultHasher.Hash(password)
}


func VerifyPassword(password, storedHash string) (bool, error) {
	algo, err := DetectAlgorithm(storedHash)
	if err != nil {
		return false, ErrInvalidHash // Usa directamente el error de hash.go
	}

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

func NeedsUpgrade(storedHash string) bool {
	return defaultHasher.NeedsUpgrade(storedHash)
}
