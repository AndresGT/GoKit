package crypto

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/scrypt"
)

// =============================================================================
// Implementación de Scrypt
// =============================================================================

// ScryptHasher implementa la interfaz Hasher usando el algoritmo scrypt.
// Scrypt fue diseñado por Colin Percival como una función de derivación de claves
// con uso intensivo de memoria, lo que la hace resistente a ataques con hardware
// especializado (GPUs, ASICs). Es una alternativa sólida a bcrypt y argon2.
type ScryptHasher struct {
	n       int // CPU/Memory cost parameter (debe ser potencia de 2)
	r       int // Block size
	p       int // Parallelization parameter
	keyLen  int // Longitud de la clave derivada
	saltLen int
}

// NewScryptHasher crea un nuevo hasher scrypt con la configuración especificada.
// Si no se proporcionan valores válidos, se usan parámetros seguros por defecto.
//
// Parámetros recomendados (según Colin Percival):
//   - N (costo CPU/memoria): 16384 mínimo, 2^14-2^20 recomendado
//   - r (tamaño de bloque): 8 (estándar)
//   - p (paralelismo): 1 (estándar para contraseñas)
//   - keyLen: 32 bytes (256 bits)
//   - saltLen: 16 bytes mínimo
//
// Nota: N debe ser potencia de 2 y mayor que 1.
func NewScryptHasher(cfg HasherConfig) (*ScryptHasher, error) {
	n := cfg.ScryptN
	if n < 16384 || (n&(n-1)) != 0 { // Verificar que sea potencia de 2
		n = 16384 // 2^14 por defecto
	}

	r := cfg.ScryptR
	if r < 8 {
		r = 8
	}

	p := cfg.ScryptP
	if p < 1 {
		p = 1
	}

	keyLen := cfg.ScryptKeyLen
	if keyLen < 32 {
		keyLen = 32
	}

	saltLen := cfg.ScryptSaltLen
	if saltLen < 16 {
		saltLen = 16
	}

	return &ScryptHasher{
		n:       n,
		r:       r,
		p:       p,
		keyLen:  keyLen,
		saltLen: saltLen,
	}, nil
}

// Hash genera un hash scrypt de la contraseña proporcionada.
// El resultado tiene el formato:
// $scrypt$ln=14,r=8,p=1$salt$hash
//
// Donde ln es el log2 de N (para facilitar la lectura).
// Este formato incluye todos los parámetros necesarios para verificar
// el hash en el futuro, permitiendo migración transparente.
func (h *ScryptHasher) Hash(password string) (string, error) {
	// Generar salt criptográficamente seguro
	salt := make([]byte, h.saltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", err
	}

	// Generar clave derivada usando scrypt
	key, err := scrypt.Key([]byte(password), salt, h.n, h.r, h.p, h.keyLen)
	if err != nil {
		return "", err
	}

	// Codificar salt y hash en base64
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Key := base64.RawStdEncoding.EncodeToString(key)

	// Calcular log2 de N para el formato
	ln := 0
	temp := h.n
	for temp > 1 {
		temp >>= 1
		ln++
	}

	// Construir el string final con todos los parámetros
	encodedHash := fmt.Sprintf("$scrypt$ln=%d,r=%d,p=%d$%s$%s",
		ln, h.r, h.p, b64Salt, b64Key)

	return encodedHash, nil
}

// Verify compara una contraseña en texto plano con un hash scrypt.
// Extrae los parámetros del hash para garantizar que se usa la misma
// configuración que cuando se generó. Usa comparación de tiempo constante.
func (h *ScryptHasher) Verify(password, hash string) (bool, error) {
	// Parsear el hash para extraer parámetros
	parts := strings.Split(hash, "$")
	if len(parts) != 5 {
		return false, ErrInvalidHash
	}

	// Extraer parámetros del hash
	var ln, r, p int
	_, err := fmt.Sscanf(parts[2], "ln=%d,r=%d,p=%d", &ln, &r, &p)
	if err != nil {
		return false, ErrInvalidHash
	}

	// Convertir ln de vuelta a N (2^ln)
	n := 1 << ln

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
	actualKey, err := scrypt.Key([]byte(password), salt, n, r, p, len(expectedKey))
	if err != nil {
		return false, err
	}

	// Comparación de tiempo constante
	return subtle.ConstantTimeCompare(actualKey, expectedKey) == 1, nil
}

// NeedsUpgrade determina si un hash scrypt debe ser regenerado porque
// los parámetros configurados actualmente son más estrictos que los usados
// para generar el hash.
func (h *ScryptHasher) NeedsUpgrade(hash string) bool {
	parts := strings.Split(hash, "$")
	if len(parts) != 5 {
		return true
	}

	var ln, r, p int
	_, err := fmt.Sscanf(parts[2], "ln=%d,r=%d,p=%d", &ln, &r, &p)
	if err != nil {
		return true
	}

	// Calcular log2 del N actual
	currentLn := 0
	temp := h.n
	for temp > 1 {
		temp >>= 1
		currentLn++
	}

	// Si cualquiera de los parámetros actuales es más estricto, necesita upgrade
	return ln < currentLn || r < h.r || p < h.p
}