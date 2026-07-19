package crypto

import (
	"crypto/sha256"
	"encoding/base64"

	"golang.org/x/crypto/bcrypt"
)

// =============================================================================
// Implementación de Bcrypt
// =============================================================================

// BcryptHasher implementa la interfaz Hasher usando el algoritmo bcrypt.
// Bcrypt es ampliamente considerado el estándar de la industria para hashing
// de contraseñas debido a su adaptabilidad (costo ajustable) y resistencia
// a ataques de fuerza bruta.
type BcryptHasher struct {
	cost int
}

// NewBcryptHasher crea un nuevo hasher bcrypt con la configuración especificada.
// Si no se proporciona un costo válido, se usa el valor predeterminado de 12.
//
// El costo debe estar entre 4 y 31. Valores más altos son más seguros pero
// más lentos. Recomendaciones:
//   - Desarrollo: 10
//   - Producción estándar: 12
//   - Alta seguridad: 14
//   - Crítico: 15+
func NewBcryptHasher(cfg HasherConfig) (*BcryptHasher, error) {
	cost := cfg.BcryptCost
	if cost < bcrypt.MinCost {
		cost = 12 // Valor seguro por defecto
	}
	if cost > 31 {
		cost = 31
	}

	return &BcryptHasher{
		cost: cost,
	}, nil
}

// preprocessPassword adapta la contraseña al límite de 72 bytes de bcrypt.
// En lugar de truncarla (lo que descartaría silenciosamente el resto de la
// contraseña y debilitaría su entropía real), las contraseñas más largas se
// pre-hashean con SHA-256 y se codifican en base64. El resultado siempre
// ocupa 44 bytes, muy por debajo del límite de bcrypt, y preserva toda la
// entropía de la contraseña original.
func preprocessPassword(password string) []byte {
	if len(password) <= 72 {
		return []byte(password)
	}

	sum := sha256.Sum256([]byte(password))
	encoded := base64.StdEncoding.EncodeToString(sum[:])
	return []byte(encoded)
}

// Hash genera un hash bcrypt de la contraseña proporcionada.
// El resultado incluye el salt y el hash en un solo string con el formato:
// $2a$12$salt...hash...
//
// Bcrypt tiene un límite de 72 bytes: las contraseñas más largas se
// pre-hashean con SHA-256 (ver preprocessPassword) en lugar de truncarse,
// para no perder entropía de la parte final de la contraseña.
func (h *BcryptHasher) Hash(password string) (string, error) {
	pwBytes := preprocessPassword(password)

	hash, err := bcrypt.GenerateFromPassword(pwBytes, h.cost)
	if err != nil {
		return "", err
	}

	return string(hash), nil
}

// Verify compara una contraseña en texto plano con un hash bcrypt.
// Usa bcrypt.CompareHashAndPassword que internamente realiza una comparación
// de tiempo constante para prevenir ataques de timing.
func (h *BcryptHasher) Verify(password, hash string) (bool, error) {
	// Aplicar el mismo preprocesamiento que en Hash para contraseñas largas
	pwBytes := preprocessPassword(password)

	err := bcrypt.CompareHashAndPassword([]byte(hash), pwBytes)
	if err != nil {
		if err == bcrypt.ErrMismatchedHashAndPassword {
			return false, nil
		}
		return false, err
	}

	return true, nil
}

// NeedsUpgrade determina si un hash bcrypt debe ser regenerado porque
// el costo configurado actualmente es mayor que el usado para generar el hash.
// Esto permite migrar gradualmente a costos más altos sin invalidar hashes existentes.
func (h *BcryptHasher) NeedsUpgrade(hash string) bool {
	cost, err := bcrypt.Cost([]byte(hash))
	if err != nil {
		return true // Si no podemos leer el costo, mejor regenerar
	}
	return cost < h.cost
}