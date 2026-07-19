package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
)

// =============================================================================
// Errores de Cifrado
// =============================================================================

var (
	// ErrInvalidKeyLength se retorna cuando la clave de cifrado no tiene
	// la longitud correcta. AES-256 requiere exactamente 32 bytes.
	ErrInvalidKeyLength = errors.New("la clave debe tener exactamente 32 bytes para AES-256")

	// ErrEncryptionFailed se retorna cuando el proceso de cifrado falla.
	// Es un error genérico que no revela detalles internos del sistema.
	ErrEncryptionFailed = errors.New("fallo al cifrar los datos")

	// ErrDecryptionFailed se retorna cuando el proceso de descifrado falla.
	// Puede deberse a una clave incorrecta, datos corruptos o manipulación.
	ErrDecryptionFailed = errors.New("fallo al descifrar los datos")

	// ErrInvalidCiphertext se retorna cuando el texto cifrado está mal formado
	// o no tiene el formato esperado (nonce + ciphertext + tag).
	ErrInvalidCiphertext = errors.New("formato de texto cifrado inválido")
)

// =============================================================================
// Constantes
// =============================================================================

const (
	// aesKeySize es el tamaño de clave para AES-256 (32 bytes = 256 bits).
	// AES-256 es el estándar actual para cifrado simétrico de alta seguridad.
	aesKeySize = 32

	// nonceSize es el tamaño del nonce para AES-GCM (12 bytes = 96 bits).
	// Este es el tamaño recomendado por NIST para GCM.
	nonceSize = 12
)

// =============================================================================
// Interfaz de Cifrado
// =============================================================================

// Encrypter define el contrato para sistemas de cifrado simétrico.
// Esta abstracción permite cambiar el algoritmo de cifrado sin modificar
// el código que lo utiliza (principio Open/Closed).
type Encrypter interface {
	// Encrypt cifra los datos proporcionados usando la clave configurada.
	// Los datos cifrados incluyen el nonce y el tag de autenticación.
	// El resultado está codificado en base64 para facilitar su almacenamiento.
	Encrypt(plaintext []byte) (string, error)

	// Decrypt descifra los datos cifrados proporcionados.
	// El input debe estar en base64 y contener el nonce, ciphertext y tag.
	// Retorna un error si la clave es incorrecta o los datos fueron manipulados.
	Decrypt(ciphertext string) ([]byte, error)

	// EncryptString es una conveniencia para cifrar strings directamente.
	EncryptString(plaintext string) (string, error)

	// DecryptString es una conveniencia para descifrar a string directamente.
	DecryptString(ciphertext string) (string, error)
}

// =============================================================================
// Implementación AES-256-GCM
// =============================================================================

// AESEncrypter implementa la interfaz Encrypter usando AES-256-GCM.
// GCM (Galois/Counter Mode) proporciona tanto confidencialidad como
// autenticación, lo que significa que detecta cualquier manipulación
// de los datos cifrados.
//
// Características de seguridad:
//   - AES-256: Cifrado simétrico de 256 bits (estándar militar/gubernamental)
//   - GCM Mode: Proporciona autenticación integrada (AEAD)
//   - Nonce aleatorio: Cada cifrado usa un nonce único de 12 bytes
//   - Sin padding: GCM no requiere padding, evitando ataques de padding oracle
type AESEncrypter struct {
	key []byte
	gcm cipher.AEAD
}

// NewAESEncrypter crea un nuevo cifrador AES-256-GCM con la clave proporcionada.
// La clave debe tener exactamente 32 bytes (256 bits).
//
// Ejemplo de uso:
//
//	// Generar una clave segura
//	key, _ := crypto.GenerateEncryptionKey()
//
//	// Crear el cifrador
//	encrypter, err := crypto.NewAESEncrypter(key)
//	if err != nil {
//	    // Manejar error (clave inválida)
//	}
//
//	// Cifrar datos
//	encrypted, _ := encrypter.EncryptString("dato-sensible")
//
//	// Descifrar datos
//	decrypted, _ := encrypter.DecryptString(encrypted)
func NewAESEncrypter(key []byte) (*AESEncrypter, error) {
	if len(key) != aesKeySize {
		return nil, ErrInvalidKeyLength
	}

	// Crear el cipher AES
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrEncryptionFailed
	}

	// Crear el modo GCM
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrEncryptionFailed
	}

	return &AESEncrypter{
		key: key,
		gcm: gcm,
	}, nil
}

// Encrypt cifra los datos proporcionados usando AES-256-GCM.
// El proceso es:
// 1. Generar un nonce aleatorio de 12 bytes
// 2. Cifrar los datos con GCM (incluye autenticación)
// 3. Concatenar nonce + ciphertext (necesario para descifrar)
// 4. Codificar en base64 para facilitar almacenamiento/transmisión
//
// El resultado tiene el formato: base64(nonce + ciphertext + tag)
//
// Ejemplo de uso:
//
//	plaintext := []byte("número de tarjeta: 4111-1111-1111-1111")
//	encrypted, err := encrypter.Encrypt(plaintext)
//	if err != nil {
//	    // Manejar error
//	}
//	// encrypted: "r4nd0mN0nc3...c1ph3rt3xt..."
func (e *AESEncrypter) Encrypt(plaintext []byte) (string, error) {
	// Generar nonce aleatorio criptográficamente seguro
	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", ErrEncryptionFailed
	}

	// Cifrar los datos (GCM añade el tag de autenticación automáticamente)
	ciphertext := e.gcm.Seal(nil, nonce, plaintext, nil)

	// Concatenar nonce + ciphertext (necesario para descifrar)
	// Formato: [nonce (12 bytes)][ciphertext + tag]
	// Se reserva un buffer nuevo en vez de usar append(nonce, ...) directamente,
	// para no depender de que 'nonce' no tenga capacidad extra en su slice.
	combined := make([]byte, 0, len(nonce)+len(ciphertext))
	combined = append(combined, nonce...)
	combined = append(combined, ciphertext...)

	// Codificar en base64 para facilitar almacenamiento
	return base64.StdEncoding.EncodeToString(combined), nil
}

// Decrypt descifra los datos cifrados proporcionados.
// El proceso es:
// 1. Decodificar de base64
// 2. Extraer el nonce (primeros 12 bytes)
// 3. Extraer el ciphertext (resto)
// 4. Descifrar y verificar autenticación con GCM
//
// Retorna un error si:
//   - El formato es inválido
//   - La clave es incorrecta
//   - Los datos fueron manipulados (tag de autenticación no coincide)
//
// Ejemplo de uso:
//
//	decrypted, err := encrypter.Decrypt(encrypted)
//	if err != nil {
//	    // Clave incorrecta o datos corruptos
//	}
func (e *AESEncrypter) Decrypt(ciphertext string) ([]byte, error) {
	// Decodificar de base64
	combined, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return nil, ErrInvalidCiphertext
	}

	// Verificar longitud mínima (nonce + al menos 1 byte de ciphertext)
	if len(combined) < nonceSize+1 {
		return nil, ErrInvalidCiphertext
	}

	// Extraer nonce y ciphertext
	nonce := combined[:nonceSize]
	encryptedData := combined[nonceSize:]

	// Descifrar y verificar autenticación
	plaintext, err := e.gcm.Open(nil, nonce, encryptedData, nil)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	return plaintext, nil
}

// EncryptString es una función de conveniencia para cifrar strings directamente.
// Internamente convierte el string a []byte, cifra, y devuelve el resultado en base64.
//
// Ejemplo de uso:
//
//	encrypted, err := encrypter.EncryptString("API Secret Key")
//	if err != nil {
//	    // Manejar error
//	}
func (e *AESEncrypter) EncryptString(plaintext string) (string, error) {
	return e.Encrypt([]byte(plaintext))
}

// DecryptString es una función de conveniencia para descifrar directamente a string.
// Internamente descifra y convierte el resultado de []byte a string.
//
// Ejemplo de uso:
//
//	decrypted, err := encrypter.DecryptString(encrypted)
//	if err != nil {
//	    // Manejar error
//	}
//	fmt.Println(decrypted) // "API Secret Key"
func (e *AESEncrypter) DecryptString(ciphertext string) (string, error) {
	plaintext, err := e.Decrypt(ciphertext)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

// =============================================================================
// Funciones Helper para Generación de Claves
// =============================================================================

// GenerateEncryptionKey genera una clave criptográficamente segura de 32 bytes
// (256 bits) para usar con AES-256. Esta clave debe mantenerse en secreto
// y almacenarse de forma segura (ej. variables de entorno, vault, KMS).
//
// IMPORTANTE: Si pierdes esta clave, los datos cifrados con ella serán
// irrecuperables. No hay forma de recuperar la clave.
//
// Ejemplo de uso:
//
//	key, err := crypto.GenerateEncryptionKey()
//	if err != nil {
//	    // Manejar error (fallo del sistema, muy raro)
//	}
//
//	// Guardar la clave de forma segura
//	// Ejemplo: os.Setenv("ENCRYPTION_KEY", base64.StdEncoding.EncodeToString(key))
//
//	// Usar la clave para crear un cifrador
//	encrypter, _ := crypto.NewAESEncrypter(key)
func GenerateEncryptionKey() ([]byte, error) {
	key := make([]byte, aesKeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, ErrEncryptionFailed
	}
	return key, nil
}

// GenerateEncryptionKeyBase64 genera una clave de cifrado y la devuelve
// codificada en base64 para facilitar su almacenamiento en variables de
// entorno o archivos de configuración.
//
// Ejemplo de uso:
//
//	keyBase64, err := crypto.GenerateEncryptionKeyBase64()
//	if err != nil {
//	    // Manejar error
//	}
//	fmt.Println(keyBase64) // "r4nd0mK3yB4s364..."
//
//	// Para usarla después:
//	key, _ := base64.StdEncoding.DecodeString(keyBase64)
//	encrypter, _ := crypto.NewAESEncrypter(key)
func GenerateEncryptionKeyBase64() (string, error) {
	key, err := GenerateEncryptionKey()
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(key), nil
}
