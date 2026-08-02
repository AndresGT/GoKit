# 🔐 Módulo Crypto - GoKit

Módulo criptográfico completo para hashing de contraseñas, cifrado simétrico y generación de datos aleatorios seguros. Diseñado con enfoque dual: **uso rápido** para prototipado y **configuración completa** para producción.

## 📋 Tabla de Contenidos

- [Características](#-características)
- [Inicio Rápido](#-inicio-rápido)
  - [Hashing de Contraseñas](#hashing-de-contraseñas)
  - [Cifrado de Datos](#cifrado-de-datos)
  - [Generación Aleatoria](#generación-aleatoria)
- [Uso Avanzado](#-uso-avanzado)
  - [Configuración de Hashers](#configuración-de-hashers)
  - [Configuración de Cifrado](#configuración-de-cifrado)
- [API Reference](#-api-reference)
- [Ejemplos Completos](#-ejemplos-completos)
- [Seguridad y Mejores Prácticas](#-seguridad-y-mejores-prácticas)

---

## ✨ Características

### Hashing de Contraseñas
- ✅ **4 algoritmos**: Argon2id (recomendado), Bcrypt, Scrypt, PBKDF2-SHA256
- ✅ **Formato PHC estándar**: `$algoritmo$parametros$salt$hash`
- ✅ **Detección automática**: Identifica el algoritmo de hashes existentes
- ✅ **NeedsUpgrade**: Detecta cuando un hash debe regenerarse con parámetros más seguros
- ✅ **Comparación en tiempo constante**: Previene ataques de timing

### Cifrado Simétrico
- ✅ **AES-256-GCM**: Estándar militar/gubernamental
- ✅ **Autenticación integrada**: Detecta manipulación de datos
- ✅ **Nonce aleatorio**: Cada cifrado usa un nonce único
- ✅ **Sin padding oracle**: GCM no requiere padding

### Generación Aleatoria
- ✅ **Criptográficamente seguro**: Usa `crypto/rand` del sistema
- ✅ **Múltiples formatos**: Bytes, strings, hex, UUIDs, API keys, OTPs
- ✅ **URL-safe**: Caracteres compatibles con URLs y headers HTTP

---

## 🚀 Inicio Rápido

### Hashing de Contraseñas

```go
package main

import (
    "fmt"
    "github.com/tu-usuario/gokit/security/crypto"
)

func main() {
    // Forma más rápida - usa Argon2id por defecto
    hash, err := crypto.HashPassword("mi-contraseña-segura")
    if err != nil {
        panic(err)
    }
    fmt.Println("Hash:", hash)
    
    // Verificar contraseña
    valid, err := crypto.VerifyPassword("mi-contraseña-segura", hash)
    if err != nil {
        panic(err)
    }
    fmt.Println("Válida:", valid) // true
    
    // Verificar si necesita actualización
    if crypto.NeedsUpgrade(hash) {
        nuevoHash, _ := crypto.HashPassword("mi-contraseña-segura")
        // Guardar nuevoHash en la base de datos
    }
}
```

### Cifrado de Datos

```go
package main

import (
    "fmt"
    "github.com/tu-usuario/gokit/security/crypto"
)

func main() {
    // ⚠️ IMPORTANTE: Configurar clave segura en producción
    key, err := crypto.GenerateEncryptionKey()
    if err != nil {
        panic(err)
    }
    crypto.SetEncryptionKey(key)
    
    // Cifrar datos
    encrypted, err := crypto.EncryptString("dato-secreto-a-guardar")
    if err != nil {
        panic(err)
    }
    fmt.Println("Cifrado:", encrypted)
    
    // Descifrar datos
    decrypted, err := crypto.DecryptString(encrypted)
    if err != nil {
        panic(err)
    }
    fmt.Println("Descifrado:", decrypted) // "dato-secreto-a-guardar"
}
```

### Generación Aleatoria

```go
package main

import (
    "fmt"
    "github.com/tu-usuario/gokit/security/crypto"
)

func main() {
    // Session ID (32 caracteres URL-safe)
    sessionID, _ := crypto.GenerateRandomString(32)
    fmt.Println("Session ID:", sessionID)
    
    // Token hexadecimal (64 caracteres)
    token, _ := crypto.GenerateSecureToken()
    fmt.Println("Token:", token)
    
    // UUID v4
    uuid, _ := crypto.GenerateUUIDv4()
    fmt.Println("UUID:", uuid)
    
    // API Key con prefijo
    apiKey, _ := crypto.GenerateAPIKeyWithPrefix("usr")
    fmt.Println("API Key:", apiKey) // usr_a1b2c3d4e5f6...
    
    // Código OTP de 6 dígitos
    otp, _ := crypto.GenerateOTP(6)
    fmt.Println("OTP:", otp) // 482913
}
```

---

## 🔧 Uso Avanzado

### Configuración de Hashers

#### Argon2id (Recomendado por OWASP)

```go
import "github.com/tu-usuario/gokit/security/crypto"

// Configuración personalizada
hasher, err := crypto.NewHasher(crypto.HasherConfig{
    Algorithm:         crypto.AlgorithmArgon2id,
    Argon2Memory:      128 * 1024, // 128 MB
    Argon2Iterations:  4,
    Argon2Parallelism: 4,
    Argon2KeyLength:   32,
    Argon2SaltLength:  16,
})
if err != nil {
    panic(err)
}

// Usar hasher
hash, err := hasher.Hash("mi-contraseña")
valid, err := hasher.Verify("mi-contraseña", hash)
needsUpgrade := hasher.NeedsUpgrade(hash)
```

**Parámetros recomendados (RFC 9106):**
| Parámetro | Mínimo | Producción | Alta Seguridad |
|-----------|--------|------------|----------------|
| Memoria | 64 MB | 128 MB | 256 MB |
| Iteraciones | 3 | 4 | 5+ |
| Paralelismo | 1 | 4 | 8 |

#### Bcrypt (Compatibilidad Legacy)

```go
hasher, err := crypto.NewHasher(crypto.HasherConfig{
    Algorithm:    crypto.AlgorithmBcrypt,
    BcryptCost:   12, // 10=dev, 12=prod, 14=high-security
})
```

#### Scrypt

```go
hasher, err := crypto.NewHasher(crypto.HasherConfig{
    Algorithm:     crypto.AlgorithmScrypt,
    ScryptN:       16384,  // 2^14
    ScryptR:       8,
    ScryptP:       1,
    ScryptKeyLen:  32,
    ScryptSaltLen: 16,
})
```

#### PBKDF2-SHA256 (Estándar NIST)

```go
hasher, err := crypto.NewHasher(crypto.HasherConfig{
    Algorithm:        crypto.AlgorithmPBKDF2,
    PBKDF2Iterations: 600000, // Recomendación OWASP 2023
    PBKDF2KeyLen:     32,
    PBKDF2SaltLen:    16,
})
```

### Funciones Directas por Algoritmo

```go
// Sin configuración - usan defaults óptimos
hash1, _ := crypto.HashWithArgon2id("password")
hash2, _ := crypto.HashWithBcrypt("password")
hash3, _ := crypto.HashWithScrypt("password")
hash4, _ := crypto.HashWithPBKDF2("password")
```

### Configuración de Cifrado

#### Con Instancia Personalizada

```go
// Generar o cargar clave (32 bytes exactos)
key, err := crypto.GenerateEncryptionKey()
if err != nil {
    panic(err)
}

// Crear cifrador
encrypter, err := crypto.NewAESEncrypter(key)
if err != nil {
    panic(err)
}

// Cifrar/descifrar
encrypted, _ := encrypter.EncryptString("secreto")
decrypted, _ := encrypter.DecryptString(encrypted)

// También con bytes
encryptedBytes, _ := encrypter.Encrypt([]byte{0x01, 0x02, 0x03})
decryptedBytes, _ := encrypter.Decrypt(encryptedBytes)
```

#### Desde Variable de Entorno (Producción)

```go
import (
    "encoding/base64"
    "os"
    "github.com/tu-usuario/gokit/security/crypto"
)

// En tu inicialización
keyBase64 := os.Getenv("ENCRYPTION_KEY")
keyBytes, err := base64.StdEncoding.DecodeString(keyBase64)
if err != nil {
    panic("clave inválida")
}

err = crypto.SetEncryptionKey(keyBytes)
if err != nil {
    panic(err)
}

// Ahora puedes usar las funciones globales
encrypted, _ := crypto.EncryptString("datos-sensibles")
```

#### Cifrado con Clave Específica (Sin Global)

```go
// Útil para multi-tenancy o claves rotativas
key1, _ := crypto.GenerateEncryptionKey()
key2, _ := crypto.GenerateEncryptionKey()

encrypted1, _ := crypto.EncryptWithKey("datos-tenant1", key1)
encrypted2, _ := crypto.EncryptWithKey("datos-tenant2", key2)

decrypted1, _ := crypto.DecryptWithKey(encrypted1, key1)
decrypted2, _ := crypto.DecryptWithKey(encrypted2, key2)
```

---

## 📖 API Reference

### Funciones de Conveniencia (Uso Rápido)

#### Hashing
| Función | Descripción | Retorna |
|---------|-------------|---------|
| `HashPassword(password string)` | Hash con Argon2id por defecto | `(hash, error)` |
| `VerifyPassword(password, hash string)` | Verifica contraseña contra hash | `(bool, error)` |
| `NeedsUpgrade(hash string)` | Chequea si hash necesita actualización | `bool` |
| `SetDefaultHasher(hasher Hasher)` | Cambia hasher global | `-` |

#### Funciones Directas por Algoritmo
| Función | Algoritmo | Defaults |
|---------|-----------|----------|
| `HashWithArgon2id(password)` | Argon2id | 64MB, 3 iter, 4 parallel |
| `HashWithBcrypt(password)` | Bcrypt | Cost 12 |
| `HashWithScrypt(password)` | Scrypt | N=16384, r=8, p=1 |
| `HashWithPBKDF2(password)` | PBKDF2-SHA256 | 600k iteraciones |

#### Cifrado
| Función | Descripción | Nota |
|---------|-------------|------|
| `EncryptString(plaintext string)` | Cifra string con clave global | ⚠️ Configurar clave primero |
| `DecryptString(ciphertext string)` | Descifra string con clave global | - |
| `EncryptBytes(plaintext []byte)` | Cifra bytes con clave global | - |
| `DecryptBytes(ciphertext string)` | Descifra bytes a []byte | - |
| `SetEncryptionKey(key []byte)` | Configura clave global (32 bytes) | **Obligatorio en producción** |
| `EncryptWithKey(plaintext, key)` | Cifra con clave específica | Sin usar global |
| `DecryptWithKey(ciphertext, key)` | Descifra con clave específica | - |

#### Generación Aleatoria
| Función | Descripción | Ejemplo de Salida |
|---------|-------------|-------------------|
| `GenerateRandomBytes(n int)` | n bytes seguros | `[0x3a, 0x7f, ...]` |
| `GenerateRandomString(n int)` | String URL-safe de n chars | `"aB3xK9mP2qL5nR8w..."` |
| `GenerateSecureToken()` | Token hex de 32 bytes | `"a1b2c3d4e5f6..."` (64 chars) |
| `GenerateUUIDv4()` | UUID versión 4 | `"550e8400-e29b-41d4-a716-446655440000"` |
| `GenerateAPIKeyWithPrefix(prefix)` | API key con prefijo | `"usr_a1b2c3d4..."` |
| `GenerateOTP(length int)` | Código numérico OTP | `"482913"` (6 dígitos) |

### Interfaces

#### Hasher
```go
type Hasher interface {
    Hash(password string) (string, error)
    Verify(password, hash string) (bool, error)
    NeedsUpgrade(hash string) bool
}
```

#### Encrypter
```go
type Encrypter interface {
    Encrypt(plaintext []byte) (string, error)
    Decrypt(ciphertext string) ([]byte, error)
    EncryptString(plaintext string) (string, error)
    DecryptString(ciphertext string) (string, error)
}
```

### Tipos y Constantes

#### Algorithm
```go
type Algorithm string

const (
    AlgorithmBcrypt    Algorithm = "bcrypt"
    AlgorithmArgon2id  Algorithm = "argon2id"  // ✅ Recomendado
    AlgorithmScrypt    Algorithm = "scrypt"
    AlgorithmPBKDF2    Algorithm = "pbkdf2"
)
```

#### HasherConfig
```go
type HasherConfig struct {
    Algorithm Algorithm
    
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
```

### Errores

#### Hashing
| Error | Descripción |
|-------|-------------|
| `ErrInvalidHash` | Formato de hash inválido |
| `ErrUnsupportedAlgorithm` | Algoritmo no registrado |
| `ErrPasswordTooShort` | Contraseña < mínimo seguro |
| `ErrPasswordTooLong` | Contraseña > máximo (mitiga DoS) |

#### Cifrado
| Error | Descripción |
|-------|-------------|
| `ErrInvalidKeyLength` | Clave ≠ 32 bytes |
| `ErrEncryptionFailed` | Fallo al cifrar |
| `ErrDecryptionFailed` | Clave incorrecta o datos corruptos |
| `ErrInvalidCiphertext` | Formato inválido |

#### Generación Aleatoria
| Error | Descripción |
|-------|-------------|
| `ErrInvalidLength` | Longitud ≤ 0 |
| `ErrRandomGenerationFailed` | Fallo del sistema (muy raro) |
| `ErrInvalidPrefix` | Prefijo con caracteres no alfanuméricos |

---

## 💡 Ejemplos Completos

### Sistema de Autenticación con Migración Gradual

```go
package auth

import (
    "database/sql"
    "github.com/tu-usuario/gokit/security/crypto"
)

type UserService struct {
    db *sql.DB
}

func (s *UserService) Register(email, password string) error {
    // Hashear con algoritmo actual (Argon2id por defecto)
    hash, err := crypto.HashPassword(password)
    if err != nil {
        return err
    }
    
    // Guardar en BD
    _, err = s.db.Exec(
        "INSERT INTO users (email, password_hash) VALUES (?, ?)",
        email, hash,
    )
    return err
}

func (s *UserService) Login(email, password string) (*User, error) {
    // Obtener usuario y hash
    var user User
    var storedHash string
    err := s.db.QueryRow(
        "SELECT id, email, password_hash FROM users WHERE email = ?",
        email,
    ).Scan(&user.ID, &user.Email, &storedHash)
    
    if err == sql.ErrNoRows {
        return nil, fmt.Errorf("usuario no encontrado")
    }
    if err != nil {
        return nil, err
    }
    
    // Verificar contraseña (detecta algoritmo automáticamente)
    valid, err := crypto.VerifyPassword(password, storedHash)
    if err != nil || !valid {
        return nil, fmt.Errorf("credenciales inválidas")
    }
    
    // Migración gradual: si necesita upgrade, regenerar hash
    if crypto.NeedsUpgrade(storedHash) {
        newHash, err := crypto.HashPassword(password)
        if err == nil {
            s.db.Exec(
                "UPDATE users SET password_hash = ? WHERE id = ?",
                newHash, user.ID,
            )
        }
    }
    
    return &user, nil
}
```

### Gestión de Sesiones Seguras

```go
package session

import (
    "github.com/tu-usuario/gokit/security/crypto"
)

type SessionManager struct {
    encryptionKey []byte
}

func NewSessionManager() (*SessionManager, error) {
    // Generar o cargar clave de cifrado
    keyBase64 := os.Getenv("SESSION_ENCRYPTION_KEY")
    keyBytes, err := base64.StdEncoding.DecodeString(keyBase64)
    if err != nil {
        return nil, err
    }
    
    return &SessionManager{encryptionKey: keyBytes}, nil
}

func (m *SessionManager) CreateSession(userID string) (string, error) {
    // Generar ID de sesión seguro
    sessionID, err := crypto.GenerateRandomString(32)
    if err != nil {
        return "", err
    }
    
    // Cifrar datos de sesión
    sessionData := fmt.Sprintf("%s:%d", userID, time.Now().Unix())
    encrypted, err := crypto.EncryptWithKey(sessionData, m.encryptionKey)
    if err != nil {
        return "", err
    }
    
    return sessionID, nil
}

func (m *SessionManager) ValidateSession(token string) (string, error) {
    // Descifrar datos de sesión
    decrypted, err := crypto.DecryptWithKey(token, m.encryptionKey)
    if err != nil {
        return "", fmt.Errorf("sesión inválida")
    }
    
    // Parsear userID
    parts := strings.Split(decrypted, ":")
    if len(parts) != 2 {
        return "", fmt.Errorf("formato de sesión inválido")
    }
    
    return parts[0], nil
}
```

### Generación de API Keys para Usuarios

```go
package api

import (
    "github.com/tu-usuario/gokit/security/crypto"
)

type APIKeyService struct {
    db *sql.DB
}

func (s *APIKeyService) GenerateKey(userID int, name string) (string, error) {
    // Generar API key única
    apiKey, err := crypto.GenerateAPIKeyWithPrefix("ak")
    if err != nil {
        return "", err
    }
    
    // Hashear la key antes de guardar (como una contraseña)
    hashedKey, err := crypto.HashPassword(apiKey)
    if err != nil {
        return "", err
    }
    
    // Guardar hash en BD (nunca guardar la key en texto plano)
    _, err = s.db.Exec(
        "INSERT INTO api_keys (user_id, name, key_hash, created_at) VALUES (?, ?, ?, NOW())",
        userID, name, hashedKey,
    )
    if err != nil {
        return "", err
    }
    
    // Retornar la key solo una vez (el usuario debe guardarla)
    return apiKey, nil
}

func (s *APIKeyService) ValidateKey(apiKey string) (int, error) {
    // Buscar todos los hashes de API keys
    rows, err := s.db.Query("SELECT id, key_hash FROM api_keys WHERE active = true")
    if err != nil {
        return 0, err
    }
    defer rows.Close()
    
    for rows.Next() {
        var id int
        var hash string
        rows.Scan(&id, &hash)
        
        valid, err := crypto.VerifyPassword(apiKey, hash)
        if err == nil && valid {
            return id, nil
        }
    }
    
    return 0, fmt.Errorf("API key inválida")
}
```

---

## 🔒 Seguridad y Mejores Prácticas

### ✅ DO (Hacer)

1. **Usar Argon2id por defecto** para nuevas aplicaciones
2. **Configurar clave de cifrado desde variables de entorno** en producción
3. **Rotar claves periódicamente** y usar `NeedsUpgrade()` para migración gradual
4. **Validar longitud de contraseñas** (mínimo 8-12 caracteres)
5. **Almacenar solo hashes**, nunca contraseñas en texto plano
6. **Usar HTTPS** siempre que se transmitan datos sensibles
7. **Registrar intentos fallidos** de verificación para detectar ataques

### ❌ DON'T (No Hacer)

1. **NO usar la clave de cifrado por defecto** en producción
2. **NO almacenar contraseñas** ni claves de cifrado en código fuente
3. **NO revelar detalles de errores** criptográficos al usuario final
4. **NO usar algoritmos deprecated** como MD5, SHA-1, o DES
5. **NO reutilizar nonces** o salts entre diferentes cifrados
6. **NO hacer log de datos sensibles** ni claves de cifrado

### Parámetros de Seguridad Recomendados (2024)

| Algoritmo | Uso | Parámetros |
|-----------|-----|------------|
| **Argon2id** | Nuevo desarrollo | 128 MB, 4 iter, 4 parallel |
| **Bcrypt** | Legacy/compatibilidad | Cost 12-14 |
| **PBKDF2** | Enterprise/NIST | 600k+ iteraciones SHA-256 |
| **AES-256-GCM** | Cifrado simétrico | Clave 32 bytes, nonce 12 bytes |

### Migración entre Algoritmos

El módulo soporta migración transparente:

```go
func MigrateHashIfNeeded(userID int, password, oldHash string) {
    // Verificar si el hash antiguo necesita actualización
    if crypto.NeedsUpgrade(oldHash) {
        // Generar nuevo hash con parámetros actuales
        newHash, err := crypto.HashPassword(password)
        if err == nil {
            // Actualizar en BD
            db.Exec("UPDATE users SET password_hash = ? WHERE id = ?", newHash, userID)
        }
    }
}
```

---

## 📚 Recursos Adicionales

- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [RFC 9106 - Argon2](https://www.rfc-editor.org/rfc/rfc9106.html)
- [NIST SP 800-132 - PBKDF](https://csrc.nist.gov/publications/detail/sp/800-132/final)
- [AES-GCM Security Recommendations](https://csrc.nist.gov/publications/detail/sp/800-38d/final)

---

**Versión:** 1.0.0  
**Licencia:** MIT  
**Go Version:** 1.26.4+
