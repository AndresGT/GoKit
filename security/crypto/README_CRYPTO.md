[![Go Version](https://img.shields.io/badge/Go-1.26+-00ADD8?style=flat&logo=go)](https://golang.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)


# GoKit Crypto

Módulo de seguridad criptográfica para el ecosistema **GoKit**: hashing de contraseñas, cifrado simétrico y generación de datos aleatorios seguros, todo con parámetros seguros por defecto.

## 🌟 Características

**Hashing de contraseñas**
- **4 algoritmos soportados**: Argon2id, Bcrypt, Scrypt y PBKDF2-SHA256
- **Interfaz común (`Hasher`)**: cambia de algoritmo sin tocar el resto del código (principio Open/Closed)
- **Parámetros seguros por defecto**, alineados con recomendaciones de OWASP / NIST / RFC 9106
- **Detección automática de algoritmo** a partir del propio hash (`DetectAlgorithm`)
- **Migración progresiva** de parámetros con `NeedsUpgrade` (rehash on login)
- **Comparación en tiempo constante** en todos los algoritmos, para prevenir ataques de timing
- **Manejo correcto del límite de 72 bytes de bcrypt** mediante pre-hash con SHA-256 (sin truncar contraseñas)

**Cifrado simétrico**
- **AES-256-GCM** (`Encrypter` / `AESEncrypter`): confidencialidad + autenticación (AEAD) en un solo paso
- Nonce aleatorio único por cada operación de cifrado
- Ayudantes para generar y codificar claves (`GenerateEncryptionKey`, `GenerateEncryptionKeyBase64`)

**Datos aleatorios seguros**
- `RandomBytes`, `RandomString`, `RandomHex` para tokens, session IDs y nonces
- `GenerateUUID` (UUID v4, RFC 4122)
- `GenerateAPIKey` con prefijo configurable
- `GenerateNumericCode` para OTPs/2FA
- Todo basado en `crypto/rand`, nunca en `math/rand`

## 📦 Instalación

```bash
go get github.com/AndresGT/GoKit/security/crypto
```

## 🚀 Inicio rápido — Hashing de contraseñas

```go
package main

import (
    "fmt"
    "github.com/AndresGT/GoKit/security/crypto"
)

func main() {
    hasher, err := crypto.NewHasher(crypto.HasherConfig{
        Algorithm: crypto.AlgorithmArgon2id,
    })
    if err != nil {
        panic(err)
    }

    hash, err := hasher.Hash("miContraseñaSegura123")
    if err != nil {
        panic(err)
    }
    fmt.Println("Hash:", hash)

    ok, err := hasher.Verify("miContraseñaSegura123", hash)
    if err != nil {
        panic(err)
    }
    fmt.Println("¿Coincide?:", ok)
}
```

## 🔑 La interfaz `Hasher`

Todos los algoritmos implementan el mismo contrato:

```go
type Hasher interface {
    Hash(password string) (string, error)
    Verify(password, hash string) (bool, error)
    NeedsUpgrade(hash string) bool
}
```

- **`Hash`**: genera un hash con salt aleatorio, codificando en el propio string todos los parámetros usados (algoritmo, costo, memoria, iteraciones, etc.) para que siempre pueda verificarse aunque la configuración por defecto cambie más adelante.
- **`Verify`**: extrae los parámetros del hash almacenado y compara la contraseña usando comparación en tiempo constante (`crypto/subtle`).
- **`NeedsUpgrade`**: indica si el hash fue generado con parámetros más débiles que los configurados actualmente — útil para regenerar el hash de forma transparente la próxima vez que el usuario inicie sesión ("rehash on login").

## ⚙️ Algoritmos disponibles

| Algoritmo   | Constante                  | Cuándo usarlo                                                        |
|-------------|-----------------------------|------------------------------------------------------------------------|
| Argon2id    | `AlgorithmArgon2id`         | Opción por defecto recomendada. Ganador del PHC (2015), resistente a GPU/ASIC. |
| Bcrypt      | `AlgorithmBcrypt`           | Estándar de la industria, ampliamente soportado y probado en el tiempo. |
| Scrypt      | `AlgorithmScrypt`           | Alternativa con uso intensivo de memoria, para sistemas legacy o requisitos específicos. |
| PBKDF2-SHA256 | `AlgorithmPBKDF2`         | Estándar NIST (SP 800-132), útil en entornos enterprise/regulados que lo exijan. |

### Argon2id

```go
hasher, _ := crypto.NewHasher(crypto.HasherConfig{
    Algorithm:         crypto.AlgorithmArgon2id,
    Argon2Memory:      64 * 1024, // KB (64 MB)
    Argon2Iterations:  3,
    Argon2Parallelism: 4,
    Argon2KeyLength:   32,
    Argon2SaltLength:  16,
})
```

Valores por defecto si no se especifican (o si son inválidos): 64 MB de memoria, 3 iteraciones, paralelismo 4, clave de 32 bytes, salt de 16 bytes — según RFC 9106.

Formato del hash: `$argon2id$v=19$m=<memoria>,t=<iteraciones>,p=<paralelismo>$<salt>$<hash>`

### Bcrypt

```go
hasher, _ := crypto.NewHasher(crypto.HasherConfig{
    Algorithm:  crypto.AlgorithmBcrypt,
    BcryptCost: 12,
})
```

Costo recomendado: 10 en desarrollo, 12 en producción estándar, 14+ para alta seguridad. Si no se especifica o es inválido, se usa 12.

Bcrypt trabaja con un límite máximo de 72 bytes por contraseña. Este módulo **no trunca** contraseñas más largas (lo cual descartaría silenciosamente parte de la contraseña); en su lugar, las pre-hashea con SHA-256 y codifica el resultado en base64 antes de pasarlo a bcrypt, preservando toda la entropía de la contraseña original.

### Scrypt

```go
hasher, _ := crypto.NewHasher(crypto.HasherConfig{
    Algorithm:     crypto.AlgorithmScrypt,
    ScryptN:       16384, // debe ser potencia de 2
    ScryptR:       8,
    ScryptP:       1,
    ScryptKeyLen:  32,
    ScryptSaltLen: 16,
})
```

`N` debe ser una potencia de 2 (por defecto 2^14 = 16384). Formato del hash: `$scrypt$ln=<log2(N)>,r=<r>,p=<p>$<salt>$<hash>`.

### PBKDF2-SHA256

```go
hasher, _ := crypto.NewHasher(crypto.HasherConfig{
    Algorithm:        crypto.AlgorithmPBKDF2,
    PBKDF2Iterations: 600000, // recomendación OWASP 2023 para SHA-256
    PBKDF2KeyLen:     32,
    PBKDF2SaltLen:    16,
})
```

Formato del hash: `$pbkdf2-sha256$i=<iteraciones>$<salt>$<hash>`.

> OWASP recomienda incrementar el número de iteraciones con el tiempo a medida que el hardware se vuelve más rápido.

## 🔎 Detección automática de algoritmo

Si tu aplicación necesita soportar varios algoritmos a la vez (por ejemplo, durante una migración), `DetectAlgorithm` identifica qué algoritmo generó un hash dado, a partir de su prefijo:

```go
alg, err := crypto.DetectAlgorithm(storedHash)
if err != nil {
    // hash con formato desconocido o no soportado
}

hasher, _ := crypto.NewHasher(crypto.HasherConfig{Algorithm: alg})
ok, _ := hasher.Verify(password, storedHash)
```

## 🔄 Migración progresiva de parámetros (rehash on login)

Cuando decides subir el costo de bcrypt, la memoria de argon2id, o las iteraciones de scrypt/PBKDF2, no hace falta invalidar los hashes existentes. Verifica con `NeedsUpgrade` en cada login exitoso y regenera el hash si es necesario:

```go
ok, err := hasher.Verify(password, storedHash)
if err != nil || !ok {
    // credenciales inválidas
    return
}

if hasher.NeedsUpgrade(storedHash) {
    newHash, err := hasher.Hash(password)
    if err == nil {
        // persistir newHash en reemplazo de storedHash
    }
}
```

## 🔐 Cifrado simétrico (AES-256-GCM)

La interfaz `Encrypter` cubre cifrado/descifrado simétrico autenticado con AES-256 en modo GCM (AEAD): además de confidencialidad, detecta cualquier manipulación de los datos cifrados.

```go
type Encrypter interface {
    Encrypt(plaintext []byte) (string, error)
    Decrypt(ciphertext string) ([]byte, error)
    EncryptString(plaintext string) (string, error)
    DecryptString(ciphertext string) (string, error)
}
```

```go
// Generar una clave de 256 bits y guardarla de forma segura
// (variable de entorno, vault, KMS...)
key, err := crypto.GenerateEncryptionKey()
if err != nil {
    panic(err)
}

encrypter, err := crypto.NewAESEncrypter(key)
if err != nil {
    panic(err)
}

encrypted, err := encrypter.EncryptString("número de tarjeta: 4111-1111-1111-1111")
if err != nil {
    panic(err)
}

decrypted, err := encrypter.DecryptString(encrypted)
if err != nil {
    // clave incorrecta o datos manipulados/corruptos
}
```

- La clave debe tener **exactamente 32 bytes** (AES-256); `NewAESEncrypter` devuelve `ErrInvalidKeyLength` si no cumple este requisito.
- Cada llamada a `Encrypt`/`EncryptString` genera un **nonce aleatorio de 12 bytes** distinto, obligatorio para la seguridad de GCM.
- El resultado se codifica en base64 con el formato `base64(nonce + ciphertext + tag)`, listo para guardar en una columna de texto o transmitir por HTTP.
- Si pierdes la clave, los datos cifrados con ella son **irrecuperables**: no existe forma de reconstruirla.

```go
// También disponible: obtener la clave ya codificada en base64
keyBase64, err := crypto.GenerateEncryptionKeyBase64()
```

## 🎲 Generación de datos aleatorios seguros

Todas las funciones usan `crypto/rand` (nunca `math/rand`), por lo que son aptas para tokens, claves y códigos de un solo uso.

| Función | Uso típico |
|---|---|
| `RandomBytes(n int)` | Base criptográfica para construir otros generadores |
| `RandomString(n int)` | Session IDs, tokens CSRF, identificadores en URLs |
| `RandomHex(n int)` | Refresh tokens, API keys, tokens de verificación por email |
| `GenerateUUID()` | Identificadores únicos distribuidos (UUID v4, RFC 4122) |
| `GenerateAPIKey(prefix string)` | API keys con formato `prefijo_hexAleatorio` (prefijo por defecto: `gk`) |
| `GenerateNumericCode(length int)` | OTPs por SMS/email, PINs temporales, códigos 2FA |

```go
sessionID, _ := crypto.RandomString(32)     // "aB3xK9mP2qL5nR8wT1yU4zV6cF0hJ7d"
token, _     := crypto.RandomHex(32)        // 64 caracteres hex
id, _        := crypto.GenerateUUID()       // "550e8400-e29b-41d4-a716-446655440000"
apiKey, _    := crypto.GenerateAPIKey("usr") // "usr_a1b2c3d4e5f6..."
otp, _       := crypto.GenerateNumericCode(6) // "482913"
```

`GenerateAPIKey` valida que el prefijo sea alfanumérico (devuelve `ErrInvalidPrefix` si no lo es) para evitar inyección en el identificador resultante.

## ❗ Errores del paquete

**Hashing** (`hash.go`)
```go
var (
    ErrInvalidHash          = errors.New("formato de hash inválido")
    ErrUnsupportedAlgorithm = errors.New("algoritmo de hashing no soportado")
    ErrPasswordTooShort     = errors.New("la contraseña es demasiado corta")
    ErrPasswordTooLong      = errors.New("la contraseña es demasiado larga")
)
```

`ErrPasswordTooShort` y `ErrPasswordTooLong` están pensados para la capa de validación de tu aplicación (este paquete no impone longitudes mínimas/máximas por sí mismo, salvo el manejo especial de bcrypt ya descrito).

**Cifrado** (`encrypt.go`)
```go
var (
    ErrInvalidKeyLength  = errors.New("la clave debe tener exactamente 32 bytes para AES-256")
    ErrEncryptionFailed  = errors.New("fallo al cifrar los datos")
    ErrDecryptionFailed  = errors.New("fallo al descifrar los datos")
    ErrInvalidCiphertext = errors.New("formato de texto cifrado inválido")
)
```

`ErrDecryptionFailed` es intencionalmente genérico: no distingue entre "clave incorrecta" y "datos manipulados" para no dar pistas a un atacante.

**Datos aleatorios** (`random.go`)
```go
var (
    ErrInvalidLength          = errors.New("la longitud debe ser mayor que cero")
    ErrRandomGenerationFailed = errors.New("fallo al generar datos aleatorios seguros")
    ErrInvalidPrefix          = errors.New("el prefijo debe ser alfanumérico")
)
```

## 🔒 Notas de seguridad

- Todas las comparaciones de hash usan `crypto/subtle.ConstantTimeCompare` para evitar ataques de timing.
- El salt se genera con `crypto/rand` (criptográficamente seguro) en cada llamada a `Hash`.
- Cada hash incluye sus propios parámetros, por lo que cambiar la configuración por defecto del paquete nunca invalida hashes ya emitidos.
- Si no tienes un requisito específico (compliance, sistema legacy), **Argon2id** es la opción recomendada para nuevos proyectos.
- El cifrado usa AES-256-GCM (AEAD): un nonce distinto por operación y verificación de integridad incluida; nunca reutilices manualmente un nonce con la misma clave.
- Toda la generación aleatoria del paquete (`random.go`, salts, nonces, claves) se basa en `crypto/rand`, el generador criptográficamente seguro del sistema operativo — nunca en `math/rand`.

## 📜 Licencia

MIT