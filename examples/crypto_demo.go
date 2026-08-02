package main

import (
	"fmt"
	"github.com/AndresGT/GoKit/security/crypto"
)

func main() {
	fmt.Println("=== GoKit Crypto Module Demo ===\n")

	// =============================================================================
	// 1. HASHING DE CONTRASEÑAS (Uso Rápido)
	// =============================================================================
	fmt.Println("1️⃣  HASHING DE CONTRASEÑAS")
	fmt.Println("-------------------------------------------")

	password := "mi-contraseña-segura-123"

	// Hash con Argon2id (por defecto)
	hash, err := crypto.HashPassword(password)
	if err != nil {
		panic(err)
	}
	fmt.Printf("✅ Password: %s\n", password)
	fmt.Printf("🔐 Hash (Argon2id): %s\n\n", hash)

	// Verificar contraseña
	valid, err := crypto.VerifyPassword(password, hash)
	if err != nil {
		panic(err)
	}
	fmt.Printf("🔍 Verificación (correcta): %v\n", valid)

	valid, _ = crypto.VerifyPassword("contraseña-incorrecta", hash)
	fmt.Printf("🔍 Verificación (incorrecta): %v\n\n", valid)

	// Verificar si necesita actualización
	if crypto.NeedsUpgrade(hash) {
		fmt.Println("⚠️  El hash necesita actualización")
	} else {
		fmt.Println("✅ El hash está actualizado")
	}
	fmt.Println()

	// =============================================================================
	// 2. HASHING CON ALGORITMOS ESPECÍFICOS
	// =============================================================================
	fmt.Println("2️⃣  ALGORITMOS ESPECÍFICOS")
	fmt.Println("-------------------------------------------")

	hashes := []struct {
		name string
		fn   func(string) (string, error)
	}{
		{"Argon2id", crypto.HashWithArgon2id},
		{"Bcrypt", crypto.HashWithBcrypt},
		{"Scrypt", crypto.HashWithScrypt},
		{"PBKDF2", crypto.HashWithPBKDF2},
	}

	for _, h := range hashes {
		hash, err := h.fn(password)
		if err != nil {
			panic(err)
		}
		fmt.Printf("🔐 %-10s: %s...\n", h.name, hash[:40])
	}
	fmt.Println()

	// =============================================================================
	// 3. CIFRADO DE DATOS
	// =============================================================================
	fmt.Println("3️⃣  CIFRADO AES-256-GCM")
	fmt.Println("-------------------------------------------")

	// Generar clave segura
	key, err := crypto.GenerateEncryptionKey()
	if err != nil {
		panic(err)
	}

	// Configurar clave global
	err = crypto.SetEncryptionKey(key)
	if err != nil {
		panic(err)
	}
	fmt.Println("✅ Clave de cifrado configurada (32 bytes)")

	// Cifrar datos
	secret := "Este es un mensaje secreto muy importante"
	encrypted, err := crypto.EncryptString(secret)
	if err != nil {
		panic(err)
	}
	fmt.Printf("🔒 Texto original: %s\n", secret)
	fmt.Printf("🔐 Cifrado: %s\n", encrypted)

	// Descifrar datos
	decrypted, err := crypto.DecryptString(encrypted)
	if err != nil {
		panic(err)
	}
	fmt.Printf("🔓 Descifrado: %s\n\n", decrypted)

	// Cifrado con clave específica (sin usar global)
	key2, _ := crypto.GenerateEncryptionKey()
	encrypted2, _ := crypto.EncryptWithKey("datos-tenant-2", key2)
	decrypted2, _ := crypto.DecryptWithKey(encrypted2, key2)
	fmt.Printf("🔑 Cifrado con clave específica: %s -> %s\n\n", "datos-tenant-2", decrypted2)

	// =============================================================================
	// 4. GENERACIÓN DE DATOS ALEATORIOS
	// =============================================================================
	fmt.Println("4️⃣  GENERACIÓN ALEATORIA SEGURA")
	fmt.Println("-------------------------------------------")

	// Bytes aleatorios
	bytes, _ := crypto.GenerateRandomBytes(16)
	fmt.Printf("🎲 Random Bytes (16): %v\n", bytes)

	// String aleatorio URL-safe
	randomStr, _ := crypto.GenerateRandomString(32)
	fmt.Printf("🔤 Random String: %s\n", randomStr)

	// Token hexadecimal
	token, _ := crypto.GenerateSecureToken()
	fmt.Printf("🎫 Secure Token: %s...\n", token[:32])

	// UUID v4
	uuid, _ := crypto.GenerateUUIDv4()
	fmt.Printf("🆔 UUID v4: %s\n", uuid)

	// API Key con prefijo
	apiKey, _ := crypto.GenerateAPIKeyWithPrefix("usr")
	fmt.Printf("🔑 API Key: %s\n", apiKey)

	// Código OTP
	otp, _ := crypto.GenerateOTP(6)
	fmt.Printf("📱 OTP (6 dígitos): %s\n\n", otp)

	// =============================================================================
	// 5. EJEMPLO COMPLETO: SISTEMA DE AUTENTICACIÓN
	// =============================================================================
	fmt.Println("5️⃣  EJEMPLO: REGISTRO Y LOGIN")
	fmt.Println("-------------------------------------------")

	// Registro de usuario
	userEmail := "usuario@example.com"
	userPassword := "password123"

	// Hashear contraseña para guardar en BD
	storedHash, err := crypto.HashPassword(userPassword)
	if err != nil {
		panic(err)
	}
	fmt.Printf("📝 Usuario registrado: %s\n", userEmail)
	fmt.Printf("💾 Hash guardado: %s...\n\n", storedHash[:50])

	// Login exitoso
	fmt.Println("🔐 Intento de login (correcto):")
	loginPassword := "password123"
	valid, _ = crypto.VerifyPassword(loginPassword, storedHash)
	if valid {
		fmt.Println("✅ Login exitoso - Contraseña válida")
	} else {
		fmt.Println("❌ Login fallido - Contraseña inválida")
	}

	// Login fallido
	fmt.Println("\n🔐 Intento de login (incorrecto):")
	loginPassword = "wrong-password"
	valid, _ = crypto.VerifyPassword(loginPassword, storedHash)
	if valid {
		fmt.Println("✅ Login exitoso")
	} else {
		fmt.Println("❌ Login fallido - Contraseña incorrecta")
	}

	// Migración gradual
	fmt.Println("\n🔄 Verificando migración:")
	if crypto.NeedsUpgrade(storedHash) {
		newHash, _ := crypto.HashPassword(userPassword)
		fmt.Printf("⚠️  Hash antiguo detectado, regenerando...\n")
		fmt.Printf("✅ Nuevo hash: %s...\n", newHash[:50])
	} else {
		fmt.Println("✅ Hash actualizado, no requiere migración")
	}

	fmt.Println("\n=== Demo Completada ===")
}
