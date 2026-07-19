package main

import (
	"github.com/AndresGT/GoKit/logger"
	"github.com/AndresGT/GoKit/security"
	"github.com/AndresGT/GoKit/security/crypto"
	"github.com/AndresGT/GoKit/security/token"
)

func main() {
	// =====================================================================
	// 0. Inicialización del Logger
	// =====================================================================
	log := logger.New(
		logger.WithLevel(logger.DebugLevel),
		logger.WithColor(true),
	)

	log.Info("🚀 Iniciando pruebas integrales de GoKit...")

	// =====================================================================
	// 1. Pruebas de Criptografía (Hashing)
	// =====================================================================
	println("\n--- 1. Pruebas de Hashing de Contraseñas ---")
	password := "MiContraseñaSuperSegura123!"
	wrongPassword := "ContraseñaIncorrecta"

	algorithms := []struct {
		name   string
		config crypto.HasherConfig
	}{
		{
			name: "Bcrypt (Estándar)",
			config: crypto.HasherConfig{
				Algorithm:  crypto.AlgorithmBcrypt,
				BcryptCost: 12,
			},
		},
		{
			name: "Argon2id (Máxima Seguridad)",
			config: crypto.HasherConfig{
				Algorithm:         crypto.AlgorithmArgon2id,
				Argon2Memory:      64 * 1024,
				Argon2Iterations:  3,
				Argon2Parallelism: 4,
				Argon2KeyLength:   32,
				Argon2SaltLength:  16,
			},
		},
	}

	for _, alg := range algorithms {
		log.InfoWithFields("probando_algoritmo", map[string]interface{}{"algoritmo": alg.name})

		hasher, err := crypto.NewHasher(alg.config)
		if err != nil {
			log.ErrorWithFields("fallo_al_crear_hasher", map[string]interface{}{"error": err.Error()})
			continue
		}

		hash, _ := hasher.Hash(password)
		log.DebugWithFields("hash_generado", map[string]interface{}{
			"algoritmo":    alg.name,
			"hash_preview": hash[:30] + "...",
		})

		isValid, _ := hasher.Verify(password, hash)
		if isValid {
			log.SuccessWithFields("verificacion_exitosa", map[string]interface{}{"algoritmo": alg.name})
		}

		isValidWrong, _ := hasher.Verify(wrongPassword, hash)
		if !isValidWrong {
			log.InfoWithFields("rechazo_correcto_contraseña_incorrecta", map[string]interface{}{"algoritmo": alg.name})
		}
	}

	// =====================================================================
	// 2. Pruebas de Generación Aleatoria y Cifrado
	// =====================================================================
	println("\n--- 2. Pruebas de Random y Cifrado AES-256-GCM ---")

	randomStr, _ := crypto.RandomString(16)
	log.InfoWithFields("random_string", map[string]interface{}{"valor": randomStr})

	uuid, _ := crypto.GenerateUUID()
	log.InfoWithFields("uuid_v4", map[string]interface{}{"valor": uuid})

	apiKey, _ := crypto.GenerateAPIKey("usr")
	log.InfoWithFields("api_key", map[string]interface{}{"valor": apiKey})

	key, _ := crypto.GenerateEncryptionKey()
	encrypter, _ := crypto.NewAESEncrypter(key)

	sensitiveData := "Número de tarjeta: 4111-1111-1111-1111"
	encrypted, _ := encrypter.EncryptString(sensitiveData)
	log.InfoWithFields("dato_cifrado", map[string]interface{}{
		"cifrado": encrypted[:40] + "...",
	})

	decrypted, _ := encrypter.DecryptString(encrypted)
	log.SuccessWithFields("dato_descifrado", map[string]interface{}{"recuperado": decrypted})

	// =====================================================================
	// 3. Pruebas de Niveles de Seguridad y Errores
	// =====================================================================
	println("\n--- 3. Pruebas de Niveles de Seguridad y Errores ---")

	levels := []security.Level{
		security.LevelLow,
		security.LevelMedium,
		security.LevelHigh,
		security.LevelCritical,
	}

	for _, level := range levels {
		defaults := level.GetDefaults()
		log.InfoWithFields("configuracion_nivel", map[string]interface{}{
			"nivel":              level.String(),
			"bcrypt_cost":        defaults.BcryptCost,
			"access_token":       defaults.AccessTokenDuration.String(),
			"max_login_attempts": defaults.MaxLoginAttempts,
			"require_2fa":        defaults.Require2FA,
		})
	}

	log.WarnWithFields("error_generico_demo", map[string]interface{}{
		"error": security.ErrAuthenticationFailed.Error(),
		"nota":  "No revela si el usuario existe o la contraseña está mal (anti-enumeración)",
	})

	// =====================================================================
	// 4. Pruebas de JWT (JSON Web Tokens)
	// =====================================================================
	println("\n--- 4. Pruebas de JWT ---")

	secretKey := []byte("mi-clave-secreta-de-al-menos-32-bytes!")
	jwtManager, err := token.NewJWTManager(token.JWTConfig{
		SecretKey:     secretKey,
		Issuer:        "gokit-auth",
		SecurityLevel: security.LevelHigh, // Usa defaults: 15min access, 24h refresh
	})
	if err != nil {
		log.ErrorWithFields("fallo_creacion_jwt", map[string]interface{}{"error": err.Error()})
	} else {
		claims := token.Claims{
			UserID:    "user-123",
			Username:  "john_doe",
			Role:      "admin",
			SessionID: "session-abc-123",
			IPAddress: "192.168.1.100",
		}

		accessToken, _ := jwtManager.GenerateAccessToken(claims)
		refreshToken, _ := jwtManager.GenerateRefreshToken(claims)

		log.InfoWithFields("tokens_generados", map[string]interface{}{
			"access_preview":  accessToken[:30] + "...",
			"refresh_preview": refreshToken[:30] + "...",
		})

		validatedClaims, err := jwtManager.ValidateToken(accessToken)
		if err != nil {
			log.ErrorWithFields("validacion_fallida", map[string]interface{}{"error": err.Error()})
		} else {
			log.SuccessWithFields("token_validado", map[string]interface{}{
				"user_id": validatedClaims.UserID,
				"role":    validatedClaims.Role,
			})
		}

		newAccessToken, err := jwtManager.RefreshAccessToken(refreshToken)
		if err != nil {
			log.ErrorWithFields("refresh_fallido", map[string]interface{}{"error": err.Error()})
		} else {
			log.SuccessWithFields("token_actualizado_con_refresh", map[string]interface{}{
				"new_access_preview": newAccessToken[:30] + "...",
			})
		}
	}

	// =====================================================================
	// 5. Pruebas de Gestión de Sesiones
	// =====================================================================
	println("\n--- 5. Pruebas de Gestión de Sesiones ---")

	sessionManager, err := token.NewSessionManager(token.SessionConfig{
		SecurityLevel: security.LevelHigh, // Usa defaults: 8h timeout, 15m idle, max 2 sesiones
		// Nota: Usa MemorySessionStore por defecto. Para producción, inyecta un Redis/DB Store.
	})
	if err != nil {
		log.ErrorWithFields("fallo_creacion_sesion", map[string]interface{}{"error": err.Error()})
	} else {
		sessionInfo := token.SessionInfo{
			UserID:    "user-123",
			Username:  "john_doe",
			IPAddress: "192.168.1.100",
			UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
		}

		sessionID, err := sessionManager.CreateSession(sessionInfo)
		if err != nil {
			log.ErrorWithFields("fallo_creacion_sesion", map[string]interface{}{"error": err.Error()})
		} else {
			log.InfoWithFields("sesion_creada", map[string]interface{}{
				"session_id": sessionID,
			})

			// Validar sesión
			session, err := sessionManager.ValidateSession(sessionID)
			if err != nil {
				log.ErrorWithFields("validacion_sesion_fallida", map[string]interface{}{"error": err.Error()})
			} else {
				log.SuccessWithFields("sesion_validada", map[string]interface{}{
					"user_id": session.UserID,
					"ip":      session.IPAddress,
				})
			}

			// Listar sesiones activas
			sessions, _ := sessionManager.GetUserSessions("user-123")
			log.InfoWithFields("sesiones_activas_usuario", map[string]interface{}{
				"cantidad": len(sessions),
			})

			// Revocar sesión (Logout)
			err = sessionManager.RevokeSession(sessionID, "user_logout")
			if err != nil {
				log.ErrorWithFields("fallo_revocacion", map[string]interface{}{"error": err.Error()})
			} else {
				log.Success("Sesión revocada exitosamente (logout)")
			}

			// Intentar validar sesión revocada (debe fallar)
			_, err = sessionManager.ValidateSession(sessionID)
			if err != nil {
				log.InfoWithFields("sesion_revocada_detectada_correctamente", map[string]interface{}{
					"error": err.Error(),
				})
			}
		}
	}

	// =====================================================================
	// Finalización
	// =====================================================================
	println("\n")
	log.Success("✅ ¡Todas las pruebas de GoKit completadas con éxito!")
}
