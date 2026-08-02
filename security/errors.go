package security

import "errors"

// =============================================================================
// Errores de Dominio de Seguridad
// =============================================================================

// Errores transversales de alto nivel que pueden ser usados por cualquier
// submódulo de security (crypto, token, rules, policy, middleware, etc.).
//
// PRINCIPIO DE DISEÑO:
// 1. NO exponen detalles internos (algoritmos, estructuras, claves, etc.)
// 2. Previenen ataques de enumeración (mismo error genérico para múltiples causas)
// 3. Son genéricos pero descriptivos para el usuario final o API
// 4. Centralizan colisiones comunes del paquete (como validaciones de hashes y ciphers)

var (
	// -----------------------------------------------------------------------------
	// Criptografía y Hashing (Agregados para resolver colisiones en subpaquetes)
	// -----------------------------------------------------------------------------

	// ErrInvalidHash se retorna cuando un hash (Argon2, Bcrypt, etc.) no cumple
	// con la estructura PHC o está corrupto.
	ErrInvalidHash = errors.New("el hash provisto no tiene un formato válido")

	// ErrIncompatibleVersion se retorna cuando el algoritmo o la versión del
	// hash no es compatible con la configuración actual del sistema.
	ErrIncompatibleVersion = errors.New("versión o algoritmo inalcanzable")

	// ErrInvalidCiphertext se retorna cuando el payload cifrado (AES-GCM) no se
	// puede autenticar o descifrar debido a corrupción o clave errónea.
	ErrInvalidCiphertext = errors.New("el texto cifrado no es válido o está corrupto")

	// ErrInvalidKeyLength se retorna cuando una clave secreta no cumple
	// con los requerimientos de tamaño del algoritmo (ej. AES-256 requiere 32 bytes).
	ErrInvalidKeyLength = errors.New("longitud de clave no válida")

	// -----------------------------------------------------------------------------
	// Autenticación y Autorización
	// -----------------------------------------------------------------------------

	// ErrAuthenticationFailed se retorna cuando las credenciales son inválidas.
	// NO especifica si el usuario no existe o la contraseña es incorrecta.
	// Esto previene ataques de enumeración de usuarios.
	ErrAuthenticationFailed = errors.New("credenciales inválidas")

	// ErrPermissionDenied se retorna cuando el usuario autenticado no tiene
	// permisos para realizar la operación solicitada.
	ErrPermissionDenied = errors.New("permiso denegado")

	// ErrInsufficientSecurityLevel se retorna cuando una operación requiere
	// un nivel de seguridad mayor al configurado (ej. 2FA requerido).
	ErrInsufficientSecurityLevel = errors.New("nivel de seguridad insuficiente para esta operación")

	// -----------------------------------------------------------------------------
	// Tokens (JWT, Session, API Key, OTP)
	// -----------------------------------------------------------------------------

	// ErrTokenInvalid se retorna cuando un token está mal formado, expirado,
	// ha sido revocado o no corresponde al usuario. No revela qué tipo de
	// token era ni por qué falló específicamente.
	ErrTokenInvalid = errors.New("token inválido o expirado")

	// ErrTokenRevoked se retorna cuando un token fue revocado explícitamente
	// (ej. logout, cambio de contraseña, reporte de robo).
	ErrTokenRevoked = errors.New("token revocado")

	// ErrSessionExpired se retorna cuando una sesión ha expirado por inactividad
	// o por alcanzar su tiempo máximo de vida.
	ErrSessionExpired = errors.New("sesión expirada")

	// -----------------------------------------------------------------------------
	// Rate Limiting y Protección contra Ataques
	// -----------------------------------------------------------------------------

	// ErrRateLimitExceeded se retorna cuando se superan los intentos permitidos
	// en un período de tiempo determinado (login, reset de contraseña, etc.).
	// No revela cuántos intentos quedan ni el tiempo exacto de bloqueo.
	ErrRateLimitExceeded = errors.New("demasiados intentos, inténtelo más tarde")

	// ErrAccountLocked se retorna cuando una cuenta ha sido bloqueada debido
	// a múltiples intentos fallidos o por acción administrativa.
	ErrAccountLocked = errors.New("cuenta bloqueada temporalmente")

	// ErrIPBlocked se retorna cuando una dirección IP ha sido bloqueada
	// por actividad sospechosa o múltiples intentos fallidos.
	ErrIPBlocked = errors.New("dirección IP bloqueada temporalmente")

	// -----------------------------------------------------------------------------
	// Validación de Entrada
	// -----------------------------------------------------------------------------

	// ErrInvalidInput se retorna cuando los datos de entrada no cumplen
	// con las políticas de validación (contraseña débil, email mal formado, etc.).
	// No especifica qué regla falló para no dar pistas a atacantes.
	ErrInvalidInput = errors.New("datos de entrada no válidos")

	// ErrWeakPassword se retorna cuando una contraseña no cumple con las
	// políticas de fortaleza configuradas (longitud, complejidad, etc.).
	ErrWeakPassword = errors.New("la contraseña no cumple los requisitos de seguridad")

	// -----------------------------------------------------------------------------
	// Operaciones
	// -----------------------------------------------------------------------------

	// ErrOperationNotAllowed se retorna cuando una operación no está permitida
	// en el estado actual (ej. cambiar contraseña durante bloqueo).
	ErrOperationNotAllowed = errors.New("operación no permitida en este momento")

	// ErrPasswordChangeRequired se retorna cuando el sistema requiere que el
	// usuario cambie su contraseña (ej. expiración, compromiso detectado).
	ErrPasswordChangeRequired = errors.New("se requiere cambiar la contraseña")
)