package token

import (
	"testing"
	"time"

	"github.com/AndresGT/GoKit/security"
)

// =============================================================================
// Tests de JWT - Funciones Básicas
// =============================================================================

func TestNewJWTManager(t *testing.T) {
	// Caso válido
	manager, err := NewJWTManager(JWTConfig{
		SecretKey:   []byte("una-clave-secreta-de-al-menos-32-bytes!!"),
		Issuer:      "test-issuer",
		SecurityLevel: security.LevelMedium,
	})
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if manager == nil {
		t.Fatal("Expected manager to be created")
	}

	config := manager.GetConfig()
	if config.Issuer != "test-issuer" {
		t.Errorf("Expected issuer 'test-issuer', got '%s'", config.Issuer)
	}
	// LevelMedium tiene AccessTokenDuration de 1h por defecto
	if config.AccessTokenDuration != 1*time.Hour {
		t.Errorf("Expected access token duration 1h, got %v", config.AccessTokenDuration)
	}
}

func TestNewJWTManager_InvalidSecretKey(t *testing.T) {
	_, err := NewJWTManager(JWTConfig{
		SecretKey: []byte("clave-corta"), // Menos de 32 bytes
	})
	if err == nil {
		t.Fatal("Expected error for short secret key, got nil")
	}
}

func TestNewJWTManager_SecurityLevels(t *testing.T) {
	tests := []struct {
		name                  string
		level                 security.Level
		expectedAccessDur     time.Duration
		expectedRefreshDur    time.Duration
	}{
		{"Low", security.LevelLow, 24 * time.Hour, 30 * 24 * time.Hour},
		{"Medium", security.LevelMedium, 1 * time.Hour, 7 * 24 * time.Hour},
		{"High", security.LevelHigh, 15 * time.Minute, 24 * time.Hour},
		{"Critical", security.LevelCritical, 5 * time.Minute, 12 * time.Hour},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager, err := NewJWTManager(JWTConfig{
				SecretKey:     []byte("una-clave-secreta-de-al-menos-32-bytes!!"),
				SecurityLevel: tt.level,
			})
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			config := manager.GetConfig()
			if config.AccessTokenDuration != tt.expectedAccessDur {
				t.Errorf("Expected access duration %v, got %v", tt.expectedAccessDur, config.AccessTokenDuration)
			}
			if config.RefreshTokenDuration != tt.expectedRefreshDur {
				t.Errorf("Expected refresh duration %v, got %v", tt.expectedRefreshDur, config.RefreshTokenDuration)
			}
		})
	}
}

// =============================================================================
// Tests de JWT - Generación y Validación
// =============================================================================

func TestGenerateAccessToken(t *testing.T) {
	manager, _ := NewJWTManager(JWTConfig{
		SecretKey:            []byte("una-clave-secreta-de-al-menos-32-bytes!!"),
		Issuer:               "test-issuer",
		AccessTokenDuration:  15 * time.Minute,
		RefreshTokenDuration: 7 * 24 * time.Hour,
	})

	claims := Claims{
		UserID:     "user-123",
		Username:   "john_doe",
		Role:       "admin",
		Email:      "john@example.com",
		SessionID:  "session-abc",
		DeviceInfo: "Chrome on Windows",
		IPAddress:  "192.168.1.100",
	}

	token, err := manager.GenerateAccessToken(claims)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if token == "" {
		t.Fatal("Expected non-empty token")
	}
}

func TestGenerateRefreshToken(t *testing.T) {
	manager, _ := NewJWTManager(JWTConfig{
		SecretKey:            []byte("una-clave-secreta-de-al-menos-32-bytes!!"),
		Issuer:               "test-issuer",
		AccessTokenDuration:  15 * time.Minute,
		RefreshTokenDuration: 7 * 24 * time.Hour,
	})

	claims := Claims{
		UserID:    "user-123",
		SessionID: "session-abc",
	}

	token, err := manager.GenerateRefreshToken(claims)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if token == "" {
		t.Fatal("Expected non-empty token")
	}
}

func TestValidateToken_Valid(t *testing.T) {
	manager, _ := NewJWTManager(JWTConfig{
		SecretKey:            []byte("una-clave-secreta-de-al-menos-32-bytes!!"),
		Issuer:               "test-issuer",
		AccessTokenDuration:  15 * time.Minute,
		RefreshTokenDuration: 7 * 24 * time.Hour,
	})

	claims := Claims{
		UserID:   "user-123",
		Username: "john_doe",
		Role:     "admin",
	}

	token, _ := manager.GenerateAccessToken(claims)
	validatedClaims, err := manager.ValidateToken(token)

	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if validatedClaims.UserID != "user-123" {
		t.Errorf("Expected UserID 'user-123', got '%s'", validatedClaims.UserID)
	}
	if validatedClaims.Role != "admin" {
		t.Errorf("Expected Role 'admin', got '%s'", validatedClaims.Role)
	}
	if validatedClaims.TokenType != TokenTypeAccess {
		t.Errorf("Expected TokenType 'access', got '%s'", validatedClaims.TokenType)
	}
}

func TestValidateToken_InvalidSignature(t *testing.T) {
	manager1, _ := NewJWTManager(JWTConfig{
		SecretKey:   []byte("una-clave-secreta-de-al-menos-32-bytes!!"),
		Issuer:      "test-issuer",
	})

	manager2, _ := NewJWTManager(JWTConfig{
		SecretKey:   []byte("otra-clave-diferente-de-32-bytes-min!!"),
		Issuer:      "test-issuer",
	})

	claims := Claims{UserID: "user-123"}
	token, _ := manager1.GenerateAccessToken(claims)

	_, err := manager2.ValidateToken(token)
	if err == nil {
		t.Fatal("Expected error for invalid signature, got nil")
	}
}

func TestValidateToken_WrongIssuer(t *testing.T) {
	manager, _ := NewJWTManager(JWTConfig{
		SecretKey:   []byte("una-clave-secreta-de-al-menos-32-bytes!!"),
		Issuer:      "issuer-1",
	})

	claims := Claims{UserID: "user-123"}
	token, _ := manager.GenerateAccessToken(claims)

	// Cambiar el issuer del manager
	manager.config.Issuer = "issuer-2"

	_, err := manager.ValidateToken(token)
	if err == nil {
		t.Fatal("Expected error for wrong issuer, got nil")
	}
}

// =============================================================================
// Tests de JWT - Refresh Token
// =============================================================================

func TestRefreshAccessToken(t *testing.T) {
	manager, _ := NewJWTManager(JWTConfig{
		SecretKey:            []byte("una-clave-secreta-de-al-menos-32-bytes!!"),
		Issuer:               "test-issuer",
		AccessTokenDuration:  15 * time.Minute,
		RefreshTokenDuration: 7 * 24 * time.Hour,
	})

	claims := Claims{
		UserID:   "user-123",
		Username: "john_doe",
		Role:     "admin",
	}

	refreshToken, _ := manager.GenerateRefreshToken(claims)
	newAccessToken, err := manager.RefreshAccessToken(refreshToken)

	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if newAccessToken == "" {
		t.Fatal("Expected non-empty access token")
	}

	// Validar el nuevo access token
	validatedClaims, err := manager.ValidateToken(newAccessToken)
	if err != nil {
		t.Fatalf("Expected new access token to be valid, got error: %v", err)
	}
	if validatedClaims.UserID != "user-123" {
		t.Errorf("Expected UserID 'user-123', got '%s'", validatedClaims.UserID)
	}
	if validatedClaims.TokenType != TokenTypeAccess {
		t.Errorf("Expected TokenType 'access', got '%s'", validatedClaims.TokenType)
	}
}

func TestRefreshAccessToken_WithAccessToken(t *testing.T) {
	manager, _ := NewJWTManager(JWTConfig{
		SecretKey:            []byte("una-clave-secreta-de-al-menos-32-bytes!!"),
		Issuer:               "test-issuer",
		AccessTokenDuration:  15 * time.Minute,
		RefreshTokenDuration: 7 * 24 * time.Hour,
	})

	claims := Claims{UserID: "user-123"}
	accessToken, _ := manager.GenerateAccessToken(claims)

	// Intentar usar access token como refresh token
	_, err := manager.RefreshAccessToken(accessToken)
	if err == nil {
		t.Fatal("Expected error when using access token as refresh token, got nil")
	}
}

// =============================================================================
// Tests de JWT - Funciones Globales
// =============================================================================

func TestGlobalFunctions(t *testing.T) {
	// Configurar manager global
	err := Init(JWTConfig{
		SecretKey:            []byte("una-clave-secreta-de-al-menos-32-bytes!!"),
		Issuer:               "test-global",
		AccessTokenDuration:  15 * time.Minute,
		RefreshTokenDuration: 7 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Failed to init global manager: %v", err)
	}

	// Probar funciones globales
	claims := Claims{UserID: "user-global", Role: "user"}
	
	token, err := GenerateAccessToken(claims)
	if err != nil {
		t.Fatalf("GenerateAccessToken failed: %v", err)
	}

	validatedClaims, err := ValidateToken(token)
	if err != nil {
		t.Fatalf("ValidateToken failed: %v", err)
	}
	if validatedClaims.UserID != "user-global" {
		t.Errorf("Expected UserID 'user-global', got '%s'", validatedClaims.UserID)
	}
}

func TestGenerateQuickToken(t *testing.T) {
	token, err := GenerateQuickToken("user-quick", "admin")
	if err != nil {
		t.Fatalf("GenerateQuickToken failed: %v", err)
	}
	if token == "" {
		t.Fatal("Expected non-empty token")
	}

	// Validar el token generado
	claims, err := GetDefault().ValidateToken(token)
	if err != nil {
		t.Fatalf("Generated token is invalid: %v", err)
	}
	if claims.UserID != "user-quick" || claims.Role != "admin" {
		t.Errorf("Unexpected claims: UserID=%s, Role=%s", claims.UserID, claims.Role)
	}
}

func TestGenerateQuickTokenWithEmail(t *testing.T) {
	token, err := GenerateQuickTokenWithEmail("user-email", "test@example.com", "user")
	if err != nil {
		t.Fatalf("GenerateQuickTokenWithEmail failed: %v", err)
	}

	claims, err := GetDefault().ValidateToken(token)
	if err != nil {
		t.Fatalf("Generated token is invalid: %v", err)
	}
	if claims.Email != "test@example.com" {
		t.Errorf("Expected email 'test@example.com', got '%s'", claims.Email)
	}
}

func TestValidateQuickToken(t *testing.T) {
	token, _ := GenerateQuickToken("user-validate", "user")

	if !ValidateQuickToken(token) {
		t.Fatal("Expected token to be valid")
	}

	if ValidateQuickToken("invalid-token") {
		t.Fatal("Expected invalid token to return false")
	}
}

func TestExtractUserID(t *testing.T) {
	token, _ := GenerateQuickToken("user-extract", "user")

	userID := ExtractUserID(token)
	if userID != "user-extract" {
		t.Errorf("Expected UserID 'user-extract', got '%s'", userID)
	}

	// Token inválido debe retornar string vacío
	invalidUserID := ExtractUserID("invalid-token")
	if invalidUserID != "" {
		t.Errorf("Expected empty string for invalid token, got '%s'", invalidUserID)
	}
}

func TestExtractClaims(t *testing.T) {
	token, _ := GenerateQuickToken("user-claims", "admin")

	claims := ExtractClaims(token)
	if claims == nil {
		t.Fatal("Expected non-nil claims")
	}
	if claims.UserID != "user-claims" {
		t.Errorf("Expected UserID 'user-claims', got '%s'", claims.UserID)
	}
	if claims.Role != "admin" {
		t.Errorf("Expected Role 'admin', got '%s'", claims.Role)
	}

	// Token inválido debe retornar nil
	invalidClaims := ExtractClaims("invalid-token")
	if invalidClaims != nil {
		t.Fatal("Expected nil claims for invalid token")
	}
}

// =============================================================================
// Tests de Sesiones - Funciones Básicas
// =============================================================================

func TestNewSessionManager(t *testing.T) {
	manager, err := NewSessionManager(SessionConfig{
		SecurityLevel:         security.LevelMedium,
		MaxConcurrentSessions: 5,
	})
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if manager == nil {
		t.Fatal("Expected manager to be created")
	}

	config := manager.GetConfig()
	if config.MaxConcurrentSessions != 5 {
		t.Errorf("Expected MaxConcurrentSessions 5, got %d", config.MaxConcurrentSessions)
	}
	// SessionTimeout por defecto es 24h para LevelMedium
	if config.SessionTimeout != 24*time.Hour {
		t.Errorf("Expected SessionTimeout 24h, got %v", config.SessionTimeout)
	}
	if config.IdleTimeout != 30*time.Minute {
		t.Errorf("Expected IdleTimeout 30m, got %v", config.IdleTimeout)
	}
}

func TestSession_IsActive(t *testing.T) {
	now := time.Now()
	
	// Sesión activa
	session := &Session{
		ID:             "session-1",
		UserID:         "user-1",
		CreatedAt:      now,
		LastActivityAt: now,
		ExpiresAt:      now.Add(1 * time.Hour),
		IsValid:        true,
	}
	
	if !session.IsActive() {
		t.Fatal("Expected session to be active")
	}

	// Sesión inválida
	session.IsValid = false
	if session.IsActive() {
		t.Fatal("Expected invalid session to be inactive")
	}

	// Sesión expirada
	session.IsValid = true
	session.ExpiresAt = now.Add(-1 * time.Hour)
	if session.IsActive() {
		t.Fatal("Expected expired session to be inactive")
	}

	// Sesión revocada
	session.ExpiresAt = now.Add(1 * time.Hour)
	session.RevokedAt = now
	if session.IsActive() {
		t.Fatal("Expected revoked session to be inactive")
	}
}

// =============================================================================
// Tests de Sesiones - Creación y Validación
// =============================================================================

func TestCreateSession(t *testing.T) {
	manager, _ := NewSessionManager(SessionConfig{
		SecurityLevel:         security.LevelMedium,
		MaxConcurrentSessions: 5,
	})

	sessionID, err := manager.CreateSession(SessionInfo{
		UserID:    "user-123",
		Username:  "john_doe",
		IPAddress: "192.168.1.100",
		UserAgent: "Mozilla/5.0",
	})
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if sessionID == "" {
		t.Fatal("Expected non-empty session ID")
	}
}

func TestValidateSession(t *testing.T) {
	manager, _ := NewSessionManager(SessionConfig{
		SecurityLevel:         security.LevelMedium,
		MaxConcurrentSessions: 5,
	})

	sessionID, _ := manager.CreateSession(SessionInfo{
		UserID:    "user-123",
		Username:  "john_doe",
		IPAddress: "192.168.1.100",
	})

	session, err := manager.ValidateSession(sessionID)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if session.UserID != "user-123" {
		t.Errorf("Expected UserID 'user-123', got '%s'", session.UserID)
	}
	if !session.IsActive() {
		t.Fatal("Expected session to be active")
	}
}

func TestValidateSession_Expired(t *testing.T) {
	manager, _ := NewSessionManager(SessionConfig{
		SessionTimeout: 1 * time.Second,
		IdleTimeout:    1 * time.Second,
		Store:          NewMemorySessionStore(),
	})

	sessionID, _ := manager.CreateSession(SessionInfo{
		UserID: "user-123",
	})

	// Esperar a que expire
	time.Sleep(2 * time.Second)

	_, err := manager.ValidateSession(sessionID)
	if err == nil {
		t.Fatal("Expected error for expired session, got nil")
	}
}

// =============================================================================
// Tests de Sesiones - Revocación
// =============================================================================

func TestRevokeSession(t *testing.T) {
	manager, _ := NewSessionManager(SessionConfig{
		SecurityLevel: security.LevelMedium,
	})

	sessionID, _ := manager.CreateSession(SessionInfo{
		UserID: "user-123",
	})

	// Revocar sesión
	err := manager.RevokeSession(sessionID, "user_logout")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Verificar que la sesión está revocada
	session, _ := manager.GetSession(sessionID)
	if session.IsValid {
		t.Fatal("Expected session to be invalid after revocation")
	}
	if session.RevokeReason != "user_logout" {
		t.Errorf("Expected RevokeReason 'user_logout', got '%s'", session.RevokeReason)
	}
}

func TestRevokeAllUserSessions(t *testing.T) {
	manager, _ := NewSessionManager(SessionConfig{
		SecurityLevel:         security.LevelMedium,
		MaxConcurrentSessions: 10,
	})

	// Crear múltiples sesiones para el mismo usuario
	var sessionIDs []string
	for i := 0; i < 3; i++ {
		sessionID, _ := manager.CreateSession(SessionInfo{
			UserID:    "user-123",
			IPAddress: "192.168.1.100",
		})
		sessionIDs = append(sessionIDs, sessionID)
	}

	// Revocar todas las sesiones
	err := manager.RevokeAllUserSessions("user-123", "password_changed")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Verificar que todas las sesiones están revocadas
	for _, sessionID := range sessionIDs {
		session, _ := manager.GetSession(sessionID)
		if session.IsValid {
			t.Errorf("Expected session %s to be invalid", sessionID)
		}
	}
}

// =============================================================================
// Tests de Sesiones - Límite de Sesiones Concurrentes
// =============================================================================

func TestConcurrentSessionLimit(t *testing.T) {
	manager, _ := NewSessionManager(SessionConfig{
		SessionTimeout:        1 * time.Hour,
		MaxConcurrentSessions: 2,
		Store:                 NewMemorySessionStore(),
	})

	// Crear 3 sesiones (el límite es 2)
	sessionID1, _ := manager.CreateSession(SessionInfo{
		UserID:    "user-123",
		IPAddress: "192.168.1.1",
	})
	time.Sleep(10 * time.Millisecond)
	
	sessionID2, _ := manager.CreateSession(SessionInfo{
		UserID:    "user-123",
		IPAddress: "192.168.1.2",
	})
	time.Sleep(10 * time.Millisecond)
	
	sessionID3, _ := manager.CreateSession(SessionInfo{
		UserID:    "user-123",
		IPAddress: "192.168.1.3",
	})

	// La primera sesión debería estar revocada
	session1, _ := manager.GetSession(sessionID1)
	if session1.IsValid {
		t.Error("Expected first session to be revoked due to concurrent limit")
	}

	// Las sesiones 2 y 3 deberían estar activas
	session2, _ := manager.GetSession(sessionID2)
	if !session2.IsActive() {
		t.Error("Expected second session to be active")
	}

	session3, _ := manager.GetSession(sessionID3)
	if !session3.IsActive() {
		t.Error("Expected third session to be active")
	}
}

// =============================================================================
// Tests de Sesiones - Funciones Globales
// =============================================================================

func TestGlobalSessionFunctions(t *testing.T) {
	// Inicializar manager global
	err := InitSession(SessionConfig{
		SecurityLevel:         security.LevelMedium,
		MaxConcurrentSessions: 5,
	})
	if err != nil {
		t.Fatalf("Failed to init global session manager: %v", err)
	}

	// Crear sesión rápida
	sessionID, err := CreateQuickSession(SessionInfo{
		UserID:    "user-global",
		Username:  "global_user",
		IPAddress: "192.168.1.1",
	})
	if err != nil {
		t.Fatalf("CreateQuickSession failed: %v", err)
	}

	// Validar sesión rápida
	if !QuickSessionExists(sessionID) {
		t.Fatal("Expected session to exist")
	}

	// Obtener UserID
	userID := GetSessionUserID(sessionID)
	if userID != "user-global" {
		t.Errorf("Expected UserID 'user-global', got '%s'", userID)
	}

	// Obtener sesiones de usuario
	sessions, err := GetQuickUserSessions("user-global")
	if err != nil {
		t.Fatalf("GetQuickUserSessions failed: %v", err)
	}
	if len(sessions) == 0 {
		t.Error("Expected at least one session")
	}

	// Revocar sesión rápida
	err = RevokeQuickSession(sessionID, "test_logout")
	if err != nil {
		t.Fatalf("RevokeQuickSession failed: %v", err)
	}

	// Verificar que ya no existe
	if QuickSessionExists(sessionID) {
		t.Fatal("Expected session to be revoked")
	}
}

// =============================================================================
// Tests de MemorySessionStore
// =============================================================================

func TestMemorySessionStore_Basic(t *testing.T) {
	store := NewMemorySessionStore()

	session := &Session{
		ID:             "session-test",
		UserID:         "user-123",
		CreatedAt:      time.Now(),
		LastActivityAt: time.Now(),
		ExpiresAt:      time.Now().Add(1 * time.Hour),
		IsValid:        true,
	}

	// Save
	err := store.Save(session)
	if err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// Get
	retrieved, err := store.Get("session-test")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if retrieved.UserID != "user-123" {
		t.Errorf("Expected UserID 'user-123', got '%s'", retrieved.UserID)
	}

	// GetByUserID
	sessions, err := store.GetByUserID("user-123")
	if err != nil {
		t.Fatalf("GetByUserID failed: %v", err)
	}
	if len(sessions) != 1 {
		t.Errorf("Expected 1 session, got %d", len(sessions))
	}

	// Delete
	err = store.Delete("session-test")
	if err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	_, err = store.Get("session-test")
	if err != ErrSessionNotFound {
		t.Error("Expected ErrSessionNotFound after delete")
	}
}

func TestMemorySessionStore_DeleteByUserID(t *testing.T) {
	store := NewMemorySessionStore()

	// Crear múltiples sesiones para diferentes usuarios
	for i := 1; i <= 3; i++ {
		session := &Session{
			ID:             "session-" + string(rune(i)),
			UserID:         "user-1",
			CreatedAt:      time.Now(),
			LastActivityAt: time.Now(),
			ExpiresAt:      time.Now().Add(1 * time.Hour),
			IsValid:        true,
		}
		store.Save(session)
	}

	session4 := &Session{
		ID:             "session-4",
		UserID:         "user-2",
		CreatedAt:      time.Now(),
		LastActivityAt: time.Now(),
		ExpiresAt:      time.Now().Add(1 * time.Hour),
		IsValid:        true,
	}
	store.Save(session4)

	// Eliminar todas las sesiones de user-1
	err := store.DeleteByUserID("user-1")
	if err != nil {
		t.Fatalf("DeleteByUserID failed: %v", err)
	}

	// Verificar que solo queda la sesión de user-2
	sessions, _ := store.GetByUserID("user-1")
	if len(sessions) != 0 {
		t.Errorf("Expected 0 sessions for user-1, got %d", len(sessions))
	}

	sessions, _ = store.GetByUserID("user-2")
	if len(sessions) != 1 {
		t.Errorf("Expected 1 session for user-2, got %d", len(sessions))
	}
}

func TestMemorySessionStore_CleanExpired(t *testing.T) {
	store := NewMemorySessionStore()

	now := time.Now()

	// Sesión válida
	session1 := &Session{
		ID:             "session-valid",
		UserID:         "user-1",
		CreatedAt:      now,
		LastActivityAt: now,
		ExpiresAt:      now.Add(1 * time.Hour),
		IsValid:        true,
	}

	// Sesión expirada
	session2 := &Session{
		ID:             "session-expired",
		UserID:         "user-1",
		CreatedAt:      now,
		LastActivityAt: now,
		ExpiresAt:      now.Add(-1 * time.Hour),
		IsValid:        true,
	}

	// Sesión inválida
	session3 := &Session{
		ID:             "session-invalid",
		UserID:         "user-1",
		CreatedAt:      now,
		LastActivityAt: now,
		ExpiresAt:      now.Add(1 * time.Hour),
		IsValid:        false,
	}

	store.Save(session1)
	store.Save(session2)
	store.Save(session3)

	// Limpiar expiradas
	count, err := store.CleanExpired()
	if err != nil {
		t.Fatalf("CleanExpired failed: %v", err)
	}
	if count != 2 {
		t.Errorf("Expected to clean 2 sessions, cleaned %d", count)
	}

	// Verificar que solo queda la sesión válida
	sessions, _ := store.GetByUserID("user-1")
	if len(sessions) != 1 {
		t.Errorf("Expected 1 session remaining, got %d", len(sessions))
	}
}

func TestMemorySessionStore_ThreadSafe(t *testing.T) {
	store := NewMemorySessionStore()

	// Crear sesión inicial
	session := &Session{
		ID:             "session-concurrent",
		UserID:         "user-1",
		CreatedAt:      time.Now(),
		LastActivityAt: time.Now(),
		ExpiresAt:      time.Now().Add(1 * time.Hour),
		IsValid:        true,
	}
	store.Save(session)

	// Leer y modificar concurrentemente
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func() {
			s, _ := store.Get("session-concurrent")
			s.LastActivityAt = time.Now()
			store.Save(s)
			done <- true
		}()
	}

	// Esperar todas las goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	// Verificar que no hubo race condition (si hubiera, el test fallaría con -race)
	_, err := store.Get("session-concurrent")
	if err != nil {
		t.Errorf("Session lost due to race condition: %v", err)
	}
}
