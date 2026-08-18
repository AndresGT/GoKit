package token

import (
	"errors"
	"testing"
	"time"

	"github.com/AndresGT/GoKit/security"
)

// =============================================================================
// Helpers
// =============================================================================

const testSecret = "una-clave-secreta-de-al-menos-32-bytes!!"

// mockFailStore envuelve MemorySessionStore y permite inyectar errores
// por operación para probar los caminos de fallo del manager.
type mockFailStore struct {
	*MemorySessionStore
	getByUserIDErr error
	saveErr        error
	getErr         error
	cleanErr       error
}

func newMockFailStore() *mockFailStore {
	return &mockFailStore{MemorySessionStore: NewMemorySessionStore()}
}

func (s *mockFailStore) GetByUserID(userID string) ([]*Session, error) {
	if s.getByUserIDErr != nil {
		return nil, s.getByUserIDErr
	}
	return s.MemorySessionStore.GetByUserID(userID)
}

func (s *mockFailStore) Save(session *Session) error {
	if s.saveErr != nil {
		return s.saveErr
	}
	return s.MemorySessionStore.Save(session)
}

func (s *mockFailStore) Get(sessionID string) (*Session, error) {
	if s.getErr != nil {
		return nil, s.getErr
	}
	return s.MemorySessionStore.Get(sessionID)
}

func (s *mockFailStore) CleanExpired() (int, error) {
	if s.cleanErr != nil {
		return 0, s.cleanErr
	}
	return s.MemorySessionStore.CleanExpired()
}

// =============================================================================
// Tests de JWT - Caminos de Error
// =============================================================================

func TestGenerateTokenUUIDError(t *testing.T) {
	old := generateUUID
	generateUUID = func() (string, error) { return "", errors.New("uuid failed") }
	defer func() { generateUUID = old }()

	m, err := NewJWTManager(JWTConfig{SecretKey: []byte(testSecret), Issuer: "test"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, err := m.GenerateAccessToken(Claims{UserID: "u"}); err != ErrJWTInvalid {
		t.Fatalf("expected ErrJWTInvalid, got %v", err)
	}
}

func TestValidateToken_Expired(t *testing.T) {
	m, _ := NewJWTManager(JWTConfig{
		SecretKey:            []byte(testSecret),
		Issuer:               "test",
		AccessTokenDuration:  -time.Minute,
		RefreshTokenDuration: time.Hour,
	})

	token, err := m.GenerateAccessToken(Claims{UserID: "u"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, err := m.ValidateToken(token); err != ErrJWTExpired {
		t.Fatalf("expected ErrJWTExpired, got %v", err)
	}
}

func TestInit_ShortSecretKey(t *testing.T) {
	if err := Init(JWTConfig{SecretKey: []byte("short")}); err == nil {
		t.Fatal("expected error for short secret key")
	}
}

func TestGlobalGenerateAndRefreshAccessToken(t *testing.T) {
	if err := Init(JWTConfig{
		SecretKey:            []byte(testSecret),
		Issuer:               "test",
		AccessTokenDuration:  time.Hour,
		RefreshTokenDuration: time.Hour,
	}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	refresh, err := GenerateRefreshToken(Claims{UserID: "u", SessionID: "s"})
	if err != nil {
		t.Fatalf("GenerateRefreshToken failed: %v", err)
	}

	access, err := RefreshAccessToken(refresh)
	if err != nil {
		t.Fatalf("RefreshAccessToken failed: %v", err)
	}
	if access == "" {
		t.Fatal("expected non-empty access token")
	}
}

func TestRefreshAccessToken_InvalidToken(t *testing.T) {
	m, _ := NewJWTManager(JWTConfig{SecretKey: []byte(testSecret), Issuer: "test"})

	if _, err := m.RefreshAccessToken("token-invalido"); err == nil {
		t.Fatal("expected error for invalid refresh token")
	}
}

// =============================================================================
// Tests de Sesiones - Expiración por Inactividad
// =============================================================================

func TestSession_IsExpired_IdleTimeout(t *testing.T) {
	s := &Session{
		LastActivityAt: time.Now().Add(-2 * time.Minute),
		ExpiresAt:      time.Now().Add(time.Hour),
		IdleTimeout:    time.Minute,
	}
	if !s.IsExpired() {
		t.Fatal("expected session to be expired by idle timeout")
	}

	s.LastActivityAt = time.Now()
	if s.IsExpired() {
		t.Fatal("expected session to be active after recent activity")
	}
}

// =============================================================================
// Tests de Sesiones - Caminos de Error en CreateSession
// =============================================================================

func TestCreateSession_RandomStringError(t *testing.T) {
	old := randomString
	randomString = func(n int) (string, error) { return "", errors.New("rand failed") }
	defer func() { randomString = old }()

	m := NewSessionManager(SessionConfig{})
	if _, err := m.CreateSession(SessionInfo{UserID: "u"}); err != ErrSessionStoreFailed {
		t.Fatalf("expected ErrSessionStoreFailed, got %v", err)
	}
}

func TestCreateSession_EnforceLimitGetByUserIDError(t *testing.T) {
	store := newMockFailStore()
	store.getByUserIDErr = errors.New("store failed")
	m := NewSessionManager(SessionConfig{MaxConcurrentSessions: 2, Store: store})

	if _, err := m.CreateSession(SessionInfo{UserID: "u"}); err == nil {
		t.Fatal("expected error when GetByUserID fails")
	}
}

func TestCreateSession_SaveError(t *testing.T) {
	store := newMockFailStore()
	store.saveErr = errors.New("store failed")
	m := NewSessionManager(SessionConfig{MaxConcurrentSessions: 5, Store: store})

	if _, err := m.CreateSession(SessionInfo{UserID: "u"}); err != ErrSessionStoreFailed {
		t.Fatalf("expected ErrSessionStoreFailed, got %v", err)
	}
}

func TestEnforceConcurrentLimit_SaveError(t *testing.T) {
	store := newMockFailStore()
	now := time.Now()
	store.Save(&Session{
		ID: "a", UserID: "u", CreatedAt: now.Add(-2 * time.Minute),
		LastActivityAt: now, ExpiresAt: now.Add(time.Hour), IsValid: true,
	})
	store.Save(&Session{
		ID: "b", UserID: "u", CreatedAt: now.Add(-time.Minute),
		LastActivityAt: now, ExpiresAt: now.Add(time.Hour), IsValid: true,
	})
	store.saveErr = errors.New("store failed")

	m := NewSessionManager(SessionConfig{MaxConcurrentSessions: 1, Store: store})
	if _, err := m.CreateSession(SessionInfo{UserID: "u"}); err == nil {
		t.Fatal("expected error when Save fails during enforce limit")
	}
}

// =============================================================================
// Tests de Sesiones - Caminos de Error en Validación y Revocación
// =============================================================================

func TestValidateSession_NotFound(t *testing.T) {
	m := NewSessionManager(SessionConfig{})
	if _, err := m.ValidateSession("no-existe"); err != ErrSessionNotFound {
		t.Fatalf("expected ErrSessionNotFound, got %v", err)
	}
}

func TestValidateSession_SaveError(t *testing.T) {
	store := newMockFailStore()
	m := NewSessionManager(SessionConfig{SessionTimeout: time.Hour, Store: store})

	sessionID, err := m.CreateSession(SessionInfo{UserID: "u"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	store.saveErr = errors.New("store failed")
	if _, err := m.ValidateSession(sessionID); err != ErrSessionStoreFailed {
		t.Fatalf("expected ErrSessionStoreFailed, got %v", err)
	}
}

func TestRevokeSession_NotFound(t *testing.T) {
	m := NewSessionManager(SessionConfig{})
	if err := m.RevokeSession("no-existe", "reason"); err != ErrSessionNotFound {
		t.Fatalf("expected ErrSessionNotFound, got %v", err)
	}
}

func TestRevokeAllUserSessions_GetByUserIDError(t *testing.T) {
	store := newMockFailStore()
	store.getByUserIDErr = errors.New("store failed")
	m := NewSessionManager(SessionConfig{Store: store})

	if err := m.RevokeAllUserSessions("u", "reason"); err == nil {
		t.Fatal("expected error when GetByUserID fails")
	}
}

func TestRevokeAllUserSessions_SaveError(t *testing.T) {
	store := newMockFailStore()
	m := NewSessionManager(SessionConfig{Store: store})

	if _, err := m.CreateSession(SessionInfo{UserID: "u"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	store.saveErr = errors.New("store failed")
	if err := m.RevokeAllUserSessions("u", "reason"); err == nil {
		t.Fatal("expected error when Save fails")
	}
}

func TestGetUserSessions_GetByUserIDError(t *testing.T) {
	store := newMockFailStore()
	store.getByUserIDErr = errors.New("store failed")
	m := NewSessionManager(SessionConfig{Store: store})

	if _, err := m.GetUserSessions("u"); err == nil {
		t.Fatal("expected error when GetByUserID fails")
	}
}

func TestCleanExpiredSessions_Error(t *testing.T) {
	store := newMockFailStore()
	store.cleanErr = errors.New("store failed")
	m := NewSessionManager(SessionConfig{Store: store})

	if _, err := m.CleanExpiredSessions(); err == nil {
		t.Fatal("expected error when CleanExpired fails")
	}
}

// =============================================================================
// Tests de Sesiones - Funciones Globales Adicionales
// =============================================================================

func TestGlobalSessionHelpers(t *testing.T) {
	InitSession(SessionConfig{
		SecurityLevel:         security.LevelMedium,
		MaxConcurrentSessions: 5,
	})

	if GetDefaultSession() == nil {
		t.Fatal("expected default session manager")
	}

	sessionID, err := CreateQuickSession(SessionInfo{UserID: "u", IPAddress: "10.0.0.1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, err := ValidateQuickSession("no-existe"); err == nil {
		t.Fatal("expected error for missing session")
	}

	if _, err := ValidateQuickSession(sessionID); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if err := RevokeAllQuickSessions("u", "reason"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := GetSessionUserID("no-existe"); got != "" {
		t.Fatalf("expected empty UserID for missing session, got %q", got)
	}
}
