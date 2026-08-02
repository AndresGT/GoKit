package token

import (
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/AndresGT/GoKit/security"
	"github.com/AndresGT/GoKit/security/crypto"
)

// =============================================================================
// Errores de Sesión
// =============================================================================

var (
	// ErrSessionNotFound se retorna cuando no se encuentra la sesión solicitada.
	// Es un error genérico que no revela si la sesión existió o fue revocada.
	ErrSessionNotFound = errors.New("sesión no encontrada")

	// ErrSessionStoreFailed se retorna cuando el almacenamiento de sesiones
	// no puede completar la operación (fallo de BD, Redis, etc.).
	ErrSessionStoreFailed = errors.New("fallo en el almacenamiento de sesiones")
)

// =============================================================================
// Estructura de Sesión
// =============================================================================

// Session representa una sesión de usuario autenticada.
// Contiene toda la información necesaria para validar y auditar la sesión
// a lo largo de su ciclo de vida.
type Session struct {
	// ID es el identificador único de la sesión (generado criptográficamente).
	ID string

	// UserID es el identificador del usuario propietario de la sesión.
	UserID string

	// Username es el nombre de usuario (opcional, para logging/auditoría).
	Username string

	// IPAddress es la IP desde donde se creó la sesión.
	IPAddress string

	// UserAgent es el User-Agent del navegador/cliente.
	UserAgent string

	// DeviceInfo contiene información adicional del dispositivo (opcional).
	DeviceInfo string

	// CreatedAt es el momento en que se creó la sesión.
	CreatedAt time.Time

	// LastActivityAt es el momento de la última actividad del usuario.
	// Se actualiza en cada validación exitosa para implementar idle timeout.
	LastActivityAt time.Time

	// ExpiresAt es el momento de expiración absoluta de la sesión.
	// Después de este tiempo, la sesión es inválida sin importar la actividad.
	ExpiresAt time.Time

	// IdleTimeout es el tiempo máximo de inactividad permitido.
	// Si pasa más tiempo que esto desde LastActivityAt, la sesión expira.
	IdleTimeout time.Duration

	// IsValid indica si la sesión está activa (no ha sido revocada).
	IsValid bool

	// RevokedAt es el momento en que la sesión fue revocada (si aplica).
	// Si es zero, la sesión no ha sido revocada.
	RevokedAt time.Time

	// RevokeReason indica la razón de la revocación (opcional, para auditoría).
	RevokeReason string
}

// IsExpired verifica si la sesión ha expirado por tiempo absoluto o inactividad.
func (s *Session) IsExpired() bool {
	now := time.Now()

	// Verificar expiración absoluta
	if now.After(s.ExpiresAt) {
		return true
	}

	// Verificar idle timeout
	if s.IdleTimeout > 0 && now.Sub(s.LastActivityAt) > s.IdleTimeout {
		return true
	}

	return false
}

// IsActive verifica si la sesión está activa (válida y no expirada).
func (s *Session) IsActive() bool {
	return s.IsValid && !s.IsExpired() && s.RevokedAt.IsZero()
}

// =============================================================================
// Configuración del Manager de Sesiones
// =============================================================================

// SessionConfig define la configuración para el manager de sesiones.
type SessionConfig struct {
	// SessionTimeout es el tiempo máximo absoluto de vida de una sesión.
	// Si es 0, se usa el valor predeterminado del nivel de seguridad.
	SessionTimeout time.Duration

	// IdleTimeout es el tiempo máximo de inactividad permitido.
	// Si es 0, se usa el valor predeterminado del nivel de seguridad.
	IdleTimeout time.Duration

	// MaxConcurrentSessions es el número máximo de sesiones activas por usuario.
	// Si es 0, se usa el valor predeterminado del nivel de seguridad.
	// Cuando se supera este límite, las sesiones más antiguas se revocan.
	MaxConcurrentSessions int

	// SecurityLevel define el nivel de seguridad para usar valores predeterminados.
	// Si no se especifica, se usa LevelMedium.
	SecurityLevel security.Level

	// Store es el almacenamiento de sesiones a utilizar.
	// Si es nil, se usa MemorySessionStore (solo para desarrollo/testing).
	Store SessionStore
}

// =============================================================================
// Interfaz de Almacenamiento de Sesiones
// =============================================================================

// SessionStore define el contrato para los backends de almacenamiento de sesiones.
// Esta abstracción permite usar diferentes backends (memoria, Redis, base de datos)
// sin modificar el código del manager.
type SessionStore interface {
	// Save guarda una sesión en el almacenamiento.
	Save(session *Session) error

	// Get recupera una sesión por su ID.
	// Retorna ErrSessionNotFound si no existe.
	Get(sessionID string) (*Session, error)

	// GetByUserID recupera todas las sesiones activas de un usuario.
	GetByUserID(userID string) ([]*Session, error)

	// Delete elimina una sesión del almacenamiento.
	Delete(sessionID string) error

	// DeleteByUserID elimina todas las sesiones de un usuario.
	DeleteByUserID(userID string) error

	// CleanExpired elimina todas las sesiones expiradas del almacenamiento.
	// Útil para tareas de mantenimiento periódico.
	CleanExpired() (int, error)
}

// =============================================================================
// Implementación en Memoria (para desarrollo/testing)
// =============================================================================

// MemorySessionStore es una implementación en memoria de SessionStore.
// NO es adecuada para producción (no persiste, no es distribuida).
// Úsala solo para desarrollo, testing o aplicaciones de un solo proceso.
type MemorySessionStore struct {
	mu       sync.RWMutex
	sessions map[string]*Session
}

// NewMemorySessionStore crea un nuevo almacenamiento en memoria.
func NewMemorySessionStore() *MemorySessionStore {
	return &MemorySessionStore{
		sessions: make(map[string]*Session),
	}
}

// Save guarda una sesión en memoria.
func (s *MemorySessionStore) Save(session *Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[session.ID] = session
	return nil
}

// Get recupera una sesión por su ID.
// Devuelve una copia para que las modificaciones del llamador (p. ej. actualizar
// LastActivityAt antes de llamar a Save) no muten el estado interno del store
// fuera de su mutex.
func (s *MemorySessionStore) Get(sessionID string) (*Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	session, exists := s.sessions[sessionID]
	if !exists {
		return nil, ErrSessionNotFound
	}
	sessionCopy := *session
	return &sessionCopy, nil
}

// GetByUserID recupera todas las sesiones de un usuario.
// Devuelve copias por la misma razón que Get.
func (s *MemorySessionStore) GetByUserID(userID string) ([]*Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []*Session
	for _, session := range s.sessions {
		if session.UserID == userID {
			sessionCopy := *session
			result = append(result, &sessionCopy)
		}
	}
	return result, nil
}

// Delete elimina una sesión.
func (s *MemorySessionStore) Delete(sessionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, sessionID)
	return nil
}

// DeleteByUserID elimina todas las sesiones de un usuario.
func (s *MemorySessionStore) DeleteByUserID(userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for id, session := range s.sessions {
		if session.UserID == userID {
			delete(s.sessions, id)
		}
	}
	return nil
}

// CleanExpired elimina todas las sesiones expiradas.
func (s *MemorySessionStore) CleanExpired() (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	count := 0
	for id, session := range s.sessions {
		if session.IsExpired() || !session.IsValid {
			delete(s.sessions, id)
			count++
		}
	}
	return count, nil
}

// =============================================================================
// Manager de Sesiones
// =============================================================================

// SessionManager maneja el ciclo de vida completo de las sesiones de usuario.
type SessionManager struct {
	config SessionConfig
	store  SessionStore
}

// NewSessionManager crea un nuevo manager de sesiones con la configuración proporcionada.
// Si no se especifica un Store, se usa MemorySessionStore (solo para desarrollo).
//
// IMPORTANTE: Para producción, DEBES proporcionar un SessionStore persistente
// (Redis, base de datos, etc.). MemorySessionStore pierde datos al reiniciar.
//
// Ejemplo de uso:
//
//	// Con valores predeterminados del nivel de seguridad
//	manager, err := token.NewSessionManager(token.SessionConfig{
//	    SecurityLevel: security.LevelHigh,
//	})
//
//	// Con configuración personalizada y Redis (ejemplo conceptual)
//	manager, err := token.NewSessionManager(token.SessionConfig{
//	    SessionTimeout:        8 * time.Hour,
//	    IdleTimeout:           15 * time.Minute,
//	    MaxConcurrentSessions: 2,
//	    Store:                 redisStore, // Implementación personalizada
//	})
func NewSessionManager(config SessionConfig) (*SessionManager, error) {
	// Aplicar valores predeterminados del nivel de seguridad
	defaults := config.SecurityLevel.GetDefaults()

	if config.SessionTimeout == 0 {
		config.SessionTimeout = defaults.SessionTimeout
	}

	if config.IdleTimeout == 0 {
		config.IdleTimeout = defaults.IdleTimeout
	}

	if config.MaxConcurrentSessions == 0 {
		config.MaxConcurrentSessions = defaults.MaxConcurrentSessions
	}

	// Usar MemorySessionStore si no se proporciona uno
	store := config.Store
	if store == nil {
		store = NewMemorySessionStore()
	}

	return &SessionManager{
		config: config,
		store:  store,
	}, nil
}

// CreateSession crea una nueva sesión para el usuario especificado.
// Si el usuario ya tiene el máximo de sesiones concurrentes permitidas,
// las sesiones más antiguas se revocan automáticamente.
//
// Retorna el ID de la nueva sesión, que debe ser enviado al cliente
// (típicamente en una cookie HttpOnly o en el cuerpo de la respuesta).
//
// Ejemplo de uso:
//
//	sessionID, err := sessionManager.CreateSession(token.SessionInfo{
//	    UserID:    "user-123",
//	    Username:  "john_doe",
//	    IPAddress: "192.168.1.100",
//	    UserAgent: "Mozilla/5.0...",
//	})
//	if err != nil {
//	    // Manejar error
//	}
//	// Enviar sessionID al cliente (cookie o respuesta)
type SessionInfo struct {
	UserID     string
	Username   string
	IPAddress  string
	UserAgent  string
	DeviceInfo string
}

func (m *SessionManager) CreateSession(info SessionInfo) (string, error) {
	// Generar ID de sesión criptográficamente seguro
	sessionID, err := crypto.RandomString(32)
	if err != nil {
		return "", ErrSessionStoreFailed
	}

	now := time.Now()

	// Crear la sesión
	session := &Session{
		ID:             sessionID,
		UserID:         info.UserID,
		Username:       info.Username,
		IPAddress:      info.IPAddress,
		UserAgent:      info.UserAgent,
		DeviceInfo:     info.DeviceInfo,
		CreatedAt:      now,
		LastActivityAt: now,
		ExpiresAt:      now.Add(m.config.SessionTimeout),
		IdleTimeout:    m.config.IdleTimeout,
		IsValid:        true,
	}

	// Aplicar límite de sesiones concurrentes
	if err := m.enforceConcurrentLimit(info.UserID); err != nil {
		return "", err
	}

	// Guardar la sesión
	if err := m.store.Save(session); err != nil {
		return "", ErrSessionStoreFailed
	}

	return sessionID, nil
}

// enforceConcurrentLimit revoca las sesiones más antiguas si el usuario
// supera el límite de sesiones concurrentes configurado.
func (m *SessionManager) enforceConcurrentLimit(userID string) error {
	sessions, err := m.store.GetByUserID(userID)
	if err != nil {
		return err
	}

	// Filtrar solo sesiones activas
	var activeSessions []*Session
	for _, s := range sessions {
		if s.IsActive() {
			activeSessions = append(activeSessions, s)
		}
	}

	// Si ya estamos en el límite, no hacer nada
	if len(activeSessions) < m.config.MaxConcurrentSessions {
		return nil
	}

	// Ordenar por CreatedAt (más antiguas primero) para revocar las
	// sesiones correctas. Es indispensable: sin este ordenamiento explícito,
	// se revocarían sesiones en un orden arbitrario (la iteración de un
	// map en Go no está garantizada), no necesariamente las más antiguas.
	// Nota: en un backend real (Redis, BD) esto se haría con ORDER BY.
	sort.Slice(activeSessions, func(i, j int) bool {
		return activeSessions[i].CreatedAt.Before(activeSessions[j].CreatedAt)
	})

	for i := 0; i < len(activeSessions)-(m.config.MaxConcurrentSessions-1); i++ {
		activeSessions[i].IsValid = false
		activeSessions[i].RevokedAt = time.Now()
		activeSessions[i].RevokeReason = "max_concurrent_sessions_exceeded"
		if err := m.store.Save(activeSessions[i]); err != nil {
			return err
		}
	}

	return nil
}

// GetSession recupera una sesión por su ID.
// Retorna ErrSessionNotFound si la sesión no existe.
func (m *SessionManager) GetSession(sessionID string) (*Session, error) {
	return m.store.Get(sessionID)
}

// ValidateSession valida una sesión y actualiza su tiempo de última actividad.
// Retorna la sesión si es válida, o un error si está expirada, revocada o no existe.
//
// Este método debe llamarse en CADA request autenticado para:
//   - Verificar que la sesión sigue activa
//   - Actualizar el LastActivityAt (para idle timeout)
//   - Detectar sesiones revocadas (logout en otro dispositivo)
//
// Ejemplo de uso:
//
//	session, err := sessionManager.ValidateSession(sessionID)
//	if err != nil {
//	    // Sesión inválida, requerir re-login
//	    return security.ErrSessionExpired
//	}
//	// Sesión válida, continuar con el request
//	userID := session.UserID
func (m *SessionManager) ValidateSession(sessionID string) (*Session, error) {
	session, err := m.store.Get(sessionID)
	if err != nil {
		return nil, ErrSessionNotFound
	}

	// Verificar si fue revocada
	if !session.IsValid || !session.RevokedAt.IsZero() {
		return nil, security.ErrSessionExpired
	}

	// Verificar si expiró
	if session.IsExpired() {
		// Marcar como inválida para limpieza posterior
		session.IsValid = false
		session.RevokedAt = time.Now()
		session.RevokeReason = "expired"
		_ = m.store.Save(session)
		return nil, security.ErrSessionExpired
	}

	// Actualizar tiempo de última actividad (slide expiration)
	session.LastActivityAt = time.Now()
	if err := m.store.Save(session); err != nil {
		return nil, ErrSessionStoreFailed
	}

	return session, nil
}

// RevokeSession revoca una sesión específica (logout).
//
// Ejemplo de uso:
//
//	err := sessionManager.RevokeSession(sessionID, "user_logout")
func (m *SessionManager) RevokeSession(sessionID, reason string) error {
	session, err := m.store.Get(sessionID)
	if err != nil {
		return ErrSessionNotFound
	}

	session.IsValid = false
	session.RevokedAt = time.Now()
	session.RevokeReason = reason

	return m.store.Save(session)
}

// RevokeAllUserSessions revoca todas las sesiones de un usuario.
// Útil para:
//   - Cambio de contraseña (invalidar todas las sesiones anteriores)
//   - Sospecha de compromiso de cuenta
//   - Logout global ("cerrar sesión en todos los dispositivos")
//
// Ejemplo de uso:
//
//	err := sessionManager.RevokeAllUserSessions("user-123", "password_changed")
func (m *SessionManager) RevokeAllUserSessions(userID, reason string) error {
	sessions, err := m.store.GetByUserID(userID)
	if err != nil {
		return err
	}

	now := time.Now()
	for _, session := range sessions {
		if session.IsActive() {
			session.IsValid = false
			session.RevokedAt = now
			session.RevokeReason = reason
			if err := m.store.Save(session); err != nil {
				return err
			}
		}
	}

	return nil
}

// GetUserSessions recupera todas las sesiones activas de un usuario.
// Útil para mostrar al usuario "Dónde estás conectado" en su perfil.
//
// Ejemplo de uso:
//
//	sessions, err := sessionManager.GetUserSessions("user-123")
//	for _, s := range sessions {
//	    fmt.Printf("Sesión desde %s, creada en %s\n", s.IPAddress, s.CreatedAt)
//	}
func (m *SessionManager) GetUserSessions(userID string) ([]*Session, error) {
	allSessions, err := m.store.GetByUserID(userID)
	if err != nil {
		return nil, err
	}

	// Filtrar solo sesiones activas
	var activeSessions []*Session
	for _, s := range allSessions {
		if s.IsActive() {
			activeSessions = append(activeSessions, s)
		}
	}

	return activeSessions, nil
}

// CleanExpiredSessions elimina todas las sesiones expiradas del almacenamiento.
// Debe llamarse periódicamente (ej. cada hora con un cron job) para evitar
// que el almacenamiento crezca indefinidamente.
//
// Ejemplo de uso:
//
//	// En un goroutine de mantenimiento
//	go func() {
//	    ticker := time.NewTicker(1 * time.Hour)
//	    for range ticker.C {
//	        cleaned, _ := sessionManager.CleanExpiredSessions()
//	        log.Info("Sesiones expiradas limpiadas: %d", cleaned)
//	    }
//	}()
func (m *SessionManager) CleanExpiredSessions() (int, error) {
	return m.store.CleanExpired()
}

// GetConfig retorna la configuración actual del manager.
func (m *SessionManager) GetConfig() SessionConfig {
	return m.config
}

// =============================================================================
// API Global a Nivel de Paquete (Fachada Simplificada)
// =============================================================================

var defaultSessionManager *SessionManager

func init() {
	// Instancia global inicializada por defecto con configuración para desarrollo.
	defaultSessionManager, _ = NewSessionManager(SessionConfig{
		SecurityLevel:         security.LevelMedium,
		MaxConcurrentSessions: 5,
	})
}

// InitSession permite reconfigurar el manager global de sesiones.
//
// Ejemplo:
//
//	token.InitSession(token.SessionConfig{
//	    SecurityLevel:         security.LevelHigh,
//	    MaxConcurrentSessions: 3,
//	})
func InitSession(config SessionConfig) error {
	manager, err := NewSessionManager(config)
	if err != nil {
		return err
	}
	defaultSessionManager = manager
	return nil
}

// GetDefaultSession devuelve la instancia global actual del SessionManager.
func GetDefaultSession() *SessionManager {
	return defaultSessionManager
}

// --- Funciones globales de uso directo para sesiones ---

// CreateQuickSession crea una sesión rápida usando el manager global.
func CreateQuickSession(info SessionInfo) (string, error) {
	return defaultSessionManager.CreateSession(info)
}

// ValidateQuickSession valida una sesión usando el manager global.
func ValidateQuickSession(sessionID string) (*Session, error) {
	return defaultSessionManager.ValidateSession(sessionID)
}

// RevokeQuickSession revoca una sesión usando el manager global.
func RevokeQuickSession(sessionID, reason string) error {
	return defaultSessionManager.RevokeSession(sessionID, reason)
}

// RevokeAllQuickSessions revoca todas las sesiones de un usuario.
func RevokeAllQuickSessions(userID, reason string) error {
	return defaultSessionManager.RevokeAllUserSessions(userID, reason)
}

// GetQuickUserSessions obtiene las sesiones activas de un usuario.
func GetQuickUserSessions(userID string) ([]*Session, error) {
	return defaultSessionManager.GetUserSessions(userID)
}

// QuickSessionExists verifica si una sesión existe y está activa.
// Retorna true si la sesión es válida, false en caso contrario.
func QuickSessionExists(sessionID string) bool {
	session, err := defaultSessionManager.ValidateSession(sessionID)
	return err == nil && session != nil && session.IsActive()
}

// GetSessionUserID extrae el UserID de una sesión válida.
// Retorna string vacío si la sesión es inválida.
func GetSessionUserID(sessionID string) string {
	session, err := defaultSessionManager.GetSession(sessionID)
	if err != nil || !session.IsActive() {
		return ""
	}
	return session.UserID
}
