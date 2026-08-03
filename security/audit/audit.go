package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/AndresGT/GoKit/logger"
)

// Event representa un evento de auditoría completo con todos los metadatos necesarios
type Event struct {
	ID              string                 `json:"id"`               // UUID único del evento
	Timestamp       time.Time              `json:"timestamp"`        // Timestamp del evento
	Actor           ActorInfo              `json:"actor"`            // Información del actor
	Action          ActionInfo             `json:"action"`           // Información de la acción
	Resource        ResourceInfo           `json:"resource"`         // Información del recurso
	Result          ResultInfo             `json:"result"`           // Resultado de la acción
	Context         ContextInfo            `json:"context"`          // Contexto de la petición
	Metadata        map[string]interface{} `json:"metadata,omitempty"` // Metadata adicional flexible
	RiskScore       float64                `json:"risk_score"`       // Score de riesgo calculado por IA
	Threats         []ThreatDetection      `json:"threats,omitempty"` // Amenazas detectadas
	DigitalFingerprint string              `json:"digital_fingerprint"` // Huella digital inmutable
}

// ActorInfo contiene información completa del actor
type ActorInfo struct {
	ID        string `json:"id,omitempty"`         // ID del usuario/actor
	Email     string `json:"email,omitempty"`      // Email del usuario
	Username  string `json:"username,omitempty"`   // Username
	Role      string `json:"role,omitempty"`       // Rol del usuario
	SessionID string `json:"session_id,omitempty"` // ID de sesión
	Type      string `json:"type"`                 // Tipo: user, system, api, anonymous
}

// ActionInfo contiene información detallada de la acción
type ActionInfo struct {
	Type        string    `json:"type"`           // Tipo de acción: CREATE, UPDATE, DELETE, LOGIN, LOGOUT, etc.
	Category    string    `json:"category"`       // Categoría: AUTH, DATA, SYSTEM, SECURITY, AUDIT
	Description string    `json:"description"`    // Descripción legible
	Method      string    `json:"method,omitempty"` // Método HTTP si aplica
	Path        string    `json:"path,omitempty"`   // Ruta/Path accedido
	Endpoint    string    `json:"endpoint,omitempty"` // Endpoint completo
}

// ResourceInfo contiene información del recurso afectado
type ResourceInfo struct {
	Type       string `json:"type"`             // Tipo de recurso: user, post, file, config, etc.
	ID         string `json:"id,omitempty"`     // ID del recurso
	Name       string `json:"name,omitempty"`   // Nombre del recurso
	Collection string `json:"collection,omitempty"` // Colección/tabla
	Tenant     string `json:"tenant,omitempty"` // Tenant/Multi-tenancy
}

// ResultInfo contiene información del resultado
type ResultInfo struct {
	Status      string `json:"status"`           // Status: SUCCESS, FAILURE, PARTIAL
	StatusCode  int    `json:"status_code"`      // Código HTTP o status code
	Message     string `json:"message,omitempty"` // Mensaje descriptivo
	Error       string `json:"error,omitempty"`   // Error si falló
	Duration    int64  `json:"duration_ms"`      // Duración en milisegundos
	ChangesCount int   `json:"changes_count,omitempty"` // Cantidad de cambios realizados
}

// ContextInfo contiene contexto completo de la petición
type ContextInfo struct {
	IPAddress      string            `json:"ip_address"`             // IP del cliente
	IPGeoLocation  GeoLocation       `json:"ip_geo_location"`        // Geolocalización de la IP
	UserAgent      string            `json:"user_agent"`             // User-Agent completo
	ClientInfo     ClientInfo        `json:"client_info"`            // Información del cliente parseada
	Referer        string            `json:"referer,omitempty"`      // Referer header
	ForwardedFor   string            `json:"forwarded_for,omitempty"` // X-Forwarded-For
	RequestID      string            `json:"request_id"`             // Request ID único
	TraceID        string            `json:"trace_id,omitempty"`     // Trace ID para distributed tracing
	SpanID         string            `json:"span_id,omitempty"`      // Span ID para distributed tracing
	Headers        map[string]string `json:"headers,omitempty"`      // Headers de la petición
	PayloadSize    int64             `json:"payload_size,omitempty"` // Tamaño del payload
	PayloadHash    string            `json:"payload_hash,omitempty"` // Hash del payload para integridad
	TLSVersion     string            `json:"tls_version,omitempty"`  // Versión TLS si usa HTTPS
	ServerPort     int               `json:"server_port,omitempty"`  // Puerto del servidor
}

// GeoLocation contiene información geográfica
type GeoLocation struct {
	Country     string  `json:"country,omitempty"`
	CountryCode string  `json:"country_code,omitempty"`
	Region      string  `json:"region,omitempty"`
	City        string  `json:"city,omitempty"`
	Latitude    float64 `json:"latitude,omitempty"`
	Longitude   float64 `json:"longitude,omitempty"`
	Timezone    string  `json:"timezone,omitempty"`
	ISP         string  `json:"isp,omitempty"`
	Org         string  `json:"org,omitempty"`
	AS          string  `json:"as,omitempty"`
}

// ClientInfo contiene información del cliente parseada
type ClientInfo struct {
	Browser     string `json:"browser,omitempty"`
	BrowserVer  string `json:"browser_version,omitempty"`
	OS          string `json:"os,omitempty"`
	OSVer       string `json:"os_version,omitempty"`
	Device      string `json:"device,omitempty"`
	DeviceType  string `json:"device_type,omitempty"` // desktop, mobile, tablet, bot
	IsBot       bool   `json:"is_bot"`
	IsMobile    bool   `json:"is_mobile"`
	IsTablet    bool   `json:"is_tablet"`
}

// ThreatDetection contiene información de amenazas detectadas por IA
type ThreatDetection struct {
	Type        string  `json:"type"`                // Tipo de amenaza: BRUTE_FORCE, SQL_INJECTION, XSS, SCRAPING, etc.
	Severity    string  `json:"severity"`            // Severidad: LOW, MEDIUM, HIGH, CRITICAL
	Confidence  float64 `json:"confidence"`          // Confianza de la detección (0-1)
	Description string  `json:"description"`         // Descripción de la amenaza
	Evidence    []string `json:"evidence"`           // Evidencias que soportan la detección
	RuleID      string  `json:"rule_id"`             // ID de la regla que detectó la amenaza
	Pattern     string  `json:"pattern,omitempty"`   // Patrón detectado
	Recommendation string `json:"recommendation"`    // Recomendación de mitigación
}

// Storage define la interfaz para almacenamiento de eventos de auditoría
type Storage interface {
	Save(ctx context.Context, event *Event) error
	SaveBatch(ctx context.Context, events []*Event) error
	GetByID(ctx context.Context, id string) (*Event, error)
	Query(ctx context.Context, filter QueryFilter) ([]*Event, error)
	Count(ctx context.Context, filter QueryFilter) (int64, error)
	DeleteOlderThan(ctx context.Context, timestamp time.Time) (int64, error)
	Export(ctx context.Context, filter QueryFilter, format ExportFormat, writer io.Writer) error
	Close() error
}

// QueryFilter define filtros para consultas de auditoría
type QueryFilter struct {
	EventIDs       []string    `json:"event_ids,omitempty"`
	ActorIDs       []string    `json:"actor_ids,omitempty"`
	ActorTypes     []string    `json:"actor_types,omitempty"`
	ActionTypes    []string    `json:"action_types,omitempty"`
	ActionCategories []string  `json:"action_categories,omitempty"`
	ResourceTypes  []string    `json:"resource_types,omitempty"`
	ResourceIDs    []string    `json:"resource_ids,omitempty"`
	Statuses       []string    `json:"statuses,omitempty"`
	IPAddresses    []string    `json:"ip_addresses,omitempty"`
	SessionIDs     []string    `json:"session_ids,omitempty"`
	ThreatTypes    []string    `json:"threat_types,omitempty"`
	MinRiskScore   float64     `json:"min_risk_score,omitempty"`
	StartTime      time.Time   `json:"start_time,omitempty"`
	EndTime        time.Time   `json:"end_time,omitempty"`
	SearchQuery    string      `json:"search_query,omitempty"` // Búsqueda full-text
	Limit          int         `json:"limit"`
	Offset         int         `json:"offset"`
	SortBy         string      `json:"sort_by"` // timestamp, risk_score, etc.
	SortOrder      string      `json:"sort_order"` // asc, desc
}

// ExportFormat define formatos de exportación
type ExportFormat string

const (
	ExportFormatJSON  ExportFormat = "json"
	ExportFormatCSV   ExportFormat = "csv"
	ExportFormatNDJSON ExportFormat = "ndjson"
)

// RetentionPolicy define políticas de retención de logs
type RetentionPolicy struct {
	MaxAgeDays        int  `json:"max_age_days"`         // Edad máxima en días
	MaxEvents         int64 `json:"max_events"`          // Máximo número de eventos
	CompressAfterDays int  `json:"compress_after_days"`  // Comprimir después de X días
	ArchiveAfterDays  int  `json:"archive_after_days"`   // Archivar después de X días
	EnableAutoDelete  bool `json:"enable_auto_delete"`   // Habilitar eliminación automática
}

// Config contiene la configuración completa del sistema de auditoría
type Config struct {
	StorageType     string          `json:"storage_type"` // memory, sqlite, postgres
	StorageConfig   interface{}     `json:"storage_config"` // Configuración específica del storage
	EnableIA        bool            `json:"enable_ia"`    // Habilitar motor de IA
	IAMinRiskThreshold float64      `json:"ia_min_risk_threshold"` // Threshold mínimo para alertas
	EnableAsync     bool            `json:"enable_async"` // Procesamiento asíncrono
	AsyncBufferSize int             `json:"async_buffer_size"` // Buffer size para procesamiento asíncrono
	Retention       RetentionPolicy `json:"retention"`    // Política de retención
	EnableEncryption bool           `json:"enable_encryption"` // Cifrar datos en reposo
	EncryptionKey   string          `json:"encryption_key,omitempty"` // Clave de cifrado
	LogLevel        string          `json:"log_level"`    // Nivel de log para auditoría
	IncludePayload  bool            `json:"include_payload"` // Incluir payload completo
	MaxPayloadSize  int64           `json:"max_payload_size"` // Tamaño máximo de payload a guardar
	SanitizePII     bool            `json:"sanitize_pii"` // Sanitizar información personal
}

// Auditor es la estructura principal del sistema de auditoría
type Auditor struct {
	config       Config
	storage      Storage
	iaEngine     *IAEngine
	logger       logger.Logger
	asyncChan    chan *Event
	wg           sync.WaitGroup
	ctx          context.Context
	cancel       context.CancelFunc
	mu           sync.RWMutex
	closed       bool
	stats        Stats
}

// Stats contiene estadísticas del sistema de auditoría
type Stats struct {
	TotalEvents      int64     `json:"total_events"`
	EventsLastHour   int64     `json:"events_last_hour"`
	EventsLastDay    int64     `json:"events_last_day"`
	ThreatsDetected  int64     `json:"threats_detected"`
	AverageRiskScore float64   `json:"average_risk_score"`
	LastEventTime    time.Time `json:"last_event_time"`
	StorageSize      int64     `json:"storage_size_bytes"`
	Uptime           time.Duration `json:"uptime"`
}

// IAEngine es el motor de inteligencia artificial para detección de amenazas
type IAEngine struct {
	mu                sync.RWMutex
	rules             []DetectionRule
	anomalyDetector   *AnomalyDetector
	behaviorProfiles  map[string]*BehaviorProfile
	ipReputation      *IPReputationDB
	enabled           bool
	minRiskThreshold  float64
	stats             IAStats
}

// DetectionRule define una regla de detección de amenazas
type DetectionRule struct {
	ID          string  `json:"id"`
	Name        string  `json:"name"`
	Description string  `json:"description"`
	Severity    string  `json:"severity"`
	Pattern     *regexp.Regexp `json:"pattern,omitempty"`
	Condition   func(event *Event) bool `json:"-"` // Función personalizada de condición
	Action      func(event *Event) *ThreatDetection `json:"-"` // Acción a tomar cuando se detecta
	Enabled     bool    `json:"enabled"`
	Hits        int64   `json:"hits"`
	LastHit     time.Time `json:"last_hit,omitempty"`
}

// AnomalyDetector detecta comportamientos anómalos usando análisis estadístico
type AnomalyDetector struct {
	historicalData map[string][]float64 // Datos históricos por actor
	thresholds     map[string]float64   // Umbrales dinámicos
	mu             sync.RWMutex
	windowSize     int // Ventana de tiempo para análisis
}

// BehaviorProfile contiene el perfil de comportamiento de un actor
type BehaviorProfile struct {
	ActorID           string    `json:"actor_id"`
	AverageRequestsPerMinute float64 `json:"avg_requests_per_minute"`
	AverageSessionDuration time.Duration `json:"avg_session_duration"`
	CommonIPs         []string  `json:"common_ips"`
	CommonLocations   []string  `json:"common_locations"`
	TypicalActions    []string  `json:"typical_actions"`
	ActiveHours       []int     `json:"active_hours"` // Horas típicas de actividad (0-23)
	Devices           []string  `json:"devices"`
	LastUpdated       time.Time `json:"last_updated"`
	RiskBaseline      float64   `json:"risk_baseline"`
}

// IPReputationDB es una base de datos de reputación de IPs
type IPReputationDB struct {
	cache      map[string]*IPReputation
	cacheMu    sync.RWMutex
	lastUpdate time.Time
}

// IPReputation contiene información de reputación de una IP
type IPReputation struct {
	IPAddress    string    `json:"ip_address"`
	RiskScore    float64   `json:"risk_score"`
	IsTor        bool      `json:"is_tor"`
	IsProxy      bool      `json:"is_proxy"`
	IsVPN        bool      `json:"is_vpn"`
	IsHosting    bool      `json:"is_hosting"`
	IsMalicious  bool      `json:"is_malicious"`
	AbuseReports int       `json:"abuse_reports"`
	Blacklisted  bool      `json:"blacklisted"`
	Categories   []string  `json:"categories"`
	LastSeen     time.Time `json:"last_seen"`
	FirstSeen    time.Time `json:"first_seen"`
}

// IAStats contiene estadísticas del motor de IA
type IAStats struct {
	TotalEvaluations   int64     `json:"total_evaluations"`
	ThreatsDetected    int64     `json:"threats_detected"`
	FalsePositives     int64     `json:"false_positives"`
	TruePositives      int64     `json:"true_positives"`
	AverageConfidence  float64   `json:"average_confidence"`
	DetectionByType    map[string]int64 `json:"detection_by_type"`
	LastEvaluationTime time.Time `json:"last_evaluation_time"`
}

// Variables globales para uso rápido
var (
	defaultAuditor *Auditor
	once           sync.Once
)

// Init inicializa el sistema de auditoría con configuración global
func Init(config Config) error {
	var initErr error
	once.Do(func() {
		defaultAuditor, initErr = NewAuditor(config)
		if initErr != nil {
			return
		}
		
		// Iniciar goroutines de mantenimiento si es necesario
		if config.Retention.EnableAutoDelete {
			go defaultAuditor.retentionMaintenance()
		}
	})
	return initErr
}

// GetDefault retorna el auditor global
func GetDefault() *Auditor {
	if defaultAuditor == nil {
		// Crear auditor por defecto con configuración mínima
		cfg := Config{
			StorageType: "memory",
			EnableIA:    true,
			LogLevel:    "info",
		}
		defaultAuditor, _ = NewAuditor(cfg)
	}
	return defaultAuditor
}

// SetDefault establece el auditor global
func SetDefault(auditor *Auditor) {
	defaultAuditor = auditor
}

// NewAuditor crea una nueva instancia de Auditor
func NewAuditor(config Config) (*Auditor, error) {
	// Validar configuración
	if err := validateConfig(&config); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	
	auditor := &Auditor{
		config: config,
		logger: logger.GetDefault(),
		ctx:    ctx,
		cancel: cancel,
		stats: Stats{
			Uptime: time.Since(time.Now()),
		},
	}

	// Inicializar storage
	storage, err := createStorage(config.StorageType, config.StorageConfig)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to create storage: %w", err)
	}
	auditor.storage = storage

	// Inicializar motor de IA si está habilitado
	if config.EnableIA {
		auditor.iaEngine = NewIAEngine(config.IAMinRiskThreshold)
		auditor.iaEngine.LoadDefaultRules()
	}

	// Inicializar canal asíncrono si está habilitado
	if config.EnableAsync {
		bufferSize := config.AsyncBufferSize
		if bufferSize <= 0 {
			bufferSize = 1000
		}
		auditor.asyncChan = make(chan *Event, bufferSize)
		auditor.wg.Add(1)
		go auditor.asyncProcessor()
	}

	auditor.logger.Info("Audit system initialized",
		"storage_type", config.StorageType,
		"ia_enabled", config.EnableIA,
		"async_enabled", config.EnableAsync,
	)

	return auditor, nil
}

// validateConfig valida la configuración del auditor
func validateConfig(config *Config) error {
	if config.StorageType == "" {
		return fmt.Errorf("storage_type is required")
	}

	validStorageTypes := map[string]bool{
		"memory":   true,
		"sqlite":   true,
		"postgres": true,
	}
	if !validStorageTypes[config.StorageType] {
		return fmt.Errorf("invalid storage_type: %s", config.StorageType)
	}

	if config.IAMinRiskThreshold < 0 || config.IAMinRiskThreshold > 1 {
		return fmt.Errorf("ia_min_risk_threshold must be between 0 and 1")
	}

	if config.EnableAsync && config.AsyncBufferSize < 0 {
		return fmt.Errorf("async_buffer_size must be positive")
	}

	return nil
}

// createStorage crea una instancia de storage según el tipo
func createStorage(storageType string, config interface{}) (Storage, error) {
	switch storageType {
	case "memory":
		return NewMemoryStorage(), nil
	case "sqlite":
		sqliteCfg, ok := config.(SQLiteConfig)
		if !ok {
			return nil, fmt.Errorf("invalid sqlite config")
		}
		return NewSQLiteStorage(sqliteCfg)
	case "postgres":
		pgCfg, ok := config.(PostgresConfig)
		if !ok {
			return nil, fmt.Errorf("invalid postgres config")
		}
		return NewPostgresStorage(pgCfg)
	default:
		return nil, fmt.Errorf("unsupported storage type: %s", storageType)
	}
}

// Record registra un evento de auditoría (síncrono)
func (a *Auditor) Record(event *Event) error {
	if a.closed {
		return fmt.Errorf("auditor is closed")
	}

	// Completar campos faltantes
	a.enrichEvent(event)

	// Ejecutar motor de IA si está habilitado
	if a.config.EnableIA && a.iaEngine != nil {
		threats, riskScore := a.iaEngine.Analyze(event)
		event.Threats = threats
		event.RiskScore = riskScore
		
		// Actualizar estadísticas
		a.mu.Lock()
		a.stats.ThreatsDetected += int64(len(threats))
		a.mu.Unlock()
	}

	// Calcular huella digital
	event.DigitalFingerprint = a.calculateFingerprint(event)

	// Guardar en storage
	if err := a.storage.Save(a.ctx, event); err != nil {
		return fmt.Errorf("failed to save event: %w", err)
	}

	// Actualizar estadísticas
	a.mu.Lock()
	a.stats.TotalEvents++
	a.stats.LastEventTime = event.Timestamp
	a.mu.Unlock()

	// Loggear si hay amenazas de alta severidad
	if len(event.Threats) > 0 {
		for _, threat := range event.Threats {
			if threat.Severity == "HIGH" || threat.Severity == "CRITICAL" {
				a.logger.Warn("Security threat detected",
					"threat_type", threat.Type,
					"severity", threat.Severity,
					"actor_id", event.Actor.ID,
					"ip_address", event.Context.IPAddress,
					"confidence", threat.Confidence,
				)
			}
		}
	}

	return nil
}

// RecordAsync registra un evento de auditoría de forma asíncrona
func (a *Auditor) RecordAsync(event *Event) error {
	if a.closed {
		return fmt.Errorf("auditor is closed")
	}

	if a.asyncChan == nil {
		return fmt.Errorf("async processing not enabled")
	}

	select {
	case a.asyncChan <- event:
		return nil
	default:
		return fmt.Errorf("async buffer full")
	}
}

// asyncProcessor procesa eventos de auditoría de forma asíncrona
func (a *Auditor) asyncProcessor() {
	defer a.wg.Done()

	for {
		select {
		case event := <-a.asyncChan:
			if err := a.Record(event); err != nil {
				a.logger.Error("Failed to process async audit event",
					"error", err,
					"event_id", event.ID,
				)
			}
		case <-a.ctx.Done():
			// Drenar canal antes de cerrar
			for len(a.asyncChan) > 0 {
				event := <-a.asyncChan
				if err := a.Record(event); err != nil {
					a.logger.Error("Failed to drain async audit event",
						"error", err,
						"event_id", event.ID,
					)
				}
			}
			return
		}
	}
}

// enrichEvent completa campos faltantes del evento
func (a *Auditor) enrichEvent(event *Event) {
	if event.ID == "" {
		event.ID = generateUUID()
	}

	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}

	if event.Metadata == nil {
		event.Metadata = make(map[string]interface{})
	}

	// Sanitizar PII si está habilitado
	if a.config.SanitizePII {
		a.sanitizePII(event)
	}

	// Limitar tamaño del payload si excede el máximo
	if a.config.MaxPayloadSize > 0 && event.Context.PayloadSize > a.config.MaxPayloadSize {
		event.Metadata["payload_truncated"] = true
		event.Metadata["original_payload_size"] = event.Context.PayloadSize
		event.Context.PayloadSize = a.config.MaxPayloadSize
	}
}

// sanitizePII sanitiza información personal identificable
func (a *Auditor) sanitizePII(event *Event) {
	// Enmascarar email
	if event.Actor.Email != "" {
		parts := strings.Split(event.Actor.Email, "@")
		if len(parts) == 2 {
			username := parts[0]
			if len(username) > 2 {
				username = username[:2] + strings.Repeat("*", len(username)-2)
			}
			event.Actor.Email = username + "@" + parts[1]
		}
	}

	// Enmascarar IP (último octeto)
	if event.Context.IPAddress != "" {
		parts := strings.Split(event.Context.IPAddress, ".")
		if len(parts) == 4 {
			parts[3] = "***"
			event.Context.IPAddress = strings.Join(parts, ".")
		}
	}
}

// calculateFingerprint calcula una huella digital única e inmutable para el evento
func (a *Auditor) calculateFingerprint(event *Event) string {
	data := fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s",
		event.ID,
		event.Timestamp.Format(time.RFC3339Nano),
		event.Actor.ID,
		event.Action.Type,
		event.Resource.ID,
		event.Result.Status,
		event.Context.IPAddress,
	)

	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// Query consulta eventos de auditoría con filtros
func (a *Auditor) Query(ctx context.Context, filter QueryFilter) ([]*Event, error) {
	if a.closed {
		return nil, fmt.Errorf("auditor is closed")
	}

	// Aplicar valores por defecto
	if filter.Limit <= 0 {
		filter.Limit = 100
	}
	if filter.Limit > 1000 {
		filter.Limit = 1000
	}
	if filter.SortBy == "" {
		filter.SortBy = "timestamp"
	}
	if filter.SortOrder == "" {
		filter.SortOrder = "desc"
	}

	return a.storage.Query(ctx, filter)
}

// GetByID obtiene un evento por su ID
func (a *Auditor) GetByID(ctx context.Context, id string) (*Event, error) {
	if a.closed {
		return nil, fmt.Errorf("auditor is closed")
	}
	return a.storage.GetByID(ctx, id)
}

// Count cuenta eventos que coinciden con los filtros
func (a *Auditor) Count(ctx context.Context, filter QueryFilter) (int64, error) {
	if a.closed {
		return 0, fmt.Errorf("auditor is closed")
	}
	return a.storage.Count(ctx, filter)
}

// Export exporta eventos a un formato específico
func (a *Auditor) Export(ctx context.Context, filter QueryFilter, format ExportFormat, writer io.Writer) error {
	if a.closed {
		return fmt.Errorf("auditor is closed")
	}
	return a.storage.Export(ctx, filter, format, writer)
}

// GetStats retorna estadísticas del sistema de auditoría
func (a *Auditor) GetStats() Stats {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.stats
}

// Close cierra el sistema de auditoría
func (a *Auditor) Close() error {
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return nil
	}
	a.closed = true
	a.mu.Unlock()

	// Cancelar contexto
	a.cancel()

	// Esperar a que termine el procesador asíncrono
	if a.asyncChan != nil {
		a.wg.Wait()
	}

	// Cerrar storage
	if a.storage != nil {
		return a.storage.Close()
	}

	return nil
}

// retentionMaintenance ejecuta mantenimiento de políticas de retención
func (a *Auditor) retentionMaintenance() {
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if a.config.Retention.MaxAgeDays > 0 {
				cutoff := time.Now().AddDate(0, 0, -a.config.Retention.MaxAgeDays)
				deleted, err := a.storage.DeleteOlderThan(a.ctx, cutoff)
				if err != nil {
					a.logger.Error("Failed to delete old audit events",
						"error", err,
						"cutoff", cutoff,
					)
				} else if deleted > 0 {
					a.logger.Info("Deleted old audit events",
						"count", deleted,
						"cutoff", cutoff,
					)
				}
			}
		case <-a.ctx.Done():
			return
		}
	}
}

// Helper functions for quick usage

// RecordQuick registra un evento de auditoría rápidamente usando el auditor global
func RecordQuick(event *Event) error {
	return GetDefault().Record(event)
}

// QueryQuick consulta eventos usando el auditor global
func QueryQuick(ctx context.Context, filter QueryFilter) ([]*Event, error) {
	return GetDefault().Query(ctx, filter)
}

// ExportQuick exporta eventos usando el auditor global
func ExportQuick(ctx context.Context, filter QueryFilter, format ExportFormat, writer io.Writer) error {
	return GetDefault().Export(ctx, filter, format, writer)
}

// GenerateUUID genera un UUID v4
func generateUUID() string {
	// Implementación simple de UUID v4
	uuid := make([]byte, 16)
	_, _ = io.ReadFull(strings.NewReader(fmt.Sprintf("%d", time.Now().UnixNano())), uuid)
	uuid[6] = (uuid[6] & 0x0f) | 0x40
	uuid[8] = (uuid[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		uuid[0:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:])
}
