package audit

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"time"

	_ "github.com/lib/pq"
)

// PostgresConfig configura la conexión a PostgreSQL
type PostgresConfig struct {
	DSN          string `json:"dsn"`           // Cadena de conexión completa (opcional)
	Host         string `json:"host"`
	Port         int    `json:"port"`
	Database     string `json:"database"`
	User         string `json:"user"`
	Password     string `json:"password"`
	SSLMode      string `json:"ssl_mode"`
	MaxOpenConns int    `json:"max_open_conns"`
	MaxIdleConns int    `json:"max_idle_conns"`
	MaxLifetime  int    `json:"max_lifetime"`
}

// dsn construye la cadena de conexión si no se provee una completa
func (c PostgresConfig) dsn() string {
	if c.DSN != "" {
		return c.DSN
	}
	host := c.Host
	if host == "" {
		host = "localhost"
	}
	port := c.Port
	if port == 0 {
		port = 5432
	}
	database := c.Database
	if database == "" {
		database = "gokit"
	}
	user := c.User
	if user == "" {
		user = "postgres"
	}
	ssl := c.SSLMode
	if ssl == "" {
		ssl = "disable"
	}
	dsn := fmt.Sprintf("host=%s port=%d dbname=%s user=%s sslmode=%s", host, port, database, user, ssl)
	if c.Password != "" {
		dsn += " password=" + c.Password
	}
	return dsn
}

// PostgresStorage implementa Storage usando PostgreSQL
type PostgresStorage struct {
	db     *sql.DB
	config PostgresConfig
}

var pgDriverName = "postgres"

// NewPostgresStorage crea un nuevo storage PostgreSQL
func NewPostgresStorage(config PostgresConfig) (*PostgresStorage, error) {
	db, err := sql.Open(pgDriverName, config.dsn())
	if err != nil {
		return nil, fmt.Errorf("failed to open postgres database: %w", err)
	}

	if config.MaxOpenConns > 0 {
		db.SetMaxOpenConns(config.MaxOpenConns)
	}
	if config.MaxIdleConns > 0 {
		db.SetMaxIdleConns(config.MaxIdleConns)
	}
	if config.MaxLifetime > 0 {
		db.SetConnMaxLifetime(time.Duration(config.MaxLifetime) * time.Second)
	}

	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to ping postgres database: %w", err)
	}
	if err := createPostgresTables(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to create tables: %w", err)
	}

	return &PostgresStorage{
		db:     db,
		config: config,
	}, nil
}

func createPostgresTables(db *sql.DB) error {
	schema := `
	CREATE TABLE IF NOT EXISTS audit_events (
		id TEXT PRIMARY KEY,
		timestamp TIMESTAMPTZ NOT NULL,
		actor_id TEXT,
		actor_email TEXT,
		actor_username TEXT,
		actor_role TEXT,
		actor_session_id TEXT,
		actor_type TEXT NOT NULL,
		action_type TEXT NOT NULL,
		action_category TEXT NOT NULL,
		action_description TEXT,
		action_method TEXT,
		action_path TEXT,
		resource_type TEXT,
		resource_id TEXT,
		resource_name TEXT,
		result_status TEXT NOT NULL,
		result_status_code INTEGER,
		result_message TEXT,
		result_error TEXT,
		result_duration_ms INTEGER,
		context_ip_address TEXT,
		context_user_agent TEXT,
		context_request_id TEXT,
		risk_score DOUBLE PRECISION DEFAULT 0,
		threats TEXT,
		metadata TEXT,
		digital_fingerprint TEXT NOT NULL,
		created_at TIMESTAMPTZ DEFAULT NOW()
	);

	CREATE INDEX IF NOT EXISTS idx_actor_id ON audit_events(actor_id);
	CREATE INDEX IF NOT EXISTS idx_timestamp ON audit_events(timestamp);
	CREATE INDEX IF NOT EXISTS idx_action_type ON audit_events(action_type);
	CREATE INDEX IF NOT EXISTS idx_ip_address ON audit_events(context_ip_address);
	CREATE INDEX IF NOT EXISTS idx_risk_score ON audit_events(risk_score);
	`

	_, err := db.Exec(schema)
	return err
}

// columnas de la tabla audit_events en orden (sin created_at)
var eventColumns = []string{
	"id", "timestamp", "actor_id", "actor_email", "actor_username", "actor_role",
	"actor_session_id", "actor_type", "action_type", "action_category", "action_description",
	"action_method", "action_path", "resource_type", "resource_id", "resource_name",
	"result_status", "result_status_code", "result_message", "result_error", "result_duration_ms",
	"context_ip_address", "context_user_agent", "context_request_id", "risk_score",
	"threats", "metadata", "digital_fingerprint",
}

func pgInsertQuery() string {
	cols := ""
	vals := ""
	for i, col := range eventColumns {
		if i > 0 {
			cols += ", "
			vals += ", "
		}
		cols += col
		vals += fmt.Sprintf("$%d", i+1)
	}
	return fmt.Sprintf("INSERT INTO audit_events (%s) VALUES (%s)", cols, vals)
}

func pgUpsertQuery() string {
	insert := pgInsertQuery()
	set := ""
	for _, col := range eventColumns {
		if col == "id" {
			continue
		}
		if set != "" {
			set += ", "
		}
		set += fmt.Sprintf("%s = EXCLUDED.%s", col, col)
	}
	return insert + " ON CONFLICT (id) DO UPDATE SET " + set
}

func pgEventArgs(event *Event) []interface{} {
	threatsJSON, _ := json.Marshal(event.Threats)
	metadataJSON, _ := json.Marshal(event.Metadata)

	return []interface{}{
		event.ID,
		event.Timestamp,
		event.Actor.ID,
		event.Actor.Email,
		event.Actor.Username,
		event.Actor.Role,
		event.Actor.SessionID,
		event.Actor.Type,
		event.Action.Type,
		event.Action.Category,
		event.Action.Description,
		event.Action.Method,
		event.Action.Path,
		event.Resource.Type,
		event.Resource.ID,
		event.Resource.Name,
		event.Result.Status,
		event.Result.StatusCode,
		event.Result.Message,
		event.Result.Error,
		event.Result.Duration,
		event.Context.IPAddress,
		event.Context.UserAgent,
		event.Context.RequestID,
		event.RiskScore,
		string(threatsJSON),
		string(metadataJSON),
		event.DigitalFingerprint,
	}
}

// Save guarda un evento individual
func (s *PostgresStorage) Save(ctx context.Context, event *Event) error {
	_, err := s.db.ExecContext(ctx, pgUpsertQuery(), pgEventArgs(event)...)
	return err
}

// SaveBatch guarda múltiples eventos de forma atómica
func (s *PostgresStorage) SaveBatch(ctx context.Context, events []*Event) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, pgUpsertQuery())
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, event := range events {
		if _, err := stmt.ExecContext(ctx, pgEventArgs(event)...); err != nil {
			return err
		}
	}

	return tx.Commit()
}

// GetByID obtiene un evento por su ID
func (s *PostgresStorage) GetByID(ctx context.Context, id string) (*Event, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+auditColumns+` FROM audit_events WHERE id = $1`, id)
	return scanEvent(row)
}

// Query consulta eventos con filtros
func (s *PostgresStorage) Query(ctx context.Context, filter QueryFilter) ([]*Event, error) {
	query, args := buildPGQuery(filter)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []*Event
	for rows.Next() {
		event, err := scanEventRow(rows)
		if err != nil {
			return nil, err
		}
		events = append(events, event)
	}

	return events, rows.Err()
}

// Count cuenta eventos que coinciden con los filtros
func (s *PostgresStorage) Count(ctx context.Context, filter QueryFilter) (int64, error) {
	query, args := buildPGCountQuery(filter)

	var count int64
	err := s.db.QueryRowContext(ctx, query, args...).Scan(&count)
	return count, err
}

// DeleteOlderThan elimina eventos anteriores a una fecha
func (s *PostgresStorage) DeleteOlderThan(ctx context.Context, timestamp time.Time) (int64, error) {
	result, err := s.db.ExecContext(ctx, `DELETE FROM audit_events WHERE timestamp < $1`, timestamp)
	if err != nil {
		return 0, err
	}

	return result.RowsAffected()
}

// Export exporta eventos a un formato específico
func (s *PostgresStorage) Export(ctx context.Context, filter QueryFilter, format ExportFormat, writer io.Writer) error {
	events, err := s.Query(ctx, filter)
	if err != nil {
		return err
	}

	switch format {
	case ExportFormatJSON:
		return exportJSON(events, writer)
	case ExportFormatCSV:
		return exportCSV(events, writer)
	case ExportFormatNDJSON:
		return exportNDJSON(events, writer)
	default:
		return fmt.Errorf("unsupported export format: %s", format)
	}
}

// Close cierra la conexión a la base de datos
func (s *PostgresStorage) Close() error {
	return s.db.Close()
}

// pgBuilder acumula una query SQL con placeholders estilo $N
type pgBuilder struct {
	query string
	args  []interface{}
	n     int
}

func newPGBuilder(base string) *pgBuilder {
	return &pgBuilder{query: base}
}

// addPlaceholder agrega un placeholder $N y retorna su texto
func (b *pgBuilder) placeholder() string {
	b.n++
	return fmt.Sprintf("$%d", b.n)
}

// add agrega un valor y retorna su placeholder
func (b *pgBuilder) add(v interface{}) string {
	p := b.placeholder()
	b.args = append(b.args, v)
	return p
}

// addList agrega una lista de valores IN (..) y retorna la cláusula
func (b *pgBuilder) addList(values []interface{}) string {
	clause := "("
	for i, v := range values {
		if i > 0 {
			clause += ", "
		}
		clause += b.add(v)
	}
	clause += ")"
	return clause
}

func buildPGQuery(filter QueryFilter) (string, []interface{}) {
	b := newPGBuilder(`SELECT ` + auditColumns + ` FROM audit_events WHERE 1=1`)

	if len(filter.EventIDs) > 0 {
		b.query += ` AND id IN ` + b.addList(toInterfaceSlice(filter.EventIDs))
	}
	if len(filter.ActorIDs) > 0 {
		b.query += ` AND actor_id IN ` + b.addList(toInterfaceSlice(filter.ActorIDs))
	}
	if len(filter.ActorTypes) > 0 {
		b.query += ` AND actor_type IN ` + b.addList(toInterfaceSlice(filter.ActorTypes))
	}
	if len(filter.ActionTypes) > 0 {
		b.query += ` AND action_type IN ` + b.addList(toInterfaceSlice(filter.ActionTypes))
	}
	if len(filter.ActionCategories) > 0 {
		b.query += ` AND action_category IN ` + b.addList(toInterfaceSlice(filter.ActionCategories))
	}
	if len(filter.ResourceTypes) > 0 {
		b.query += ` AND resource_type IN ` + b.addList(toInterfaceSlice(filter.ResourceTypes))
	}
	if len(filter.ResourceIDs) > 0 {
		b.query += ` AND resource_id IN ` + b.addList(toInterfaceSlice(filter.ResourceIDs))
	}
	if len(filter.Statuses) > 0 {
		b.query += ` AND result_status IN ` + b.addList(toInterfaceSlice(filter.Statuses))
	}
	if len(filter.IPAddresses) > 0 {
		b.query += ` AND context_ip_address IN ` + b.addList(toInterfaceSlice(filter.IPAddresses))
	}
	if len(filter.SessionIDs) > 0 {
		b.query += ` AND actor_session_id IN ` + b.addList(toInterfaceSlice(filter.SessionIDs))
	}

	if !filter.StartTime.IsZero() {
		b.query += ` AND timestamp >= ` + b.add(filter.StartTime)
	}
	if !filter.EndTime.IsZero() {
		b.query += ` AND timestamp <= ` + b.add(filter.EndTime)
	}
	if filter.MinRiskScore > 0 {
		b.query += ` AND risk_score >= ` + b.add(filter.MinRiskScore)
	}
	if filter.SearchQuery != "" {
		like := "%" + filter.SearchQuery + "%"
		b.query += ` AND (actor_id LIKE ` + b.add(like) +
			` OR actor_email LIKE ` + b.add(like) +
			` OR actor_username LIKE ` + b.add(like) +
			` OR action_type LIKE ` + b.add(like) +
			` OR action_category LIKE ` + b.add(like) +
			` OR resource_type LIKE ` + b.add(like) +
			` OR resource_id LIKE ` + b.add(like) +
			` OR result_message LIKE ` + b.add(like) +
			` OR context_ip_address LIKE ` + b.add(like) + `)`
	}

	sortBy := filter.SortBy
	if !sortColumns[sortBy] {
		sortBy = "timestamp"
	}
	sortOrder := filter.SortOrder
	if sortOrder != "asc" && sortOrder != "desc" {
		sortOrder = "desc"
	}
	b.query += ` ORDER BY ` + sortBy + ` ` + sortOrder
	b.query += ` LIMIT ` + b.add(filter.Limit) + ` OFFSET ` + b.add(filter.Offset)

	return b.query, b.args
}

func buildPGCountQuery(filter QueryFilter) (string, []interface{}) {
	b := newPGBuilder(`SELECT COUNT(*) FROM audit_events WHERE 1=1`)

	if len(filter.EventIDs) > 0 {
		b.query += ` AND id IN ` + b.addList(toInterfaceSlice(filter.EventIDs))
	}
	if len(filter.ActorIDs) > 0 {
		b.query += ` AND actor_id IN ` + b.addList(toInterfaceSlice(filter.ActorIDs))
	}
	if len(filter.ActionTypes) > 0 {
		b.query += ` AND action_type IN ` + b.addList(toInterfaceSlice(filter.ActionTypes))
	}
	if !filter.StartTime.IsZero() {
		b.query += ` AND timestamp >= ` + b.add(filter.StartTime)
	}
	if !filter.EndTime.IsZero() {
		b.query += ` AND timestamp <= ` + b.add(filter.EndTime)
	}
	if filter.MinRiskScore > 0 {
		b.query += ` AND risk_score >= ` + b.add(filter.MinRiskScore)
	}

	return b.query, b.args
}

// toInterfaceSlice convierte una slice de strings a []interface{}
func toInterfaceSlice(values []string) []interface{} {
	result := make([]interface{}, len(values))
	for i, v := range values {
		result[i] = v
	}
	return result
}
