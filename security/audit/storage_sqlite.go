package audit

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// SQLiteConfig configura la conexión a SQLite
type SQLiteConfig struct {
	DSN          string `json:"dsn"`           // Path al archivo SQLite
	MaxOpenConns int    `json:"max_open_conns"` // Máximas conexiones abiertas
	MaxIdleConns int    `json:"max_idle_conns"` // Máximas conexiones idle
	MaxLifetime  int    `json:"max_lifetime"`   // Máximo tiempo de vida de conexión (segundos)
}

// SQLiteStorage implementa Storage usando SQLite
type SQLiteStorage struct {
	db     *sql.DB
	config SQLiteConfig
}

// NewSQLiteStorage crea un nuevo storage SQLite
func NewSQLiteStorage(config SQLiteConfig) (*SQLiteStorage, error) {
	db, err := sql.Open("sqlite3", config.DSN)
	if err != nil {
		return nil, fmt.Errorf("failed to open sqlite database: %w", err)
	}

	// Configurar pool de conexiones
	if config.MaxOpenConns > 0 {
		db.SetMaxOpenConns(config.MaxOpenConns)
	}
	if config.MaxIdleConns > 0 {
		db.SetMaxIdleConns(config.MaxIdleConns)
	}
	if config.MaxLifetime > 0 {
		db.SetConnMaxLifetime(time.Duration(config.MaxLifetime) * time.Second)
	}

	// Crear tablas
	if err := createTables(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to create tables: %w", err)
	}

	return &SQLiteStorage{
		db:     db,
		config: config,
	}, nil
}

// createTables crea las tablas necesarias en la base de datos
func createTables(db *sql.DB) error {
	schema := `
	CREATE TABLE IF NOT EXISTS audit_events (
		id TEXT PRIMARY KEY,
		timestamp DATETIME NOT NULL,
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
		risk_score REAL DEFAULT 0,
		threats TEXT,
		metadata TEXT,
		digital_fingerprint TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
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

// Save guarda un evento individual
func (s *SQLiteStorage) Save(ctx context.Context, event *Event) error {
	query := `
	INSERT OR REPLACE INTO audit_events (
		id, timestamp, actor_id, actor_email, actor_username, actor_role,
		actor_session_id, actor_type, action_type, action_category, action_description,
		action_method, action_path, resource_type, resource_id, resource_name,
		result_status, result_status_code, result_message, result_error, result_duration_ms,
		context_ip_address, context_user_agent, context_request_id, risk_score,
		threats, metadata, digital_fingerprint
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	threatsJSON, _ := json.Marshal(event.Threats)
	metadataJSON, _ := json.Marshal(event.Metadata)

	_, err := s.db.ExecContext(ctx, query,
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
	)

	return err
}

// SaveBatch guarda múltiples eventos
func (s *SQLiteStorage) SaveBatch(ctx context.Context, events []*Event) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	for _, event := range events {
		if err := s.Save(ctx, event); err != nil {
			return err
		}
	}

	return tx.Commit()
}

// GetByID obtiene un evento por su ID
func (s *SQLiteStorage) GetByID(ctx context.Context, id string) (*Event, error) {
	query := `SELECT * FROM audit_events WHERE id = ?`
	
	row := s.db.QueryRowContext(ctx, query, id)
	return scanEvent(row)
}

// Query consulta eventos con filtros
func (s *SQLiteStorage) Query(ctx context.Context, filter QueryFilter) ([]*Event, error) {
	query, args := buildQuery(filter)
	
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
func (s *SQLiteStorage) Count(ctx context.Context, filter QueryFilter) (int64, error) {
	query, args := buildCountQuery(filter)
	
	var count int64
	err := s.db.QueryRowContext(ctx, query, args...).Scan(&count)
	return count, err
}

// DeleteOlderThan elimina eventos anteriores a una fecha
func (s *SQLiteStorage) DeleteOlderThan(ctx context.Context, timestamp time.Time) (int64, error) {
	query := `DELETE FROM audit_events WHERE timestamp < ?`
	
	result, err := s.db.ExecContext(ctx, query, timestamp)
	if err != nil {
		return 0, err
	}

	return result.RowsAffected()
}

// Export exporta eventos a un formato específico
func (s *SQLiteStorage) Export(ctx context.Context, filter QueryFilter, format ExportFormat, writer io.Writer) error {
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
func (s *SQLiteStorage) Close() error {
	return s.db.Close()
}

// Helper functions

func scanEvent(row scanner) (*Event, error) {
	event := &Event{}
	
	var threatsJSON, metadataJSON []byte
	
	err := row.Scan(
		&event.ID,
		&event.Timestamp,
		&event.Actor.ID,
		&event.Actor.Email,
		&event.Actor.Username,
		&event.Actor.Role,
		&event.Actor.SessionID,
		&event.Actor.Type,
		&event.Action.Type,
		&event.Action.Category,
		&event.Action.Description,
		&event.Action.Method,
		&event.Action.Path,
		&event.Resource.Type,
		&event.Resource.ID,
		&event.Resource.Name,
		&event.Result.Status,
		&event.Result.StatusCode,
		&event.Result.Message,
		&event.Result.Error,
		&event.Result.Duration,
		&event.Context.IPAddress,
		&event.Context.UserAgent,
		&event.Context.RequestID,
		&event.RiskScore,
		&threatsJSON,
		&metadataJSON,
		&event.DigitalFingerprint,
	)
	
	if err != nil {
		return nil, err
	}

	if len(threatsJSON) > 0 {
		json.Unmarshal(threatsJSON, &event.Threats)
	}
	if len(metadataJSON) > 0 {
		json.Unmarshal(metadataJSON, &event.Metadata)
	}

	return event, nil
}

func scanEventRow(rows *sql.Rows) (*Event, error) {
	event := &Event{}
	
	var threatsJSON, metadataJSON []byte
	
	err := rows.Scan(
		&event.ID,
		&event.Timestamp,
		&event.Actor.ID,
		&event.Actor.Email,
		&event.Actor.Username,
		&event.Actor.Role,
		&event.Actor.SessionID,
		&event.Actor.Type,
		&event.Action.Type,
		&event.Action.Category,
		&event.Action.Description,
		&event.Action.Method,
		&event.Action.Path,
		&event.Resource.Type,
		&event.Resource.ID,
		&event.Resource.Name,
		&event.Result.Status,
		&event.Result.StatusCode,
		&event.Result.Message,
		&event.Result.Error,
		&event.Result.Duration,
		&event.Context.IPAddress,
		&event.Context.UserAgent,
		&event.Context.RequestID,
		&event.RiskScore,
		&threatsJSON,
		&metadataJSON,
		&event.DigitalFingerprint,
	)
	
	if err != nil {
		return nil, err
	}

	if len(threatsJSON) > 0 {
		json.Unmarshal(threatsJSON, &event.Threats)
	}
	if len(metadataJSON) > 0 {
		json.Unmarshal(metadataJSON, &event.Metadata)
	}

	return event, nil
}

func buildQuery(filter QueryFilter) (string, []interface{}) {
	query := `SELECT * FROM audit_events WHERE 1=1`
	var args []interface{}

	if len(filter.EventIDs) > 0 {
		query += ` AND id IN (?` + repeatPlaceholder(len(filter.EventIDs)-1) + `)`
		for _, id := range filter.EventIDs {
			args = append(args, id)
		}
	}

	if len(filter.ActorIDs) > 0 {
		query += ` AND actor_id IN (?` + repeatPlaceholder(len(filter.ActorIDs)-1) + `)`
		for _, id := range filter.ActorIDs {
			args = append(args, id)
		}
	}

	if len(filter.ActionTypes) > 0 {
		query += ` AND action_type IN (?` + repeatPlaceholder(len(filter.ActionTypes)-1) + `)`
		for _, actionType := range filter.ActionTypes {
			args = append(args, actionType)
		}
	}

	if !filter.StartTime.IsZero() {
		query += ` AND timestamp >= ?`
		args = append(args, filter.StartTime)
	}

	if !filter.EndTime.IsZero() {
		query += ` AND timestamp <= ?`
		args = append(args, filter.EndTime)
	}

	if filter.MinRiskScore > 0 {
		query += ` AND risk_score >= ?`
		args = append(args, filter.MinRiskScore)
	}

	query += ` ORDER BY ` + filter.SortBy + ` ` + filter.SortOrder
	query += ` LIMIT ? OFFSET ?`
	args = append(args, filter.Limit, filter.Offset)

	return query, args
}

func buildCountQuery(filter QueryFilter) (string, []interface{}) {
	query := `SELECT COUNT(*) FROM audit_events WHERE 1=1`
	var args []interface{}

	// Mismos filtros que buildQuery pero sin ORDER BY ni LIMIT
	if len(filter.EventIDs) > 0 {
		query += ` AND id IN (?` + repeatPlaceholder(len(filter.EventIDs)-1) + `)`
		for _, id := range filter.EventIDs {
			args = append(args, id)
		}
	}

	if len(filter.ActorIDs) > 0 {
		query += ` AND actor_id IN (?` + repeatPlaceholder(len(filter.ActorIDs)-1) + `)`
		for _, id := range filter.ActorIDs {
			args = append(args, id)
		}
	}

	if !filter.StartTime.IsZero() {
		query += ` AND timestamp >= ?`
		args = append(args, filter.StartTime)
	}

	if !filter.EndTime.IsZero() {
		query += ` AND timestamp <= ?`
		args = append(args, filter.EndTime)
	}

	return query, args
}

func repeatPlaceholder(n int) string {
	result := ""
	for i := 0; i < n; i++ {
		result += ",?"
	}
	return result
}

type scanner interface {
	Scan(dest ...interface{}) error
}

// Helper export functions
func exportJSON(events []*Event, writer io.Writer) error {
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(events)
}

func exportCSV(events []*Event, writer io.Writer) error {
	header := "id,timestamp,actor_id,action_type,status,ip_address,risk_score\n"
	if _, err := io.WriteString(writer, header); err != nil {
		return err
	}

	for _, event := range events {
		row := fmt.Sprintf("%s,%s,%s,%s,%s,%s,%.2f\n",
			event.ID,
			event.Timestamp.Format(time.RFC3339),
			event.Actor.ID,
			event.Action.Type,
			event.Result.Status,
			event.Context.IPAddress,
			event.RiskScore,
		)
		if _, err := io.WriteString(writer, row); err != nil {
			return err
		}
	}

	return nil
}

func exportNDJSON(events []*Event, writer io.Writer) error {
	encoder := json.NewEncoder(writer)
	for _, event := range events {
		if err := encoder.Encode(event); err != nil {
			return err
		}
	}
	return nil
}
