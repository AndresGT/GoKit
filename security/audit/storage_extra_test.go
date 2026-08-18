package audit

import (
	"context"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

// ---------------------------------------------------------------------------
// MemoryStorage
// ---------------------------------------------------------------------------

func TestMemoryStorageBranches(t *testing.T) {
	ctx := context.Background()

	base := func(id string) *Event {
		return &Event{
			ID:        id,
			Timestamp: time.Now().UTC(),
			Actor:     ActorInfo{ID: "u-" + id, Type: "user"},
			Action:    ActionInfo{Type: "LOGIN", Category: "AUTH", Description: "login " + id},
			Resource:  ResourceInfo{Type: "user", ID: "r-" + id},
			Result:    ResultInfo{Status: "SUCCESS", Message: "ok " + id},
			Context:   ContextInfo{IPAddress: "10.0.0." + id},
			Threats:   []ThreatDetection{{Type: "XSS", Description: "xss"}},
		}
	}

	t.Run("SaveBatch", func(t *testing.T) {
		ms := NewMemoryStorage()
		if err := ms.SaveBatch(ctx, []*Event{base("1"), base("2")}); err != nil {
			t.Fatalf("savebatch failed: %v", err)
		}
		n, _ := ms.Count(ctx, QueryFilter{})
		if n != 2 {
			t.Errorf("expected 2 events, got %d", n)
		}
	})

	t.Run("GetByID no encontrado", func(t *testing.T) {
		ms := NewMemoryStorage()
		if _, err := ms.GetByID(ctx, "nope"); err == nil {
			t.Error("expected not found error")
		}
	})

	t.Run("Query con offset y límite", func(t *testing.T) {
		ms := NewMemoryStorage()
		for i := 0; i < 5; i++ {
			if err := ms.Save(ctx, base(string(rune('1'+i)))); err != nil {
				t.Fatalf("save failed: %v", err)
			}
		}
		// Offset más grande que el total
		evs, err := ms.Query(ctx, QueryFilter{Offset: 100, Limit: 10})
		if err != nil {
			t.Fatalf("query failed: %v", err)
		}
		if len(evs) != 0 {
			t.Errorf("expected empty results, got %d", len(evs))
		}
		// Límite mayor al total
		evs, err = ms.Query(ctx, QueryFilter{Offset: 1, Limit: 100})
		if err != nil {
			t.Fatalf("query failed: %v", err)
		}
		if len(evs) != 4 {
			t.Errorf("expected 4 results, got %d", len(evs))
		}
	})

	t.Run("Export formato no soportado", func(t *testing.T) {
		ms := NewMemoryStorage()
		if err := ms.Export(ctx, QueryFilter{}, ExportFormat("xml"), &sink{}); err == nil {
			t.Error("expected unsupported format error")
		}
	})

	t.Run("Export CSV writer error", func(t *testing.T) {
		ms := NewMemoryStorage()
		_ = ms.Save(ctx, base("1"))
		if err := ms.Export(ctx, QueryFilter{}, ExportFormatCSV, &failWriter{}); err == nil {
			t.Error("expected writer error")
		}
	})

	t.Run("Export CSV row error", func(t *testing.T) {
		ms := NewMemoryStorage()
		_ = ms.Save(ctx, base("1"))
		header := "id,timestamp,actor_id,actor_type,action_type,action_category,resource_type,resource_id,status,ip_address,risk_score\n"
		if err := ms.Export(ctx, QueryFilter{Limit: 10}, ExportFormatCSV, &failAfterWriter{max: len(header)}); err == nil {
			t.Error("expected row write error")
		}
	})

	t.Run("Export NDJSON writer error", func(t *testing.T) {
		ms := NewMemoryStorage()
		big := base("1")
		big.Metadata = map[string]interface{}{"blob": strings.Repeat("x", 4096)}
		_ = ms.Save(ctx, big)
		if err := ms.Export(ctx, QueryFilter{Limit: 10}, ExportFormatNDJSON, &failWriter{}); err == nil {
			t.Error("expected writer error")
		}
	})
}

type failWriter struct{}

func (f failWriter) Write(p []byte) (int, error) { return 0, errors.New("write failed") }

func TestMemoryMatchesFilter(t *testing.T) {
	ctx := context.Background()
	ms := NewMemoryStorage()
	ev := &Event{
		ID:        "m1",
		Timestamp: time.Now().UTC(),
		Actor:     ActorInfo{ID: "a1", Type: "user", Email: "x@y.com", Username: "xuser"},
		Action:    ActionInfo{Type: "CREATE", Category: "DATA", Description: "create thing"},
		Resource:  ResourceInfo{Type: "post", ID: "p1"},
		Result:    ResultInfo{Status: "SUCCESS", Message: "created ok"},
		Context:   ContextInfo{IPAddress: "9.9.9.9"},
		Threats:   []ThreatDetection{{Type: "ANOMALY", Description: "unusual"}},
		RiskScore: 0.7,
	}
	if err := ms.Save(ctx, ev); err != nil {
		t.Fatalf("save failed: %v", err)
	}

	cases := []struct {
		name string
		f    QueryFilter
		want int
	}{
		{"EventIDs match", QueryFilter{EventIDs: []string{"m1"}}, 1},
		{"EventIDs no match", QueryFilter{EventIDs: []string{"zz"}}, 0},
		{"ActorIDs", QueryFilter{ActorIDs: []string{"a1"}}, 1},
		{"ActorIDs no match", QueryFilter{ActorIDs: []string{"zz"}}, 0},
		{"ActorTypes", QueryFilter{ActorTypes: []string{"user"}}, 1},
		{"ActionTypes", QueryFilter{ActionTypes: []string{"CREATE"}}, 1},
		{"ActionTypes no match", QueryFilter{ActionTypes: []string{"NOPE"}}, 0},
		{"ActionCategories", QueryFilter{ActionCategories: []string{"DATA"}}, 1},
		{"ActionCategories no match", QueryFilter{ActionCategories: []string{"NOPE"}}, 0},
		{"ResourceTypes", QueryFilter{ResourceTypes: []string{"post"}}, 1},
		{"ResourceIDs", QueryFilter{ResourceIDs: []string{"p1"}}, 1},
		{"Statuses", QueryFilter{Statuses: []string{"SUCCESS"}}, 1},
		{"Statuses no match", QueryFilter{Statuses: []string{"FAILURE"}}, 0},
		{"IPAddresses", QueryFilter{IPAddresses: []string{"9.9.9.9"}}, 1},
		{"ThreatTypes match", QueryFilter{ThreatTypes: []string{"ANOMALY"}}, 1},
		{"ThreatTypes no match con amenazas", QueryFilter{ThreatTypes: []string{"DDOS"}}, 0},
		{"MinRiskScore", QueryFilter{MinRiskScore: 0.6}, 1},
		{"MinRiskScore alto", QueryFilter{MinRiskScore: 0.9}, 0},
		{"StartTime pasado", QueryFilter{StartTime: time.Now().Add(-time.Hour)}, 1},
		{"StartTime futuro", QueryFilter{StartTime: time.Now().Add(time.Hour)}, 0},
		{"EndTime pasado", QueryFilter{EndTime: time.Now().Add(-time.Hour)}, 0},
		{"EndTime futuro", QueryFilter{EndTime: time.Now().Add(time.Hour)}, 1},
		{"SearchQuery en mensaje", QueryFilter{SearchQuery: "created"}, 1},
		{"SearchQuery en amenaza", QueryFilter{SearchQuery: "unusual"}, 1},
		{"SearchQuery sin match", QueryFilter{SearchQuery: "nonsense"}, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			c.f.Limit = 10
			evs, err := ms.Query(ctx, c.f)
			if err != nil {
				t.Fatalf("query failed: %v", err)
			}
			if len(evs) != c.want {
				t.Errorf("expected %d results, got %d", c.want, len(evs))
			}
		})
	}

	// ThreatTypes sin amenazas en el evento: no excluye
	plain := &Event{ID: "plain", Timestamp: time.Now().UTC(), Actor: ActorInfo{ID: "a2"}, Action: ActionInfo{Type: "READ"}}
	_ = ms.Save(ctx, plain)
	evs, err := ms.Query(ctx, QueryFilter{ThreatTypes: []string{"DDOS"}, Limit: 10})
	if err != nil {
		t.Fatalf("query failed: %v", err)
	}
	found := false
	for _, e := range evs {
		if e.ID == "plain" {
			found = true
		}
	}
	if !found {
		t.Error("expected event without threats to pass ThreatTypes filter")
	}
}

func TestMemorySortAndClose(t *testing.T) {
	ctx := context.Background()
	ms := NewMemoryStorage()
	old := &Event{ID: "old", Timestamp: time.Now().Add(-2 * time.Hour), Actor: ActorInfo{ID: "u"}, Action: ActionInfo{Type: "A"}}
	now := &Event{ID: "now", Timestamp: time.Now(), Actor: ActorInfo{ID: "u"}, Action: ActionInfo{Type: "B"}}
	_ = ms.Save(ctx, old)
	_ = ms.Save(ctx, now)

	// Orden desc por timestamp
	evs, err := ms.Query(ctx, QueryFilter{SortBy: "timestamp", SortOrder: "desc", Limit: 10})
	if err != nil {
		t.Fatalf("query failed: %v", err)
	}
	if evs[0].ID != "now" {
		t.Errorf("expected 'now' first in desc order, got %q", evs[0].ID)
	}
	// Orden por risk_score (sin sort específico)
	if _, err := ms.Query(ctx, QueryFilter{SortBy: "risk_score", Limit: 10}); err != nil {
		t.Fatalf("query failed: %v", err)
	}
	// SortBy no permitido
	if _, err := ms.Query(ctx, QueryFilter{SortBy: "evil", SortOrder: "evil", Limit: 10}); err != nil {
		t.Fatalf("query failed: %v", err)
	}
	// DeleteOlderThan
	deleted, err := ms.DeleteOlderThan(ctx, time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatalf("delete failed: %v", err)
	}
	if deleted != 1 {
		t.Errorf("expected 1 deleted, got %d", deleted)
	}
	// Close vacía
	if err := ms.Close(); err != nil {
		t.Fatalf("close failed: %v", err)
	}
	if len(ms.events) != 0 {
		t.Error("expected empty events after close")
	}
}

func TestMemorySortAllBranches(t *testing.T) {
	ctx := context.Background()
	ms := NewMemoryStorage()
	mk := func(id, actorID, actionType string, ts time.Time, risk float64) *Event {
		return &Event{ID: id, Timestamp: ts, Actor: ActorInfo{ID: actorID}, Action: ActionInfo{Type: actionType}, RiskScore: risk}
	}
	base := time.Now()
	for _, e := range []*Event{
		mk("e1", "a", "LOGIN", base.Add(-3*time.Hour), 0.3),
		mk("e2", "b", "CREATE", base.Add(-1*time.Hour), 0.9),
		mk("e3", "c", "DELETE", base, 0.5),
	} {
		_ = ms.Save(ctx, e)
	}

	ids := func(evs []*Event) []string {
		out := make([]string, len(evs))
		for i, e := range evs {
			out[i] = e.ID
		}
		return out
	}

	cases := []struct {
		sortBy string
		order  string
		first  string
	}{
		{"timestamp", "asc", "e1"},
		{"timestamp", "desc", "e3"},
		{"risk_score", "asc", "e1"},
		{"risk_score", "desc", "e2"},
		{"actor_id", "asc", "e1"},
		{"actor_id", "desc", "e3"},
		{"action_type", "asc", "e2"},
		{"action_type", "desc", "e1"},
	}
	for _, c := range cases {
		t.Run(c.sortBy+"_"+c.order, func(t *testing.T) {
			evs, err := ms.Query(ctx, QueryFilter{SortBy: c.sortBy, SortOrder: c.order, Limit: 10})
			if err != nil {
				t.Fatalf("query failed: %v", err)
			}
			if len(evs) != 3 || evs[0].ID != c.first {
				t.Errorf("sort %s %s: expected first %q, got %v", c.sortBy, c.order, c.first, ids(evs))
			}
		})
	}
}

// ---------------------------------------------------------------------------
// SQLiteStorage
// ---------------------------------------------------------------------------

func TestNewSQLiteStorageBranches(t *testing.T) {
	t.Run("DSN vacío usa memoria", func(t *testing.T) {
		s, err := NewSQLiteStorage(SQLiteConfig{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer s.Close()
	})
	t.Run("Config pool", func(t *testing.T) {
		s, err := NewSQLiteStorage(SQLiteConfig{DSN: ":memory:", MaxOpenConns: 4, MaxIdleConns: 2, MaxLifetime: 60})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer s.Close()
	})
	t.Run("DSN archivo", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "audit.db")
		s, err := NewSQLiteStorage(SQLiteConfig{DSN: path})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer s.Close()
	})
	t.Run("DSN inválido", func(t *testing.T) {
		if _, err := NewSQLiteStorage(SQLiteConfig{DSN: "/nonexistent/dir/x.db"}); err == nil {
			t.Error("expected error for bad DSN")
		}
	})
}

func TestSQLiteStorageCRUD(t *testing.T) {
	s, err := NewSQLiteStorage(SQLiteConfig{DSN: ":memory:"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer s.Close()
	ctx := context.Background()

	mk := func(id string, risk float64) *Event {
		return &Event{
			ID:                 id,
			Timestamp:          time.Now().UTC(),
			Actor:              ActorInfo{ID: "act-" + id, Email: id + "@x.com", Type: "user"},
			Action:             ActionInfo{Type: "LOGIN", Category: "AUTH"},
			Resource:           ResourceInfo{Type: "auth"},
			Result:             ResultInfo{Status: "SUCCESS"},
			Context:            ContextInfo{IPAddress: "10.1.1." + id, UserAgent: "ua", RequestID: "req-" + id},
			RiskScore:          risk,
			Threats:            []ThreatDetection{{Type: "XSS", Description: "xss"}},
			Metadata:           map[string]interface{}{"k": "v"},
			DigitalFingerprint: "fp-" + id,
		}
	}

	if err := s.Save(ctx, mk("1", 0.5)); err != nil {
		t.Fatalf("save failed: %v", err)
	}
	if err := s.SaveBatch(ctx, []*Event{mk("2", 0.2), mk("3", 0.9)}); err != nil {
		t.Fatalf("savebatch failed: %v", err)
	}

	ev, err := s.GetByID(ctx, "1")
	if err != nil {
		t.Fatalf("getbyid failed: %v", err)
	}
	if ev.ID != "1" || len(ev.Threats) != 1 || ev.Metadata["k"] != "v" {
		t.Errorf("unexpected event: %+v", ev)
	}
	if _, err := s.GetByID(ctx, "nope"); err == nil {
		t.Error("expected not found error")
	}

	evs, err := s.Query(ctx, QueryFilter{ActorIDs: []string{"act-2"}, Limit: 10})
	if err != nil {
		t.Fatalf("query failed: %v", err)
	}
	if len(evs) != 1 || evs[0].ID != "2" {
		t.Errorf("expected 1 event, got %d", len(evs))
	}

	// Filtros múltiples + search + sort + paginación
	evs, err = s.Query(ctx, QueryFilter{
		IPAddresses: []string{"10.1.1.1", "10.1.1.2"},
		Statuses:    []string{"SUCCESS"},
		MinRiskScore: 0.1,
		SearchQuery:  "LOGIN",
		SortBy:       "risk_score",
		SortOrder:    "asc",
		Limit:        5,
		Offset:       0,
	})
	if err != nil {
		t.Fatalf("query failed: %v", err)
	}
	if len(evs) != 2 {
		t.Errorf("expected 2 events with filters, got %d", len(evs))
	}

	// SortBy no permitido y EndTime
	evs, err = s.Query(ctx, QueryFilter{
		EndTime:   time.Now().Add(time.Minute),
		StartTime: time.Now().Add(-time.Minute),
		SortBy:    "evil",
		SortOrder: "evil",
		Limit:     10,
	})
	if err != nil {
		t.Fatalf("query failed: %v", err)
	}
	if len(evs) != 3 {
		t.Errorf("expected 3 events, got %d", len(evs))
	}

	n, err := s.Count(ctx, QueryFilter{ActionTypes: []string{"LOGIN"}})
	if err != nil {
		t.Fatalf("count failed: %v", err)
	}
	if n != 3 {
		t.Errorf("expected count 3, got %d", n)
	}
	n, err = s.Count(ctx, QueryFilter{EventIDs: []string{"1", "2"}, StartTime: time.Now().Add(-time.Hour), EndTime: time.Now().Add(time.Hour), MinRiskScore: 0.1})
	if err != nil {
		t.Fatalf("count failed: %v", err)
	}
	if n != 2 {
		t.Errorf("expected count 2, got %d", n)
	}

	// Export formatos
	var buf strings.Builder
	if err := s.Export(ctx, QueryFilter{Limit: 10}, ExportFormatJSON, &buf); err != nil {
		t.Fatalf("export json failed: %v", err)
	}
	buf.Reset()
	if err := s.Export(ctx, QueryFilter{Limit: 10}, ExportFormatCSV, &buf); err != nil {
		t.Fatalf("export csv failed: %v", err)
	}
	if !strings.Contains(buf.String(), "id,timestamp") {
		t.Error("expected CSV header")
	}
	buf.Reset()
	if err := s.Export(ctx, QueryFilter{Limit: 10}, ExportFormatNDJSON, &buf); err != nil {
		t.Fatalf("export ndjson failed: %v", err)
	}
	if err := s.Export(ctx, QueryFilter{Limit: 10}, ExportFormat("xml"), &buf); err == nil {
		t.Error("expected unsupported format error")
	}

	// DeleteOlderThan
	deleted, err := s.DeleteOlderThan(ctx, time.Now().Add(-time.Minute))
	if err != nil {
		t.Fatalf("delete failed: %v", err)
	}
	if deleted != 0 {
		t.Errorf("expected 0 deleted (recent), got %d", deleted)
	}
	deleted, err = s.DeleteOlderThan(ctx, time.Now().Add(time.Minute))
	if err != nil {
		t.Fatalf("delete failed: %v", err)
	}
	if deleted != 3 {
		t.Errorf("expected 3 deleted, got %d", deleted)
	}
}

func TestSQLiteHelpers(t *testing.T) {
	// buildQuery y buildCountQuery con todas las cláusulas
	q, args := buildQuery(QueryFilter{
		EventIDs:         []string{"e1", "e2"},
		ActorIDs:         []string{"a1", "a2"},
		ActorTypes:       []string{"user"},
		ActionTypes:      []string{"LOGIN"},
		ActionCategories: []string{"AUTH"},
		ResourceTypes:    []string{"auth"},
		ResourceIDs:      []string{"r1"},
		Statuses:         []string{"SUCCESS"},
		IPAddresses:      []string{"1.1.1.1", "2.2.2.2"},
		SessionIDs:       []string{"s1"},
		StartTime:        time.Now(),
		EndTime:          time.Now(),
		MinRiskScore:     0.5,
		SearchQuery:      "foo",
		SortBy:           "actor_id",
		SortOrder:        "asc",
		Limit:            5,
		Offset:           2,
	})
	if !strings.Contains(q, "id IN (?") || !strings.Contains(q, "ORDER BY actor_id asc") {
		t.Errorf("unexpected query: %s", q)
	}
	if len(args) != 27 { // 2+2+1+1+1+1+1+1+2+1+1+1+1+9+1+1
		t.Errorf("expected 27 args, got %d", len(args))
	}

	qc, ac := buildCountQuery(QueryFilter{
		EventIDs:     []string{"e1"},
		ActorIDs:     []string{"a1"},
		ActionTypes:  []string{"LOGIN"},
		StartTime:    time.Now(),
		EndTime:      time.Now(),
		MinRiskScore: 0.1,
	})
	if !strings.HasPrefix(qc, "SELECT COUNT(*)") {
		t.Errorf("unexpected count query: %s", qc)
	}
	if len(ac) != 6 {
		t.Errorf("expected 6 count args, got %d", len(ac))
	}

	if got := repeatPlaceholder(3); got != ",?,?,?" {
		t.Errorf("unexpected placeholders: %q", got)
	}
	if got := repeatPlaceholder(0); got != "" {
		t.Errorf("expected empty, got %q", got)
	}
}

// ---------------------------------------------------------------------------
// Postgres: helpers y configuración
// ---------------------------------------------------------------------------

func TestPostgresDSN(t *testing.T) {
	cases := []struct {
		name string
		cfg  PostgresConfig
		want string
	}{
		{"DSN completo", PostgresConfig{DSN: "host=x port=1 dbname=y user=z"}, "host=x port=1 dbname=y user=z"},
		{"Defaults", PostgresConfig{}, "host=localhost port=5432 dbname=gokit user=postgres sslmode=disable"},
		{"Custom", PostgresConfig{Host: "h", Port: 9999, Database: "d", User: "u", SSLMode: "require"}, "host=h port=9999 dbname=d user=u sslmode=require"},
		{"Con password", PostgresConfig{Host: "h", Password: "secret"}, "host=h port=5432 dbname=gokit user=postgres sslmode=disable password=secret"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.cfg.dsn(); got != c.want {
				t.Errorf("expected %q, got %q", c.want, got)
			}
		})
	}
}

func TestPostgresQueryBuilders(t *testing.T) {
	if got := pgInsertQuery(); !strings.HasPrefix(got, "INSERT INTO audit_events") {
		t.Errorf("unexpected insert query: %s", got)
	}
	upsert := pgUpsertQuery()
	if !strings.Contains(upsert, "ON CONFLICT (id) DO UPDATE SET") {
		t.Errorf("unexpected upsert query: %s", upsert)
	}
	ev := &Event{ID: "x", Timestamp: time.Now(), Actor: ActorInfo{ID: "a"}, Action: ActionInfo{Type: "T"}, Result: ResultInfo{Status: "S"}, DigitalFingerprint: "fp"}
	args := pgEventArgs(ev)
	if len(args) != 28 {
		t.Errorf("expected 28 args, got %d", len(args))
	}
	if got := toInterfaceSlice([]string{"a", "b"}); len(got) != 2 {
		t.Errorf("expected 2 interface values, got %d", len(got))
	}

	// buildPGQuery con todas las cláusulas
	q, args := buildPGQuery(QueryFilter{
		EventIDs:         []string{"e1", "e2"},
		ActorIDs:         []string{"a1"},
		ActorTypes:       []string{"user"},
		ActionTypes:      []string{"LOGIN"},
		ActionCategories: []string{"AUTH"},
		ResourceTypes:    []string{"auth"},
		ResourceIDs:      []string{"r1"},
		Statuses:         []string{"SUCCESS"},
		IPAddresses:      []string{"1.1.1.1"},
		SessionIDs:       []string{"s1"},
		StartTime:        time.Now(),
		EndTime:          time.Now(),
		MinRiskScore:     0.5,
		SearchQuery:      "foo",
		SortBy:           "evil",
		SortOrder:        "evil",
		Limit:            5,
		Offset:           1,
	})
	for _, sub := range []string{"id IN ($1, $2)", "ORDER BY timestamp desc", "LIMIT $", "OFFSET $"} {
		if !strings.Contains(q, sub) {
			t.Errorf("query missing %q: %s", sub, q)
		}
	}
	if len(args) == 0 {
		t.Error("expected args")
	}

	qc, ac := buildPGCountQuery(QueryFilter{EventIDs: []string{"e1"}, ActorIDs: []string{"a1"}, ActionTypes: []string{"LOGIN"}, StartTime: time.Now(), EndTime: time.Now(), MinRiskScore: 0.1})
	if !strings.HasPrefix(qc, "SELECT COUNT(*)") {
		t.Errorf("unexpected count query: %s", qc)
	}
	if len(ac) != 6 {
		t.Errorf("expected 6 count args, got %d", len(ac))
	}

	// buildPGQuery sin filtros (ORDER BY por defecto)
	q2, _ := buildPGQuery(QueryFilter{})
	if !strings.Contains(q2, "ORDER BY timestamp desc") {
		t.Errorf("expected default ordering: %s", q2)
	}
}

func TestNewPostgresStoragePingError(t *testing.T) {
	_, err := NewPostgresStorage(PostgresConfig{DSN: "host=127.0.0.1 port=1 dbname=x user=x sslmode=disable connect_timeout=1"})
	if err == nil {
		t.Skip("no error — postgres server reachable")
	}
}

// ---------------------------------------------------------------------------
// PostgresStorage via sqlmock
// ---------------------------------------------------------------------------

// scanColumns es el orden de columnas que espera scanEvent/scanEventRow
var scanColumns = []string{
	"id", "timestamp", "actor_id", "actor_email", "actor_username", "actor_role",
	"actor_session_id", "actor_type", "action_type", "action_category", "action_description",
	"action_method", "action_path", "resource_type", "resource_id", "resource_name",
	"result_status", "result_status_code", "result_message", "result_error", "result_duration_ms",
	"context_ip_address", "context_user_agent", "context_request_id", "risk_score",
	"threats", "metadata", "digital_fingerprint",
}

func mockRow(event *Event) []driver.Value {
	threats, _ := json.Marshal(event.Threats)
	metadata, _ := json.Marshal(event.Metadata)
	return []driver.Value{
		event.ID, event.Timestamp, event.Actor.ID, event.Actor.Email, event.Actor.Username, event.Actor.Role,
		event.Actor.SessionID, event.Actor.Type, event.Action.Type, event.Action.Category, event.Action.Description,
		event.Action.Method, event.Action.Path, event.Resource.Type, event.Resource.ID, event.Resource.Name,
		event.Result.Status, event.Result.StatusCode, event.Result.Message, event.Result.Error, event.Result.Duration,
		event.Context.IPAddress, event.Context.UserAgent, event.Context.RequestID, event.RiskScore,
		threats, metadata, event.DigitalFingerprint,
	}
}

func TestPostgresStorageMethods(t *testing.T) {
	ctx := context.Background()
	ev := &Event{
		ID:                 "p1",
		Timestamp:          time.Now().UTC(),
		Actor:              ActorInfo{ID: "a1", Type: "user"},
		Action:             ActionInfo{Type: "LOGIN", Category: "AUTH"},
		Resource:           ResourceInfo{Type: "auth"},
		Result:             ResultInfo{Status: "SUCCESS"},
		Context:            ContextInfo{IPAddress: "1.1.1.1"},
		RiskScore:          0.3,
		Threats:            []ThreatDetection{{Type: "XSS", Description: "xss"}},
		Metadata:           map[string]interface{}{"k": "v"},
		DigitalFingerprint: "fp1",
	}

	t.Run("Save", func(t *testing.T) {
		db, mock, err := sqlmock.New()
		if err != nil {
			t.Fatalf("sqlmock: %v", err)
		}
		defer db.Close()
		s := &PostgresStorage{db: db}
		mock.ExpectExec("INSERT INTO audit_events").WillReturnResult(sqlmock.NewResult(1, 1))
		if err := s.Save(ctx, ev); err != nil {
			t.Fatalf("save failed: %v", err)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatalf("unmet expectations: %v", err)
		}
	})

	t.Run("Save error", func(t *testing.T) {
		db, mock, _ := sqlmock.New()
		defer db.Close()
		s := &PostgresStorage{db: db}
		mock.ExpectExec("INSERT INTO audit_events").WillReturnError(errors.New("db down"))
		if err := s.Save(ctx, ev); err == nil {
			t.Error("expected save error")
		}
	})

	t.Run("SaveBatch", func(t *testing.T) {
		db, mock, _ := sqlmock.New()
		defer db.Close()
		s := &PostgresStorage{db: db}
		mock.ExpectBegin()
		mock.ExpectPrepare("INSERT INTO audit_events")
		mock.ExpectExec("INSERT INTO audit_events").WillReturnResult(sqlmock.NewResult(1, 1))
		mock.ExpectExec("INSERT INTO audit_events").WillReturnResult(sqlmock.NewResult(1, 1))
		mock.ExpectCommit()
		if err := s.SaveBatch(ctx, []*Event{ev, ev}); err != nil {
			t.Fatalf("savebatch failed: %v", err)
		}
	})

	t.Run("SaveBatch error begin", func(t *testing.T) {
		db, mock, _ := sqlmock.New()
		defer db.Close()
		s := &PostgresStorage{db: db}
		mock.ExpectBegin().WillReturnError(errors.New("no tx"))
		if err := s.SaveBatch(ctx, []*Event{ev}); err == nil {
			t.Error("expected begin error")
		}
	})

	t.Run("SaveBatch error exec", func(t *testing.T) {
		db, mock, _ := sqlmock.New()
		defer db.Close()
		s := &PostgresStorage{db: db}
		mock.ExpectBegin()
		mock.ExpectPrepare("INSERT INTO audit_events")
		mock.ExpectExec("INSERT INTO audit_events").WillReturnError(errors.New("exec failed"))
		if err := s.SaveBatch(ctx, []*Event{ev}); err == nil {
			t.Error("expected exec error")
		}
	})

	t.Run("GetByID", func(t *testing.T) {
		db, mock, _ := sqlmock.New()
		defer db.Close()
		s := &PostgresStorage{db: db}
		rows := sqlmock.NewRows(scanColumns).AddRow(mockRow(ev)...)
		mock.ExpectQuery("WHERE id = \\$1").WithArgs("p1").WillReturnRows(rows)
		got, err := s.GetByID(ctx, "p1")
		if err != nil {
			t.Fatalf("getbyid failed: %v", err)
		}
		if got.ID != "p1" || len(got.Threats) != 1 || got.Metadata["k"] != "v" {
			t.Errorf("unexpected event: %+v", got)
		}
	})

	t.Run("GetByID sin resultado", func(t *testing.T) {
		db, mock, _ := sqlmock.New()
		defer db.Close()
		s := &PostgresStorage{db: db}
		mock.ExpectQuery("WHERE id = \\$1").WithArgs("zz").WillReturnRows(sqlmock.NewRows(scanColumns))
		if _, err := s.GetByID(ctx, "zz"); err == nil {
			t.Error("expected not found error")
		}
	})

	t.Run("Query", func(t *testing.T) {
		db, mock, _ := sqlmock.New()
		defer db.Close()
		s := &PostgresStorage{db: db}
		rows := sqlmock.NewRows(scanColumns).AddRow(mockRow(ev)...)
		mock.ExpectQuery("SELECT id, timestamp,").WillReturnRows(rows)
		evs, err := s.Query(ctx, QueryFilter{Limit: 10})
		if err != nil {
			t.Fatalf("query failed: %v", err)
		}
		if len(evs) != 1 || evs[0].ID != "p1" {
			t.Errorf("expected 1 event, got %d", len(evs))
		}
	})

	t.Run("Query error", func(t *testing.T) {
		db, mock, _ := sqlmock.New()
		defer db.Close()
		s := &PostgresStorage{db: db}
		mock.ExpectQuery("SELECT id, timestamp,").WillReturnError(errors.New("query down"))
		if _, err := s.Query(ctx, QueryFilter{Limit: 10}); err == nil {
			t.Error("expected query error")
		}
	})

	t.Run("Query scan error", func(t *testing.T) {
		db, mock, _ := sqlmock.New()
		defer db.Close()
		s := &PostgresStorage{db: db}
		badRows := sqlmock.NewRows([]string{"only_one"}).AddRow("x")
		mock.ExpectQuery("SELECT id, timestamp,").WillReturnRows(badRows)
		if _, err := s.Query(ctx, QueryFilter{Limit: 10}); err == nil {
			t.Error("expected scan error")
		}
	})

	t.Run("Count", func(t *testing.T) {
		db, mock, _ := sqlmock.New()
		defer db.Close()
		s := &PostgresStorage{db: db}
		mock.ExpectQuery("SELECT COUNT").WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(7))
		n, err := s.Count(ctx, QueryFilter{})
		if err != nil {
			t.Fatalf("count failed: %v", err)
		}
		if n != 7 {
			t.Errorf("expected 7, got %d", n)
		}
	})

	t.Run("DeleteOlderThan", func(t *testing.T) {
		db, mock, _ := sqlmock.New()
		defer db.Close()
		s := &PostgresStorage{db: db}
		mock.ExpectExec("DELETE FROM audit_events").WillReturnResult(sqlmock.NewResult(0, 3))
		n, err := s.DeleteOlderThan(ctx, time.Now())
		if err != nil {
			t.Fatalf("delete failed: %v", err)
		}
		if n != 3 {
			t.Errorf("expected 3, got %d", n)
		}
	})

	t.Run("DeleteOlderThan error", func(t *testing.T) {
		db, mock, _ := sqlmock.New()
		defer db.Close()
		s := &PostgresStorage{db: db}
		mock.ExpectExec("DELETE FROM audit_events").WillReturnError(errors.New("db down"))
		if _, err := s.DeleteOlderThan(ctx, time.Now()); err == nil {
			t.Error("expected delete error")
		}
	})

	t.Run("Export", func(t *testing.T) {
		db, mock, _ := sqlmock.New()
		defer db.Close()
		s := &PostgresStorage{db: db}
		mock.ExpectQuery("SELECT id, timestamp,").WillReturnRows(sqlmock.NewRows(scanColumns).AddRow(mockRow(ev)...))
		var buf strings.Builder
		if err := s.Export(ctx, QueryFilter{Limit: 10}, ExportFormatJSON, &buf); err != nil {
			t.Fatalf("export failed: %v", err)
		}
		if buf.Len() == 0 {
			t.Error("expected exported data")
		}
	})

	t.Run("Export query error", func(t *testing.T) {
		db, mock, _ := sqlmock.New()
		defer db.Close()
		s := &PostgresStorage{db: db}
		mock.ExpectQuery("SELECT id, timestamp,").WillReturnError(errors.New("down"))
		if err := s.Export(ctx, QueryFilter{Limit: 10}, ExportFormatJSON, &sink{}); err == nil {
			t.Error("expected export error")
		}
	})

	t.Run("Export formato no soportado", func(t *testing.T) {
		db, mock, _ := sqlmock.New()
		defer db.Close()
		s := &PostgresStorage{db: db}
		mock.ExpectQuery("SELECT id, timestamp,").WillReturnRows(sqlmock.NewRows(scanColumns))
		if err := s.Export(ctx, QueryFilter{Limit: 10}, ExportFormat("xml"), &sink{}); err == nil {
			t.Error("expected unsupported format error")
		}
	})

	t.Run("Close", func(t *testing.T) {
		db, mock, _ := sqlmock.New()
		s := &PostgresStorage{db: db}
		mock.ExpectClose()
		if err := s.Close(); err != nil {
			t.Fatalf("close failed: %v", err)
		}
	})

	t.Run("createPostgresTables", func(t *testing.T) {
		db, mock, _ := sqlmock.New()
		defer db.Close()
		mock.ExpectExec("CREATE TABLE IF NOT EXISTS audit_events").WillReturnResult(sqlmock.NewResult(0, 0))
		if err := createPostgresTables(db); err != nil {
			t.Fatalf("create tables failed: %v", err)
		}
	})

	t.Run("SaveBatch error prepare", func(t *testing.T) {
		db, mock, _ := sqlmock.New()
		defer db.Close()
		s := &PostgresStorage{db: db}
		mock.ExpectBegin()
		mock.ExpectPrepare("INSERT INTO audit_events").WillReturnError(errors.New("no stmt"))
		if err := s.SaveBatch(ctx, []*Event{ev}); err == nil {
			t.Error("expected prepare error")
		}
	})

	t.Run("Export CSV", func(t *testing.T) {
		db, mock, _ := sqlmock.New()
		defer db.Close()
		s := &PostgresStorage{db: db}
		mock.ExpectQuery("SELECT id, timestamp,").WillReturnRows(sqlmock.NewRows(scanColumns).AddRow(mockRow(ev)...))
		var buf strings.Builder
		if err := s.Export(ctx, QueryFilter{Limit: 10}, ExportFormatCSV, &buf); err != nil {
			t.Fatalf("export csv failed: %v", err)
		}
		if !strings.Contains(buf.String(), "id,timestamp") {
			t.Error("expected CSV header")
		}
	})

	t.Run("Export NDJSON", func(t *testing.T) {
		db, mock, _ := sqlmock.New()
		defer db.Close()
		s := &PostgresStorage{db: db}
		mock.ExpectQuery("SELECT id, timestamp,").WillReturnRows(sqlmock.NewRows(scanColumns).AddRow(mockRow(ev)...))
		var buf strings.Builder
		if err := s.Export(ctx, QueryFilter{Limit: 10}, ExportFormatNDJSON, &buf); err != nil {
			t.Fatalf("export ndjson failed: %v", err)
		}
		if buf.Len() == 0 {
			t.Error("expected NDJSON data")
		}
	})
}

// ---------------------------------------------------------------------------
// NewPostgresStorage: éxito y ramas de error vía sqlmock
// ---------------------------------------------------------------------------

func TestNewPostgresStorageBranches(t *testing.T) {
	t.Run("sql.Open error", func(t *testing.T) {
		old := pgDriverName
		pgDriverName = "__missing_driver__"
		defer func() { pgDriverName = old }()
		if _, err := NewPostgresStorage(PostgresConfig{}); err == nil {
			t.Error("expected sql.Open error")
		}
	})

	t.Run("createTables error", func(t *testing.T) {
		dsn := PostgresConfig{Host: "errhost"}.dsn()
		db, mock, err := sqlmock.NewWithDSN(dsn)
		if err != nil {
			t.Fatalf("sqlmock: %v", err)
		}
		defer db.Close()
		old := pgDriverName
		pgDriverName = "sqlmock"
		defer func() { pgDriverName = old }()
		mock.ExpectExec("CREATE TABLE IF NOT EXISTS audit_events").WillReturnError(errors.New("boom"))
		if _, err := NewPostgresStorage(PostgresConfig{Host: "errhost"}); err == nil {
			t.Error("expected createTables error")
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatalf("unmet expectations: %v", err)
		}
	})

	t.Run("éxito con pool y createStorage", func(t *testing.T) {
		dsn := PostgresConfig{}.dsn()
		db, mock, err := sqlmock.NewWithDSN(dsn)
		if err != nil {
			t.Fatalf("sqlmock: %v", err)
		}
		defer db.Close()
		old := pgDriverName
		pgDriverName = "sqlmock"
		defer func() { pgDriverName = old }()
		mock.ExpectExec("CREATE TABLE IF NOT EXISTS audit_events").WillReturnResult(sqlmock.NewResult(0, 0))
		mock.ExpectExec("CREATE TABLE IF NOT EXISTS audit_events").WillReturnResult(sqlmock.NewResult(0, 0))

		cfg := PostgresConfig{MaxOpenConns: 5, MaxIdleConns: 2, MaxLifetime: 30}
		s, err := NewPostgresStorage(cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if s.config != cfg {
			t.Errorf("config not stored")
		}

		st, err := createStorage("postgres", cfg)
		if err != nil {
			t.Fatalf("createStorage postgres failed: %v", err)
		}
		if _, ok := st.(*PostgresStorage); !ok {
			t.Errorf("expected *PostgresStorage, got %T", st)
		}
		_ = st.Close()
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatalf("unmet expectations: %v", err)
		}
	})
}

// ---------------------------------------------------------------------------
// SQLiteStorage: ramas de error vía sqlmock
// ---------------------------------------------------------------------------

func TestSQLiteStorageErrors(t *testing.T) {
	ctx := context.Background()
	ev := &Event{
		ID:        "e1",
		Timestamp: time.Now().UTC(),
		Actor:     ActorInfo{ID: "a1", Type: "user"},
		Action:    ActionInfo{Type: "LOGIN", Category: "AUTH"},
		Result:    ResultInfo{Status: "SUCCESS"},
	}

	t.Run("sql.Open error", func(t *testing.T) {
		old := sqliteDriverName
		sqliteDriverName = "__missing_driver__"
		defer func() { sqliteDriverName = old }()
		if _, err := NewSQLiteStorage(SQLiteConfig{DSN: "x.db"}); err == nil {
			t.Error("expected sql.Open error")
		}
	})

	t.Run("createTables error", func(t *testing.T) {
		db, mock, err := sqlmock.NewWithDSN("sqlite-tables-err")
		if err != nil {
			t.Fatalf("sqlmock: %v", err)
		}
		defer db.Close()
		old := sqliteDriverName
		sqliteDriverName = "sqlmock"
		defer func() { sqliteDriverName = old }()
		mock.ExpectExec("CREATE TABLE IF NOT EXISTS audit_events").WillReturnError(errors.New("boom"))
		if _, err := NewSQLiteStorage(SQLiteConfig{DSN: "sqlite-tables-err"}); err == nil {
			t.Error("expected createTables error")
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatalf("unmet expectations: %v", err)
		}
	})

	t.Run("SaveBatch error begin", func(t *testing.T) {
		db, mock, _ := sqlmock.New()
		defer db.Close()
		s := &SQLiteStorage{db: db}
		mock.ExpectBegin().WillReturnError(errors.New("no tx"))
		if err := s.SaveBatch(ctx, []*Event{ev}); err == nil {
			t.Error("expected begin error")
		}
	})

	t.Run("SaveBatch error prepare", func(t *testing.T) {
		db, mock, _ := sqlmock.New()
		defer db.Close()
		s := &SQLiteStorage{db: db}
		mock.ExpectBegin()
		mock.ExpectPrepare("INSERT OR REPLACE INTO audit_events").WillReturnError(errors.New("no stmt"))
		if err := s.SaveBatch(ctx, []*Event{ev}); err == nil {
			t.Error("expected prepare error")
		}
	})

	t.Run("SaveBatch error exec", func(t *testing.T) {
		db, mock, _ := sqlmock.New()
		defer db.Close()
		s := &SQLiteStorage{db: db}
		mock.ExpectBegin()
		mock.ExpectPrepare("INSERT OR REPLACE INTO audit_events")
		mock.ExpectExec("INSERT OR REPLACE INTO audit_events").WillReturnError(errors.New("exec failed"))
		if err := s.SaveBatch(ctx, []*Event{ev}); err == nil {
			t.Error("expected exec error")
		}
	})

	t.Run("Query error", func(t *testing.T) {
		db, mock, _ := sqlmock.New()
		defer db.Close()
		s := &SQLiteStorage{db: db}
		mock.ExpectQuery("SELECT id, timestamp,").WillReturnError(errors.New("down"))
		if _, err := s.Query(ctx, QueryFilter{Limit: 10}); err == nil {
			t.Error("expected query error")
		}
	})

	t.Run("Query scan error", func(t *testing.T) {
		db, mock, _ := sqlmock.New()
		defer db.Close()
		s := &SQLiteStorage{db: db}
		badRows := sqlmock.NewRows([]string{"only_one"}).AddRow("x")
		mock.ExpectQuery("SELECT id, timestamp,").WillReturnRows(badRows)
		if _, err := s.Query(ctx, QueryFilter{Limit: 10}); err == nil {
			t.Error("expected scan error")
		}
	})

	t.Run("DeleteOlderThan error", func(t *testing.T) {
		db, mock, _ := sqlmock.New()
		defer db.Close()
		s := &SQLiteStorage{db: db}
		mock.ExpectExec("DELETE FROM audit_events").WillReturnError(errors.New("down"))
		if _, err := s.DeleteOlderThan(ctx, time.Now()); err == nil {
			t.Error("expected delete error")
		}
	})

	t.Run("Export query error", func(t *testing.T) {
		db, mock, _ := sqlmock.New()
		defer db.Close()
		s := &SQLiteStorage{db: db}
		mock.ExpectQuery("SELECT id, timestamp,").WillReturnError(errors.New("down"))
		if err := s.Export(ctx, QueryFilter{Limit: 10}, ExportFormatJSON, &sink{}); err == nil {
			t.Error("expected export error")
		}
	})
}

func TestSQLiteExportHelpers(t *testing.T) {
	ev := &Event{ID: "e", Timestamp: time.Now(), Actor: ActorInfo{ID: "a"}, Action: ActionInfo{Type: "T"}, Result: ResultInfo{Status: "S"}}

	t.Run("exportCSV header error", func(t *testing.T) {
		if err := exportCSV([]*Event{ev}, &failWriter{}); err == nil {
			t.Error("expected header write error")
		}
	})

	t.Run("exportCSV row error", func(t *testing.T) {
		header := "id,timestamp,actor_id,action_type,status,ip_address,risk_score\n"
		if err := exportCSV([]*Event{ev}, &failAfterWriter{max: len(header)}); err == nil {
			t.Error("expected row write error")
		}
	})

	t.Run("exportNDJSON error", func(t *testing.T) {
		if err := exportNDJSON([]*Event{ev}, &failWriter{}); err == nil {
			t.Error("expected ndjson write error")
		}
	})
}

// failAfterWriter falla después de permitir max bytes exitosos
type failAfterWriter struct {
	max int
	n   int
}

func (f *failAfterWriter) Write(p []byte) (int, error) {
	if f.n+len(p) > f.max {
		return 0, errors.New("write failed")
	}
	f.n += len(p)
	return len(p), nil
}