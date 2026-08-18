package audit

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/AndresGT/GoKit/logger"
)

// failStore es un Storage que falla según configuración
type failStore struct {
	saveErr   error
	queryErr  error
	countErr  error
	deleteErr error
	exportErr error
	getErr    error
}

func (f failStore) Save(ctx context.Context, event *Event) error { return f.saveErr }
func (f failStore) SaveBatch(ctx context.Context, events []*Event) error {
	if f.saveErr != nil {
		return f.saveErr
	}
	return nil
}
func (f failStore) GetByID(ctx context.Context, id string) (*Event, error) {
	return nil, f.getErr
}
func (f failStore) Query(ctx context.Context, filter QueryFilter) ([]*Event, error) {
	return nil, f.queryErr
}
func (f failStore) Count(ctx context.Context, filter QueryFilter) (int64, error) {
	return 0, f.countErr
}
func (f failStore) DeleteOlderThan(ctx context.Context, timestamp time.Time) (int64, error) {
	return 0, f.deleteErr
}
func (f failStore) Export(ctx context.Context, filter QueryFilter, format ExportFormat, writer io.Writer) error {
	return f.exportErr
}
func (f failStore) Close() error { return nil }

// capturingStore captura el filtro recibido en Query
type capturingStore struct {
	Storage
	lastQuery QueryFilter
}

func (c *capturingStore) Query(ctx context.Context, filter QueryFilter) ([]*Event, error) {
	c.lastQuery = filter
	return c.Storage.Query(ctx, filter)
}

// resetGlobalAuditor guarda y restaura el estado global del auditor
func resetGlobalAuditor(t *testing.T) {
	t.Helper()
	old := defaultAuditor
	defaultAuditor = nil
	once = sync.Once{}
	t.Cleanup(func() {
		if defaultAuditor != nil && defaultAuditor != old {
			_ = defaultAuditor.Close()
		}
		defaultAuditor = old
	})
}

func TestInitGlobal(t *testing.T) {
	t.Run("Init válido", func(t *testing.T) {
		resetGlobalAuditor(t)
		err := Init(Config{StorageType: "memory"})
		if err != nil {
			t.Fatalf("Init should not fail: %v", err)
		}
		if GetDefault() == nil {
			t.Fatal("defaultAuditor should be set")
		}
	})

	t.Run("Init inválido", func(t *testing.T) {
		resetGlobalAuditor(t)
		err := Init(Config{StorageType: "redis"})
		if err == nil {
			t.Fatal("Init should fail for invalid storage")
		}
	})

	t.Run("Init una sola vez", func(t *testing.T) {
		resetGlobalAuditor(t)
		if err := Init(Config{StorageType: "memory"}); err != nil {
			t.Fatalf("first Init failed: %v", err)
		}
		first := GetDefault()
		if err := Init(Config{StorageType: "sqlite", StorageConfig: SQLiteConfig{DSN: ":memory:"}}); err != nil {
			t.Fatalf("second Init should not error: %v", err)
		}
		if GetDefault() != first {
			t.Error("defaultAuditor should not be replaced after first Init")
		}
	})

	t.Run("Init con auto delete", func(t *testing.T) {
		resetGlobalAuditor(t)
		oldInterval := retentionCheckInterval.Load()
		retentionCheckInterval.Store(int64(20 * time.Millisecond))
		defer func() { retentionCheckInterval.Store(oldInterval) }()
		err := Init(Config{StorageType: "memory", Retention: RetentionPolicy{MaxAgeDays: 1, EnableAutoDelete: true}})
		if err != nil {
			t.Fatalf("Init should not fail: %v", err)
		}
		// Esperar a que el mantenimiento ejecute al menos una vez
		time.Sleep(60 * time.Millisecond)
	})
}

func TestGetDefaultAndSetDefault(t *testing.T) {
	t.Run("GetDefault crea auditor", func(t *testing.T) {
		resetGlobalAuditor(t)
		a := GetDefault()
		if a == nil {
			t.Fatal("GetDefault should create an auditor")
		}
		if a.config.StorageType != "memory" {
			t.Errorf("expected memory storage, got %q", a.config.StorageType)
		}
	})

	t.Run("SetDefault establece auditor", func(t *testing.T) {
		resetGlobalAuditor(t)
		custom, err := NewAuditor(Config{StorageType: "memory", EnableIA: false})
		if err != nil {
			t.Fatalf("failed to create custom auditor: %v", err)
		}
		SetDefault(custom)
		if GetDefault() != custom {
			t.Error("GetDefault should return the custom auditor")
		}
	})
}

func TestNewAuditorBranches(t *testing.T) {
	t.Run("Async con buffer negativo", func(t *testing.T) {
		_, err := NewAuditor(Config{StorageType: "memory", EnableAsync: true, AsyncBufferSize: -1})
		if err == nil {
			t.Fatal("expected error for negative async buffer")
		}
	})

	t.Run("SQLite config inválido", func(t *testing.T) {
		_, err := NewAuditor(Config{StorageType: "sqlite", StorageConfig: "wrong"})
		if err == nil {
			t.Fatal("expected error for invalid sqlite config")
		}
	})

	t.Run("SQLite DSN inválido", func(t *testing.T) {
		_, err := NewAuditor(Config{StorageType: "sqlite", StorageConfig: SQLiteConfig{DSN: "/nonexistent/dir/gokit.db"}})
		if err == nil {
			t.Fatal("expected error for bad sqlite DSN")
		}
	})

	t.Run("SQLite válido", func(t *testing.T) {
		a, err := NewAuditor(Config{StorageType: "sqlite", StorageConfig: SQLiteConfig{DSN: ":memory:"}})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		_ = a.Close()
	})

	t.Run("Postgres config inválido", func(t *testing.T) {
		_, err := NewAuditor(Config{StorageType: "postgres", StorageConfig: "wrong"})
		if err == nil {
			t.Fatal("expected error for invalid postgres config")
		}
	})

	t.Run("IA deshabilitado", func(t *testing.T) {
		a, err := NewAuditor(Config{StorageType: "memory", EnableIA: false})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer a.Close()
		if a.iaEngine != nil {
			t.Error("iaEngine should be nil")
		}
	})

	t.Run("Async habilitado", func(t *testing.T) {
		a, err := NewAuditor(Config{StorageType: "memory", EnableAsync: true, AsyncBufferSize: 0})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer a.Close()
		if cap(a.asyncChan) != 1000 {
			t.Errorf("expected default buffer 1000, got %d", cap(a.asyncChan))
		}
	})

	t.Run("Close idempotente", func(t *testing.T) {
		a, err := NewAuditor(Config{StorageType: "memory"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if err := a.Close(); err != nil {
			t.Fatalf("first close failed: %v", err)
		}
		if err := a.Close(); err != nil {
			t.Fatalf("second close should be nil: %v", err)
		}
	})
}

func TestValidateConfig(t *testing.T) {
	if err := validateConfig(&Config{}); err == nil {
		t.Error("expected error for missing storage_type")
	}
	if err := validateConfig(&Config{StorageType: "redis"}); err == nil {
		t.Error("expected error for invalid storage_type")
	}
	if err := validateConfig(&Config{StorageType: "memory", IAMinRiskThreshold: -0.1}); err == nil {
		t.Error("expected error for negative IA threshold")
	}
	if err := validateConfig(&Config{StorageType: "memory", EnableAsync: true, AsyncBufferSize: -2}); err == nil {
		t.Error("expected error for negative async buffer")
	}
	if err := validateConfig(&Config{StorageType: "memory"}); err != nil {
		t.Errorf("valid config should pass: %v", err)
	}
}

func TestCreateStorage(t *testing.T) {
	if _, err := createStorage("memory", nil); err != nil {
		t.Errorf("memory should work: %v", err)
	}
	s, err := createStorage("sqlite", SQLiteConfig{DSN: ":memory:"})
	if err != nil {
		t.Errorf("sqlite should work: %v", err)
	}
	_ = s.Close()
	if _, err := createStorage("sqlite", "wrong"); err == nil {
		t.Error("expected error for invalid sqlite config")
	}
	if _, err := createStorage("postgres", "wrong"); err == nil {
		t.Error("expected error for invalid postgres config")
	}
	if _, err := createStorage("redis", nil); err == nil {
		t.Error("expected error for unsupported storage type")
	}
}

func TestCloseNilStorage(t *testing.T) {
	a, err := NewAuditor(Config{StorageType: "memory"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	a.storage = nil
	if err := a.Close(); err != nil {
		t.Errorf("expected nil error from Close with nil storage, got %v", err)
	}
}

func TestRecordBranches(t *testing.T) {
	t.Run("Auditor cerrado", func(t *testing.T) {
		a, err := NewAuditor(Config{StorageType: "memory"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		_ = a.Close()
		if err := a.Record(&Event{}); err == nil {
			t.Error("expected error recording to closed auditor")
		}
	})

	t.Run("Error del storage", func(t *testing.T) {
		a, err := NewAuditor(Config{StorageType: "memory"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer a.Close()
		a.storage = failStore{saveErr: errors.New("disk full")}
		if err := a.Record(&Event{ID: "x"}); err == nil {
			t.Error("expected storage error")
		}
	})

	t.Run("UUID falla y usa fallback", func(t *testing.T) {
		old := uuidGenerator
		uuidGenerator = func() (string, error) { return "", errors.New("rng broken") }
		defer func() { uuidGenerator = old }()

		a, err := NewAuditor(Config{StorageType: "memory"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer a.Close()
		ev := &Event{}
		if err := a.Record(ev); err != nil {
			t.Fatalf("record failed: %v", err)
		}
		if len(ev.ID) < 5 {
			t.Errorf("expected fallback ID, got %q", ev.ID)
		}
	})

	t.Run("UUID ok asigna id", func(t *testing.T) {
		a, err := NewAuditor(Config{StorageType: "memory"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer a.Close()
		ev := &Event{}
		if err := a.Record(ev); err != nil {
			t.Fatalf("record failed: %v", err)
		}
		if ev.ID == "" {
			t.Error("expected generated ID on success path")
		}
	})

	t.Run("Truncar payload grande", func(t *testing.T) {
		a, err := NewAuditor(Config{StorageType: "memory", MaxPayloadSize: 100})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer a.Close()
		ev := &Event{ID: "big", Context: ContextInfo{PayloadSize: 5000}}
		if err := a.Record(ev); err != nil {
			t.Fatalf("record failed: %v", err)
		}
		if ev.Metadata["payload_truncated"] != true {
			t.Error("expected payload_truncated metadata")
		}
		if ev.Context.PayloadSize != 100 {
			t.Errorf("expected payload capped at 100, got %d", ev.Context.PayloadSize)
		}
	})

	t.Run("Amenazas HIGH/CRITICAL loggeadas", func(t *testing.T) {
		a, err := NewAuditor(Config{StorageType: "memory", EnableIA: true, LogLevel: "info"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer a.Close()
		ip := "10.0.0.77"
		for i := 0; i < bruteForceThreshold; i++ {
			ev := &Event{
				ID:     fmt.Sprintf("bf-%d", i),
				Actor:  ActorInfo{ID: "att", Type: "user"},
				Action: ActionInfo{Type: "LOGIN", Category: "AUTH"},
				Result: ResultInfo{Status: "FAILURE"},
				Context: ContextInfo{IPAddress: ip},
			}
			if err := a.Record(ev); err != nil {
				t.Fatalf("record %d failed: %v", i, err)
			}
		}
		last := QueryFilter{IPAddresses: []string{ip}, ThreatTypes: []string{"BRUTE_FORCE"}, Limit: 10}
		ctx := context.Background()
		events, err := a.Query(ctx, last)
		if err != nil {
			t.Fatalf("query failed: %v", err)
		}
		if len(events) == 0 {
			t.Fatal("expected a brute-force threat event")
		}
	})
}

func TestRecordAsyncBranches(t *testing.T) {
	t.Run("Auditor cerrado", func(t *testing.T) {
		a, err := NewAuditor(Config{StorageType: "memory", EnableAsync: true})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		_ = a.Close()
		if err := a.RecordAsync(&Event{}); err == nil {
			t.Error("expected error for closed auditor")
		}
	})

	t.Run("Async no habilitado", func(t *testing.T) {
		a, err := NewAuditor(Config{StorageType: "memory"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer a.Close()
		if err := a.RecordAsync(&Event{}); err == nil {
			t.Error("expected error when async not enabled")
		}
	})

	t.Run("Buffer lleno", func(t *testing.T) {
		a := &Auditor{asyncChan: make(chan *Event, 1)}
		a.asyncChan <- &Event{ID: "first"}
		if err := a.RecordAsync(&Event{ID: "second"}); err == nil {
			t.Error("expected buffer full error")
		}
	})
}

func TestAsyncProcessor(t *testing.T) {
	t.Run("Procesa eventos", func(t *testing.T) {
		a, err := NewAuditor(Config{StorageType: "memory", EnableAsync: true, AsyncBufferSize: 2})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer a.Close()
		if err := a.RecordAsync(&Event{ID: "a1", Actor: ActorInfo{ID: "u1"}}); err != nil {
			t.Fatalf("async record failed: %v", err)
		}
		if err := a.RecordAsync(&Event{ID: "a2", Actor: ActorInfo{ID: "u1"}}); err != nil {
			t.Fatalf("async record failed: %v", err)
		}
		deadline := time.Now().Add(2 * time.Second)
		for a.GetStats().TotalEvents < 2 && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
		}
		if a.GetStats().TotalEvents != 2 {
			t.Errorf("expected 2 processed events, got %d", a.GetStats().TotalEvents)
		}
	})

	t.Run("Cerrar no bloquea", func(t *testing.T) {
		for i := 0; i < 10; i++ {
			a, err := NewAuditor(Config{StorageType: "memory", EnableAsync: true, AsyncBufferSize: 1})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if err := a.RecordAsync(&Event{ID: fmt.Sprintf("drain-%d", i), Actor: ActorInfo{ID: "u"}}); err != nil {
				t.Fatalf("async record failed: %v", err)
			}
			// Close espera al procesador; no debe bloquear indefinidamente
			done := make(chan struct{})
			go func() {
				_ = a.Close()
				close(done)
			}()
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Fatal("Close blocked waiting for async processor")
			}
		}
	})

	t.Run("Error al procesar", func(t *testing.T) {
		for i := 0; i < 30; i++ {
			ctx, cancel := context.WithCancel(context.Background())
			a := &Auditor{
				config:    Config{StorageType: "memory"},
				storage:   failStore{saveErr: errors.New("boom")},
				logger:    logger.GetDefault(),
				ctx:       ctx,
				cancel:    cancel,
				asyncChan: make(chan *Event, 1),
			}
			a.asyncChan <- &Event{ID: "fail-ev"}
			a.cancel()
			a.wg.Add(1)
			go a.asyncProcessor()
			a.wg.Wait()
		}
	})
}

// TestQueryDefaults prueba los valores por defecto de Query
func TestQueryDefaults(t *testing.T) {
	a, err := NewAuditor(Config{StorageType: "memory"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer a.Close()

	cap := &capturingStore{Storage: a.storage}
	a.storage = cap
	ctx := context.Background()

	if _, err := a.Query(ctx, QueryFilter{}); err != nil {
		t.Fatalf("query failed: %v", err)
	}
	if cap.lastQuery.Limit != 100 {
		t.Errorf("expected default limit 100, got %d", cap.lastQuery.Limit)
	}
	if cap.lastQuery.SortBy != "timestamp" {
		t.Errorf("expected default sort_by timestamp, got %q", cap.lastQuery.SortBy)
	}
	if cap.lastQuery.SortOrder != "desc" {
		t.Errorf("expected default sort_order desc, got %q", cap.lastQuery.SortOrder)
	}

	if _, err := a.Query(ctx, QueryFilter{Limit: 5000}); err != nil {
		t.Fatalf("query failed: %v", err)
	}
	if cap.lastQuery.Limit != 1000 {
		t.Errorf("expected limit capped at 1000, got %d", cap.lastQuery.Limit)
	}
}

func TestAuditorClosedMethods(t *testing.T) {
	a, err := NewAuditor(Config{StorageType: "memory"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_ = a.Close()
	ctx := context.Background()

	if _, err := a.Query(ctx, QueryFilter{}); err == nil {
		t.Error("expected error on closed auditor Query")
	}
	if _, err := a.GetByID(ctx, "x"); err == nil {
		t.Error("expected error on closed auditor GetByID")
	}
	if _, err := a.Count(ctx, QueryFilter{}); err == nil {
		t.Error("expected error on closed auditor Count")
	}
	var buf sink
	if err := a.Export(ctx, QueryFilter{}, ExportFormatJSON, &buf); err == nil {
		t.Error("expected error on closed auditor Export")
	}
}

type sink struct{}

func (s sink) Write(p []byte) (int, error) { return len(p), nil }

func TestGetByIDAndCount(t *testing.T) {
	a, err := NewAuditor(Config{StorageType: "memory"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer a.Close()
	ctx := context.Background()

	ev := &Event{ID: "ev-1", Actor: ActorInfo{ID: "u1"}, Action: ActionInfo{Type: "LOGIN"}}
	if err := a.Record(ev); err != nil {
		t.Fatalf("record failed: %v", err)
	}
	got, err := a.GetByID(ctx, "ev-1")
	if err != nil {
		t.Fatalf("getbyid failed: %v", err)
	}
	if got.ID != "ev-1" {
		t.Errorf("expected ev-1, got %q", got.ID)
	}
	if _, err := a.GetByID(ctx, "missing"); err == nil {
		t.Error("expected not found error")
	}
	n, err := a.Count(ctx, QueryFilter{ActorIDs: []string{"u1"}})
	if err != nil {
		t.Fatalf("count failed: %v", err)
	}
	if n != 1 {
		t.Errorf("expected count 1, got %d", n)
	}
}

func TestGetStatsBranches(t *testing.T) {
	a, err := NewAuditor(Config{StorageType: "memory"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer a.Close()
	// Sin eventos: avgRisk 0
	stats := a.GetStats()
	if stats.AverageRiskScore != 0 {
		t.Errorf("expected avg risk 0, got %v", stats.AverageRiskScore)
	}
	// Con eventos: avgRisk calculado y counts de última hora/día
	if err := a.Record(&Event{ID: "s1", Actor: ActorInfo{ID: "u"}, Timestamp: time.Now().UTC()}); err != nil {
		t.Fatalf("record failed: %v", err)
	}
	stats = a.GetStats()
	if stats.TotalEvents != 1 {
		t.Errorf("expected 1 event, got %d", stats.TotalEvents)
	}
	if stats.EventsLastHour != 1 {
		t.Errorf("expected 1 event last hour, got %d", stats.EventsLastHour)
	}
	if stats.EventsLastDay != 1 {
		t.Errorf("expected 1 event last day, got %d", stats.EventsLastDay)
	}
}

func TestRetentionMaintenance(t *testing.T) {
	oldInterval := retentionCheckInterval.Load()
	defer func() { retentionCheckInterval.Store(oldInterval) }()

	t.Run("Elimina eventos antiguos", func(t *testing.T) {
		retentionCheckInterval.Store(int64(20 * time.Millisecond))
		a, err := NewAuditor(Config{StorageType: "memory", Retention: RetentionPolicy{MaxAgeDays: 1}})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer a.Close()
		old := &Event{ID: "old", Timestamp: time.Now().Add(-48 * time.Hour)}
		recent := &Event{ID: "recent", Timestamp: time.Now()}
		if err := a.Record(old); err != nil {
			t.Fatalf("record failed: %v", err)
		}
		if err := a.Record(recent); err != nil {
			t.Fatalf("record failed: %v", err)
		}
		go a.retentionMaintenance()
		time.Sleep(80 * time.Millisecond)
		ctx := context.Background()
		events, err := a.Query(ctx, QueryFilter{Limit: 10})
		if err != nil {
			t.Fatalf("query failed: %v", err)
		}
		if len(events) != 1 || events[0].ID != "recent" {
			t.Errorf("expected only recent event, got %d events", len(events))
		}
	})

	t.Run("Error al eliminar", func(t *testing.T) {
		retentionCheckInterval.Store(int64(20 * time.Millisecond))
		ctx, cancel := context.WithCancel(context.Background())
		a := &Auditor{
			config:  Config{StorageType: "memory", Retention: RetentionPolicy{MaxAgeDays: 1}},
			storage: failStore{deleteErr: errors.New("db locked")},
			logger:  logger.GetDefault(),
			ctx:     ctx,
			cancel:  cancel,
		}
		go a.retentionMaintenance()
		time.Sleep(60 * time.Millisecond)
		a.cancel()
	})

	t.Run("MaxAgeDays 0 no elimina", func(t *testing.T) {
		retentionCheckInterval.Store(int64(20 * time.Millisecond))
		a, err := NewAuditor(Config{StorageType: "memory"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer a.Close()
		go a.retentionMaintenance()
		time.Sleep(60 * time.Millisecond)
	})
}
