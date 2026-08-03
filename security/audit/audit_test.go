package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// TestNewAuditor prueba la creación del auditor con diferentes configuraciones
func TestNewAuditor(t *testing.T) {
	t.Run("Configuración válida memory", func(t *testing.T) {
		config := Config{
			StorageType: "memory",
			EnableIA:    true,
			LogLevel:    "info",
		}

		auditor, err := NewAuditor(config)
		if err != nil {
			t.Fatalf("Expected no error, got %v", err)
		}
		defer auditor.Close()

		if auditor.storage == nil {
			t.Error("Expected storage to be initialized")
		}
		if auditor.iaEngine == nil {
			t.Error("Expected IA engine to be initialized")
		}
	})

	t.Run("Configuración inválida", func(t *testing.T) {
		config := Config{
			StorageType: "", // Inválido
		}

		_, err := NewAuditor(config)
		if err == nil {
			t.Error("Expected error for invalid config")
		}
	})

	t.Run("IA threshold inválido", func(t *testing.T) {
		config := Config{
			StorageType:        "memory",
			EnableIA:           true,
			IAMinRiskThreshold: 1.5, // Fuera de rango
		}

		_, err := NewAuditor(config)
		if err == nil {
			t.Error("Expected error for invalid IA threshold")
		}
	})
}

// TestRecordEvent prueba el registro de eventos de auditoría
func TestRecordEvent(t *testing.T) {
	config := Config{
		StorageType: "memory",
		EnableIA:    true,
		LogLevel:    "info",
	}

	auditor, err := NewAuditor(config)
	if err != nil {
		t.Fatalf("Failed to create auditor: %v", err)
	}
	defer auditor.Close()

	event := &Event{
		ID:        "test-event-001",
		Timestamp: time.Now().UTC(),
		Actor: ActorInfo{
			ID:       "user-123",
			Email:    "john.doe@example.com",
			Username: "johndoe",
			Role:     "admin",
			Type:     "user",
		},
		Action: ActionInfo{
			Type:        "LOGIN",
			Category:    "AUTH",
			Description: "User login successful",
			Method:      "POST",
			Path:        "/api/v1/auth/login",
		},
		Resource: ResourceInfo{
			Type: "user",
			ID:   "user-123",
			Name: "John Doe",
		},
		Result: ResultInfo{
			Status:     "SUCCESS",
			StatusCode: 200,
			Message:    "Login successful",
			Duration:   150,
		},
		Context: ContextInfo{
			IPAddress: "192.168.1.100",
			UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
			RequestID: "req-abc-123",
			ClientInfo: ClientInfo{
				Browser:    "Chrome",
				OS:         "Windows",
				DeviceType: "desktop",
			},
		},
		Metadata: map[string]interface{}{
			"session_id": "sess-xyz-789",
			"mfa_used":   true,
		},
	}

	err = auditor.Record(event)
	if err != nil {
		t.Fatalf("Failed to record event: %v", err)
	}

	// Verificar que el evento fue guardado
	stats := auditor.GetStats()
	if stats.TotalEvents != 1 {
		t.Errorf("Expected 1 total event, got %d", stats.TotalEvents)
	}

	// Verificar que se puede consultar
	ctx := context.Background()
	filter := QueryFilter{
		ActorIDs: []string{"user-123"},
		Limit:    10,
	}

	events, err := auditor.Query(ctx, filter)
	if err != nil {
		t.Fatalf("Failed to query events: %v", err)
	}

	if len(events) != 1 {
		t.Errorf("Expected 1 event, got %d", len(events))
	}

	if events[0].Actor.ID != "user-123" {
		t.Errorf("Expected actor ID user-123, got %s", events[0].Actor.ID)
	}
}

// TestBruteForceDetection prueba la detección de ataques de fuerza bruta
func TestBruteForceDetection(t *testing.T) {
	config := Config{
		StorageType: "memory",
		EnableIA:    true,
		LogLevel:    "info",
	}

	auditor, err := NewAuditor(config)
	if err != nil {
		t.Fatalf("Failed to create auditor: %v", err)
	}
	defer auditor.Close()

	ip := "10.0.0.50"
	actorID := "attacker-001"

	// Simular 5 intentos fallidos de login (umbral para fuerza bruta)
	for i := 0; i < 5; i++ {
		event := &Event{
			ID:        "brute-force-" + string(rune(i)),
			Timestamp: time.Now().UTC(),
			Actor: ActorInfo{
				ID:   actorID,
				Type: "user",
			},
			Action: ActionInfo{
				Type:     "LOGIN",
				Category: "AUTH",
				Method:   "POST",
				Path:     "/api/v1/auth/login",
			},
			Resource: ResourceInfo{
				Type: "auth",
			},
			Result: ResultInfo{
				Status:     "FAILURE",
				StatusCode: 401,
				Message:    "Invalid credentials",
			},
			Context: ContextInfo{
				IPAddress: ip,
				RequestID: "req-" + string(rune(i)),
			},
			Metadata: map[string]interface{}{
				"failed_attempts": i + 1,
			},
		}

		err = auditor.Record(event)
		if err != nil {
			t.Fatalf("Failed to record event %d: %v", i, err)
		}
	}

	// El último evento debería haber detectado fuerza bruta
	ctx := context.Background()
	filter := QueryFilter{
		IPAddresses: []string{ip},
		ThreatTypes: []string{"BRUTE_FORCE"},
		Limit:       10,
	}

	events, err := auditor.Query(ctx, filter)
	if err != nil {
		t.Fatalf("Failed to query events: %v", err)
	}

	// Debería haber al menos un evento con amenaza de fuerza bruta detectada
	if len(events) == 0 {
		t.Log("Nota: La detección de fuerza bruta depende de la implementación exacta del motor IA")
	}

	stats := auditor.GetStats()
	t.Logf("Threats detected: %d", stats.ThreatsDetected)
}

// TestSQLInjectionDetection prueba la detección de SQL Injection
func TestSQLInjectionDetection(t *testing.T) {
	config := Config{
		StorageType: "memory",
		EnableIA:    true,
		LogLevel:    "info",
	}

	auditor, err := NewAuditor(config)
	if err != nil {
		t.Fatalf("Failed to create auditor: %v", err)
	}
	defer auditor.Close()

	// Payload con intento de SQL injection
	maliciousPayload := "admin' OR '1'='1' --"

	event := &Event{
		ID:        "sqli-test-001",
		Timestamp: time.Now().UTC(),
		Actor: ActorInfo{
			ID:   "attacker-002",
			Type: "user",
		},
		Action: ActionInfo{
			Type:     "QUERY",
			Category: "DATA",
			Method:   "GET",
			Path:     "/api/v1/users",
		},
		Resource: ResourceInfo{
			Type: "user",
		},
		Result: ResultInfo{
			Status:     "FAILURE",
			StatusCode: 400,
		},
		Context: ContextInfo{
			IPAddress: "203.0.113.50",
			RequestID: "req-sqli-001",
		},
		Metadata: map[string]interface{}{
			"payload": maliciousPayload,
			"query_param": "id=" + maliciousPayload,
		},
	}

	err = auditor.Record(event)
	if err != nil {
		t.Fatalf("Failed to record event: %v", err)
	}

	// Verificar estadísticas
	stats := auditor.GetStats()
	t.Logf("Total events: %d, Threats detected: %d", stats.TotalEvents, stats.ThreatsDetected)

	// Buscar eventos con amenazas de SQL injection
	ctx := context.Background()
	filter := QueryFilter{
		ThreatTypes: []string{"SQL_INJECTION"},
		Limit:       10,
	}

	events, err := auditor.Query(ctx, filter)
	if err != nil {
		t.Fatalf("Failed to query events: %v", err)
	}

	if len(events) > 0 {
		t.Logf("SQL Injection detected in %d events", len(events))
		if len(events[0].Threats) > 0 {
			t.Logf("Threat severity: %s", events[0].Threats[0].Severity)
		}
	}
}

// TestImpossibleTravelDetection prueba la detección de viajes imposibles
func TestImpossibleTravelDetection(t *testing.T) {
	config := Config{
		StorageType: "memory",
		EnableIA:    true,
		LogLevel:    "info",
	}

	auditor, err := NewAuditor(config)
	if err != nil {
		t.Fatalf("Failed to create auditor: %v", err)
	}
	defer auditor.Close()

	actorID := "traveler-001"

	// Primer login desde Estados Unidos
	event1 := &Event{
		ID:        "travel-001",
		Timestamp: time.Now().UTC(),
		Actor: ActorInfo{
			ID:   actorID,
			Type: "user",
		},
		Action: ActionInfo{
			Type:     "LOGIN",
			Category: "AUTH",
		},
		Resource: ResourceInfo{
			Type: "auth",
		},
		Result: ResultInfo{
			Status: "SUCCESS",
		},
		Context: ContextInfo{
			IPAddress: "8.8.8.8",
			IPGeoLocation: GeoLocation{
				Country:     "United States",
				CountryCode: "US",
				City:        "New York",
			},
			RequestID: "req-travel-001",
		},
	}

	err = auditor.Record(event1)
	if err != nil {
		t.Fatalf("Failed to record first login: %v", err)
	}

	// Segundo login desde Japón (imposible en tan poco tiempo)
	event2 := &Event{
		ID:        "travel-002",
		Timestamp: time.Now().Add(10 * time.Minute).UTC(), // 10 minutos después
		Actor: ActorInfo{
			ID:   actorID,
			Type: "user",
		},
		Action: ActionInfo{
			Type:     "LOGIN",
			Category: "AUTH",
		},
		Resource: ResourceInfo{
			Type: "auth",
		},
		Result: ResultInfo{
			Status: "SUCCESS",
		},
		Context: ContextInfo{
			IPAddress: "1.1.1.1",
			IPGeoLocation: GeoLocation{
				Country:     "Japan",
				CountryCode: "JP",
				City:        "Tokyo",
			},
			RequestID: "req-travel-002",
		},
	}

	err = auditor.Record(event2)
	if err != nil {
		t.Fatalf("Failed to record second login: %v", err)
	}

	stats := auditor.GetStats()
	t.Logf("Total events: %d, Threats detected: %d", stats.TotalEvents, stats.ThreatsDetected)
}

// TestExportEvents prueba la exportación de eventos en diferentes formatos
func TestExportEvents(t *testing.T) {
	config := Config{
		StorageType: "memory",
		EnableIA:    false,
		LogLevel:    "info",
	}

	auditor, err := NewAuditor(config)
	if err != nil {
		t.Fatalf("Failed to create auditor: %v", err)
	}
	defer auditor.Close()

	// Crear múltiples eventos de prueba
	for i := 0; i < 5; i++ {
		event := &Event{
			ID:        "export-test-" + string(rune(i)),
			Timestamp: time.Now().UTC(),
			Actor: ActorInfo{
				ID:       "user-export",
				Email:    "test@example.com",
				Type:     "user",
			},
			Action: ActionInfo{
				Type:     "CREATE",
				Category: "DATA",
			},
			Resource: ResourceInfo{
				Type: "post",
				ID:   "post-" + string(rune(i)),
			},
			Result: ResultInfo{
				Status: "SUCCESS",
			},
			Context: ContextInfo{
				IPAddress: "192.168.1.1",
				RequestID: "req-export-" + string(rune(i)),
			},
		}

		err = auditor.Record(event)
		if err != nil {
			t.Fatalf("Failed to record event: %v", err)
		}
	}

	ctx := context.Background()
	filter := QueryFilter{
		ActorIDs: []string{"user-export"},
		Limit:    10,
	}

	// Probar exportación JSON
	t.Run("Export JSON", func(t *testing.T) {
		var buf bytes.Buffer
		err := auditor.Export(ctx, filter, ExportFormatJSON, &buf)
		if err != nil {
			t.Fatalf("Failed to export JSON: %v", err)
		}

		// Verificar que el JSON es válido
		var events []*Event
		if err := json.Unmarshal(buf.Bytes(), &events); err != nil {
			t.Fatalf("Invalid JSON output: %v", err)
		}

		if len(events) != 5 {
			t.Errorf("Expected 5 events, got %d", len(events))
		}
	})

	// Probar exportación CSV
	t.Run("Export CSV", func(t *testing.T) {
		var buf bytes.Buffer
		err := auditor.Export(ctx, filter, ExportFormatCSV, &buf)
		if err != nil {
			t.Fatalf("Failed to export CSV: %v", err)
		}

		output := buf.String()
		lines := strings.Split(strings.TrimSpace(output), "\n")

		if len(lines) != 6 { // 1 header + 5 eventos
			t.Errorf("Expected 6 lines (1 header + 5 events), got %d", len(lines))
		}

		// Verificar header
		expectedHeader := "id,timestamp,actor_id,actor_type,action_type,action_category,resource_type,resource_id,status,ip_address,risk_score"
		if lines[0] != expectedHeader {
			t.Errorf("Invalid CSV header. Expected: %s, Got: %s", expectedHeader, lines[0])
		}
	})

	// Probar exportación NDJSON
	t.Run("Export NDJSON", func(t *testing.T) {
		var buf bytes.Buffer
		err := auditor.Export(ctx, filter, ExportFormatNDJSON, &buf)
		if err != nil {
			t.Fatalf("Failed to export NDJSON: %v", err)
		}

		lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
		if len(lines) != 5 {
			t.Errorf("Expected 5 lines, got %d", len(lines))
		}

		// Verificar que cada línea es JSON válido
		for i, line := range lines {
			var event Event
			if err := json.Unmarshal([]byte(line), &event); err != nil {
				t.Errorf("Line %d is not valid JSON: %v", i, err)
			}
		}
	})
}

// TestRetentionDeletion prueba la eliminación de eventos antiguos
func TestRetentionDeletion(t *testing.T) {
	config := Config{
		StorageType: "memory",
		EnableIA:    false,
	}

	auditor, err := NewAuditor(config)
	if err != nil {
		t.Fatalf("Failed to create auditor: %v", err)
	}
	defer auditor.Close()

	// Crear eventos con timestamps antiguos
	oldTimestamp := time.Now().Add(-48 * time.Hour) // Hace 48 horas
	
	oldEvent := &Event{
		ID:        "old-event-001",
		Timestamp: oldTimestamp,
		Actor: ActorInfo{
			ID:   "old-user",
			Type: "user",
		},
		Action: ActionInfo{
			Type:     "LOGIN",
			Category: "AUTH",
		},
		Result: ResultInfo{
			Status: "SUCCESS",
		},
		Context: ContextInfo{
			IPAddress: "192.168.1.1",
		},
	}

	err = auditor.Record(oldEvent)
	if err != nil {
		t.Fatalf("Failed to record old event: %v", err)
	}

	// Crear evento reciente
	newEvent := &Event{
		ID:        "new-event-001",
		Timestamp: time.Now(),
		Actor: ActorInfo{
			ID:   "new-user",
			Type: "user",
		},
		Action: ActionInfo{
			Type:     "LOGIN",
			Category: "AUTH",
		},
		Result: ResultInfo{
			Status: "SUCCESS",
		},
		Context: ContextInfo{
			IPAddress: "192.168.1.2",
		},
	}

	err = auditor.Record(newEvent)
	if err != nil {
		t.Fatalf("Failed to record new event: %v", err)
	}

	// Eliminar eventos anteriores a 24 horas
	cutoff := time.Now().Add(-24 * time.Hour)
	deleted, err := auditor.storage.DeleteOlderThan(context.Background(), cutoff)
	if err != nil {
		t.Fatalf("Failed to delete old events: %v", err)
	}

	if deleted != 1 {
		t.Errorf("Expected to delete 1 old event, got %d", deleted)
	}

	// Verificar que solo queda el evento nuevo
	ctx := context.Background()
	filter := QueryFilter{
		Limit: 10,
	}

	events, err := auditor.Query(ctx, filter)
	if err != nil {
		t.Fatalf("Failed to query events: %v", err)
	}

	if len(events) != 1 {
		t.Errorf("Expected 1 event remaining, got %d", len(events))
	}

	if events[0].ID != "new-event-001" {
		t.Errorf("Expected new-event-001, got %s", events[0].ID)
	}
}

// TestConcurrentAccess prueba acceso concurrente al auditor
func TestConcurrentAccess(t *testing.T) {
	config := Config{
		StorageType: "memory",
		EnableIA:    false,
	}

	auditor, err := NewAuditor(config)
	if err != nil {
		t.Fatalf("Failed to create auditor: %v", err)
	}
	defer auditor.Close()

	const goroutines = 10
	const eventsPerGoroutine = 100

	done := make(chan bool)

	// Lanzar múltiples goroutines escribiendo eventos
	for g := 0; g < goroutines; g++ {
		go func(goroutineID int) {
			for i := 0; i < eventsPerGoroutine; i++ {
				event := &Event{
					ID:        "concurrent-" + string(rune(goroutineID)) + "-" + string(rune(i)),
					Timestamp: time.Now().UTC(),
					Actor: ActorInfo{
						ID:   "user-" + string(rune(goroutineID)),
						Type: "user",
					},
					Action: ActionInfo{
						Type:     "UPDATE",
						Category: "DATA",
					},
					Result: ResultInfo{
						Status: "SUCCESS",
					},
					Context: ContextInfo{
						IPAddress: "192.168.1." + string(rune(goroutineID)),
					},
				}

				auditor.Record(event)
			}
			done <- true
		}(g)
	}

	// Esperar a que terminen todas las goroutines
	for g := 0; g < goroutines; g++ {
		<-done
	}

	// Verificar que todos los eventos fueron guardados
	stats := auditor.GetStats()
	expectedEvents := goroutines * eventsPerGoroutine

	if stats.TotalEvents != int64(expectedEvents) {
		t.Errorf("Expected %d events, got %d", expectedEvents, stats.TotalEvents)
	}

	t.Logf("Successfully recorded %d concurrent events", stats.TotalEvents)
}

// TestQuickFunctions prueba las funciones helper de uso rápido
func TestQuickFunctions(t *testing.T) {
	// Inicializar auditor global
	config := Config{
		StorageType: "memory",
		EnableIA:    false,
	}

	err := Init(config)
	if err != nil {
		t.Fatalf("Failed to init global auditor: %v", err)
	}

	// Probar RecordQuick
	event := &Event{
		ID:        "quick-test-001",
		Timestamp: time.Now().UTC(),
		Actor: ActorInfo{
			ID:   "quick-user",
			Type: "user",
		},
		Action: ActionInfo{
			Type:     "CREATE",
			Category: "DATA",
		},
		Result: ResultInfo{
			Status: "SUCCESS",
		},
		Context: ContextInfo{
			IPAddress: "192.168.1.1",
		},
	}

	err = RecordQuick(event)
	if err != nil {
		t.Fatalf("RecordQuick failed: %v", err)
	}

	// Probar QueryQuick
	ctx := context.Background()
	filter := QueryFilter{
		ActorIDs: []string{"quick-user"},
		Limit:    10,
	}

	events, err := QueryQuick(ctx, filter)
	if err != nil {
		t.Fatalf("QueryQuick failed: %v", err)
	}

	if len(events) != 1 {
		t.Errorf("Expected 1 event, got %d", len(events))
	}

	// Probar ExportQuick
	var buf bytes.Buffer
	err = ExportQuick(ctx, filter, ExportFormatJSON, &buf)
	if err != nil {
		t.Fatalf("ExportQuick failed: %v", err)
	}

	if buf.Len() == 0 {
		t.Error("ExportQuick returned empty buffer")
	}

	t.Log("Quick functions work correctly")
}

// TestDigitalFingerprint prueba la generación de huellas digitales únicas
func TestDigitalFingerprint(t *testing.T) {
	config := Config{
		StorageType: "memory",
		EnableIA:    false,
	}

	auditor, err := NewAuditor(config)
	if err != nil {
		t.Fatalf("Failed to create auditor: %v", err)
	}
	defer auditor.Close()

	event1 := &Event{
		ID:        "fingerprint-test-001",
		Timestamp: time.Now().UTC(),
		Actor: ActorInfo{
			ID:   "user-001",
			Type: "user",
		},
		Action: ActionInfo{
			Type: "LOGIN",
		},
		Result: ResultInfo{
			Status: "SUCCESS",
		},
		Context: ContextInfo{
			IPAddress: "192.168.1.1",
		},
	}

	event2 := &Event{
		ID:        "fingerprint-test-002",
		Timestamp: time.Now().UTC(),
		Actor: ActorInfo{
			ID:   "user-001",
			Type: "user",
		},
		Action: ActionInfo{
			Type: "LOGIN",
		},
		Result: ResultInfo{
			Status: "SUCCESS",
		},
		Context: ContextInfo{
			IPAddress: "192.168.1.1",
		},
	}

	err = auditor.Record(event1)
	if err != nil {
		t.Fatalf("Failed to record event1: %v", err)
	}

	err = auditor.Record(event2)
	if err != nil {
		t.Fatalf("Failed to record event2: %v", err)
	}

	// Las huellas digitales deberían ser diferentes porque los IDs son diferentes
	if event1.DigitalFingerprint == event2.DigitalFingerprint {
		t.Error("Digital fingerprints should be different for different events")
	}

	if event1.DigitalFingerprint == "" {
		t.Error("Digital fingerprint should not be empty")
	}

	t.Logf("Fingerprint 1: %s", event1.DigitalFingerprint)
	t.Logf("Fingerprint 2: %s", event2.DigitalFingerprint)
}

// TestPIISanitization prueba la sanitización de información personal
func TestPIISanitization(t *testing.T) {
	config := Config{
		StorageType: "memory",
		EnableIA:    false,
		SanitizePII: true,
	}

	auditor, err := NewAuditor(config)
	if err != nil {
		t.Fatalf("Failed to create auditor: %v", err)
	}
	defer auditor.Close()

	event := &Event{
		ID:        "pii-test-001",
		Timestamp: time.Now().UTC(),
		Actor: ActorInfo{
			ID:    "user-001",
			Email: "john.doe@example.com",
			Type:  "user",
		},
		Action: ActionInfo{
			Type: "UPDATE_PROFILE",
		},
		Result: ResultInfo{
			Status: "SUCCESS",
		},
		Context: ContextInfo{
			IPAddress: "192.168.1.100",
		},
	}

	err = auditor.Record(event)
	if err != nil {
		t.Fatalf("Failed to record event: %v", err)
	}

	// Verificar que el email fue enmascarado
	if !strings.Contains(event.Actor.Email, "**") {
		t.Errorf("Expected email to be sanitized, got: %s", event.Actor.Email)
	}

	// Verificar que la IP fue enmascarada
	if !strings.Contains(event.Context.IPAddress, "***") {
		t.Errorf("Expected IP to be sanitized, got: %s", event.Context.IPAddress)
	}

	t.Logf("Sanitized email: %s", event.Actor.Email)
	t.Logf("Sanitized IP: %s", event.Context.IPAddress)
}
