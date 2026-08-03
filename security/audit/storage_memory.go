package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
)

// MemoryStorage implementa Storage usando memoria RAM (ideal para tests)
type MemoryStorage struct {
	events map[string]*Event
	mu     sync.RWMutex
	index  map[string][]string // Índice por campo: actor_id -> [event_ids]
}

// NewMemoryStorage crea un nuevo storage en memoria
func NewMemoryStorage() *MemoryStorage {
	return &MemoryStorage{
		events: make(map[string]*Event),
		index:  make(map[string][]string),
	}
}

// Save guarda un evento individual
func (s *MemoryStorage) Save(ctx context.Context, event *Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.events[event.ID] = event

	// Actualizar índices
	s.indexEvent(event)

	return nil
}

// SaveBatch guarda múltiples eventos
func (s *MemoryStorage) SaveBatch(ctx context.Context, events []*Event) error {
	for _, event := range events {
		if err := s.Save(ctx, event); err != nil {
			return err
		}
	}
	return nil
}

// GetByID obtiene un evento por su ID
func (s *MemoryStorage) GetByID(ctx context.Context, id string) (*Event, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	event, exists := s.events[id]
	if !exists {
		return nil, fmt.Errorf("event not found: %s", id)
	}

	return event, nil
}

// Query consulta eventos con filtros
func (s *MemoryStorage) Query(ctx context.Context, filter QueryFilter) ([]*Event, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var results []*Event

	for _, event := range s.events {
		if s.matchesFilter(event, filter) {
			results = append(results, event)
		}
	}

	// Ordenar resultados
	s.sortResults(results, filter.SortBy, filter.SortOrder)

	// Aplicar paginación
	start := filter.Offset
	if start > len(results) {
		start = len(results)
	}
	end := start + filter.Limit
	if end > len(results) {
		end = len(results)
	}

	return results[start:end], nil
}

// Count cuenta eventos que coinciden con los filtros
func (s *MemoryStorage) Count(ctx context.Context, filter QueryFilter) (int64, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	count := int64(0)
	for _, event := range s.events {
		if s.matchesFilter(event, filter) {
			count++
		}
	}

	return count, nil
}

// DeleteOlderThan elimina eventos anteriores a una fecha
func (s *MemoryStorage) DeleteOlderThan(ctx context.Context, timestamp time.Time) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	deleted := int64(0)
	for id, event := range s.events {
		if event.Timestamp.Before(timestamp) {
			delete(s.events, id)
			deleted++
		}
	}

	return deleted, nil
}

// Export exporta eventos a un formato específico
func (s *MemoryStorage) Export(ctx context.Context, filter QueryFilter, format ExportFormat, writer io.Writer) error {
	events, err := s.Query(ctx, filter)
	if err != nil {
		return err
	}

	switch format {
	case ExportFormatJSON:
		return s.exportJSON(events, writer)
	case ExportFormatCSV:
		return s.exportCSV(events, writer)
	case ExportFormatNDJSON:
		return s.exportNDJSON(events, writer)
	default:
		return fmt.Errorf("unsupported export format: %s", format)
	}
}

// Close cierra el storage (limpia memoria)
func (s *MemoryStorage) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = make(map[string]*Event)
	s.index = make(map[string][]string)
	return nil
}

// indexEvent actualiza los índices para un evento
func (s *MemoryStorage) indexEvent(event *Event) {
	// Índice por actor ID
	if event.Actor.ID != "" {
		key := "actor:" + event.Actor.ID
		s.index[key] = append(s.index[key], event.ID)
	}

	// Índice por IP
	if event.Context.IPAddress != "" {
		key := "ip:" + event.Context.IPAddress
		s.index[key] = append(s.index[key], event.ID)
	}

	// Índice por tipo de acción
	key := "action:" + event.Action.Type
	s.index[key] = append(s.index[key], event.ID)
}

// matchesFilter verifica si un evento coincide con los filtros
func (s *MemoryStorage) matchesFilter(event *Event, filter QueryFilter) bool {
	// Filtro por IDs de eventos
	if len(filter.EventIDs) > 0 {
		found := false
		for _, id := range filter.EventIDs {
			if event.ID == id {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Filtro por IDs de actores
	if len(filter.ActorIDs) > 0 {
		found := false
		for _, id := range filter.ActorIDs {
			if event.Actor.ID == id {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Filtro por tipos de acción
	if len(filter.ActionTypes) > 0 {
		found := false
		for _, actionType := range filter.ActionTypes {
			if event.Action.Type == actionType {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Filtro por categorías de acción
	if len(filter.ActionCategories) > 0 {
		found := false
		for _, category := range filter.ActionCategories {
			if event.Action.Category == category {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Filtro por status
	if len(filter.Statuses) > 0 {
		found := false
		for _, status := range filter.Statuses {
			if event.Result.Status == status {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Filtro por IPs
	if len(filter.IPAddresses) > 0 {
		found := false
		for _, ip := range filter.IPAddresses {
			if event.Context.IPAddress == ip {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Filtro por tipos de amenaza
	if len(filter.ThreatTypes) > 0 {
		found := false
		for _, threat := range event.Threats {
			for _, filterType := range filter.ThreatTypes {
				if threat.Type == filterType {
					found = true
					break
				}
			}
			if found {
				break
			}
		}
		if !found && len(event.Threats) > 0 {
			return false
		}
	}

	// Filtro por score de riesgo mínimo
	if filter.MinRiskScore > 0 {
		if event.RiskScore < filter.MinRiskScore {
			return false
		}
	}

	// Filtro por rango de tiempo
	if !filter.StartTime.IsZero() && event.Timestamp.Before(filter.StartTime) {
		return false
	}
	if !filter.EndTime.IsZero() && event.Timestamp.After(filter.EndTime) {
		return false
	}

	// Búsqueda full-text
	if filter.SearchQuery != "" {
		if !s.searchInEvent(event, filter.SearchQuery) {
			return false
		}
	}

	return true
}

// searchInEvent busca una cadena en los campos del evento
func (s *MemoryStorage) searchInEvent(event *Event, query string) bool {
	query = strings.ToLower(query)

	// Buscar en campos principales
	fieldsToSearch := []string{
		event.ID,
		event.Actor.ID,
		event.Actor.Email,
		event.Actor.Username,
		event.Action.Type,
		event.Action.Description,
		event.Resource.Type,
		event.Resource.ID,
		event.Result.Message,
		event.Context.IPAddress,
	}

	for _, field := range fieldsToSearch {
		if strings.Contains(strings.ToLower(field), query) {
			return true
		}
	}

	// Buscar en amenazas
	for _, threat := range event.Threats {
		if strings.Contains(strings.ToLower(threat.Type), query) ||
			strings.Contains(strings.ToLower(threat.Description), query) {
			return true
		}
	}

	return false
}

// sortResults ordena los resultados
func (s *MemoryStorage) sortResults(events []*Event, sortBy, sortOrder string) {
	// Implementación simple de ordenamiento
	// En producción usaría sort.Slice con comparadores más sofisticados
	switch sortBy {
	case "timestamp":
		// Ya están ordenados por timestamp de inserción
		if sortOrder == "desc" {
			// Invertir orden
			for i, j := 0, len(events)-1; i < j; i, j = i+1, j-1 {
				events[i], events[j] = events[j], events[i]
			}
		}
	case "risk_score":
		// Ordenar por risk_score
		// Implementación simplificada
	}
}

// exportJSON exporta eventos en formato JSON
func (s *MemoryStorage) exportJSON(events []*Event, writer io.Writer) error {
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(events)
}

// exportCSV exporta eventos en formato CSV
func (s *MemoryStorage) exportCSV(events []*Event, writer io.Writer) error {
	// Escribir header
	header := "id,timestamp,actor_id,actor_type,action_type,action_category,resource_type,resource_id,status,ip_address,risk_score\n"
	if _, err := io.WriteString(writer, header); err != nil {
		return err
	}

	// Escribir filas
	for _, event := range events {
		row := fmt.Sprintf("%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%.2f\n",
			event.ID,
			event.Timestamp.Format(time.RFC3339),
			event.Actor.ID,
			event.Actor.Type,
			event.Action.Type,
			event.Action.Category,
			event.Resource.Type,
			event.Resource.ID,
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

// exportNDJSON exporta eventos en formato NDJSON (Newline Delimited JSON)
func (s *MemoryStorage) exportNDJSON(events []*Event, writer io.Writer) error {
	encoder := json.NewEncoder(writer)
	for _, event := range events {
		if err := encoder.Encode(event); err != nil {
			return err
		}
	}
	return nil
}
