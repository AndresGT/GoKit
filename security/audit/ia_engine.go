package audit

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"
)

// EventQuerier consulta eventos almacenados para la detección de amenazas.
// El auditor inyecta su storage.Query para que el motor no dependa de un
// storage concreto.
type EventQuerier func(ctx context.Context, filter QueryFilter) ([]*Event, error)

// Umbrales de detección. Son variables en lugar de constantes para permitir
// ajustes en pruebas y configuración en runtime.
var (
	bruteForceThreshold   = 5
	bruteForceWindow      = 5 * time.Minute
	scrapingThreshold     = 30
	scrapingWindow        = time.Minute
	ddosThreshold         = 200
	ddosWindow            = 10 * time.Second
	impossibleTravelWindow = time.Hour
	maliciousIPRiskScore  = 0.8
)

// Patrones de ataques comunes
var (
	sqlInjectionPattern = regexp.MustCompile(`(?i)(union\s+select|insert\s+into|delete\s+from|drop\s+table|update\s+.*\s+set|or\s+1\s*=\s*1|'\s*or\s*'|--\s*$)`)
	xssPattern          = regexp.MustCompile(`(?i)(<script|javascript:|on\w+\s*=|<iframe|<object|<embed)`)
)

// NewIAEngine crea un nuevo motor de IA para detección de amenazas
func NewIAEngine(minRiskThreshold float64, history EventQuerier) *IAEngine {
	return &IAEngine{
		enabled:          true,
		minRiskThreshold: minRiskThreshold,
		history:          history,
		rules:            make([]DetectionRule, 0),
		behaviorProfiles: make(map[string]*BehaviorProfile),
		ipReputation:     &IPReputationDB{cache: make(map[string]*IPReputation)},
		anomalyDetector: &AnomalyDetector{
			historicalData: make(map[string][]float64),
			thresholds:     make(map[string]float64),
			windowSize:     100,
		},
		stats: IAStats{
			DetectionByType: make(map[string]int64),
		},
	}
}

// LoadDefaultRules carga las reglas de detección por defecto
func (e *IAEngine) LoadDefaultRules() {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.rules = []DetectionRule{
		{
			ID:          "BRUTE_FORCE_001",
			Name:        "Brute Force Login Attempt",
			Description: "Detecta múltiples intentos fallidos de login desde la misma IP",
			Severity:    "HIGH",
			Condition:   e.detectBruteForce,
			Action:      e.actionBruteForce,
			Enabled:     true,
		},
		{
			ID:          "SQL_INJECTION_001",
			Name:        "SQL Injection Attempt",
			Description: "Detecta patrones comunes de SQL injection en payloads",
			Severity:    "CRITICAL",
			Pattern:     sqlInjectionPattern,
			Condition:   e.detectSQLInjection,
			Action:      e.actionSQLInjection,
			Enabled:     true,
		},
		{
			ID:          "XSS_001",
			Name:        "Cross-Site Scripting Attempt",
			Description: "Detecta patrones de XSS en payloads",
			Severity:    "HIGH",
			Pattern:     xssPattern,
			Condition:   e.detectXSS,
			Action:      e.actionXSS,
			Enabled:     true,
		},
		{
			ID:          "SCRAPING_001",
			Name:        "Web Scraping Detection",
			Description: "Detecta comportamiento de scraping basado en frecuencia de peticiones",
			Severity:    "MEDIUM",
			Condition:   e.detectScraping,
			Action:      e.actionScraping,
			Enabled:     true,
		},
		{
			ID:          "IMPOSSIBLE_TRAVEL_001",
			Name:        "Impossible Travel Detection",
			Description: "Detecta logins desde ubicaciones geográficas imposibles en poco tiempo",
			Severity:    "CRITICAL",
			Condition:   e.detectImpossibleTravel,
			Action:      e.actionImpossibleTravel,
			Enabled:     true,
		},
		{
			ID:          "DDOS_001",
			Name:        "DDoS Attack Detection",
			Description: "Detecta patrones de ataque DDoS basados en volumen de peticiones",
			Severity:    "CRITICAL",
			Condition:   e.detectDDoS,
			Action:      e.actionDDoS,
			Enabled:     true,
		},
		{
			ID:          "ANOMALY_001",
			Name:        "Behavioral Anomaly Detection",
			Description: "Detecta comportamientos anómalos usando análisis estadístico",
			Severity:    "MEDIUM",
			Condition:   e.detectAnomaly,
			Action:      e.actionAnomaly,
			Enabled:     true,
		},
		{
			ID:          "MALICIOUS_IP_001",
			Name:        "Malicious IP Detection",
			Description: "Detecta peticiones desde IPs con mala reputación",
			Severity:    "HIGH",
			Condition:   e.detectMaliciousIP,
			Action:      e.actionMaliciousIP,
			Enabled:     true,
		},
	}
}

// Analyze analiza un evento y retorna amenazas detectadas y score de riesgo
func (e *IAEngine) Analyze(event *Event) ([]ThreatDetection, float64) {
	if !e.enabled {
		return nil, 0
	}

	e.mu.RLock()
	rules := make([]DetectionRule, len(e.rules))
	copy(rules, e.rules)
	e.mu.RUnlock()

	var threats []ThreatDetection
	totalRisk := 0.0

	e.mu.Lock()
	e.stats.TotalEvaluations++
	e.stats.LastEvaluationTime = time.Now().UTC()
	e.mu.Unlock()

	for i := range rules {
		rule := &rules[i]
		if !rule.Enabled || rule.Condition == nil || rule.Action == nil {
			continue
		}

		if rule.Condition(event) {
			threat := rule.Action(event)
			if threat != nil {
				threat.RuleID = rule.ID
				threats = append(threats, *threat)

				e.mu.Lock()
				if i < len(e.rules) {
					e.rules[i].Hits++
					e.rules[i].LastHit = time.Now().UTC()
				}
				e.stats.DetectionByType[threat.Type]++
				e.mu.Unlock()

				riskMultiplier := getSeverityMultiplier(threat.Severity)
				totalRisk += threat.Confidence * riskMultiplier
			}
		}
	}

	riskScore := 0.0
	if len(rules) > 0 {
		riskScore = totalRisk / float64(len(rules))
		if riskScore > 1.0 {
			riskScore = 1.0
		}
	}

	if len(threats) > 0 {
		e.mu.Lock()
		e.stats.ThreatsDetected += int64(len(threats))
		e.mu.Unlock()
	}

	return threats, riskScore
}

// countRecentEvents cuenta eventos recientes que coinciden con el filtro,
// incluyendo el evento actual en análisis.
func (e *IAEngine) countRecentEvents(filter QueryFilter) int {
	count := 1
	if e.history == nil {
		return count
	}
	// El conteo requiere todos los eventos de la ventana, no aplicar paginación
	filter.Offset = 0
	filter.Limit = 1000
	events, err := e.history(context.Background(), filter)
	if err != nil {
		return count
	}
	return count + len(events)
}

// extractPayload extrae el payload a analizar desde metadata o path
func (e *IAEngine) extractPayload(event *Event) string {
	if p, ok := event.Metadata["payload"]; ok {
		if s, ok := p.(string); ok && s != "" {
			return s
		}
	}
	return event.Action.Path
}

// actorID retorna el ID del actor, usando la IP como fallback
func (e *IAEngine) actorID(event *Event) string {
	if event.Actor.ID != "" {
		return event.Actor.ID
	}
	return event.Context.IPAddress
}

// detectBruteForce detecta intentos de fuerza bruta
func (e *IAEngine) detectBruteForce(event *Event) bool {
	if event.Action.Category != "AUTH" || event.Action.Type != "LOGIN" {
		return false
	}
	if event.Result.Status != "FAILURE" {
		return false
	}
	now := time.Now()
	count := e.countRecentEvents(QueryFilter{
		IPAddresses:      []string{event.Context.IPAddress},
		Statuses:         []string{"FAILURE"},
		ActionTypes:      []string{"LOGIN"},
		ActionCategories: []string{"AUTH"},
		StartTime:        now.Add(-bruteForceWindow),
	})
	return count >= bruteForceThreshold
}

// detectSQLInjection detecta intentos de SQL injection
func (e *IAEngine) detectSQLInjection(event *Event) bool {
	return sqlInjectionPattern.MatchString(e.extractPayload(event))
}

// detectXSS detecta intentos de XSS
func (e *IAEngine) detectXSS(event *Event) bool {
	return xssPattern.MatchString(e.extractPayload(event))
}

// detectScraping detecta comportamiento de scraping
func (e *IAEngine) detectScraping(event *Event) bool {
	profile := e.getOrCreateProfile(e.actorID(event))
	count := e.countRecentEvents(QueryFilter{
		IPAddresses: []string{event.Context.IPAddress},
		StartTime:   time.Now().Add(-scrapingWindow),
	})
	profile.AverageRequestsPerMinute = (profile.AverageRequestsPerMinute + float64(count)) / 2
	profile.LastUpdated = time.Now().UTC()
	return count >= scrapingThreshold
}

// detectImpossibleTravel detecta viajes imposibles
func (e *IAEngine) detectImpossibleTravel(event *Event) bool {
	if event.Action.Category != "AUTH" || event.Action.Type != "LOGIN" {
		return false
	}
	if event.Result.Status != "SUCCESS" {
		return false
	}

	actorID := event.Actor.ID
	if actorID == "" {
		return false
	}

	profile := e.getOrCreateProfile(actorID)
	currentLocation := event.Context.IPGeoLocation.CountryCode
	if currentLocation == "" {
		return false
	}

	now := time.Now()
	suspicious := false
	if len(profile.CommonLocations) > 0 {
		lastLocation := profile.CommonLocations[len(profile.CommonLocations)-1]
		if lastLocation != currentLocation && lastLocation != "" &&
			!profile.LastUpdated.IsZero() &&
			now.Sub(profile.LastUpdated) <= impossibleTravelWindow {
			suspicious = true
		}
	}

	profile.LastUpdated = now
	found := false
	for _, loc := range profile.CommonLocations {
		if loc == currentLocation {
			found = true
			break
		}
	}
	if !found {
		profile.CommonLocations = append(profile.CommonLocations, currentLocation)
		if len(profile.CommonLocations) > 10 {
			profile.CommonLocations = profile.CommonLocations[1:]
		}
	}

	return suspicious
}

// detectDDoS detecta patrones de ataque DDoS
func (e *IAEngine) detectDDoS(event *Event) bool {
	if event.Context.IPAddress == "" {
		return false
	}
	count := e.countRecentEvents(QueryFilter{
		IPAddresses: []string{event.Context.IPAddress},
		StartTime:   time.Now().Add(-ddosWindow),
	})
	return count >= ddosThreshold
}

// detectAnomaly detecta anomalías de comportamiento
func (e *IAEngine) detectAnomaly(event *Event) bool {
	profile := e.getOrCreateProfile(e.actorID(event))

	isTypical := false
	for _, action := range profile.TypicalActions {
		if action == event.Action.Type {
			isTypical = true
			break
		}
	}

	anomalous := !isTypical && len(profile.TypicalActions) > 0
	if !isTypical {
		profile.TypicalActions = append(profile.TypicalActions, event.Action.Type)
		if len(profile.TypicalActions) > 20 {
			profile.TypicalActions = profile.TypicalActions[1:]
		}
	}
	return anomalous
}

// detectMaliciousIP detecta IPs maliciosas
func (e *IAEngine) detectMaliciousIP(event *Event) bool {
	ip := event.Context.IPAddress
	if ip == "" {
		return false
	}
	reputation := e.ipReputation.Get(ip)
	return reputation.IsMalicious || reputation.Blacklisted || reputation.RiskScore > maliciousIPRiskScore
}

// Acciones de las reglas

func (e *IAEngine) actionBruteForce(event *Event) *ThreatDetection {
	return &ThreatDetection{
		Type:           "BRUTE_FORCE",
		Severity:       "HIGH",
		Confidence:     0.9,
		Description:    "Múltiples intentos fallidos de login desde la misma IP",
		Evidence:       []string{fmt.Sprintf("IP %s", event.Context.IPAddress)},
		Recommendation: "Bloquear temporalmente la IP y activar autenticación multifactor",
	}
}

func (e *IAEngine) actionSQLInjection(event *Event) *ThreatDetection {
	payload := e.extractPayload(event)
	return &ThreatDetection{
		Type:           "SQL_INJECTION",
		Severity:       "CRITICAL",
		Confidence:     0.85,
		Description:    "Intento de inyección SQL detectado",
		Evidence:       []string{payload},
		Pattern:        sqlInjectionPattern.FindString(payload),
		Recommendation: "Validar y escapar toda entrada del usuario; usar consultas parametrizadas",
	}
}

func (e *IAEngine) actionXSS(event *Event) *ThreatDetection {
	payload := e.extractPayload(event)
	return &ThreatDetection{
		Type:           "XSS",
		Severity:       "HIGH",
		Confidence:     0.85,
		Description:    "Intento de Cross-Site Scripting detectado",
		Evidence:       []string{payload},
		Pattern:        xssPattern.FindString(payload),
		Recommendation: "Escapar la salida y sanitizar toda entrada del usuario",
	}
}

func (e *IAEngine) actionScraping(event *Event) *ThreatDetection {
	return &ThreatDetection{
		Type:           "SCRAPING",
		Severity:       "MEDIUM",
		Confidence:     0.7,
		Description:    "Frecuencia de peticiones anormalmente alta desde la misma IP",
		Evidence:       []string{fmt.Sprintf("IP %s", event.Context.IPAddress)},
		Recommendation: "Aplicar rate limiting y validar el User-Agent del cliente",
	}
}

func (e *IAEngine) actionImpossibleTravel(event *Event) *ThreatDetection {
	return &ThreatDetection{
		Type:           "IMPOSSIBLE_TRAVEL",
		Severity:       "CRITICAL",
		Confidence:     0.95,
		Description:    "Login exitoso desde una ubicación imposible de alcanzar en el tiempo transcurrido",
		Evidence:       []string{fmt.Sprintf("País %s", event.Context.IPGeoLocation.CountryCode)},
		Recommendation: "Verificar la identidad del usuario y revisar la sesión",
	}
}

func (e *IAEngine) actionDDoS(event *Event) *ThreatDetection {
	return &ThreatDetection{
		Type:           "DDOS",
		Severity:       "CRITICAL",
		Confidence:     0.9,
		Description:    "Volumen anormalmente alto de peticiones desde la misma IP",
		Evidence:       []string{fmt.Sprintf("IP %s", event.Context.IPAddress)},
		Recommendation: "Bloquear la IP y activar mitigación de DDoS",
	}
}

func (e *IAEngine) actionAnomaly(event *Event) *ThreatDetection {
	return &ThreatDetection{
		Type:           "ANOMALY",
		Severity:       "MEDIUM",
		Confidence:     0.6,
		Description:    "Acción poco habitual para el actor identificado",
		Evidence:       []string{fmt.Sprintf("Acción %s", event.Action.Type)},
		Recommendation: "Revisar si la acción fue realizada por el usuario legítimo",
	}
}

func (e *IAEngine) actionMaliciousIP(event *Event) *ThreatDetection {
	return &ThreatDetection{
		Type:           "MALICIOUS_IP",
		Severity:       "HIGH",
		Confidence:     0.8,
		Description:    "Petición desde una IP con mala reputación",
		Evidence:       []string{fmt.Sprintf("IP %s", event.Context.IPAddress)},
		Recommendation: "Bloquear la IP y monitorear actividad futura",
	}
}

// getOrCreateProfile obtiene o crea un perfil de comportamiento
func (e *IAEngine) getOrCreateProfile(actorID string) *BehaviorProfile {
	if actorID == "" {
		actorID = "unknown"
	}
	e.profileMu.Lock()
	defer e.profileMu.Unlock()
	profile, exists := e.behaviorProfiles[actorID]
	if !exists {
		profile = &BehaviorProfile{
			ActorID:           actorID,
			CommonIPs:         make([]string, 0),
			CommonLocations:   make([]string, 0),
			TypicalActions:    make([]string, 0),
			ActiveHours:       make([]int, 0),
			Devices:           make([]string, 0),
			LastUpdated:       time.Now().UTC(),
		}
		e.behaviorProfiles[actorID] = profile
	}
	return profile
}

// getSeverityMultiplier retorna el multiplicador de riesgo según severidad
func getSeverityMultiplier(severity string) float64 {
	switch severity {
	case "CRITICAL":
		return 1.0
	case "HIGH":
		return 0.75
	case "MEDIUM":
		return 0.5
	case "LOW":
		return 0.25
	default:
		return 0.5
	}
}

// GetStats retorna las estadísticas del motor de IA
func (e *IAEngine) GetStats() IAStats {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.stats
}

// Enable habilita el motor de IA
func (e *IAEngine) Enable() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.enabled = true
}

// Disable deshabilita el motor de IA
func (e *IAEngine) Disable() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.enabled = false
}

// AddRule agrega una regla personalizada
func (e *IAEngine) AddRule(rule DetectionRule) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rules = append(e.rules, rule)
}

// RemoveRule elimina una regla por ID
func (e *IAEngine) RemoveRule(ruleID string) {
	e.mu.Lock()
	defer e.mu.Unlock()

	for i, rule := range e.rules {
		if rule.ID == ruleID {
			e.rules = append(e.rules[:i], e.rules[i+1:]...)
			return
		}
	}
}

// Get retorna la reputación de una IP
func (db *IPReputationDB) Get(ip string) *IPReputation {
	db.cacheMu.RLock()
	defer db.cacheMu.RUnlock()

	if rep, exists := db.cache[ip]; exists {
		return rep
	}

	return &IPReputation{
		IPAddress: ip,
		RiskScore: 0.0,
	}
}

// Update actualiza la reputación de una IP
func (db *IPReputationDB) Update(rep *IPReputation) {
	db.cacheMu.Lock()
	defer db.cacheMu.Unlock()
	db.cache[rep.IPAddress] = rep
}

// MarkAsMalicious marca una IP como maliciosa
func (db *IPReputationDB) MarkAsMalicious(ip string, reason string) {
	rep := db.Get(ip)
	rep.IsMalicious = true
	rep.RiskScore = 1.0
	rep.Categories = append(rep.Categories, reason)
	rep.LastSeen = time.Now().UTC()
	db.Update(rep)
}

// IsTorExitNode verifica si la IP es un exit node conocido de Tor
func IsTorExitNode(ip string) bool {
	// Lista simplificada de exit nodes de Tor
	// En producción, usaría una lista actualizada de https://check.torproject.org/
	torExits := map[string]bool{
		"185.220.101.0": true,
		"185.220.102.0": true,
	}

	parts := strings.Split(ip, ".")
	if len(parts) >= 3 {
		prefix := strings.Join(parts[:3], ".") + ".0"
		return torExits[prefix]
	}

	return false
}

// LookupGeoIP realiza una búsqueda GeoIP simplificada
func LookupGeoIP(ip string) GeoLocation {
	netIP := net.ParseIP(ip)
	if netIP == nil {
		return GeoLocation{}
	}

	if netIP.IsLoopback() {
		return GeoLocation{
			Country:     "Localhost",
			CountryCode: "LO",
			City:        "Localhost",
		}
	}

	if netIP.IsPrivate() {
		return GeoLocation{
			Country:     "Private Network",
			CountryCode: "PN",
		}
	}

	return GeoLocation{
		Country:     "Unknown",
		CountryCode: "XX",
	}
}
