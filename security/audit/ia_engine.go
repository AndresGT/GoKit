package audit

import (
	"net"
	"regexp"
	"strings"
	"sync"
	"time"
)

// NewIAEngine crea un nuevo motor de IA para detección de amenazas
func NewIAEngine(minRiskThreshold float64) *IAEngine {
	return &IAEngine{
		enabled:          true,
		minRiskThreshold: minRiskThreshold,
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
		// Detección de Fuerza Bruta
		{
			ID:          "BRUTE_FORCE_001",
			Name:        "Brute Force Login Attempt",
			Description: "Detecta múltiples intentos fallidos de login desde la misma IP",
			Severity:    "HIGH",
			Condition:   e.detectBruteForce,
			Enabled:     true,
		},
		// Detección de SQL Injection
		{
			ID:          "SQL_INJECTION_001",
			Name:        "SQL Injection Attempt",
			Description: "Detecta patrones comunes de SQL injection en payloads",
			Severity:    "CRITICAL",
			Pattern:     regexp.MustCompile(`(?i)(union\s+select|insert\s+into|delete\s+from|drop\s+table|update\s+.*\s+set|or\s+1\s*=\s*1|'\s*or\s*'|--\s*$)`),
			Condition:   e.detectSQLInjection,
			Enabled:     true,
		},
		// Detección de XSS
		{
			ID:          "XSS_001",
			Name:        "Cross-Site Scripting Attempt",
			Description: "Detecta patrones de XSS en payloads",
			Severity:    "HIGH",
			Pattern:     regexp.MustCompile(`(?i)(<script|javascript:|on\w+\s*=|<iframe|<object|<embed)`),
			Condition:   e.detectXSS,
			Enabled:     true,
		},
		// Detección de Scraping
		{
			ID:          "SCRAPING_001",
			Name:        "Web Scraping Detection",
			Description: "Detecta comportamiento de scraping basado en frecuencia de peticiones",
			Severity:    "MEDIUM",
			Condition:   e.detectScraping,
			Enabled:     true,
		},
		// Detección de Viaje Imposible
		{
			ID:          "IMPOSSIBLE_TRAVEL_001",
			Name:        "Impossible Travel Detection",
			Description: "Detecta logins desde ubicaciones geográficas imposibles en poco tiempo",
			Severity:    "CRITICAL",
			Condition:   e.detectImpossibleTravel,
			Enabled:     true,
		},
		// Detección de DDoS
		{
			ID:          "DDOS_001",
			Name:        "DDoS Attack Detection",
			Description: "Detecta patrones de ataque DDoS basados en volumen de peticiones",
			Severity:    "CRITICAL",
			Condition:   e.detectDDoS,
			Enabled:     true,
		},
		// Detección de Anomalías
		{
			ID:          "ANOMALY_001",
			Name:        "Behavioral Anomaly Detection",
			Description: "Detecta comportamientos anómalos usando análisis estadístico",
			Severity:    "MEDIUM",
			Condition:   e.detectAnomaly,
			Enabled:     true,
		},
		// Detección de IPs Maliciosas
		{
			ID:          "MALICIOUS_IP_001",
			Name:        "Malicious IP Detection",
			Description: "Detecta peticiones desde IPs con mala reputación",
			Severity:    "HIGH",
			Condition:   e.detectMaliciousIP,
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
	defer e.mu.RUnlock()

	var threats []ThreatDetection
	totalRisk := 0.0

	// Actualizar estadísticas
	e.stats.TotalEvaluations++
	e.stats.LastEvaluationTime = time.Now().UTC()

	// Ejecutar todas las reglas habilitadas
	for i := range e.rules {
		rule := &e.rules[i]
		if !rule.Enabled {
			continue
		}

		if rule.Condition(event) {
			threat := rule.Action(event)
			if threat != nil {
				threat.RuleID = rule.ID
				threats = append(threats, *threat)
				
				// Actualizar estadísticas de la regla
				rule.Hits++
				rule.LastHit = time.Now().UTC()
				
				// Actualizar estadísticas por tipo
				e.stats.DetectionByType[threat.Type]++
				
				// Calcular riesgo basado en severidad
				riskMultiplier := getSeverityMultiplier(threat.Severity)
				totalRisk += threat.Confidence * riskMultiplier
			}
		}
	}

	// Normalizar score de riesgo (0-1)
	riskScore := totalRisk / float64(len(e.rules))
	if riskScore > 1.0 {
		riskScore = 1.0
	}

	// Actualizar estadísticas globales
	if len(threats) > 0 {
		e.stats.ThreatsDetected += int64(len(threats))
	}

	return threats, riskScore
}

// detectBruteForce detecta intentos de fuerza bruta
func (e *IAEngine) detectBruteForce(event *Event) bool {
	// Verificar si es un intento de login fallido
	if event.Action.Category != "AUTH" || event.Action.Type != "LOGIN" {
		return false
	}
	
	if event.Result.Status != "FAILURE" {
		return false
	}

	ip := event.Context.IPAddress
	
	// Contar intentos fallidos recientes desde la misma IP
	failedAttempts := 0
	cutoff := time.Now().Add(-5 * time.Minute)
	
	// En una implementación real, esto consultaría la base de datos
	// Aquí simulamos con metadata
	if attempts, ok := event.Metadata["failed_attempts"]; ok {
		if count, ok := attempts.(int); ok {
			failedAttempts = count
		}
	}

	return failedAttempts >= 5
}

// detectSQLInjection detecta intentos de SQL injection
func (e *IAEngine) detectSQLInjection(event *Event) bool {
	// Buscar patrones de SQL injection en el payload o path
	payload := ""
	if p, ok := event.Metadata["payload"]; ok {
		if str, ok := p.(string); ok {
			payload = str
		}
	}

	if payload == "" {
		payload = event.Action.Path
	}

	for _, rule := range e.rules {
		if rule.ID == "SQL_INJECTION_001" && rule.Pattern != nil {
			return rule.Pattern.MatchString(payload)
		}
	}
	return false
}

// detectXSS detecta intentos de XSS
func (e *IAEngine) detectXSS(event *Event) bool {
	payload := ""
	if p, ok := event.Metadata["payload"]; ok {
		if str, ok := p.(string); ok {
			payload = str
		}
	}

	if payload == "" {
		payload = event.Action.Path
	}

	for _, rule := range e.rules {
		if rule.ID == "XSS_001" && rule.Pattern != nil {
			return rule.Pattern.MatchString(payload)
		}
	}
	return false
}

// detectScraping detecta comportamiento de scraping
func (e *IAEngine) detectScraping(event *Event) bool {
	actorID := event.Actor.ID
	if actorID == "" {
		actorID = event.Context.IPAddress
	}

	// Obtener o crear perfil de comportamiento
	profile := e.getOrCreateProfile(actorID)
	
	// Calcular requests por minuto actuales
	now := time.Now()
	timeWindow := 1 * time.Minute
	
	// En una implementación real, usaríamos una ventana deslizante
	// Aquí simplificamos contando eventos recientes
	requestCount := 1 // El evento actual
	
	// Si hay más de 100 requests por minuto, es sospechoso
	requestsPerMinute := float64(requestCount)
	
	// Actualizar perfil
	profile.AverageRequestsPerMinute = (profile.AverageRequestsPerMinute + requestsPerMinute) / 2
	profile.LastUpdated = now

	return requestsPerMinute > 100
}

// detectImpossibleTravel detecta viajes imposibles
func (e *IAEngine) detectImpossibleTravel(event *Event) bool {
	if event.Action.Category != "AUTH" || event.Action.Type != "LOGIN" {
		return false
	}

	actorID := event.Actor.ID
	if actorID == "" {
		return false
	}

	profile := e.getOrCreateProfile(actorID)
	currentLocation := event.Context.IPGeoLocation.CountryCode
	
	// Si hay ubicaciones previas, verificar distancia y tiempo
	if len(profile.CommonLocations) > 0 {
		lastLocation := profile.CommonLocations[len(profile.CommonLocations)-1]
		
		// Si las ubicaciones son diferentes países y el último login fue hace menos de 1 hora
		if lastLocation != currentLocation && lastLocation != "" {
			// En una implementación real, calcularíamos la distancia geográfica
			// y verificaríamos si es posible viajar en el tiempo transcurrido
			// Aquí simplificamos: diferentes países en menos de 1 hora = imposible
			return true
		}
	}

	// Actualizar perfil
	found := false
	for _, loc := range profile.CommonLocations {
		if loc == currentLocation {
			found = true
			break
		}
	}
	if !found && currentLocation != "" {
		profile.CommonLocations = append(profile.CommonLocations, currentLocation)
		if len(profile.CommonLocations) > 10 {
			profile.CommonLocations = profile.CommonLocations[1:]
		}
	}

	return false
}

// detectDDoS detecta patrones de ataque DDoS
func (e *IAEngine) detectDDoS(event *Event) bool {
	ip := event.Context.IPAddress
	
	// Contar peticiones recientes desde la misma IP
	requestCount := 1
	
	// Si hay más de 1000 requests por segundo desde la misma IP, es DDoS
	return requestCount > 1000
}

// detectAnomaly detecta anomalías de comportamiento
func (e *IAEngine) detectAnomaly(event *Event) bool {
	actorID := event.Actor.ID
	if actorID == "" {
		actorID = event.Context.IPAddress
	}

	profile := e.getOrCreateProfile(actorID)
	
	// Verificar si la acción es típica para este actor
	isTypical := false
	for _, action := range profile.TypicalActions {
		if action == event.Action.Type {
			isTypical = true
			break
		}
	}

	// Si no es típica y el actor tiene historial, marcar como anomalía
	if !isTypical && len(profile.TypicalActions) > 0 {
		return true
	}

	// Actualizar perfil con acción típica
	if !isTypical {
		profile.TypicalActions = append(profile.TypicalActions, event.Action.Type)
		if len(profile.TypicalActions) > 20 {
			profile.TypicalActions = profile.TypicalActions[1:]
		}
	}

	return false
}

// detectMaliciousIP detecta IPs maliciosas
func (e *IAEngine) detectMaliciousIP(event *Event) bool {
	ip := event.Context.IPAddress
	
	// Obtener reputación de la IP
	reputation := e.ipReputation.Get(ip)
	
	return reputation.IsMalicious || reputation.Blacklisted || reputation.RiskScore > 0.8
}

// getOrCreateProfile obtiene o crea un perfil de comportamiento
func (e *IAEngine) getOrCreateProfile(actorID string) *BehaviorProfile {
	profile, exists := e.behaviorProfiles[actorID]
	if !exists {
		profile = &BehaviorProfile{
			ActorID:      actorID,
			CommonIPs:    make([]string, 0),
			CommonLocations: make([]string, 0),
			TypicalActions: make([]string, 0),
			ActiveHours:  make([]int, 0),
			Devices:      make([]string, 0),
			LastUpdated:  time.Now().UTC(),
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

// Get stats del motor de IA
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

// Get Reputation de una IP
func (db *IPReputationDB) Get(ip string) *IPReputation {
	db.cacheMu.RLock()
	defer db.cacheMu.RUnlock()
	
	if rep, exists := db.cache[ip]; exists {
		return rep
	}
	
	// Retornar reputación por defecto si no existe
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

// IsTor checks if IP is a known Tor exit node
func IsTorExitNode(ip string) bool {
	// Lista simplificada de exit nodes de Tor
	// En producción, usaría una lista actualizada de https://check.torproject.org/
	torExits := map[string]bool{
		"185.220.101.0": true,
		"185.220.102.0": true,
	}
	
	// Verificar prefijo de IP
	parts := strings.Split(ip, ".")
	if len(parts) >= 3 {
		prefix := strings.Join(parts[:3], ".") + ".0"
		return torExits[prefix]
	}
	
	return false
}

// GeoIP lookup simplificado
func LookupGeoIP(ip string) GeoLocation {
	// En producción, usaría una base de datos GeoIP real como MaxMind
	// Aquí retornamos datos dummy basados en rangos de IP
	
	netIP := net.ParseIP(ip)
	if netIP == nil {
		return GeoLocation{}
	}

	// Simplificación extrema para demo
	if netIP.IsLoopback() {
		return GeoLocation{
			Country:     "Localhost",
			CountryCode: "LO",
			City:        "Localhost",
		}
	}

	// Detectar IP privada
	if netIP.IsPrivate() {
		return GeoLocation{
			Country:     "Private Network",
			CountryCode: "PN",
		}
	}

	// Default
	return GeoLocation{
		Country:     "Unknown",
		CountryCode: "XX",
	}
}
