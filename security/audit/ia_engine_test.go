package audit

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestNewIAEngine(t *testing.T) {
	e := NewIAEngine(0.5, nil)
	if e == nil {
		t.Fatal("expected engine")
	}
	if !e.enabled {
		t.Error("engine should start enabled")
	}
	if e.minRiskThreshold != 0.5 {
		t.Errorf("expected threshold 0.5, got %v", e.minRiskThreshold)
	}
	if len(e.rules) != 0 {
		t.Errorf("expected 0 rules, got %d", len(e.rules))
	}
	e.LoadDefaultRules()
	if len(e.rules) != 8 {
		t.Errorf("expected 8 default rules, got %d", len(e.rules))
	}
}

func TestIAEngineEnableDisable(t *testing.T) {
	e := NewIAEngine(0, nil)
	e.Disable()
	if _, risk := e.Analyze(&Event{}); risk != 0 {
		t.Errorf("disabled engine should return 0 risk, got %v", risk)
	}
	e.Enable()
	e.LoadDefaultRules()
	threats, _ := e.Analyze(&Event{
		ID:      "sqli",
		Action:  ActionInfo{Type: "QUERY", Category: "DATA", Path: "/x"},
		Metadata: map[string]interface{}{"payload": "union select 1 from users"},
	})
	if len(threats) == 0 {
		t.Error("expected SQL injection threat")
	}
}

func TestIARuleManagement(t *testing.T) {
	e := NewIAEngine(0, nil)
	e.AddRule(DetectionRule{ID: "CUSTOM", Condition: func(*Event) bool { return true }, Action: func(*Event) *ThreatDetection { return &ThreatDetection{Type: "CUSTOM"} }})
	if len(e.rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(e.rules))
	}
	e.RemoveRule("NOPE")
	if len(e.rules) != 1 {
		t.Errorf("remove unknown rule should not change count")
	}
	e.RemoveRule("CUSTOM")
	if len(e.rules) != 0 {
		t.Errorf("expected 0 rules after remove, got %d", len(e.rules))
	}
}

func TestAnalyzeSkippedRules(t *testing.T) {
	e := NewIAEngine(0, nil)
	e.AddRule(DetectionRule{ID: "A", Enabled: false, Condition: func(*Event) bool { return true }, Action: func(*Event) *ThreatDetection { return &ThreatDetection{Type: "A"} }})
	e.AddRule(DetectionRule{ID: "B", Enabled: true, Condition: nil, Action: func(*Event) *ThreatDetection { return &ThreatDetection{Type: "B"} }})
	e.AddRule(DetectionRule{ID: "C", Enabled: true, Condition: func(*Event) bool { return true }, Action: func(*Event) *ThreatDetection { return &ThreatDetection{Type: "C"} }})
	threats, _ := e.Analyze(&Event{})
	if len(threats) != 1 || threats[0].Type != "C" {
		t.Errorf("expected only C threat, got %+v", threats)
	}
	stats := e.GetStats()
	if stats.TotalEvaluations != 1 {
		t.Errorf("expected 1 evaluation, got %d", stats.TotalEvaluations)
	}
	if stats.DetectionByType["C"] != 1 {
		t.Errorf("expected DetectionByType C=1, got %d", stats.DetectionByType["C"])
	}
}

func TestAnalyzeRiskClamp(t *testing.T) {
	e := NewIAEngine(0, nil)
	e.AddRule(DetectionRule{
		ID: "BIG", Enabled: true,
		Condition: func(*Event) bool { return true },
		Action: func(*Event) *ThreatDetection {
			return &ThreatDetection{Type: "BIG", Severity: "CRITICAL", Confidence: 9.0}
		},
	})
	_, risk := e.Analyze(&Event{})
	if risk != 1.0 {
		t.Errorf("expected clamped risk 1.0, got %v", risk)
	}
}

func TestCountRecentEvents(t *testing.T) {
	if got := (&IAEngine{}).countRecentEvents(QueryFilter{}); got != 1 {
		t.Errorf("nil history should return 1, got %d", got)
	}
	errEngine := &IAEngine{history: func(context.Context, QueryFilter) ([]*Event, error) {
		return nil, errors.New("boom")
	}}
	if got := errEngine.countRecentEvents(QueryFilter{}); got != 1 {
		t.Errorf("error history should return 1, got %d", got)
	}
	okEngine := &IAEngine{history: func(context.Context, QueryFilter) ([]*Event, error) {
		return []*Event{{}, {}}, nil
	}}
	if got := okEngine.countRecentEvents(QueryFilter{}); got != 3 {
		t.Errorf("expected 3 (1+2), got %d", got)
	}
}

func TestExtractPayloadAndActorID(t *testing.T) {
	e := &IAEngine{}
	if got := e.extractPayload(&Event{Metadata: map[string]interface{}{"payload": "hello"}}); got != "hello" {
		t.Errorf("expected payload from metadata, got %q", got)
	}
	if got := e.extractPayload(&Event{Metadata: map[string]interface{}{"payload": 42}}); got != "" {
		t.Errorf("expected empty for non-string payload, got %q", got)
	}
	if got := e.extractPayload(&Event{Action: ActionInfo{Path: "/fallback"}}); got != "/fallback" {
		t.Errorf("expected fallback path, got %q", got)
	}
	if got := e.actorID(&Event{Actor: ActorInfo{ID: "act"}, Context: ContextInfo{IPAddress: "1.2.3.4"}}); got != "act" {
		t.Errorf("expected actor id, got %q", got)
	}
	if got := e.actorID(&Event{Context: ContextInfo{IPAddress: "9.9.9.9"}}); got != "9.9.9.9" {
		t.Errorf("expected IP fallback, got %q", got)
	}
}

func TestDetectSQLInjectionAndXSS(t *testing.T) {
	e := &IAEngine{}
	if !e.detectSQLInjection(&Event{Metadata: map[string]interface{}{"payload": "admin' OR '1'='1"}}) {
		t.Error("expected SQLi detection")
	}
	if e.detectSQLInjection(&Event{Action: ActionInfo{Path: "/safe"}}) {
		t.Error("did not expect SQLi")
	}
	if !e.detectXSS(&Event{Metadata: map[string]interface{}{"payload": "<script>alert(1)</script>"}}) {
		t.Error("expected XSS detection")
	}
	if e.detectXSS(&Event{Action: ActionInfo{Path: "/safe"}}) {
		t.Error("did not expect XSS")
	}
}

func TestDetectBruteForce(t *testing.T) {
	base := func(n int) *IAEngine {
		return &IAEngine{history: func(context.Context, QueryFilter) ([]*Event, error) {
			return make([]*Event, n), nil
		}}
	}
	ev := &Event{
		Action: ActionInfo{Type: "LOGIN", Category: "AUTH"},
		Result: ResultInfo{Status: "FAILURE"},
		Context: ContextInfo{IPAddress: "1.1.1.1"},
	}
	// 4 previos + actual = 5 >= umbral
	if !base(4).detectBruteForce(ev) {
		t.Error("expected brute force detection with 4 prior events")
	}
	if base(3).detectBruteForce(ev) {
		t.Error("did not expect brute force with 3 prior events")
	}
	// Categoría/type/status incorrectos
	notAuth := *ev
	notAuth.Action.Category = "DATA"
	if base(10).detectBruteForce(&notAuth) {
		t.Error("expected false for non-auth category")
	}
	notLogin := *ev
	notLogin.Action.Type = "LOGOUT"
	if base(10).detectBruteForce(&notLogin) {
		t.Error("expected false for non-login type")
	}
	notFail := *ev
	notFail.Result.Status = "SUCCESS"
	if base(10).detectBruteForce(&notFail) {
		t.Error("expected false for success status")
	}
}

func TestDetectScraping(t *testing.T) {
	e := NewIAEngine(0, func(context.Context, QueryFilter) ([]*Event, error) {
		return make([]*Event, scrapingThreshold), nil
	})
	ev := &Event{Actor: ActorInfo{ID: "a"}, Context: ContextInfo{IPAddress: "5.5.5.5"}}
	if !e.detectScraping(ev) {
		t.Error("expected scraping detection")
	}
	if e.behaviorProfiles["a"].AverageRequestsPerMinute == 0 {
		t.Error("expected profile average updated")
	}
	// Sin historial: count = 1 < umbral
	e2 := NewIAEngine(0, nil)
	if e2.detectScraping(ev) {
		t.Error("did not expect scraping without history")
	}
	// actorID vacío → profile "unknown"
	e3 := NewIAEngine(0, nil)
	if e3.detectScraping(&Event{}) {
		t.Error("did not expect scraping")
	}
	if e3.behaviorProfiles["unknown"] == nil {
		t.Error("expected unknown profile")
	}
}

func TestDetectImpossibleTravel(t *testing.T) {
	newEngine := func() *IAEngine {
		return &IAEngine{behaviorProfiles: make(map[string]*BehaviorProfile)}
	}
	login := func(country string, updated bool) *Event {
		ev := &Event{
			Actor: ActorInfo{ID: "user"},
			Action: ActionInfo{Type: "LOGIN", Category: "AUTH"},
			Result: ResultInfo{Status: "SUCCESS"},
			Context: ContextInfo{IPGeoLocation: GeoLocation{CountryCode: country}},
		}
		if updated {
			ev.Timestamp = time.Now()
		}
		return ev
	}

	// Precondiciones falsas
	e := newEngine()
	if e.detectImpossibleTravel(&Event{Action: ActionInfo{Type: "GET", Category: "DATA"}}) {
		t.Error("expected false for non-login")
	}
	if e.detectImpossibleTravel(&Event{Action: ActionInfo{Type: "LOGIN", Category: "AUTH"}, Result: ResultInfo{Status: "FAILURE"}}) {
		t.Error("expected false for failure")
	}
	if e.detectImpossibleTravel(&Event{Action: ActionInfo{Type: "LOGIN", Category: "AUTH"}, Result: ResultInfo{Status: "SUCCESS"}}) {
		t.Error("expected false when actor has no ID")
	}
	noCountry := &Event{
		Actor: ActorInfo{ID: "u"},
		Action: ActionInfo{Type: "LOGIN", Category: "AUTH"},
		Result: ResultInfo{Status: "SUCCESS"},
	}
	if e.detectImpossibleTravel(noCountry) {
		t.Error("expected false when no country")
	}

	// Primera visita: registra ubicación, no sospechoso
	e = newEngine()
	if e.detectImpossibleTravel(login("US", true)) {
		t.Error("first visit should not be suspicious")
	}
	// Segunda visita en otra ubicación dentro de la ventana → sospechoso
	time.Sleep(time.Millisecond)
	if !e.detectImpossibleTravel(login("JP", true)) {
		t.Error("expected impossible travel detection")
	}
	// Misma ubicación → no sospechoso
	if e.detectImpossibleTravel(login("JP", true)) {
		t.Error("same location should not be suspicious")
	}

	// Fuera de la ventana temporal
	e = newEngine()
	e.detectImpossibleTravel(login("US", true))
	prof := e.behaviorProfiles["user"]
	prof.LastUpdated = time.Now().Add(-2 * time.Hour)
	if e.detectImpossibleTravel(login("JP", true)) {
		t.Error("expected false when outside window")
	}

	// Límite de 10 ubicaciones
	eng := newEngine()
	eng.detectImpossibleTravel(login("AA", true))
	eng.detectImpossibleTravel(login("AB", true))
	eng.detectImpossibleTravel(login("AC", true))
	eng.detectImpossibleTravel(login("AD", true))
	eng.detectImpossibleTravel(login("AE", true))
	eng.detectImpossibleTravel(login("AF", true))
	eng.detectImpossibleTravel(login("AG", true))
	eng.detectImpossibleTravel(login("AH", true))
	eng.detectImpossibleTravel(login("AI", true))
	eng.detectImpossibleTravel(login("AJ", true))
	eng.detectImpossibleTravel(login("AK", true))
	if len(eng.behaviorProfiles["user"].CommonLocations) != 10 {
		t.Errorf("expected 10 locations after cap, got %d", len(eng.behaviorProfiles["user"].CommonLocations))
	}
}

func TestDetectDDoS(t *testing.T) {
	e := &IAEngine{history: func(context.Context, QueryFilter) ([]*Event, error) {
		return make([]*Event, ddosThreshold), nil
	}}
	if !e.detectDDoS(&Event{Context: ContextInfo{IPAddress: "6.6.6.6"}}) {
		t.Error("expected DDoS detection")
	}
	e2 := &IAEngine{history: func(context.Context, QueryFilter) ([]*Event, error) {
		return make([]*Event, ddosThreshold-2), nil
	}}
	if e2.detectDDoS(&Event{Context: ContextInfo{IPAddress: "6.6.6.6"}}) {
		t.Error("did not expect DDoS below threshold")
	}
	if e2.detectDDoS(&Event{}) {
		t.Error("expected false for empty IP")
	}
}

func TestDetectAnomaly(t *testing.T) {
	e := &IAEngine{behaviorProfiles: make(map[string]*BehaviorProfile)}
	ev := func(tpe string) *Event {
		return &Event{Actor: ActorInfo{ID: "u"}, Action: ActionInfo{Type: tpe}}
	}
	if e.detectAnomaly(ev("READ")) {
		t.Error("first action should not be anomalous")
	}
	if !e.detectAnomaly(ev("DELETE")) {
		t.Error("different action should be anomalous")
	}
	if e.detectAnomaly(ev("READ")) {
		t.Error("known action should not be anomalous")
	}
	// Límite de 20 acciones típicas
	e2 := &IAEngine{behaviorProfiles: make(map[string]*BehaviorProfile)}
	for i := 0; i < 25; i++ {
		e2.detectAnomaly(ev(string(rune('A'+i))))
	}
	if len(e2.behaviorProfiles["u"].TypicalActions) > 20 {
		t.Errorf("expected at most 20 typical actions, got %d", len(e2.behaviorProfiles["u"].TypicalActions))
	}
}

func TestDetectMaliciousIP(t *testing.T) {
	e := NewIAEngine(0, nil)
	if e.detectMaliciousIP(&Event{}) {
		t.Error("expected false for empty IP")
	}
	if e.detectMaliciousIP(&Event{Context: ContextInfo{IPAddress: "1.2.3.4"}}) {
		t.Error("expected false for unknown IP")
	}
	e.ipReputation.Update(&IPReputation{IPAddress: "1.2.3.4", RiskScore: 0.95})
	if !e.detectMaliciousIP(&Event{Context: ContextInfo{IPAddress: "1.2.3.4"}}) {
		t.Error("expected detection for high risk IP")
	}
	e.ipReputation.Update(&IPReputation{IPAddress: "2.3.4.5", Blacklisted: true})
	if !e.detectMaliciousIP(&Event{Context: ContextInfo{IPAddress: "2.3.4.5"}}) {
		t.Error("expected detection for blacklisted IP")
	}
	e.ipReputation.Update(&IPReputation{IPAddress: "3.4.5.6", IsMalicious: true})
	if !e.detectMaliciousIP(&Event{Context: ContextInfo{IPAddress: "3.4.5.6"}}) {
		t.Error("expected detection for malicious IP")
	}
}

func TestActions(t *testing.T) {
	e := &IAEngine{}
	ev := &Event{Context: ContextInfo{IPAddress: "9.9.9.9", IPGeoLocation: GeoLocation{CountryCode: "ES"}}, Action: ActionInfo{Type: "READ", Path: "/p"}, Metadata: map[string]interface{}{"payload": "union select"}}
	cases := map[string]*ThreatDetection{
		"BRUTE_FORCE":      e.actionBruteForce(ev),
		"SQL_INJECTION":    e.actionSQLInjection(ev),
		"XSS":              e.actionXSS(ev),
		"SCRAPING":         e.actionScraping(ev),
		"IMPOSSIBLE_TRAVEL": e.actionImpossibleTravel(ev),
		"DDOS":             e.actionDDoS(ev),
		"ANOMALY":          e.actionAnomaly(ev),
		"MALICIOUS_IP":     e.actionMaliciousIP(ev),
	}
	for tpe, threat := range cases {
		if threat == nil {
			t.Errorf("action %s returned nil", tpe)
			continue
		}
		if threat.Type != tpe {
			t.Errorf("expected type %s, got %s", tpe, threat.Type)
		}
	}
	// Severidad de XSS viene del patrón
	xssEv := &Event{Action: ActionInfo{Path: "/p"}, Metadata: map[string]interface{}{"payload": "<script>x</script>"}}
	if e.actionXSS(xssEv).Pattern != "<script" {
		t.Errorf("expected XSS pattern, got %q", e.actionXSS(xssEv).Pattern)
	}
}

func TestGetSeverityMultiplier(t *testing.T) {
	cases := map[string]float64{"CRITICAL": 1.0, "HIGH": 0.75, "MEDIUM": 0.5, "LOW": 0.25, "UNKNOWN": 0.5}
	for sev, want := range cases {
		if got := getSeverityMultiplier(sev); got != want {
			t.Errorf("severity %s: expected %v, got %v", sev, want, got)
		}
	}
}

func TestIPReputationDB(t *testing.T) {
	db := &IPReputationDB{cache: make(map[string]*IPReputation)}
	if db.Get("1.1.1.1").RiskScore != 0 {
		t.Error("expected default reputation")
	}
	db.Update(&IPReputation{IPAddress: "2.2.2.2", RiskScore: 0.5})
	if db.Get("2.2.2.2").RiskScore != 0.5 {
		t.Error("expected updated reputation")
	}
	db.MarkAsMalicious("3.3.3.3", "abuse")
	rep := db.Get("3.3.3.3")
	if !rep.IsMalicious || rep.RiskScore != 1.0 || len(rep.Categories) != 1 {
		t.Errorf("expected malicious reputation, got %+v", rep)
	}
}

func TestIsTorExitNode(t *testing.T) {
	if !IsTorExitNode("185.220.101.55") {
		t.Error("expected TOR exit for known prefix")
	}
	if IsTorExitNode("8.8.8.8") {
		t.Error("did not expect TOR for random IP")
	}
	if IsTorExitNode("127") {
		t.Error("malformed IP should not panic and return false")
	}
}

func TestLookupGeoIP(t *testing.T) {
	if got := LookupGeoIP("invalid"); got.CountryCode != "" {
		t.Errorf("expected empty geo for invalid IP, got %+v", got)
	}
	if got := LookupGeoIP("127.0.0.1"); got.CountryCode != "LO" {
		t.Errorf("expected LO for loopback, got %+v", got)
	}
	if got := LookupGeoIP("10.0.0.5"); got.CountryCode != "PN" {
		t.Errorf("expected PN for private, got %+v", got)
	}
	if got := LookupGeoIP("8.8.8.8"); got.CountryCode != "XX" {
		t.Errorf("expected XX for public, got %+v", got)
	}
}

func TestBruteForceEndToEnd(t *testing.T) {
	a, err := NewAuditor(Config{StorageType: "memory", EnableIA: true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer a.Close()
	ip := "10.0.0.99"
	for i := 0; i < bruteForceThreshold; i++ {
		ev := &Event{
			ID:     string(rune('a' + i)),
			Actor:  ActorInfo{ID: "att", Type: "user"},
			Action: ActionInfo{Type: "LOGIN", Category: "AUTH"},
			Result: ResultInfo{Status: "FAILURE"},
			Context: ContextInfo{IPAddress: ip},
		}
		if err := a.Record(ev); err != nil {
			t.Fatalf("record %d failed: %v", i, err)
		}
	}
	ctx := context.Background()
	events, err := a.Query(ctx, QueryFilter{IPAddresses: []string{ip}, ThreatTypes: []string{"BRUTE_FORCE"}, Limit: 10})
	if err != nil {
		t.Fatalf("query failed: %v", err)
	}
	if len(events) == 0 {
		t.Fatal("expected brute force detection end to end")
	}
	stats := a.GetStats()
	if stats.ThreatsDetected == 0 {
		t.Error("expected threats detected in stats")
	}
}

func TestGetOrCreateProfile(t *testing.T) {
	e := &IAEngine{behaviorProfiles: make(map[string]*BehaviorProfile)}
	p := e.getOrCreateProfile("")
	if p.ActorID != "unknown" {
		t.Errorf("expected unknown profile, got %q", p.ActorID)
	}
	p2 := e.getOrCreateProfile("")
	if p != p2 {
		t.Error("expected same unknown profile")
	}
	p3 := e.getOrCreateProfile("x")
	if p3.ActorID != "x" {
		t.Errorf("expected x profile, got %q", p3.ActorID)
	}
}
