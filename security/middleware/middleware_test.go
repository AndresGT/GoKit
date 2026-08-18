package middleware

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/AndresGT/GoKit/security/token"
	"github.com/gin-gonic/gin"
	"github.com/gofiber/fiber/v2"
)

const mwTestSecret = "una-clave-secreta-de-al-menos-32-bytes!!"

func newTestJWTManager(t *testing.T) *token.JWTManager {
	t.Helper()
	m, err := token.NewJWTManager(token.JWTConfig{
		SecretKey:            []byte(mwTestSecret),
		Issuer:               "test",
		AccessTokenDuration:  time.Hour,
		RefreshTokenDuration: time.Hour,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return m
}

// =============================================================================
// Chain y contexto
// =============================================================================

func TestChain(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Order", r.Header.Get("X-Order")+"handler")
	})
	mw := func(tag string) Middleware {
		return func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				r.Header.Set("X-Order", r.Header.Get("X-Order")+tag)
				next.ServeHTTP(w, r)
			})
		}
	}

	final := Chain(h, mw("a"), mw("b"))
	rec := httptest.NewRecorder()
	final.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Header().Get("X-Order") != "abhandler" {
		t.Errorf("expected order 'abhandler', got %q", rec.Header().Get("X-Order"))
	}

	// Chain sin middlewares pasa directo al handler.
	plain := Chain(h)
	rec2 := httptest.NewRecorder()
	plain.ServeHTTP(rec2, httptest.NewRequest("GET", "/", nil))
	if rec2.Header().Get("X-Order") != "handler" {
		t.Errorf("expected order 'handler', got %q", rec2.Header().Get("X-Order"))
	}
}

func TestClaimsFromContext(t *testing.T) {
	// Con un handler que no pasa por RequireAuth, no hay claims.
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := ClaimsFromContext(r.Context()); ok {
			t.Error("expected no claims in plain handler")
		}
	})
	h(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil))
}

// =============================================================================
// RequireAuth
// =============================================================================

func performRequest(h http.Handler, method, path, authHeader string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestRequireAuth(t *testing.T) {
	m := newTestJWTManager(t)
	h := Chain(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), RequireAuth(m))

	access, _ := m.GenerateAccessToken(token.Claims{UserID: "u", Role: "admin"})

	tests := []struct {
		name       string
		authHeader string
		wantStatus int
	}{
		{"sin header", "", http.StatusUnauthorized},
		{"malformado", "Basic abc", http.StatusUnauthorized},
		{"token inválido", "Bearer token-basura", http.StatusUnauthorized},
		{"sin espacio", "Bearer", http.StatusUnauthorized},
		{"token vacío", "Bearer   ", http.StatusUnauthorized},
		{"token válido", "Bearer " + access, http.StatusOK},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := performRequest(h, "GET", "/", tt.authHeader)
			if rec.Code != tt.wantStatus {
				t.Errorf("expected status %d, got %d", tt.wantStatus, rec.Code)
			}
			if rec.Code == http.StatusUnauthorized && !strings.Contains(rec.Body.String(), "error") {
				t.Errorf("expected JSON error body, got %q", rec.Body.String())
			}
		})
	}
}

func TestRequireAuth_RejectsRefreshToken(t *testing.T) {
	m := newTestJWTManager(t)
	h := Chain(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), RequireAuth(m))

	refresh, _ := m.GenerateRefreshToken(token.Claims{UserID: "u"})
	rec := performRequest(h, "GET", "/", "Bearer "+refresh)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for refresh token, got %d", rec.Code)
	}
}

func TestRequireAuth_ClaimsInContext(t *testing.T) {
	m := newTestJWTManager(t)
	access, _ := m.GenerateAccessToken(token.Claims{UserID: "user-1", Role: "admin"})

	h := Chain(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, ok := ClaimsFromContext(r.Context())
		if !ok || claims.UserID != "user-1" {
			t.Errorf("expected claims with UserID user-1, ok=%v", ok)
		}
	}), RequireAuth(m))

	if rec := performRequest(h, "GET", "/", "Bearer "+access); rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

// =============================================================================
// RequireRole
// =============================================================================

func TestRequireRole(t *testing.T) {
	m := newTestJWTManager(t)
	admin, _ := m.GenerateAccessToken(token.Claims{UserID: "a", Role: "admin"})
	user, _ := m.GenerateAccessToken(token.Claims{UserID: "u", Role: "user"})

	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Sin RequireAuth antes: no hay claims en el contexto → 401.
	noAuth := Chain(ok, RequireRole("admin"))
	if rec := performRequest(noAuth, "GET", "/", "Bearer "+admin); rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for missing context claims, got %d", rec.Code)
	}

	// Con auth pero rol no permitido: 403.
	authed := Chain(ok, RequireAuth(m), RequireRole("admin"))
	if rec := performRequest(authed, "GET", "/", "Bearer "+user); rec.Code != http.StatusForbidden {
		t.Errorf("expected 403 for disallowed role, got %d", rec.Code)
	}

	// Rol permitido: 200.
	if rec := performRequest(authed, "GET", "/", "Bearer "+admin); rec.Code != http.StatusOK {
		t.Errorf("expected 200 for allowed role, got %d", rec.Code)
	}
}

// =============================================================================
// RequireActiveSession
// =============================================================================

func TestRequireActiveSession(t *testing.T) {
	jwtM := newTestJWTManager(t)
	sessions := token.NewSessionManager(token.SessionConfig{
		SessionTimeout: time.Hour,
		IdleTimeout:    time.Hour,
	})
	sessionID, err := sessions.CreateSession(token.SessionInfo{UserID: "u"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	withSession, _ := jwtM.GenerateAccessToken(token.Claims{UserID: "u", SessionID: sessionID})
	withoutSession, _ := jwtM.GenerateAccessToken(token.Claims{UserID: "u"})
	withMissingSession, _ := jwtM.GenerateAccessToken(token.Claims{UserID: "u", SessionID: "no-existe"})

	h := Chain(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), RequireAuth(jwtM), RequireActiveSession(sessions))

	tests := []struct {
		name       string
		authHeader string
		wantStatus int
	}{
		{"sesión válida", "Bearer " + withSession, http.StatusOK},
		{"sin SessionID", "Bearer " + withoutSession, http.StatusUnauthorized},
		{"sesión inexistente", "Bearer " + withMissingSession, http.StatusUnauthorized},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := performRequest(h, "GET", "/", tt.authHeader)
			if rec.Code != tt.wantStatus {
				t.Errorf("expected status %d, got %d", tt.wantStatus, rec.Code)
			}
		})
	}
}

// =============================================================================
// CORS
// =============================================================================

func TestCORS(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	cfg := CORSConfig{
		AllowedOrigins:   []string{"https://app.example.com", "*"},
		AllowCredentials: true,
		MaxAge:           600,
	}
	h := CORS(cfg)(next)

	// Origen permitido + credenciales.
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Origin", "https://app.example.com")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Header().Get("Access-Control-Allow-Origin") != "https://app.example.com" {
		t.Errorf("expected echo origin, got %q", rec.Header().Get("Access-Control-Allow-Origin"))
	}
	if rec.Header().Get("Vary") != "Origin" {
		t.Errorf("expected Vary: Origin, got %q", rec.Header().Get("Vary"))
	}
	if rec.Header().Get("Access-Control-Allow-Credentials") != "true" {
		t.Error("expected credentials header")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}

	// Wildcard: con credenciales no se aplica.
	req2 := httptest.NewRequest("GET", "/", nil)
	req2.Header.Set("Origin", "https://other.com")
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)
	if rec2.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Errorf("expected no wildcard with credentials, got %q", rec2.Header().Get("Access-Control-Allow-Origin"))
	}

	// Preflight OPTIONS.
	req3 := httptest.NewRequest("OPTIONS", "/", nil)
	req3.Header.Set("Origin", "https://app.example.com")
	rec3 := httptest.NewRecorder()
	h.ServeHTTP(rec3, req3)
	if rec3.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d", rec3.Code)
	}
	if rec3.Header().Get("Access-Control-Allow-Methods") == "" {
		t.Error("expected allowed methods header")
	}
	if rec3.Header().Get("Access-Control-Allow-Headers") == "" {
		t.Error("expected allowed headers header")
	}
	if rec3.Header().Get("Access-Control-Max-Age") != "600" {
		t.Errorf("expected max age 600, got %q", rec3.Header().Get("Access-Control-Max-Age"))
	}
}

func TestCORS_DefaultsAndWildcard(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Sin origen: solo se añaden cabeceras en OPTIONS.
	h := CORS(CORSConfig{AllowedOrigins: []string{"*"}})(next)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Error("expected no CORS headers without Origin")
	}

	// Wildcard sin credenciales: ACAO "*".
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Origin", "https://any.com")
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req)
	if rec2.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Errorf("expected *, got %q", rec2.Header().Get("Access-Control-Allow-Origin"))
	}
}

// =============================================================================
// RequestLogger
// =============================================================================

type captureLogger struct {
	messages []string
}

func (l *captureLogger) Info(message string) {
	l.messages = append(l.messages, message)
}

func TestRequestLogger(t *testing.T) {
	log := &captureLogger{}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	h := RequestLogger(log)(next)

	rec := performRequest(h, "POST", "/recurso", "")
	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rec.Code)
	}
	if len(log.messages) != 1 {
		t.Fatalf("expected 1 log message, got %d", len(log.messages))
	}
	if !strings.Contains(log.messages[0], "POST /recurso 404") {
		t.Errorf("unexpected log message %q", log.messages[0])
	}
}

func TestRequestLogger_DefaultStatus(t *testing.T) {
	log := &captureLogger{}

	// Handler que nunca llama a WriteHeader: se asume 200.
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})
	h := RequestLogger(log)(next)
	rec := performRequest(h, "GET", "/", "")
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	if !strings.Contains(log.messages[0], " 200 ") {
		t.Errorf("expected status 200 in log, got %q", log.messages[0])
	}
}

func TestStatusRecorder_WriteHeader(t *testing.T) {
	rec := httptest.NewRecorder()
	sr := &statusRecorder{ResponseWriter: rec}
	sr.WriteHeader(http.StatusAccepted)
	if sr.status != http.StatusAccepted {
		t.Errorf("expected status 202, got %d", sr.status)
	}
	if rec.Code != http.StatusAccepted {
		t.Errorf("expected recorder status 202, got %d", rec.Code)
	}
}

// =============================================================================
// Rate limiting
// =============================================================================

func TestMemoryRateLimiter_Defaults(t *testing.T) {
	l := NewMemoryRateLimiter(0, 0)
	if l.limit != 1 {
		t.Errorf("expected limit 1, got %d", l.limit)
	}
	if l.window != time.Minute {
		t.Errorf("expected window 1m, got %v", l.window)
	}
}

func TestMemoryRateLimiter_Allow(t *testing.T) {
	l := NewMemoryRateLimiter(2, time.Hour)
	if !l.Allow("k") {
		t.Fatal("expected first request allowed")
	}
	if !l.Allow("k") {
		t.Fatal("expected second request allowed")
	}
	if l.Allow("k") {
		t.Fatal("expected third request rejected")
	}
	// Claves distintas no comparten contador.
	if !l.Allow("otra") {
		t.Fatal("expected different key allowed")
	}
}

func TestMemoryRateLimiter_WindowReset(t *testing.T) {
	l := NewMemoryRateLimiter(1, 10*time.Millisecond)
	if !l.Allow("k") {
		t.Fatal("expected first request allowed")
	}
	if l.Allow("k") {
		t.Fatal("expected request rejected within window")
	}
	time.Sleep(20 * time.Millisecond)
	if !l.Allow("k") {
		t.Fatal("expected request allowed after window reset")
	}
}

func TestMemoryRateLimiter_Cleanup(t *testing.T) {
	l := NewMemoryRateLimiter(1, 10*time.Millisecond)
	l.Allow("vieja")
	time.Sleep(20 * time.Millisecond)
	l.Allow("nueva")

	l.Cleanup()
	if _, exists := l.counters["vieja"]; exists {
		t.Error("expected expired key removed")
	}
	if _, exists := l.counters["nueva"]; !exists {
		t.Error("expected fresh key to remain")
	}
}

func TestRemoteIPKeyFunc(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.168.1.10:54321"
	if got := RemoteIPKeyFunc(req); got != "192.168.1.10" {
		t.Errorf("expected IP without port, got %q", got)
	}

	req2 := httptest.NewRequest("GET", "/", nil)
	req2.RemoteAddr = "sin-puerto"
	if got := RemoteIPKeyFunc(req2); got != "sin-puerto" {
		t.Errorf("expected fallback to RemoteAddr, got %q", got)
	}
}

func TestRateLimit(t *testing.T) {
	limiter := NewMemoryRateLimiter(1, time.Hour)
	h := RateLimit(limiter, nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}

	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req)
	if rec2.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429, got %d", rec2.Code)
	}
	if !strings.Contains(rec2.Body.String(), "error") {
		t.Errorf("expected JSON error body, got %q", rec2.Body.String())
	}
}

func TestRateLimit_CustomKeyFunc(t *testing.T) {
	limiter := NewMemoryRateLimiter(1, time.Hour)
	keyFunc := func(r *http.Request) string { return r.Header.Get("X-API-Key") }
	h := RateLimit(limiter, keyFunc)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-API-Key", "clave-1")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}

	req2 := httptest.NewRequest("GET", "/", nil)
	req2.Header.Set("X-API-Key", "clave-1")
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429, got %d", rec2.Code)
	}

	// Otra clave no está limitada.
	req3 := httptest.NewRequest("GET", "/", nil)
	req3.Header.Set("X-API-Key", "clave-2")
	rec3 := httptest.NewRecorder()
	h.ServeHTTP(rec3, req3)
	if rec3.Code != http.StatusOK {
		t.Errorf("expected 200 for other key, got %d", rec3.Code)
	}
}

// =============================================================================
// Registro de rutas (opciones y logging)
// =============================================================================

func TestRegisterOptions(t *testing.T) {
	m := newTestJWTManager(t)

	o := buildRegisterOptions([]RegisterOption{WithAuthManager(m), WithGroupName("admin")})
	if o.AuthManager != m {
		t.Error("expected AuthManager set")
	}
	if o.GroupName != "admin" {
		t.Errorf("expected group admin, got %q", o.GroupName)
	}

	o2 := buildRegisterOptions(nil)
	if o2.AuthManager != nil || o2.GroupName != "" {
		t.Error("expected empty options")
	}
}

func TestLogRouteRegistered(t *testing.T) {
	// Solo se verifica que no panique en todas las combinaciones.
	logRouteRegistered("GET", "/publico", false, false, "")
	logRouteRegistered("GET", "/protegido", true, true, "api")
	logRouteRegistered("GET", "/protegido", true, false, "")
}

func TestRegisterGinRoutes(t *testing.T) {
	gin.SetMode(gin.TestMode)
	m := newTestJWTManager(t)
	access, _ := m.GenerateAccessToken(token.Claims{UserID: "u", Role: "admin"})

	ok := func(c *gin.Context) { c.String(http.StatusOK, "ok") }

	r := gin.New()
	group := r.Group("/api")
	RegisterGinRoutes(group, []Route[gin.HandlerFunc]{
		{Method: "GET", Path: "/publico", Handler: ok, Protected: false},
		{Method: "GET", Path: "/secreto", Handler: ok, Protected: true},
	}, WithAuthManager(m), WithGroupName("api"))

	req := httptest.NewRequest("GET", "/api/publico", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 for public route, got %d", rec.Code)
	}

	req2 := httptest.NewRequest("GET", "/api/secreto", nil)
	rec2 := httptest.NewRecorder()
	r.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for protected route without token, got %d", rec2.Code)
	}

	reqMal := httptest.NewRequest("GET", "/api/secreto", nil)
	reqMal.Header.Set("Authorization", "Basic abc")
	recMal := httptest.NewRecorder()
	r.ServeHTTP(recMal, reqMal)
	if recMal.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for malformed header, got %d", recMal.Code)
	}

	reqBad := httptest.NewRequest("GET", "/api/secreto", nil)
	reqBad.Header.Set("Authorization", "Bearer basura")
	recBad := httptest.NewRecorder()
	r.ServeHTTP(recBad, reqBad)
	if recBad.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for invalid token, got %d", recBad.Code)
	}

	req3 := httptest.NewRequest("GET", "/api/secreto", nil)
	req3.Header.Set("Authorization", "Bearer "+access)
	rec3 := httptest.NewRecorder()
	r.ServeHTTP(rec3, req3)
	if rec3.Code != http.StatusOK {
		t.Errorf("expected 200 for protected route with token, got %d", rec3.Code)
	}
}

func TestRegisterGinRoutes_NoAuthManager(t *testing.T) {
	gin.SetMode(gin.TestMode)

	r := gin.New()
	group := r.Group("/api")
	RegisterGinRoutes(group, []Route[gin.HandlerFunc]{
		{Method: "GET", Path: "/secreto", Handler: func(c *gin.Context) { c.String(http.StatusOK, "ok") }, Protected: true},
	})

	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest("GET", "/api/secreto", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 without auth manager, got %d", rec.Code)
	}
}

func TestRegisterFiberRoutes(t *testing.T) {
	m := newTestJWTManager(t)
	access, _ := m.GenerateAccessToken(token.Claims{UserID: "u", Role: "admin"})

	app := fiber.New()
	api := app.Group("/api")
	RegisterFiberRoutes(api, []Route[fiber.Handler]{
		{Method: "GET", Path: "/publico", Handler: func(c *fiber.Ctx) error { return c.SendString("ok") }, Protected: false},
		{Method: "GET", Path: "/secreto", Handler: func(c *fiber.Ctx) error { return c.SendString("ok") }, Protected: true},
	}, WithAuthManager(m), WithGroupName("api"))

	req := httptest.NewRequest("GET", "/api/publico", nil)
	if resp, err := app.Test(req); err != nil || resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 for public route, got %d err=%v", statusOf(resp), err)
	}

	req2 := httptest.NewRequest("GET", "/api/secreto", nil)
	if resp, err := app.Test(req2); err != nil || resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 for protected route without token, got %d err=%v", statusOf(resp), err)
	}

	reqMal := httptest.NewRequest("GET", "/api/secreto", nil)
	reqMal.Header.Set("Authorization", "Basic abc")
	if resp, err := app.Test(reqMal); err != nil || resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 for malformed header, got %d err=%v", statusOf(resp), err)
	}

	reqBad := httptest.NewRequest("GET", "/api/secreto", nil)
	reqBad.Header.Set("Authorization", "Bearer basura")
	if resp, err := app.Test(reqBad); err != nil || resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 for invalid token, got %d err=%v", statusOf(resp), err)
	}

	req3 := httptest.NewRequest("GET", "/api/secreto", nil)
	req3.Header.Set("Authorization", "Bearer "+access)
	if resp, err := app.Test(req3); err != nil || resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 for protected route with token, got %d err=%v", statusOf(resp), err)
	}
}

func TestRegisterFiberRoutes_NoAuthManager(t *testing.T) {
	app := fiber.New()
	api := app.Group("/api")
	RegisterFiberRoutes(api, []Route[fiber.Handler]{
		{Method: "GET", Path: "/secreto", Handler: func(c *fiber.Ctx) error { return c.SendString("ok") }, Protected: true},
	})

	resp, err := app.Test(httptest.NewRequest("GET", "/api/secreto", nil))
	if err != nil || statusOf(resp) != http.StatusOK {
		t.Errorf("expected 200 without auth manager, got %d err=%v", statusOf(resp), err)
	}
}

func statusOf(r *http.Response) int {
	if r == nil {
		return 0
	}
	return r.StatusCode
}

// =============================================================================
// Gin auth/logger/recovery
// =============================================================================

func initGlobalToken(t *testing.T) {
	t.Helper()
	if err := token.Init(token.JWTConfig{
		SecretKey:            []byte(mwTestSecret),
		Issuer:               "test",
		AccessTokenDuration:  time.Hour,
		RefreshTokenDuration: time.Hour,
	}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestGinAuth(t *testing.T) {
	gin.SetMode(gin.TestMode)
	initGlobalToken(t)
	access, _ := token.GenerateAccessToken(token.Claims{UserID: "u", Role: "admin"})

	r := gin.New()
	r.Use(GinAuth())
	r.GET("/", func(c *gin.Context) { c.String(http.StatusOK, "ok") })

	tests := []struct {
		name       string
		authHeader string
		wantStatus int
	}{
		{"sin header", "", http.StatusUnauthorized},
		{"malformado", "Basic abc", http.StatusUnauthorized},
		{"token inválido", "Bearer basura", http.StatusUnauthorized},
		{"token válido", "Bearer " + access, http.StatusOK},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}
			rec := httptest.NewRecorder()
			r.ServeHTTP(rec, req)
			if rec.Code != tt.wantStatus {
				t.Errorf("expected status %d, got %d", tt.wantStatus, rec.Code)
			}
		})
	}

	// Los claims quedan en el contexto de Gin.
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+access)
	rec := httptest.NewRecorder()
	r2 := gin.New()
	r2.Use(GinAuth())
	r2.GET("/", func(c *gin.Context) {
		if c.GetString("user_id") != "u" {
			t.Error("expected user_id in gin context")
		}
		c.String(http.StatusOK, "ok")
	})
	r2.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

func TestGinLogger(t *testing.T) {
	gin.SetMode(gin.TestMode)

	r := gin.New()
	r.Use(GinLogger())
	r.GET("/ok", func(c *gin.Context) { c.String(http.StatusOK, "ok") })
	r.GET("/warn", func(c *gin.Context) { c.String(http.StatusNotFound, "no") })
	r.GET("/err", func(c *gin.Context) {
		_ = c.Error(errors.New("boom"))
		c.String(http.StatusInternalServerError, "err")
	})

	if rec := requestGin(r, "GET", "/ok"); rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	if rec := requestGin(r, "GET", "/warn"); rec.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rec.Code)
	}
	if rec := requestGin(r, "GET", "/err"); rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", rec.Code)
	}
}

func TestGinRecovery(t *testing.T) {
	gin.SetMode(gin.TestMode)

	r := gin.New()
	r.Use(GinRecovery())
	r.GET("/", func(c *gin.Context) {
		panic("boom")
	})

	rec := requestGin(r, "GET", "/")
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "error") {
		t.Errorf("expected JSON error body, got %q", rec.Body.String())
	}
}

func requestGin(r *gin.Engine, method, path string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

// =============================================================================
// Fiber auth/logger/recovery
// =============================================================================

func TestFiberAuth(t *testing.T) {
	initGlobalToken(t)
	access, _ := token.GenerateAccessToken(token.Claims{UserID: "u", Role: "admin"})

	app := fiber.New()
	app.Use(FiberAuth())
	app.Get("/", func(c *fiber.Ctx) error { return c.SendString("ok") })

	tests := []struct {
		name       string
		authHeader string
		wantStatus int
	}{
		{"sin header", "", http.StatusUnauthorized},
		{"malformado", "Basic abc", http.StatusUnauthorized},
		{"token inválido", "Bearer basura", http.StatusUnauthorized},
		{"token válido", "Bearer " + access, http.StatusOK},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}
			resp, err := app.Test(req)
			if err != nil || statusOf(resp) != tt.wantStatus {
				t.Errorf("expected status %d, got %d err=%v", tt.wantStatus, statusOf(resp), err)
			}
		})
	}
}

func TestFiberLogger(t *testing.T) {
	app := fiber.New()
	app.Use(FiberLogger())
	app.Get("/ok", func(c *fiber.Ctx) error { return c.SendString("ok") })
	app.Get("/warn", func(c *fiber.Ctx) error { return c.Status(http.StatusNotFound).SendString("no") })
	app.Get("/err", func(c *fiber.Ctx) error { return c.Status(http.StatusInternalServerError).SendString("err") })

	if resp, err := app.Test(httptest.NewRequest("GET", "/ok", nil)); err != nil || statusOf(resp) != http.StatusOK {
		t.Errorf("expected 200, got %d err=%v", statusOf(resp), err)
	}
	if resp, err := app.Test(httptest.NewRequest("GET", "/warn", nil)); err != nil || statusOf(resp) != http.StatusNotFound {
		t.Errorf("expected 404, got %d err=%v", statusOf(resp), err)
	}
	if resp, err := app.Test(httptest.NewRequest("GET", "/err", nil)); err != nil || statusOf(resp) != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d err=%v", statusOf(resp), err)
	}
}

func TestFiberRecovery(t *testing.T) {
	app := fiber.New()
	app.Use(FiberRecovery())
	app.Get("/", func(c *fiber.Ctx) error {
		panic("boom")
	})

	resp, err := app.Test(httptest.NewRequest("GET", "/", nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", resp.StatusCode)
	}
}
