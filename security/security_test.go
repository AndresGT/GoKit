package security

import (
	"errors"
	"testing"
)

func TestDomainErrors(t *testing.T) {
	errs := []error{
		ErrInvalidHash,
		ErrIncompatibleVersion,
		ErrInvalidCiphertext,
		ErrInvalidKeyLength,
		ErrAuthenticationFailed,
		ErrPermissionDenied,
		ErrInsufficientSecurityLevel,
		ErrTokenInvalid,
		ErrTokenRevoked,
		ErrSessionExpired,
		ErrRateLimitExceeded,
		ErrAccountLocked,
		ErrIPBlocked,
		ErrInvalidInput,
		ErrWeakPassword,
		ErrOperationNotAllowed,
		ErrPasswordChangeRequired,
	}
	for _, e := range errs {
		if e == nil {
			t.Fatal("error var should not be nil")
		}
		if e.Error() == "" {
			t.Fatalf("error message should not be empty: %v", e)
		}
	}

	// errors.Is / As funcionan con los errores de dominio
	if !errors.Is(ErrTokenInvalid, ErrTokenInvalid) {
		t.Error("errors.Is should match the same error")
	}
	if errors.Is(ErrTokenInvalid, ErrTokenRevoked) {
		t.Error("distinct domain errors must not be equal")
	}
	if got := ErrRateLimitExceeded.Error(); got == "" {
		t.Error("expected a descriptive message")
	}
}

func TestLevelString(t *testing.T) {
	cases := []struct {
		level Level
		want  string
	}{
		{LevelDefault, "DEFAULT"},
		{LevelLow, "LOW"},
		{LevelMedium, "MEDIUM"},
		{LevelHigh, "HIGH"},
		{LevelCritical, "CRITICAL"},
		{Level(99), "UNKNOWN"},
	}
	for _, c := range cases {
		if got := c.level.String(); got != c.want {
			t.Errorf("Level(%d).String() = %q, want %q", c.level, got, c.want)
		}
	}
}

func TestLevelIsValid(t *testing.T) {
	for l := LevelDefault; l <= Level(99); l++ {
		want := l >= LevelLow && l <= LevelCritical
		if got := l.IsValid(); got != want {
			t.Errorf("Level(%d).IsValid() = %v, want %v", l, got, want)
		}
	}
}

func TestLevelGetDefaults(t *testing.T) {
	cases := []struct {
		level       Level
		bcryptCost  int
		maxAttempts int
		require2FA  bool
	}{
		{LevelLow, 10, 10, false},
		{LevelMedium, 12, 5, false},
		{LevelHigh, 14, 3, true},
		{LevelCritical, 15, 3, true},
	}
	for _, c := range cases {
		d := c.level.GetDefaults()
		if d.BcryptCost != c.bcryptCost {
			t.Errorf("Level(%d) BcryptCost = %d, want %d", c.level, d.BcryptCost, c.bcryptCost)
		}
		if d.MaxLoginAttempts != c.maxAttempts {
			t.Errorf("Level(%d) MaxLoginAttempts = %d, want %d", c.level, d.MaxLoginAttempts, c.maxAttempts)
		}
		if d.Require2FA != c.require2FA {
			t.Errorf("Level(%d) Require2FA = %v, want %v", c.level, d.Require2FA, c.require2FA)
		}
		if d.AccessTokenDuration <= 0 || d.RefreshTokenDuration <= 0 || d.SessionTimeout <= 0 || d.IdleTimeout <= 0 {
			t.Errorf("Level(%d) durations should be positive: %+v", c.level, d)
		}
		if d.LockoutDuration <= 0 || d.PasswordResetMaxPerHour <= 0 || d.MaxConcurrentSessions <= 0 {
			t.Errorf("Level(%d) limits should be positive: %+v", c.level, d)
		}
	}

	// Monotonicidad de las políticas de seguridad
	high := LevelHigh.GetDefaults()
	if high.BcryptCost <= LevelMedium.GetDefaults().BcryptCost {
		t.Error("LevelHigh should be stricter than LevelMedium")
	}
	if high.AccessTokenDuration >= LevelMedium.GetDefaults().AccessTokenDuration {
		t.Error("LevelHigh tokens should expire sooner than LevelMedium")
	}
}

func TestLevelDefaultFallsBackToMedium(t *testing.T) {
	if got := LevelDefault.GetDefaults(); got != LevelMedium.GetDefaults() {
		t.Errorf("LevelDefault should fall back to LevelMedium, got %+v", got)
	}
	if got := Level(255).GetDefaults(); got != LevelMedium.GetDefaults() {
		t.Errorf("invalid level should fall back to LevelMedium, got %+v", got)
	}
}

func TestSecurityDefaultsFields(t *testing.T) {
	d := LevelMedium.GetDefaults()
	fields := []interface{}{
		d.BcryptCost,
		d.AccessTokenDuration,
		d.RefreshTokenDuration,
		d.MaxLoginAttempts,
		d.LockoutDuration,
		d.PasswordResetMaxPerHour,
		d.MaxConcurrentSessions,
		d.SessionTimeout,
		d.IdleTimeout,
		d.Require2FA,
	}
	for _, f := range fields {
		if f == nil {
			t.Error("field should not be nil")
		}
	}
}
