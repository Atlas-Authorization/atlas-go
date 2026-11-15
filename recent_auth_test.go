package atlas

import (
	"testing"
	"time"
)

func TestAuthenticatedWithin(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	claims := &SessionClaims{AuthTime: now.Add(-2 * time.Minute).Unix()}
	if !AuthenticatedWithinAt(claims, 5*time.Minute, now) {
		t.Fatal("2 minutes ago is within 5 minutes")
	}
	if AuthenticatedWithinAt(claims, time.Minute, now) {
		t.Fatal("2 minutes ago is not within 1 minute")
	}
	if AuthenticatedWithinAt(&SessionClaims{}, time.Hour, now) || AuthenticatedWithinAt(nil, time.Hour, now) {
		t.Fatal("a token without auth_time is never recent")
	}
}

func TestUsedMultiFactor(t *testing.T) {
	if !UsedMultiFactor(&SessionClaims{Acr: "urn:atlas:acr:mfa"}) || !UsedMultiFactor(&SessionClaims{Amr: []string{"pwd", "mfa"}}) {
		t.Fatal("acr mfa and amr mfa both count")
	}
	if UsedMultiFactor(&SessionClaims{Acr: "urn:atlas:acr:basic", Amr: []string{"pwd"}}) || UsedMultiFactor(nil) {
		t.Fatal("a password-only session did not use a second factor")
	}
}
