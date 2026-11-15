package atlas

import "time"

// AuthenticatedWithin reports whether the session's auth_time (the first-factor
// sign-in, or the last step-up) is no older than maxAge. A token without
// auth_time is never recent. Use it to gate sensitive actions and answer 401
// with a "reauthentication_required" hint when it is false:
//
//	if !atlas.AuthenticatedWithin(claims, 5*time.Minute) {
//	        // ask the browser to step up, then retry
//	}
func AuthenticatedWithin(c *SessionClaims, maxAge time.Duration) bool {
	return AuthenticatedWithinAt(c, maxAge, time.Now())
}

// AuthenticatedWithinAt is AuthenticatedWithin against an explicit clock.
func AuthenticatedWithinAt(c *SessionClaims, maxAge time.Duration, now time.Time) bool {
	if c == nil || c.AuthTime <= 0 {
		return false
	}
	return now.Sub(time.Unix(c.AuthTime, 0)) <= maxAge
}

// UsedMultiFactor reports whether the session proved a second factor: acr is
// urn:atlas:acr:mfa, or amr includes "mfa". It is narrower than MFASatisfied,
// which also honours the server's own verdict and enterprise SSO sign-ins.
func UsedMultiFactor(c *SessionClaims) bool {
	if c == nil {
		return false
	}
	if c.Acr == "urn:atlas:acr:mfa" {
		return true
	}
	for _, m := range c.Amr {
		if m == "mfa" {
			return true
		}
	}
	return false
}
