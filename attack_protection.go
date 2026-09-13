package atlas

import "context"

// AttackProtectionService is the /v1/attack_protection namespace.
type AttackProtectionService struct{ client *Client }

// BruteForceTier is one lockout tier in the brute-force policy.
type BruteForceTier struct {
	Threshold    int  `json:"threshold"`
	WindowMS     int  `json:"window_ms"`
	LockMS       int  `json:"lock_ms"`
	NotifyUser   bool `json:"notify_user"`
	FlagForAdmin bool `json:"flag_for_admin"`
}

// AttackProtection is the instance attack-protection configuration. Only the two
// enabled flags are writable; the rest is read-only.
type AttackProtection struct {
	Object     string `json:"object"`
	BruteForce struct {
		Enabled bool             `json:"enabled"`
		Tiers   []BruteForceTier `json:"tiers"`
	} `json:"brute_force"`
	BreachedPassword struct {
		Enabled bool `json:"enabled"`
	} `json:"breached_password"`
	SuspiciousIP struct {
		Enabled     bool     `json:"enabled"`
		IPAllowlist []string `json:"ip_allowlist"`
		ManagedBy   string   `json:"managed_by"`
	} `json:"suspicious_ip"`
	Captcha struct {
		Provider   string `json:"provider"`
		SiteKeySet bool   `json:"site_key_set"`
		SecretSet  bool   `json:"secret_set"`
		ManagedBy  string `json:"managed_by"`
	} `json:"captcha"`
}

// UpdateAttackProtectionParams toggles the two writable flags.
type UpdateAttackProtectionParams struct {
	BruteForce *struct {
		Enabled *bool `json:"enabled,omitempty"`
	} `json:"brute_force,omitempty"`
	BreachedPassword *struct {
		Enabled *bool `json:"enabled,omitempty"`
	} `json:"breached_password,omitempty"`
}

// Get returns the attack-protection configuration. GET /v1/attack_protection.
func (s *AttackProtectionService) Get(ctx context.Context) (*AttackProtection, error) {
	out := &AttackProtection{}
	return out, s.client.get(ctx, "/v1/attack_protection", nil, out)
}

// Update patches the writable flags. PATCH /v1/attack_protection.
func (s *AttackProtectionService) Update(ctx context.Context, params UpdateAttackProtectionParams) (*AttackProtection, error) {
	out := &AttackProtection{}
	return out, s.client.patch(ctx, "/v1/attack_protection", params, out)
}
