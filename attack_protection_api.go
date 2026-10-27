package atlas

import (
	"context"
	"net/url"
)

// SetAppAttestationSecret: Store the Play Integrity response-decryption key (base64 AES-256) for
// app attestation. Write-only; the public verification key is
// attackProtection.appAttestation.android.verificationKey.
// PUT /v1/attack_protection/app_attestation_secret.
func (s *AttackProtectionService) SetAppAttestationSecret(ctx context.Context, params AttackProtectionSetAppAttestationSecretParams, opts ...RequestOption) (*MFAFactorsSetYubicoSecretResult, error) {
	out := &MFAFactorsSetYubicoSecretResult{}
	return out, s.client.do(ctx, "PUT", "/v1/attack_protection/app_attestation_secret", nil, params, out, opts...)
}

// AttackProtectionRemoveAppAttestationSecretQuery holds the query parameters of AttackProtectionService.RemoveAppAttestationSecret.
type AttackProtectionRemoveAppAttestationSecretQuery struct {
	// Which secret to remove. Default play_integrity.
	Kind string
}

func (q AttackProtectionRemoveAppAttestationSecretQuery) values() url.Values {
	v := url.Values{}
	if q.Kind != "" {
		v.Set("kind", q.Kind)
	}
	return v
}

// RemoveAppAttestationSecret: Remove a stored attestation secret: the Play Integrity decryption
// key (default) or, with kind=devicecheck, the Apple DeviceCheck key. That platform then refuses
// every request.
// DELETE /v1/attack_protection/app_attestation_secret.
func (s *AttackProtectionService) RemoveAppAttestationSecret(ctx context.Context, query AttackProtectionRemoveAppAttestationSecretQuery, opts ...RequestOption) (*MFAFactorsRemoveYubicoSecretResult, error) {
	out := &MFAFactorsRemoveYubicoSecretResult{}
	return out, s.client.do(ctx, "DELETE", "/v1/attack_protection/app_attestation_secret", query.values(), nil, out, opts...)
}
