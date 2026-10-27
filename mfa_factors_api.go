package atlas

import (
	"context"
	"net/url"
)

// MFAFactorsService is the mfaFactors resource.
type MFAFactorsService struct {
	client            *Client
	Yubikeys          *MFAFactorsYubikeysService
	SmartCardMappings *MFAFactorsSmartCardMappingsService
}

// SetYubicoSecret: Store (write-only, encrypted) the Yubico cloud API secret key (base64, from
// upgrade.yubico.com/getapikey). The client id is mfa.yubikey.clientId. Used when mfa.yubikey.mode
// is "cloud".
// PUT /v1/instance/yubico_secret.
func (s *MFAFactorsService) SetYubicoSecret(ctx context.Context, params MFAFactorsSetYubicoSecretParams, opts ...RequestOption) (*MFAFactorsSetYubicoSecretResult, error) {
	out := &MFAFactorsSetYubicoSecretResult{}
	return out, s.client.do(ctx, "PUT", "/v1/instance/yubico_secret", nil, params, out, opts...)
}

// RemoveYubicoSecret: Remove the stored Yubico cloud secret. Cloud-mode YubiKey sign-ins then fail
// until a new one is stored.
// DELETE /v1/instance/yubico_secret.
func (s *MFAFactorsService) RemoveYubicoSecret(ctx context.Context, opts ...RequestOption) (*MFAFactorsRemoveYubicoSecretResult, error) {
	out := &MFAFactorsRemoveYubicoSecretResult{}
	return out, s.client.do(ctx, "DELETE", "/v1/instance/yubico_secret", nil, nil, out, opts...)
}

// SetDuoSecret: Store (write-only, encrypted) the Duo Web SDK / Universal Prompt client secret.
// The client id (integration key) and API host are mfa.duo.clientId and mfa.duo.apiHost.
// PUT /v1/instance/duo_secret.
func (s *MFAFactorsService) SetDuoSecret(ctx context.Context, params MFAFactorsSetDuoSecretParams, opts ...RequestOption) (*MFAFactorsSetYubicoSecretResult, error) {
	out := &MFAFactorsSetYubicoSecretResult{}
	return out, s.client.do(ctx, "PUT", "/v1/instance/duo_secret", nil, params, out, opts...)
}

// RemoveDuoSecret: Remove the stored Duo client secret.
// DELETE /v1/instance/duo_secret.
func (s *MFAFactorsService) RemoveDuoSecret(ctx context.Context, opts ...RequestOption) (*MFAFactorsRemoveYubicoSecretResult, error) {
	out := &MFAFactorsRemoveYubicoSecretResult{}
	return out, s.client.do(ctx, "DELETE", "/v1/instance/duo_secret", nil, nil, out, opts...)
}

// SetSmartCardSecret: Store (write-only, encrypted) the shared secret your TLS proxy sends in the
// mfa.smartCard.secretHeader header, so Atlas believes the certificate headers only from your
// proxy. Use a random value of at least 24 characters.
// PUT /v1/instance/smart_card_secret.
func (s *MFAFactorsService) SetSmartCardSecret(ctx context.Context, params MFAFactorsSetSmartCardSecretParams, opts ...RequestOption) (*MFAFactorsSetYubicoSecretResult, error) {
	out := &MFAFactorsSetYubicoSecretResult{}
	return out, s.client.do(ctx, "PUT", "/v1/instance/smart_card_secret", nil, params, out, opts...)
}

// RemoveSmartCardSecret: Remove the stored proxy secret. Smart card sign-in then refuses every
// request.
// DELETE /v1/instance/smart_card_secret.
func (s *MFAFactorsService) RemoveSmartCardSecret(ctx context.Context, opts ...RequestOption) (*MFAFactorsRemoveYubicoSecretResult, error) {
	out := &MFAFactorsRemoveYubicoSecretResult{}
	return out, s.client.do(ctx, "DELETE", "/v1/instance/smart_card_secret", nil, nil, out, opts...)
}

// DuoHealthCheck: Ask Duo whether the configured integration key, stored secret and API host are
// accepted (Duo's health check). Reports ok and a message; nothing is changed.
// POST /v1/instance/duo_health_check.
func (s *MFAFactorsService) DuoHealthCheck(ctx context.Context, opts ...RequestOption) (*MFAFactorsDuoHealthCheckResult, error) {
	out := &MFAFactorsDuoHealthCheckResult{}
	return out, s.client.do(ctx, "POST", "/v1/instance/duo_health_check", nil, nil, out, opts...)
}

// ResetSecurityQuestions: Clear a user's security-question answers (and any lockout). They set new
// ones from their account.
// DELETE /v1/users/{id}/security_questions.
func (s *MFAFactorsService) ResetSecurityQuestions(ctx context.Context, id string, opts ...RequestOption) (*MFAFactorsResetSecurityQuestionsResult, error) {
	out := &MFAFactorsResetSecurityQuestionsResult{}
	return out, s.client.do(ctx, "DELETE", "/v1/users/"+url.PathEscape(id)+"/security_questions", nil, nil, out, opts...)
}

// MFAFactorsYubikeysService is the mfaFactors yubikeys group of MFAFactorsService.
type MFAFactorsYubikeysService struct {
	client *Client
}

// List: List the registered self-held YubiKeys (public id, owner, replay counter). The AES keys
// are never returned.
// GET /v1/yubikeys.
func (s *MFAFactorsYubikeysService) List(ctx context.Context, params ListParams) (*MFAFactorsYubikeysListResult, error) {
	out := &MFAFactorsYubikeysListResult{}
	return out, s.client.do(ctx, "GET", "/v1/yubikeys", params.values(), nil, out)
}

// Register: Register a YubiKey's AES key for self-held Yubico OTP (mfa.yubikey.mode "self_held").
// The key is stored encrypted and never returned. Give user_id to assign it; otherwise the first
// user to enrol it with a valid OTP claims it. 409 when the public id is already registered.
// POST /v1/yubikeys.
func (s *MFAFactorsYubikeysService) Register(ctx context.Context, params MFAFactorsYubikeysRegisterParams, opts ...RequestOption) (*MFAFactorsYubikeysListResultDataItem, error) {
	out := &MFAFactorsYubikeysListResultDataItem{}
	return out, s.client.do(ctx, "POST", "/v1/yubikeys", nil, params, out, opts...)
}

// Remove: Remove a registered YubiKey. A factor already enrolled with it stops verifying.
// DELETE /v1/yubikeys/{id}.
func (s *MFAFactorsYubikeysService) Remove(ctx context.Context, id string, opts ...RequestOption) (*UsersDeleteDeviceKeyResult, error) {
	out := &UsersDeleteDeviceKeyResult{}
	return out, s.client.do(ctx, "DELETE", "/v1/yubikeys/"+url.PathEscape(id), nil, nil, out, opts...)
}

// MFAFactorsSmartCardMappingsService is the mfaFactors smartCardMappings group of MFAFactorsService.
type MFAFactorsSmartCardMappingsService struct {
	client *Client
}

// List: List the certificate attributes registered for a user.
// GET /v1/users/{id}/smartcard_mappings.
func (s *MFAFactorsSmartCardMappingsService) List(ctx context.Context, id string, params ListParams) (*MFAFactorsSmartCardMappingsListResult, error) {
	out := &MFAFactorsSmartCardMappingsListResult{}
	return out, s.client.do(ctx, "GET", "/v1/users/"+url.PathEscape(id)+"/smartcard_mappings", params.values(), nil, out)
}

// Add: Pre-register the certificate attribute that signs this user in with a smart card: kind
// fingerprint (SHA-256, 64 hex), serial (hex, plus the issuer DN), san_email, san_upn or
// subject_cn. A registered mapping only applies while its kind is listed in
// mfa.smartCard.mappingRules. 409 when the value is already mapped.
// POST /v1/users/{id}/smartcard_mappings.
func (s *MFAFactorsSmartCardMappingsService) Add(ctx context.Context, id string, params MFAFactorsSmartCardMappingsAddParams, opts ...RequestOption) (*MFAFactorsSmartCardMappingsListResultDataItem, error) {
	out := &MFAFactorsSmartCardMappingsListResultDataItem{}
	return out, s.client.do(ctx, "POST", "/v1/users/"+url.PathEscape(id)+"/smartcard_mappings", nil, params, out, opts...)
}

// Remove: Remove a registered certificate mapping.
// DELETE /v1/users/{id}/smartcard_mappings/{mappingId}.
func (s *MFAFactorsSmartCardMappingsService) Remove(ctx context.Context, id string, mappingID string, opts ...RequestOption) (*UsersDeleteDeviceKeyResult, error) {
	out := &UsersDeleteDeviceKeyResult{}
	return out, s.client.do(ctx, "DELETE", "/v1/users/"+url.PathEscape(id)+"/smartcard_mappings/"+url.PathEscape(mappingID), nil, nil, out, opts...)
}
