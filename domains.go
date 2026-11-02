package atlas

import (
	"context"
	"net/url"
)

// DomainsService is the /v1/domains namespace (instance custom domains).
type DomainsService struct{ client *Client }

// CustomDomain is a FAPI/accounts custom domain.
type CustomDomain struct {
	Object string `json:"object"`
	ID     string `json:"id"`
	Role   string `json:"role"`
	Host   string `json:"host"`
	Status string `json:"status"`
	Action string `json:"action"`
	Live   bool   `json:"live"`
	// Method is cname, or path: a path mount on your own host, proven by an
	// https file (no DNS).
	Method string `json:"method,omitempty"`
	// CNAMETarget is "" for a path mount (no CNAME).
	CNAMETarget          string  `json:"cname_target"`
	LastCheckedAt        *int64  `json:"last_checked_at"`
	LastObservedTarget   *string `json:"last_observed_target"`
	FailureReason        *string `json:"failure_reason"`
	CertificateExpiresAt *int64  `json:"certificate_expires_at"`
	CookieDomain         *string `json:"cookie_domain"`
	// DNS is the DNS automation provider for this host (the token is never
	// returned), or nil.
	DNS *CustomDomainDNS `json:"dns,omitempty"`
	// BasePath (path mount) is the prefix the Frontend API is served under.
	BasePath *string `json:"base_path,omitempty"`
	// Routing (path mount, once verified) is atlas_ingress or customer_proxy.
	Routing *string `json:"routing,omitempty"`
	// FrontendAPIURL (path mount) is https://<host><base_path>: the Frontend
	// API and, once verified, the issuer.
	FrontendAPIURL string `json:"frontend_api_url,omitempty"`
	// Verification (path mount): publish Content at URL (status 200, no
	// redirect), then Verify.
	Verification *CustomDomainFileVerification `json:"verification,omitempty"`
	// Instructions (path mount, once verified): nothing to add, or the
	// reverse-proxy rule (headers, nginx / Caddy / Traefik snippets).
	Instructions map[string]interface{} `json:"instructions,omitempty"`
	// Verified and Issuer are set by Verify; Issuer on a verified path mount
	// is the issuer tokens now carry.
	Verified *bool  `json:"verified,omitempty"`
	Issuer   string `json:"issuer,omitempty"`
}

// CustomDomainFileVerification is the https file that proves a path mount.
type CustomDomainFileVerification struct {
	// Method is https_file.
	Method       string `json:"method"`
	URL          string `json:"url"`
	Token        string `json:"token"`
	Content      string `json:"content"`
	Instructions string `json:"instructions"`
}

// CustomDomainDNS reports a domain's DNS automation.
type CustomDomainDNS struct {
	Provider string `json:"provider"`
	TokenSet bool   `json:"token_set"`
}

// CustomDomainDNSParams lets Atlas write the domain's DNS record. APIToken is
// write-only.
type CustomDomainDNSParams struct {
	// Provider is cloudflare.
	Provider string `json:"provider"`
	APIToken string `json:"api_token"`
	// Overwrite replaces a conflicting existing record.
	Overwrite bool `json:"overwrite,omitempty"`
}

// ListDomainsResponse is the enriched list envelope for custom domains.
type ListDomainsResponse struct {
	Object       string                 `json:"object"`
	Data         []CustomDomain         `json:"data"`
	CNAMETarget  string                 `json:"cname_target"`
	Instructions map[string]interface{} `json:"instructions"`
	CookieChecks []struct {
		Origin     string `json:"origin"`
		FirstParty bool   `json:"first_party"`
	} `json:"cookie_checks"`
	Required    bool   `json:"required"`
	Environment string `json:"environment"`
}

// CreateDomainParams is the body of POST /v1/domains.
type CreateDomainParams struct {
	// Host is the hostname (Hostname is an alias).
	Host     string `json:"host,omitempty"`
	Hostname string `json:"hostname,omitempty"`
	Role     string `json:"role,omitempty"`
	// Method is cname (default) or path: the Frontend API under BasePath
	// (default /__atlas) on a host you already run, proven by an https file.
	Method   string `json:"method,omitempty"`
	BasePath string `json:"base_path,omitempty"`
	// DNS has Atlas write the record (optional).
	DNS *CustomDomainDNSParams `json:"dns,omitempty"`
}

// CustomDomainWithInstructions is the create response, carrying DNS setup steps.
type CustomDomainWithInstructions struct {
	CustomDomain
	Instructions map[string]interface{} `json:"instructions"`
}

// List returns all custom domains. GET /v1/domains.
func (s *DomainsService) List(ctx context.Context) (*ListDomainsResponse, error) {
	out := &ListDomainsResponse{}
	return out, s.client.get(ctx, "/v1/domains", nil, out)
}

// Create adds a custom domain. POST /v1/domains.
func (s *DomainsService) Create(ctx context.Context, params CreateDomainParams, opts ...RequestOption) (*CustomDomainWithInstructions, error) {
	out := &CustomDomainWithInstructions{}
	return out, s.client.post(ctx, "/v1/domains", params, out, opts...)
}

// Verify triggers verification of a custom domain. POST /v1/domains/:id/verify.
func (s *DomainsService) Verify(ctx context.Context, id string, opts ...RequestOption) (*CustomDomain, error) {
	out := &CustomDomain{}
	return out, s.client.post(ctx, "/v1/domains/"+url.PathEscape(id)+"/verify", nil, out, opts...)
}

// Delete removes a custom domain. DELETE /v1/domains/:id.
func (s *DomainsService) Delete(ctx context.Context, id string, opts ...RequestOption) (*DeletedObject, error) {
	out := &DeletedObject{}
	return out, s.client.del(ctx, "/v1/domains/"+url.PathEscape(id), out, opts...)
}
