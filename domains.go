package atlas

import (
	"context"
	"net/url"
)

// DomainsService is the /v1/domains namespace (instance custom domains).
type DomainsService struct{ client *Client }

// CustomDomain is a FAPI/accounts custom domain.
type CustomDomain struct {
	Object               string  `json:"object"`
	ID                   string  `json:"id"`
	Role                 string  `json:"role"`
	Host                 string  `json:"host"`
	Status               string  `json:"status"`
	Action               string  `json:"action"`
	Live                 bool    `json:"live"`
	CNAMETarget          string  `json:"cname_target"`
	LastCheckedAt        *int64  `json:"last_checked_at"`
	LastObservedTarget   *string `json:"last_observed_target"`
	FailureReason        *string `json:"failure_reason"`
	CertificateExpiresAt *int64  `json:"certificate_expires_at"`
	CookieDomain         *string `json:"cookie_domain"`
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
	Host string `json:"host"`
	Role string `json:"role,omitempty"`
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
func (s *DomainsService) Verify(ctx context.Context, id string) (*CustomDomain, error) {
	out := &CustomDomain{}
	return out, s.client.post(ctx, "/v1/domains/"+url.PathEscape(id)+"/verify", nil, out)
}

// Delete removes a custom domain. DELETE /v1/domains/:id.
func (s *DomainsService) Delete(ctx context.Context, id string) (*DeletedObject, error) {
	out := &DeletedObject{}
	return out, s.client.del(ctx, "/v1/domains/"+url.PathEscape(id), out)
}
