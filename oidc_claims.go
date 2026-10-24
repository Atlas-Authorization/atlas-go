package atlas

import (
	"net/url"
)

// Atlas-specific claims on the ID tokens and userinfo of an OIDC relying
// party: the organization a sign-in was made in (org_id, org_slug, org_role,
// org_permissions), every membership (orgs, with the organizations scope) and
// the enterprise SSO connection (sso_connection_id, sso_tenant_id, sso_issuer,
// sso_domain). Pass the verified claims of the token as a map.
//
//	if org := atlas.OIDCOrganizationOf(claims); org != nil { ... org.ID, org.Role }
//	memberships := atlas.OIDCOrganizationsOf(claims)
//	sso := atlas.OIDCSSOOf(claims)

// OIDCScopeOrganizations is the scope that adds the orgs membership list to the
// ID token and userinfo.
const OIDCScopeOrganizations = "organizations"

// OIDCOrganizationParam is the authorize parameter that pins the organization
// (id or slug) a sign-in is made in.
const OIDCOrganizationParam = "organization"

// OIDCOrganization is the organization a sign-in was made in (the token's
// org_* claims).
type OIDCOrganization struct {
	// ID is org_id.
	ID string
	// Slug is org_slug.
	Slug string
	// Role is org_role: the user's role key in it.
	Role string
	// Permissions is org_permissions.
	Permissions []string
}

// OIDCOrganizationMembership is one entry of the orgs claim.
type OIDCOrganizationMembership struct {
	ID   string
	Slug string
	Role string
}

// OIDCSSOContext is the enterprise SSO context of a sign-in (the token's sso_*
// claims). Optional parts are "" when Atlas did not send them.
type OIDCSSOContext struct {
	// ConnectionID is sso_connection_id: the connection the user signed in
	// through.
	ConnectionID string
	// OrganizationID is sso_organization_id: the Atlas organization that owns the
	// connection, "" for an instance-wide connection. Independent of the
	// organization claims: scope a per-organization "require SSO" rule on this,
	// never on "signed in via SSO".
	OrganizationID string
	// Type is sso_connection_type: saml or oidc ("" when absent).
	Type string
	// TenantID is sso_tenant_id: the IdP-side tenant (Entra tid, Google hd,
	// SAML entity id), when known.
	TenantID string
	// Issuer is sso_issuer: the IdP issuer, when known.
	Issuer string
	// Domain is sso_domain: the connection domain matching the user's email.
	Domain string
}

func claimString(claims map[string]interface{}, key string) (string, bool) {
	v, ok := claims[key].(string)
	return v, ok
}

// OIDCOrganizationOf reads the organization from verified ID-token or userinfo
// claims; nil when no organization was involved.
func OIDCOrganizationOf(claims map[string]interface{}) *OIDCOrganization {
	id, ok := claimString(claims, "org_id")
	if !ok {
		return nil
	}
	org := &OIDCOrganization{ID: id, Permissions: []string{}}
	org.Slug, _ = claimString(claims, "org_slug")
	org.Role, _ = claimString(claims, "org_role")
	if perms, ok := claims["org_permissions"].([]interface{}); ok {
		for _, p := range perms {
			if s, ok := p.(string); ok {
				org.Permissions = append(org.Permissions, s)
			}
		}
	} else if perms, ok := claims["org_permissions"].([]string); ok {
		org.Permissions = append(org.Permissions, perms...)
	}
	return org
}

// OIDCOrganizationsOf reads the orgs membership list (the organizations scope);
// nil when the scope was not requested.
func OIDCOrganizationsOf(claims map[string]interface{}) []OIDCOrganizationMembership {
	raw, ok := claims["orgs"].([]interface{})
	if !ok {
		return nil
	}
	out := []OIDCOrganizationMembership{}
	for _, entry := range raw {
		m, ok := entry.(map[string]interface{})
		if !ok {
			continue
		}
		id, ok := claimString(m, "id")
		if !ok {
			continue
		}
		membership := OIDCOrganizationMembership{ID: id}
		membership.Slug, _ = claimString(m, "slug")
		membership.Role, _ = claimString(m, "role")
		out = append(out, membership)
	}
	return out
}

// OIDCSSOOf reads the enterprise SSO connection the user signed in through; nil
// when none was involved.
func OIDCSSOOf(claims map[string]interface{}) *OIDCSSOContext {
	id, ok := claimString(claims, "sso_connection_id")
	if !ok {
		return nil
	}
	sso := &OIDCSSOContext{ConnectionID: id}
	sso.OrganizationID, _ = claimString(claims, "sso_organization_id")
	if t, _ := claimString(claims, "sso_connection_type"); t == "saml" || t == "oidc" {
		sso.Type = t
	}
	sso.TenantID, _ = claimString(claims, "sso_tenant_id")
	sso.Issuer, _ = claimString(claims, "sso_issuer")
	sso.Domain, _ = claimString(claims, "sso_domain")
	return sso
}

// OIDCAuthorizeURLWithOrganization adds (or replaces) the organization
// authorize parameter: the sign-in must be made in that organization (a user
// who is not a member gets access_denied) and the token's org_* claims are that
// organization's.
func OIDCAuthorizeURLWithOrganization(authorizeURL, organization string) (string, error) {
	u, err := url.Parse(authorizeURL)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set(OIDCOrganizationParam, organization)
	u.RawQuery = q.Encode()
	return u.String(), nil
}
