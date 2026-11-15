package atlas

// RPOrganization is the organization a sign-in was made in (the ID token's
// org_* claims).
type RPOrganization struct {
	// ID is org_id.
	ID string
	// Slug is org_slug.
	Slug string
	// Role is org_role: the user's role key in it.
	Role string
	// Permissions is org_permissions.
	Permissions []string
}

// RPOrganizationMembership is one entry of the orgs claim (the organizations
// scope).
type RPOrganizationMembership struct {
	ID   string
	Slug string
	Role string
}

// RPSsoContext is the enterprise SSO context of a sign-in (the ID token's sso_*
// claims). Empty strings mean the claim was absent.
type RPSsoContext struct {
	// ConnectionID is sso_connection_id: the connection the user signed in through.
	ConnectionID string
	// OrganizationID is sso_organization_id: the Atlas organization that owns the
	// connection, "" for an instance-wide one. It is independent of the
	// organization the sign-in was made in: scope a per-organization "require
	// SSO" rule on this, never on "signed in via SSO".
	OrganizationID string
	// Type is sso_connection_type: saml, oidc, or "" when unknown.
	Type string
	// TenantID is sso_tenant_id: the IdP-side tenant (Entra tid, Google hd, SAML
	// entity id), when known.
	TenantID string
	// Issuer is sso_issuer: the IdP issuer, when known.
	Issuer string
	// Domain is sso_domain: the connection domain matching the user's email.
	Domain string
}

// RPOrganizationOf reads the organization (org_*) from verified ID-token or
// userinfo claims; nil when the sign-in involved none.
func RPOrganizationOf(claims map[string]interface{}) *RPOrganization {
	id, ok := claims["org_id"].(string)
	if !ok {
		return nil
	}
	org := &RPOrganization{ID: id, Slug: rpString(claims["org_slug"]), Role: rpString(claims["org_role"]), Permissions: []string{}}
	if list, ok := claims["org_permissions"].([]interface{}); ok {
		for _, p := range list {
			if s, ok := p.(string); ok {
				org.Permissions = append(org.Permissions, s)
			}
		}
	}
	return org
}

// RPOrganizationsOf reads the orgs membership list (the organizations scope);
// nil when the claim is absent. Malformed entries are skipped.
func RPOrganizationsOf(claims map[string]interface{}) []RPOrganizationMembership {
	list, ok := claims["orgs"].([]interface{})
	if !ok {
		return nil
	}
	out := []RPOrganizationMembership{}
	for _, e := range list {
		m, ok := e.(map[string]interface{})
		if !ok {
			continue
		}
		id, ok := m["id"].(string)
		if !ok {
			continue
		}
		out = append(out, RPOrganizationMembership{ID: id, Slug: rpString(m["slug"]), Role: rpString(m["role"])})
	}
	return out
}

// RPSsoOf reads the enterprise SSO context (sso_*); nil when the user did not
// sign in through an SSO connection.
func RPSsoOf(claims map[string]interface{}) *RPSsoContext {
	conn, ok := claims["sso_connection_id"].(string)
	if !ok {
		return nil
	}
	t := rpString(claims["sso_connection_type"])
	if t != "saml" && t != "oidc" {
		t = ""
	}
	return &RPSsoContext{
		ConnectionID:   conn,
		OrganizationID: rpString(claims["sso_organization_id"]),
		Type:           t,
		TenantID:       rpString(claims["sso_tenant_id"]),
		Issuer:         rpString(claims["sso_issuer"]),
		Domain:         rpString(claims["sso_domain"]),
	}
}
