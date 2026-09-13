package atlas

import (
	"context"
	"net/url"
)

// Identifier is an allowlist or blocklist entry (both share this shape).
type Identifier struct {
	Object     string `json:"object"`
	ID         string `json:"id"`
	Identifier string `json:"identifier"`
	CreatedAt  int64  `json:"created_at"`
}

// AllowlistService is the /v1/allowlist_identifiers namespace.
type AllowlistService struct{ client *Client }

// List returns all allowlist identifiers. GET /v1/allowlist_identifiers.
func (s *AllowlistService) List(ctx context.Context) (*ListPage[Identifier], error) {
	return listRestriction(ctx, s.client, "/v1/allowlist_identifiers")
}

// Add adds an allowlist identifier. POST /v1/allowlist_identifiers.
func (s *AllowlistService) Add(ctx context.Context, identifier string) (*Identifier, error) {
	return addRestriction(ctx, s.client, "/v1/allowlist_identifiers", identifier)
}

// Remove removes an allowlist identifier. DELETE /v1/allowlist_identifiers/:id.
func (s *AllowlistService) Remove(ctx context.Context, id string) (*DeletedObject, error) {
	return removeRestriction(ctx, s.client, "/v1/allowlist_identifiers", id)
}

// BlocklistService is the /v1/blocklist_identifiers namespace.
type BlocklistService struct{ client *Client }

// List returns all blocklist identifiers. GET /v1/blocklist_identifiers.
func (s *BlocklistService) List(ctx context.Context) (*ListPage[Identifier], error) {
	return listRestriction(ctx, s.client, "/v1/blocklist_identifiers")
}

// Add adds a blocklist identifier. POST /v1/blocklist_identifiers.
func (s *BlocklistService) Add(ctx context.Context, identifier string) (*Identifier, error) {
	return addRestriction(ctx, s.client, "/v1/blocklist_identifiers", identifier)
}

// Remove removes a blocklist identifier. DELETE /v1/blocklist_identifiers/:id.
func (s *BlocklistService) Remove(ctx context.Context, id string) (*DeletedObject, error) {
	return removeRestriction(ctx, s.client, "/v1/blocklist_identifiers", id)
}

// Allowlist and blocklist share an identical route shape; only the path differs.
func listRestriction(ctx context.Context, c *Client, path string) (*ListPage[Identifier], error) {
	out := &ListPage[Identifier]{}
	return out, c.get(ctx, path, nil, out)
}

func addRestriction(ctx context.Context, c *Client, path, identifier string) (*Identifier, error) {
	out := &Identifier{}
	body := map[string]string{"identifier": identifier}
	return out, c.post(ctx, path, body, out)
}

func removeRestriction(ctx context.Context, c *Client, path, id string) (*DeletedObject, error) {
	out := &DeletedObject{}
	return out, c.del(ctx, path+"/"+url.PathEscape(id), out)
}
