package atlas

import (
	"context"
	"net/url"
)

// AuditEventSchemasService is the auditEventSchemas resource.
type AuditEventSchemasService struct {
	client *Client
}

// List: List the registered audit event schemas, by action then version (newest first).
// GET /v1/audit_event_schemas.
func (s *AuditEventSchemasService) List(ctx context.Context, params ListParams) (*CursorPage[AuditEventSchemasListItem], error) {
	out := &CursorPage[AuditEventSchemasListItem]{}
	return out, s.client.do(ctx, "GET", "/v1/audit_event_schemas", params.values(), nil, out)
}

// Register: Register a schema for an action: the target types and actor types it allows and a JSON
// Schema its metadata must satisfy. `version` defaults to the next number for that action; a
// version is immutable (registering it again is a 409) - change a schema by registering a new
// version. From then on events with this action are validated on write.
// POST /v1/audit_event_schemas.
func (s *AuditEventSchemasService) Register(ctx context.Context, params AuditEventSchemasRegisterParams, opts ...RequestOption) (*AuditEventSchemasListItem, error) {
	out := &AuditEventSchemasListItem{}
	return out, s.client.do(ctx, "POST", "/v1/audit_event_schemas", nil, params, out, opts...)
}

// Get: One audit event schema.
// GET /v1/audit_event_schemas/{id}.
func (s *AuditEventSchemasService) Get(ctx context.Context, id string) (*AuditEventSchemasListItem, error) {
	out := &AuditEventSchemasListItem{}
	return out, s.client.do(ctx, "GET", "/v1/audit_event_schemas/"+url.PathEscape(id), nil, nil, out)
}

// Update: Change a schema version's description or status. A deprecated version is no longer
// applied by default but still validates events that name it with `schema_version`.
// PATCH /v1/audit_event_schemas/{id}.
func (s *AuditEventSchemasService) Update(ctx context.Context, id string, params AuditEventSchemasUpdateParams, opts ...RequestOption) (*AuditEventSchemasListItem, error) {
	out := &AuditEventSchemasListItem{}
	return out, s.client.do(ctx, "PATCH", "/v1/audit_event_schemas/"+url.PathEscape(id), nil, params, out, opts...)
}

// Delete: Remove a schema version. Events already recorded keep their `schema_version` number.
// DELETE /v1/audit_event_schemas/{id}.
func (s *AuditEventSchemasService) Delete(ctx context.Context, id string, opts ...RequestOption) (*UsersDeleteDeviceKeyResult, error) {
	out := &UsersDeleteDeviceKeyResult{}
	return out, s.client.do(ctx, "DELETE", "/v1/audit_event_schemas/"+url.PathEscape(id), nil, nil, out, opts...)
}

// Redact: Blank named fields of one audit event (replaced by [redacted]) without deleting it:
// `actor_id`, `target_id`, `target_name` or `metadata.<dotted.path>`. A `reason` is required. The
// redaction is recorded in its own log (GET /v1/audit_events/:id/redactions) and in Atlas's audit
// log as `audit_event.redacted` - the fields and the reason, never the removed values.
// POST /v1/audit_events/{id}/redact.
func (s *AuditEventSchemasService) Redact(ctx context.Context, id string, params AuditEventSchemasRedactParams, opts ...RequestOption) (*AuditEventSchemasRedactResult, error) {
	out := &AuditEventSchemasRedactResult{}
	return out, s.client.do(ctx, "POST", "/v1/audit_events/"+url.PathEscape(id)+"/redact", nil, params, out, opts...)
}

// Redactions: An audit event's redaction history: which fields were blanked, why, and by which
// key.
// GET /v1/audit_events/{id}/redactions.
func (s *AuditEventSchemasService) Redactions(ctx context.Context, id string, params ListParams) (*CursorPage[AuditEventSchemasRedactionsItem], error) {
	out := &CursorPage[AuditEventSchemasRedactionsItem]{}
	return out, s.client.do(ctx, "GET", "/v1/audit_events/"+url.PathEscape(id)+"/redactions", params.values(), nil, out)
}
