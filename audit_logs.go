package atlas

import "context"

// AuditLogsService is the /v1/audit_logs namespace.
type AuditLogsService struct{ client *Client }

// AuditLog is one audit-trail entry.
type AuditLog struct {
	Object     string                 `json:"object"`
	ID         string                 `json:"id"`
	ActorType  string                 `json:"actor_type"`
	ActorID    *string                `json:"actor_id"`
	Action     string                 `json:"action"`
	TargetType *string                `json:"target_type"`
	TargetID   *string                `json:"target_id"`
	Metadata   map[string]interface{} `json:"metadata"`
	CreatedAt  int64                  `json:"created_at"`
}

// ListAuditLogsParams filters and paginates the audit log.
type ListAuditLogsParams struct {
	ListParams
	ActorID string
	Action  string
}

// List returns one cursor page of audit logs. GET /v1/audit_logs.
func (s *AuditLogsService) List(ctx context.Context, params ListAuditLogsParams) (*CursorPage[AuditLog], error) {
	out := &CursorPage[AuditLog]{}
	q := params.ListParams.values()
	if params.ActorID != "" {
		q.Set("actor_id", params.ActorID)
	}
	if params.Action != "" {
		q.Set("action", params.Action)
	}
	return out, s.client.get(ctx, "/v1/audit_logs", q, out)
}
