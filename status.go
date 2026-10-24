package atlas

import (
	"context"
	"net/url"
	"strconv"
)

// Atlas service status for your instance: the incident subscription (owner
// email, status.incident.* webhooks, a private RSS / Atom feed) filtered by
// region, component and impact; the incidents that concern you; and the
// upstream status pages (any Statuspage-compatible URL) your app depends on.
//
// The public Statuspage-compatible feed itself needs no key:
// https://<frontend api>/v1/status/api/v2/summary.json.

// Status webhook events.
const (
	WebhookEventStatusIncidentCreated  = "status.incident.created"
	WebhookEventStatusIncidentUpdated  = "status.incident.updated"
	WebhookEventStatusIncidentResolved = "status.incident.resolved"
)

// Preflight codes of the status dependencies.
const (
	PreflightStatusDependencyUnreachable = "status_dependency_unreachable"
	PreflightStatusDependencyOutage      = "status_dependency_outage"
)

// Status components.
const (
	StatusComponentFrontendAPI    = "frontend_api"
	StatusComponentBackendAPI     = "backend_api"
	StatusComponentDatabase       = "database"
	StatusComponentCache          = "cache"
	StatusComponentBackgroundJobs = "background_jobs"
)

// StatusGroup groups components on the status page.
type StatusGroup struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	ComponentIDs []string `json:"component_ids"`
}

// StatusComponent is one component's status.
type StatusComponent struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// Status is operational, degraded, major_outage or unknown.
	Status      string   `json:"status"`
	Description string   `json:"description"`
	Group       string   `json:"group"`
	Regions     []string `json:"regions"`
}

// StatusIncidentSummary is an open incident on GET /v1/status.
type StatusIncidentSummary struct {
	ID string `json:"id"`
	// Kind is incident or maintenance.
	Kind  string `json:"kind"`
	Title string `json:"title"`
	// Status is investigating, identified, monitoring, resolved, scheduled,
	// in_progress or completed.
	Status string `json:"status"`
	// Impact is none, minor, major or critical.
	Impact       string   `json:"impact"`
	Regions      []string `json:"regions"`
	ComponentIDs []string `json:"component_ids"`
	StartedAt    int64    `json:"started_at"`
	ResolvedAt   *int64   `json:"resolved_at"`
	UpdatedAt    int64    `json:"updated_at"`
}

// ServiceStatus is GET /v1/status (public).
type ServiceStatus struct {
	Object string `json:"object"`
	// Status is operational, degraded or major_outage.
	Status     string                  `json:"status"`
	UpdatedAt  int64                   `json:"updated_at"`
	Regions    []string                `json:"regions"`
	Groups     []StatusGroup           `json:"groups"`
	Components []StatusComponent       `json:"components"`
	Incidents  []StatusIncidentSummary `json:"incidents"`
}

// StatusAvailableComponent is a component a subscription can filter on.
type StatusAvailableComponent struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// StatusSubscription is the instance's incident subscription.
type StatusSubscription struct {
	Object string `json:"object"`
	// Subscribed: a subscription exists (it may be disabled).
	Subscribed bool `json:"subscribed"`
	Enabled    bool `json:"enabled"`
	// Regions: empty = every region. ComponentIDs: empty = every component.
	Regions      []string `json:"regions"`
	ComponentIDs []string `json:"component_ids"`
	// MinImpact is minor, major or critical.
	MinImpact          string `json:"min_impact"`
	IncludeMaintenance bool   `json:"include_maintenance"`
	EmailOwners        bool   `json:"email_owners"`
	Webhook            bool   `json:"webhook"`
	// RSSURL and AtomURL are the private feed; treat it as a secret
	// (RotateFeed replaces it).
	RSSURL              *string                    `json:"rss_url"`
	AtomURL             *string                    `json:"atom_url"`
	AvailableRegions    []string                   `json:"available_regions"`
	AvailableComponents []StatusAvailableComponent `json:"available_components"`
	UpdatedAt           *int64                     `json:"updated_at"`
}

// UpdateStatusSubscriptionParams is the body of PUT
// /v1/instance/status_subscription: only the fields set change. Set Regions
// or ComponentIDs to an empty non-nil slice to mean "every".
type UpdateStatusSubscriptionParams struct {
	Enabled            *bool    `json:"enabled,omitempty"`
	Regions            []string `json:"-"`
	ComponentIDs       []string `json:"-"`
	MinImpact          string   `json:"min_impact,omitempty"`
	IncludeMaintenance *bool    `json:"include_maintenance,omitempty"`
	EmailOwners        *bool    `json:"email_owners,omitempty"`
	Webhook            *bool    `json:"webhook,omitempty"`
}

// MarshalJSON sends Regions and ComponentIDs whenever they are non-nil, so an
// empty slice sets "every".
func (p UpdateStatusSubscriptionParams) MarshalJSON() ([]byte, error) {
	type plain UpdateStatusSubscriptionParams
	extra := map[string]interface{}{}
	if p.Regions != nil {
		extra["regions"] = p.Regions
	}
	if p.ComponentIDs != nil {
		extra["component_ids"] = p.ComponentIDs
	}
	return marshalWithExtra(plain(p), extra)
}

// StatusIncidentUpdate is one update of an incident.
type StatusIncidentUpdate struct {
	ID        string `json:"id"`
	Status    string `json:"status"`
	Body      string `json:"body"`
	CreatedAt int64  `json:"created_at"`
}

// StatusIncident is an incident that concerns this instance.
type StatusIncident struct {
	Object       string   `json:"object"`
	ID           string   `json:"id"`
	Kind         string   `json:"kind"`
	Title        string   `json:"title"`
	Status       string   `json:"status"`
	Impact       string   `json:"impact"`
	Regions      []string `json:"regions"`
	ComponentIDs []string `json:"component_ids"`
	StartedAt    int64    `json:"started_at"`
	ResolvedAt   *int64   `json:"resolved_at"`
	UpdatedAt    int64    `json:"updated_at"`
	// Source is atlas, import or another source.
	Source         string `json:"source"`
	ScheduledFor   *int64 `json:"scheduled_for"`
	ScheduledUntil *int64 `json:"scheduled_until"`
	// Updates are oldest first.
	Updates []StatusIncidentUpdate `json:"updates"`
}

// StatusIncidentEventData is the data of the status.incident.created /
// updated / resolved webhook events.
type StatusIncidentEventData struct {
	Object       string   `json:"object"`
	ID           string   `json:"id"`
	Kind         string   `json:"kind"`
	Title        string   `json:"title"`
	Status       string   `json:"status"`
	Impact       string   `json:"impact"`
	Regions      []string `json:"regions"`
	ComponentIDs []string `json:"component_ids"`
	// AffectedRegions and AffectedComponentIDs are the part of the incident
	// that matches your subscription.
	AffectedRegions      []string             `json:"affected_regions"`
	AffectedComponentIDs []string             `json:"affected_component_ids"`
	StartedAt            int64                `json:"started_at"`
	ResolvedAt           *int64               `json:"resolved_at"`
	Update               StatusIncidentUpdate `json:"update"`
	// URL is the incident on the status page.
	URL string `json:"url"`
}

// StatusDependencyComponent is a component of an upstream status page.
type StatusDependencyComponent struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Status string `json:"status"`
}

// StatusDependencyIncident is an incident on an upstream status page.
type StatusDependencyIncident struct {
	ID        string  `json:"id"`
	Name      string  `json:"name"`
	Status    string  `json:"status"`
	Impact    string  `json:"impact"`
	UpdatedAt *string `json:"updatedAt"`
}

// StatusDependency is an upstream status page your app depends on.
type StatusDependency struct {
	Object string `json:"object"`
	ID     string `json:"id"`
	Name   string `json:"name"`
	// URL is the base URL of the Statuspage-compatible page (Atlas reads
	// {url}/api/v2/summary.json).
	URL             string   `json:"url"`
	ComponentFilter []string `json:"component_filter"`
	Enabled         bool     `json:"enabled"`
	// State is operational, degraded, partial_outage, major_outage,
	// maintenance or unknown.
	State         string                      `json:"state"`
	Indicator     *string                     `json:"indicator"`
	Description   *string                     `json:"description"`
	Components    []StatusDependencyComponent `json:"components"`
	Incidents     []StatusDependencyIncident  `json:"incidents"`
	LastCheckedAt *int64                      `json:"last_checked_at"`
	LastSuccessAt *int64                      `json:"last_success_at"`
	LastError     *string                     `json:"last_error"`
	// Stale: the last check failed or none has succeeded yet, so State may be
	// out of date.
	Stale     bool  `json:"stale"`
	CreatedAt int64 `json:"created_at"`
}

// StatusDependencyList is the dependency list with the worst state among the
// enabled ones.
type StatusDependencyList struct {
	Object string             `json:"object"`
	Data   []StatusDependency `json:"data"`
	State  string             `json:"state"`
}

// StatusIncidentList is the incident list.
type StatusIncidentList struct {
	Object string           `json:"object"`
	Data   []StatusIncident `json:"data"`
}

// CreateStatusDependencyParams is the body of POST /v1/instance/status_dependencies.
type CreateStatusDependencyParams struct {
	Name            string   `json:"name"`
	URL             string   `json:"url"`
	ComponentFilter []string `json:"component_filter,omitempty"`
	Enabled         *bool    `json:"enabled,omitempty"`
}

// UpdateStatusDependencyParams is the body of PATCH
// /v1/instance/status_dependencies/:id.
type UpdateStatusDependencyParams struct {
	Name            string   `json:"name,omitempty"`
	ComponentFilter []string `json:"component_filter,omitempty"`
	Enabled         *bool    `json:"enabled,omitempty"`
}

// ListStatusIncidentsParams filters GET /v1/instance/status_incidents.
type ListStatusIncidentsParams struct {
	// Open lists only unresolved incidents.
	Open  bool
	Limit int
}

// StatusService is the service status, the instance's incident subscription
// and its status dependencies.
type StatusService struct{ client *Client }

// Service returns the public service status (components with group and
// regions, open incidents). GET /v1/status.
func (s *StatusService) Service(ctx context.Context) (*ServiceStatus, error) {
	out := &ServiceStatus{}
	return out, s.client.get(ctx, "/v1/status", nil, out)
}

// GetSubscription returns the incident subscription.
// GET /v1/instance/status_subscription.
func (s *StatusService) GetSubscription(ctx context.Context) (*StatusSubscription, error) {
	out := &StatusSubscription{}
	return out, s.client.get(ctx, "/v1/instance/status_subscription", nil, out)
}

// UpdateSubscription creates or changes the subscription.
// PUT /v1/instance/status_subscription.
func (s *StatusService) UpdateSubscription(ctx context.Context, params UpdateStatusSubscriptionParams, opts ...RequestOption) (*StatusSubscription, error) {
	out := &StatusSubscription{}
	return out, s.client.put(ctx, "/v1/instance/status_subscription", params, out, opts...)
}

// DisableSubscription turns the subscription off (settings are kept).
// DELETE /v1/instance/status_subscription.
func (s *StatusService) DisableSubscription(ctx context.Context, opts ...RequestOption) (*StatusSubscription, error) {
	out := &StatusSubscription{}
	return out, s.client.del(ctx, "/v1/instance/status_subscription", out, opts...)
}

// RotateFeed issues a new private feed URL; the old one 404s.
// POST /v1/instance/status_subscription/rotate_feed.
func (s *StatusService) RotateFeed(ctx context.Context, opts ...RequestOption) (*StatusSubscription, error) {
	out := &StatusSubscription{}
	return out, s.client.post(ctx, "/v1/instance/status_subscription/rotate_feed", nil, out, opts...)
}

// ListIncidents returns the incidents that concern this instance, newest
// first. GET /v1/instance/status_incidents.
func (s *StatusService) ListIncidents(ctx context.Context, params ListStatusIncidentsParams) (*StatusIncidentList, error) {
	out := &StatusIncidentList{}
	q := url.Values{}
	if params.Open {
		q.Set("open", "true")
	}
	if params.Limit > 0 {
		q.Set("limit", strconv.Itoa(params.Limit))
	}
	return out, s.client.get(ctx, "/v1/instance/status_incidents", q, out)
}

// ListDependencies returns the status dependencies, with State the worst
// among the enabled ones. GET /v1/instance/status_dependencies.
func (s *StatusService) ListDependencies(ctx context.Context) (*StatusDependencyList, error) {
	out := &StatusDependencyList{}
	return out, s.client.get(ctx, "/v1/instance/status_dependencies", nil, out)
}

// CreateDependency adds a dependency; Atlas reads it at once, so the answer
// carries the state or LastError. POST /v1/instance/status_dependencies.
func (s *StatusService) CreateDependency(ctx context.Context, params CreateStatusDependencyParams, opts ...RequestOption) (*StatusDependency, error) {
	out := &StatusDependency{}
	return out, s.client.post(ctx, "/v1/instance/status_dependencies", params, out, opts...)
}

// GetDependency returns one dependency. GET /v1/instance/status_dependencies/:id.
func (s *StatusService) GetDependency(ctx context.Context, id string) (*StatusDependency, error) {
	out := &StatusDependency{}
	return out, s.client.get(ctx, "/v1/instance/status_dependencies/"+url.PathEscape(id), nil, out)
}

// UpdateDependency changes a dependency. PATCH /v1/instance/status_dependencies/:id.
func (s *StatusService) UpdateDependency(ctx context.Context, id string, params UpdateStatusDependencyParams, opts ...RequestOption) (*StatusDependency, error) {
	out := &StatusDependency{}
	return out, s.client.patch(ctx, "/v1/instance/status_dependencies/"+url.PathEscape(id), params, out, opts...)
}

// DeleteDependency removes a dependency. DELETE /v1/instance/status_dependencies/:id.
func (s *StatusService) DeleteDependency(ctx context.Context, id string, opts ...RequestOption) (*DeletedObject, error) {
	out := &DeletedObject{}
	return out, s.client.del(ctx, "/v1/instance/status_dependencies/"+url.PathEscape(id), out, opts...)
}

// RefreshDependency reads the upstream page now.
// POST /v1/instance/status_dependencies/:id/refresh.
func (s *StatusService) RefreshDependency(ctx context.Context, id string, opts ...RequestOption) (*StatusDependency, error) {
	out := &StatusDependency{}
	return out, s.client.post(ctx, "/v1/instance/status_dependencies/"+url.PathEscape(id)+"/refresh", nil, out, opts...)
}
