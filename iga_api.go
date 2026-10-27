package atlas

import (
	"context"
	"net/url"
	"strconv"
)

// IGAService is the iga resource.
type IGAService struct {
	client       *Client
	Entitlements *IGAEntitlementsService
	Requests     *IGARequestsService
	Grants       *IGAGrantsService
	Delegations  *IGADelegationsService
	SOD          *IGASODService
	Lifecycle    *IGALifecycleService
	Campaigns    *IGACampaignsService
}

// IGAEntitlementsService is the iga entitlements group of IGAService.
type IGAEntitlementsService struct {
	client *Client
}

// IGAEntitlementsListQuery holds the query parameters of IGAEntitlementsService.List.
type IGAEntitlementsListQuery struct {
	// Only this kind.
	Kind string
	// Page size, 1-500. Without limit (and without starting_after) the whole list is returned.
	Limit int64
	// Cursor: return only items after this one. Pass the previous page's `next_cursor` (the last
	// item's id). An unknown cursor is a 400.
	StartingAfter string
}

func (q IGAEntitlementsListQuery) values() url.Values {
	v := url.Values{}
	if q.Kind != "" {
		v.Set("kind", q.Kind)
	}
	if q.Limit != 0 {
		v.Set("limit", strconv.FormatInt(q.Limit, 10))
	}
	if q.StartingAfter != "" {
		v.Set("starting_after", q.StartingAfter)
	}
	return v
}

// List: List the governed entitlement catalog.
// GET /v1/iga/entitlements.
func (s *IGAEntitlementsService) List(ctx context.Context, query IGAEntitlementsListQuery) (*CursorPage[IGAEntitlementsListItem], error) {
	out := &CursorPage[IGAEntitlementsListItem]{}
	return out, s.client.do(ctx, "GET", "/v1/iga/entitlements", query.values(), nil, out)
}

// Create: Add an entitlement to the catalog: a role, organization membership, group, resource
// role, installed-app assignment or custom item, with an owner, a risk level and approval rules.
// The target must exist. 409 for a key already in use.
// POST /v1/iga/entitlements.
func (s *IGAEntitlementsService) Create(ctx context.Context, params IGAEntitlementsCreateParams, opts ...RequestOption) (*IGAEntitlementsListItem, error) {
	out := &IGAEntitlementsListItem{}
	return out, s.client.do(ctx, "POST", "/v1/iga/entitlements", nil, params, out, opts...)
}

// Get: Read one entitlement by id or key.
// GET /v1/iga/entitlements/{id}.
func (s *IGAEntitlementsService) Get(ctx context.Context, id string) (*IGAEntitlementsListItem, error) {
	out := &IGAEntitlementsListItem{}
	return out, s.client.do(ctx, "GET", "/v1/iga/entitlements/"+url.PathEscape(id), nil, nil, out)
}

// Update: Change an entitlement (its kind cannot change). A change to the approval rules applies
// to requests filed afterwards.
// PATCH /v1/iga/entitlements/{id}.
func (s *IGAEntitlementsService) Update(ctx context.Context, id string, params IGAEntitlementsUpdateParams, opts ...RequestOption) (*IGAEntitlementsListItem, error) {
	out := &IGAEntitlementsListItem{}
	return out, s.client.do(ctx, "PATCH", "/v1/iga/entitlements/"+url.PathEscape(id), nil, params, out, opts...)
}

// Delete: Remove an entitlement. 409 while it still has active grants.
// DELETE /v1/iga/entitlements/{id}.
func (s *IGAEntitlementsService) Delete(ctx context.Context, id string, opts ...RequestOption) (*UsersDeleteDeviceKeyResult, error) {
	out := &UsersDeleteDeviceKeyResult{}
	return out, s.client.do(ctx, "DELETE", "/v1/iga/entitlements/"+url.PathEscape(id), nil, nil, out, opts...)
}

// IGARequestsService is the iga requests group of IGAService.
type IGARequestsService struct {
	client *Client
}

// IGARequestsListQuery holds the query parameters of IGARequestsService.List.
type IGARequestsListQuery struct {
	// Only requests in this state.
	Status string
	// Only requests for this user.
	UserID string
	// Only requests filed by this user.
	RequesterUserID string
	// Only requests for this entitlement (id or key).
	Entitlement string
	// How many to return (default 100, at most 500).
	Limit int64
	// Cursor: return only items after this one. Pass the previous page's `next_cursor` (the last
	// item's id). An unknown cursor is a 400.
	StartingAfter string
}

func (q IGARequestsListQuery) values() url.Values {
	v := url.Values{}
	if q.Status != "" {
		v.Set("status", q.Status)
	}
	if q.UserID != "" {
		v.Set("user_id", q.UserID)
	}
	if q.RequesterUserID != "" {
		v.Set("requester_user_id", q.RequesterUserID)
	}
	if q.Entitlement != "" {
		v.Set("entitlement", q.Entitlement)
	}
	if q.Limit != 0 {
		v.Set("limit", strconv.FormatInt(q.Limit, 10))
	}
	if q.StartingAfter != "" {
		v.Set("starting_after", q.StartingAfter)
	}
	return v
}

// List: List access requests, newest first.
// GET /v1/iga/requests.
func (s *IGARequestsService) List(ctx context.Context, query IGARequestsListQuery) (*CursorPage[IGARequestsListItem], error) {
	out := &CursorPage[IGARequestsListItem]{}
	return out, s.client.do(ctx, "GET", "/v1/iga/requests", query.values(), nil, out)
}

// Create: File an access request on behalf of a user. It follows the entitlement's approval steps
// (and any extra step a separation-of-duties rule adds); with no steps it is fulfilled at once. A
// blocking separation-of-duties conflict, a user who already holds the access, or a pending
// duplicate is a 409. `duration_seconds` makes the grant time-bound (default and maximum: the
// entitlement's limit).
// POST /v1/iga/requests.
func (s *IGARequestsService) Create(ctx context.Context, params IGARequestsCreateParams, opts ...RequestOption) (*IGARequestsListItem, error) {
	out := &IGARequestsListItem{}
	return out, s.client.do(ctx, "POST", "/v1/iga/requests", nil, params, out, opts...)
}

// Get: Read one request with its steps and the approvals recorded so far.
// GET /v1/iga/requests/{id}.
func (s *IGARequestsService) Get(ctx context.Context, id string) (*IGARequestsListItem, error) {
	out := &IGARequestsListItem{}
	return out, s.client.do(ctx, "GET", "/v1/iga/requests/"+url.PathEscape(id), nil, nil, out)
}

// Decide: Decide the open step. With `approver_user_id` the decision is recorded as that person
// (who must be an approver of the step or hold a delegation); without it the call is an
// administrator override that settles the step. A denial ends the request. 409 when it is no
// longer pending.
// POST /v1/iga/requests/{id}/decide.
func (s *IGARequestsService) Decide(ctx context.Context, id string, params IGARequestsDecideParams, opts ...RequestOption) (*IGARequestsListItem, error) {
	out := &IGARequestsListItem{}
	return out, s.client.do(ctx, "POST", "/v1/iga/requests/"+url.PathEscape(id)+"/decide", nil, params, out, opts...)
}

// Cancel: Cancel a pending request.
// POST /v1/iga/requests/{id}/cancel.
func (s *IGARequestsService) Cancel(ctx context.Context, id string, opts ...RequestOption) (*IGARequestsListItem, error) {
	out := &IGARequestsListItem{}
	return out, s.client.do(ctx, "POST", "/v1/iga/requests/"+url.PathEscape(id)+"/cancel", nil, nil, out, opts...)
}

// IGARequestsInboxQuery holds the query parameters of IGARequestsService.Inbox.
type IGARequestsInboxQuery struct {
	// The approver.
	ApproverUserID string
	// Page size, 1-500. Without limit (and without starting_after) the whole list is returned.
	Limit int64
	// Cursor: return only items after this one. Pass the previous page's `next_cursor` (the last
	// item's id). An unknown cursor is a 400.
	StartingAfter string
}

func (q IGARequestsInboxQuery) values() url.Values {
	v := url.Values{}
	v.Set("approver_user_id", q.ApproverUserID)
	if q.Limit != 0 {
		v.Set("limit", strconv.FormatInt(q.Limit, 10))
	}
	if q.StartingAfter != "" {
		v.Set("starting_after", q.StartingAfter)
	}
	return v
}

// Inbox: The requests waiting on one person's decision, including those delegated to them.
// GET /v1/iga/approvals.
func (s *IGARequestsService) Inbox(ctx context.Context, query IGARequestsInboxQuery) (*CursorPage[IGARequestsListItem], error) {
	out := &CursorPage[IGARequestsListItem]{}
	return out, s.client.do(ctx, "GET", "/v1/iga/approvals", query.values(), nil, out)
}

// IGAGrantsService is the iga grants group of IGAService.
type IGAGrantsService struct {
	client *Client
}

// IGAGrantsListQuery holds the query parameters of IGAGrantsService.List.
type IGAGrantsListQuery struct {
	// Only this user's grants.
	UserID string
	// Only this entitlement (id or key).
	Entitlement string
	// Only grants in this state.
	Status string
	// How many to return (default 100, at most 500).
	Limit int64
	// Cursor: return only items after this one. Pass the previous page's `next_cursor` (the last
	// item's id). An unknown cursor is a 400.
	StartingAfter string
}

func (q IGAGrantsListQuery) values() url.Values {
	v := url.Values{}
	if q.UserID != "" {
		v.Set("user_id", q.UserID)
	}
	if q.Entitlement != "" {
		v.Set("entitlement", q.Entitlement)
	}
	if q.Status != "" {
		v.Set("status", q.Status)
	}
	if q.Limit != 0 {
		v.Set("limit", strconv.FormatInt(q.Limit, 10))
	}
	if q.StartingAfter != "" {
		v.Set("starting_after", q.StartingAfter)
	}
	return v
}

// List: List grants (what each user was given through governance), newest first.
// GET /v1/iga/grants.
func (s *IGAGrantsService) List(ctx context.Context, query IGAGrantsListQuery) (*CursorPage[IGAGrantsListItem], error) {
	out := &CursorPage[IGAGrantsListItem]{}
	return out, s.client.do(ctx, "GET", "/v1/iga/grants", query.values(), nil, out)
}

// Create: Give a user an entitlement now, without a request. `expires_at` makes it time-bound. A
// blocking separation-of-duties rule refuses it; a require-approval rule refuses unless
// `override_reason` is given, which records an accepted violation.
// POST /v1/iga/grants.
func (s *IGAGrantsService) Create(ctx context.Context, params IGAGrantsCreateParams, opts ...RequestOption) (*IGAGrantsListItem, error) {
	out := &IGAGrantsListItem{}
	return out, s.client.do(ctx, "POST", "/v1/iga/grants", nil, params, out, opts...)
}

// Revoke: Take the access away and close the grant, including access that existed before
// governance adopted it (an expiry, by contrast, leaves adopted access in place).
// POST /v1/iga/grants/{id}/revoke.
func (s *IGAGrantsService) Revoke(ctx context.Context, id string, params IGAGrantsRevokeParams, opts ...RequestOption) (*IGAGrantsListItem, error) {
	out := &IGAGrantsListItem{}
	return out, s.client.do(ctx, "POST", "/v1/iga/grants/"+url.PathEscape(id)+"/revoke", nil, params, out, opts...)
}

// IGADelegationsService is the iga delegations group of IGAService.
type IGADelegationsService struct {
	client *Client
}

// IGADelegationsListQuery holds the query parameters of IGADelegationsService.List.
type IGADelegationsListQuery struct {
	// Only this person's delegations.
	DelegatorUserID string
	// Page size, 1-500. Without limit (and without starting_after) the whole list is returned.
	Limit int64
	// Cursor: return only items after this one. Pass the previous page's `next_cursor` (the last
	// item's id). An unknown cursor is a 400.
	StartingAfter string
}

func (q IGADelegationsListQuery) values() url.Values {
	v := url.Values{}
	if q.DelegatorUserID != "" {
		v.Set("delegator_user_id", q.DelegatorUserID)
	}
	if q.Limit != 0 {
		v.Set("limit", strconv.FormatInt(q.Limit, 10))
	}
	if q.StartingAfter != "" {
		v.Set("starting_after", q.StartingAfter)
	}
	return v
}

// List: List approval delegations.
// GET /v1/iga/delegations.
func (s *IGADelegationsService) List(ctx context.Context, query IGADelegationsListQuery) (*CursorPage[IGADelegationsListItem], error) {
	out := &CursorPage[IGADelegationsListItem]{}
	return out, s.client.do(ctx, "GET", "/v1/iga/delegations", query.values(), nil, out)
}

// Create: Let another user decide a person's approvals (and reviews) for a period of up to a year.
// POST /v1/iga/delegations.
func (s *IGADelegationsService) Create(ctx context.Context, params IGADelegationsCreateParams, opts ...RequestOption) (*IGADelegationsListItem, error) {
	out := &IGADelegationsListItem{}
	return out, s.client.do(ctx, "POST", "/v1/iga/delegations", nil, params, out, opts...)
}

// Delete: End an approval delegation.
// DELETE /v1/iga/delegations/{id}.
func (s *IGADelegationsService) Delete(ctx context.Context, id string, opts ...RequestOption) (*UsersDeleteDeviceKeyResult, error) {
	out := &UsersDeleteDeviceKeyResult{}
	return out, s.client.do(ctx, "DELETE", "/v1/iga/delegations/"+url.PathEscape(id), nil, nil, out, opts...)
}

// IGASODService is the iga sod group of IGAService.
type IGASODService struct {
	client *Client
}

// ListRules: List separation-of-duties rules: pairs of entitlements one person should not hold
// together.
// GET /v1/iga/sod_rules.
func (s *IGASODService) ListRules(ctx context.Context, params ListParams) (*CursorPage[IGASODListRulesItem], error) {
	out := &CursorPage[IGASODListRulesItem]{}
	return out, s.client.do(ctx, "GET", "/v1/iga/sod_rules", params.values(), nil, out)
}

// CreateRule: Create a rule. `mode` is `block` (refuse) or `require_approval` (an extra approval
// step on a request; `approver` names who, default the owner).
// POST /v1/iga/sod_rules.
func (s *IGASODService) CreateRule(ctx context.Context, params IGASODCreateRuleParams, opts ...RequestOption) (*IGASODListRulesItem, error) {
	out := &IGASODListRulesItem{}
	return out, s.client.do(ctx, "POST", "/v1/iga/sod_rules", nil, params, out, opts...)
}

// UpdateRule: Change a separation-of-duties rule.
// PATCH /v1/iga/sod_rules/{id}.
func (s *IGASODService) UpdateRule(ctx context.Context, id string, params IGASODUpdateRuleParams, opts ...RequestOption) (*IGASODListRulesItem, error) {
	out := &IGASODListRulesItem{}
	return out, s.client.do(ctx, "PATCH", "/v1/iga/sod_rules/"+url.PathEscape(id), nil, params, out, opts...)
}

// DeleteRule: Delete a rule and its recorded violations.
// DELETE /v1/iga/sod_rules/{id}.
func (s *IGASODService) DeleteRule(ctx context.Context, id string, opts ...RequestOption) (*UsersDeleteDeviceKeyResult, error) {
	out := &UsersDeleteDeviceKeyResult{}
	return out, s.client.do(ctx, "DELETE", "/v1/iga/sod_rules/"+url.PathEscape(id), nil, nil, out, opts...)
}

// IGASODViolationsQuery holds the query parameters of IGASODService.Violations.
type IGASODViolationsQuery struct {
	// Only violations in this state.
	Status string
	// Page size, 1-500. Without limit (and without starting_after) the whole list is returned.
	Limit int64
	// Cursor: return only items after this one. Pass the previous page's `next_cursor` (the last
	// item's id). An unknown cursor is a 400.
	StartingAfter string
}

func (q IGASODViolationsQuery) values() url.Values {
	v := url.Values{}
	if q.Status != "" {
		v.Set("status", q.Status)
	}
	if q.Limit != 0 {
		v.Set("limit", strconv.FormatInt(q.Limit, 10))
	}
	if q.StartingAfter != "" {
		v.Set("starting_after", q.StartingAfter)
	}
	return v
}

// Violations: The violations report: users who hold both sides of a rule (found by a scan, or
// accepted at request or assignment time).
// GET /v1/iga/sod_violations.
func (s *IGASODService) Violations(ctx context.Context, query IGASODViolationsQuery) (*CursorPage[IGASODViolationsItem], error) {
	out := &CursorPage[IGASODViolationsItem]{}
	return out, s.client.do(ctx, "GET", "/v1/iga/sod_violations", query.values(), nil, out)
}

// Scan: Check every rule against what people hold right now: record new conflicts and resolve
// those that cleared.
// POST /v1/iga/sod_violations/scan.
func (s *IGASODService) Scan(ctx context.Context, opts ...RequestOption) (*IGASODScanResult, error) {
	out := &IGASODScanResult{}
	return out, s.client.do(ctx, "POST", "/v1/iga/sod_violations/scan", nil, nil, out, opts...)
}

// IGALifecycleService is the iga lifecycle group of IGAService.
type IGALifecycleService struct {
	client *Client
}

// ListBirthrightRules: List birthright rules.
// GET /v1/iga/birthright_rules.
func (s *IGALifecycleService) ListBirthrightRules(ctx context.Context, params ListParams) (*CursorPage[IGALifecycleListBirthrightRulesItem], error) {
	out := &CursorPage[IGALifecycleListBirthrightRulesItem]{}
	return out, s.client.do(ctx, "GET", "/v1/iga/birthright_rules", params.values(), nil, out)
}

// CreateBirthrightRule: Create a birthright rule: everyone matching `match` (a group, organization
// and role, app role or verified email domain; all conditions must hold) holds the listed
// entitlements. When someone stops matching, the grants the rule gave are revoked unless
// `revoke_on_unmatch` is false.
// POST /v1/iga/birthright_rules.
func (s *IGALifecycleService) CreateBirthrightRule(ctx context.Context, params IGALifecycleCreateBirthrightRuleParams, opts ...RequestOption) (*IGALifecycleListBirthrightRulesItem, error) {
	out := &IGALifecycleListBirthrightRulesItem{}
	return out, s.client.do(ctx, "POST", "/v1/iga/birthright_rules", nil, params, out, opts...)
}

// UpdateBirthrightRule: Change a birthright rule.
// PATCH /v1/iga/birthright_rules/{id}.
func (s *IGALifecycleService) UpdateBirthrightRule(ctx context.Context, id string, params IGALifecycleUpdateBirthrightRuleParams, opts ...RequestOption) (*IGALifecycleListBirthrightRulesItem, error) {
	out := &IGALifecycleListBirthrightRulesItem{}
	return out, s.client.do(ctx, "PATCH", "/v1/iga/birthright_rules/"+url.PathEscape(id), nil, params, out, opts...)
}

// DeleteBirthrightRule: Delete a birthright rule (grants it already gave stay until revoked).
// DELETE /v1/iga/birthright_rules/{id}.
func (s *IGALifecycleService) DeleteBirthrightRule(ctx context.Context, id string, opts ...RequestOption) (*UsersDeleteDeviceKeyResult, error) {
	out := &UsersDeleteDeviceKeyResult{}
	return out, s.client.do(ctx, "DELETE", "/v1/iga/birthright_rules/"+url.PathEscape(id), nil, nil, out, opts...)
}

// Reconcile: Re-evaluate one user's birthright access now (joiner or mover).
// POST /v1/iga/users/{id}/reconcile.
func (s *IGALifecycleService) Reconcile(ctx context.Context, id string, opts ...RequestOption) (*IGALifecycleReconcileResult, error) {
	out := &IGALifecycleReconcileResult{}
	return out, s.client.do(ctx, "POST", "/v1/iga/users/"+url.PathEscape(id)+"/reconcile", nil, nil, out, opts...)
}

// Offboard: Offboard a leaver: revoke every grant, cancel pending requests and delegations, and
// with `close_account` schedule the account closure through the data-rights path (so downstream
// erasure webhooks and any DSAR orchestrator run as for any deletion). `grace_seconds` sets the
// cancellation window.
// POST /v1/iga/users/{id}/offboard.
func (s *IGALifecycleService) Offboard(ctx context.Context, id string, params IGALifecycleOffboardParams, opts ...RequestOption) (*IGALifecycleOffboardResult, error) {
	out := &IGALifecycleOffboardResult{}
	return out, s.client.do(ctx, "POST", "/v1/iga/users/"+url.PathEscape(id)+"/offboard", nil, params, out, opts...)
}

// Settings: Joiner/mover/leaver settings.
// GET /v1/iga/settings.
func (s *IGALifecycleService) Settings(ctx context.Context) (*IGALifecycleSettingsResult, error) {
	out := &IGALifecycleSettingsResult{}
	return out, s.client.do(ctx, "GET", "/v1/iga/settings", nil, nil, out)
}

// UpdateSettings: Turn the joiner/mover/leaver automation on or off and choose what a deactivated
// account triggers: `revoke` (end the grants) or `revoke_and_close` (also schedule the closure
// after `leaver_close_grace_seconds`).
// PUT /v1/iga/settings.
func (s *IGALifecycleService) UpdateSettings(ctx context.Context, params IGALifecycleUpdateSettingsParams, opts ...RequestOption) (*IGALifecycleSettingsResult, error) {
	out := &IGALifecycleSettingsResult{}
	return out, s.client.do(ctx, "PUT", "/v1/iga/settings", nil, params, out, opts...)
}

// IGACampaignsService is the iga campaigns group of IGAService.
type IGACampaignsService struct {
	client *Client
}

// IGACampaignsListQuery holds the query parameters of IGACampaignsService.List.
type IGACampaignsListQuery struct {
	// Only campaigns in this state.
	Status string
	// Page size, 1-500. Without limit (and without starting_after) the whole list is returned.
	Limit int64
	// Cursor: return only items after this one. Pass the previous page's `next_cursor` (the last
	// item's id). An unknown cursor is a 400.
	StartingAfter string
}

func (q IGACampaignsListQuery) values() url.Values {
	v := url.Values{}
	if q.Status != "" {
		v.Set("status", q.Status)
	}
	if q.Limit != 0 {
		v.Set("limit", strconv.FormatInt(q.Limit, 10))
	}
	if q.StartingAfter != "" {
		v.Set("starting_after", q.StartingAfter)
	}
	return v
}

// List: List certification (access review) campaigns.
// GET /v1/iga/campaigns.
func (s *IGACampaignsService) List(ctx context.Context, query IGACampaignsListQuery) (*CursorPage[IGACampaignsListItem], error) {
	out := &CursorPage[IGACampaignsListItem]{}
	return out, s.client.do(ctx, "GET", "/v1/iga/campaigns", query.values(), nil, out)
}

// Create: Create a draft campaign scoped to everything, specific entitlements, or the entitlements
// for an app, role, group or organization, with reviewers (the person's manager, the entitlement
// owner, or named users), a due date and reminder days. With `auto_revoke` the access reviewers
// mark for revocation is removed when the campaign closes.
// POST /v1/iga/campaigns.
func (s *IGACampaignsService) Create(ctx context.Context, params IGACampaignsCreateParams, opts ...RequestOption) (*IGACampaignsListItem, error) {
	out := &IGACampaignsListItem{}
	return out, s.client.do(ctx, "POST", "/v1/iga/campaigns", nil, params, out, opts...)
}

// Get: Read a campaign with its progress.
// GET /v1/iga/campaigns/{id}.
func (s *IGACampaignsService) Get(ctx context.Context, id string) (*IGACampaignsListItem, error) {
	out := &IGACampaignsListItem{}
	return out, s.client.do(ctx, "GET", "/v1/iga/campaigns/"+url.PathEscape(id), nil, nil, out)
}

// Delete: Delete a draft or closed campaign.
// DELETE /v1/iga/campaigns/{id}.
func (s *IGACampaignsService) Delete(ctx context.Context, id string, opts ...RequestOption) (*UsersDeleteDeviceKeyResult, error) {
	out := &UsersDeleteDeviceKeyResult{}
	return out, s.client.do(ctx, "DELETE", "/v1/iga/campaigns/"+url.PathEscape(id), nil, nil, out, opts...)
}

// Launch: Launch a draft campaign: it adopts access that exists in Atlas but was never granted
// through governance, freezes the review list and notifies reviewers.
// POST /v1/iga/campaigns/{id}/launch.
func (s *IGACampaignsService) Launch(ctx context.Context, id string, opts ...RequestOption) (*IGACampaignsListItem, error) {
	out := &IGACampaignsListItem{}
	return out, s.client.do(ctx, "POST", "/v1/iga/campaigns/"+url.PathEscape(id)+"/launch", nil, nil, out, opts...)
}

// Close: Close a campaign and apply its revoke decisions (with `auto_revoke`). Items nobody
// reviewed are left in place and reported as pending.
// POST /v1/iga/campaigns/{id}/close.
func (s *IGACampaignsService) Close(ctx context.Context, id string, opts ...RequestOption) (*IGACampaignsListItem, error) {
	out := &IGACampaignsListItem{}
	return out, s.client.do(ctx, "POST", "/v1/iga/campaigns/"+url.PathEscape(id)+"/close", nil, nil, out, opts...)
}

// IGACampaignsItemsQuery holds the query parameters of IGACampaignsService.Items.
type IGACampaignsItemsQuery struct {
	// Only items with this decision.
	Decision string
	// Only items this person may decide.
	ReviewerUserID string
	// Page size, 1-500. Without limit (and without starting_after) the whole list is returned.
	Limit int64
	// Cursor: return only items after this one. Pass the previous page's `next_cursor` (the last
	// item's id). An unknown cursor is a 400.
	StartingAfter string
}

func (q IGACampaignsItemsQuery) values() url.Values {
	v := url.Values{}
	if q.Decision != "" {
		v.Set("decision", q.Decision)
	}
	if q.ReviewerUserID != "" {
		v.Set("reviewer_user_id", q.ReviewerUserID)
	}
	if q.Limit != 0 {
		v.Set("limit", strconv.FormatInt(q.Limit, 10))
	}
	if q.StartingAfter != "" {
		v.Set("starting_after", q.StartingAfter)
	}
	return v
}

// Items: The review items of a campaign.
// GET /v1/iga/campaigns/{id}/items.
func (s *IGACampaignsService) Items(ctx context.Context, id string, query IGACampaignsItemsQuery) (*CursorPage[IGACampaignsItemsItem], error) {
	out := &CursorPage[IGACampaignsItemsItem]{}
	return out, s.client.do(ctx, "GET", "/v1/iga/campaigns/"+url.PathEscape(id)+"/items", query.values(), nil, out)
}

// Progress: Progress: totals, percent complete, whether it is overdue, and per-reviewer counts.
// GET /v1/iga/campaigns/{id}/progress.
func (s *IGACampaignsService) Progress(ctx context.Context, id string) (*IGACampaignsProgressResult, error) {
	out := &IGACampaignsProgressResult{}
	return out, s.client.do(ctx, "GET", "/v1/iga/campaigns/"+url.PathEscape(id)+"/progress", nil, nil, out)
}

// IGACampaignsEvidenceQuery holds the query parameters of IGACampaignsService.Evidence.
type IGACampaignsEvidenceQuery struct {
	// Output format (default json).
	Format string
	// Add a masked email column.
	MaskedEmails string
}

func (q IGACampaignsEvidenceQuery) values() url.Values {
	v := url.Values{}
	if q.Format != "" {
		v.Set("format", q.Format)
	}
	if q.MaskedEmails != "" {
		v.Set("masked_emails", q.MaskedEmails)
	}
	return v
}

// Evidence: The audit evidence for a campaign as JSON, or CSV with `format=csv`. People are
// identified by id only (an erased user is flagged), free-text comments are never included, and
// `masked_emails=true` adds an address reduced to its first letter and domain.
// GET /v1/iga/campaigns/{id}/evidence.
func (s *IGACampaignsService) Evidence(ctx context.Context, id string, query IGACampaignsEvidenceQuery) (*IGACampaignsEvidenceResult, error) {
	out := &IGACampaignsEvidenceResult{}
	return out, s.client.do(ctx, "GET", "/v1/iga/campaigns/"+url.PathEscape(id)+"/evidence", query.values(), nil, out)
}

// Decide: Certify or revoke one review item. With `reviewer_user_id` the decision is the
// reviewer's (they must be allowed to review it, and may not review their own access); without it
// it is an administrator decision.
// POST /v1/iga/campaign_items/{id}/decide.
func (s *IGACampaignsService) Decide(ctx context.Context, id string, params IGACampaignsDecideParams, opts ...RequestOption) (*IGACampaignsItemsItem, error) {
	out := &IGACampaignsItemsItem{}
	return out, s.client.do(ctx, "POST", "/v1/iga/campaign_items/"+url.PathEscape(id)+"/decide", nil, params, out, opts...)
}
