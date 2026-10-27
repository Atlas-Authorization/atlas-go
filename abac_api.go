package atlas

import (
	"context"
	"net/url"
	"strconv"
)

// ABACService is the abac resource.
type ABACService struct {
	client    *Client
	Templates *ABACTemplatesService
	Links     *ABACLinksService
	Schema    *ABACSchemaService
}

// List: List the ABAC policies (current version of each).
// GET /v1/abac_policies.
func (s *ABACService) List(ctx context.Context, params ListParams) (*CursorPage[ABACListItem], error) {
	out := &CursorPage[ABACListItem]{}
	return out, s.client.do(ctx, "GET", "/v1/abac_policies", params.values(), nil, out)
}

// Create: Create an ABAC policy from `source` written in the Cedar-subset policy language
// (permit/forbid with when/unless over principal, action, resource and context attributes;
// `fga.check(...)` consults the policy’s FGA store). Source that does not parse is refused with
// the character position; with an entity schema set it is also type-checked and every problem is
// reported. Optional `tests` are saved with version 1.
// POST /v1/abac_policies.
func (s *ABACService) Create(ctx context.Context, params ABACCreateParams, opts ...RequestOption) (*ABACListItem, error) {
	out := &ABACListItem{}
	return out, s.client.do(ctx, "POST", "/v1/abac_policies", nil, params, out, opts...)
}

// Get: Read one ABAC policy with its current source and tests.
// GET /v1/abac_policies/{id}.
func (s *ABACService) Get(ctx context.Context, id string) (*ABACListItem, error) {
	out := &ABACListItem{}
	return out, s.client.do(ctx, "GET", "/v1/abac_policies/"+url.PathEscape(id), nil, nil, out)
}

// Update: Update an ABAC policy. Sending `source` appends a new version and makes it current;
// `current_version` (without `source`) rolls back to an earlier version; name, description,
// enabled and fga_store_id change in place.
// PATCH /v1/abac_policies/{id}.
func (s *ABACService) Update(ctx context.Context, id string, params ABACUpdateParams, opts ...RequestOption) (*ABACListItem, error) {
	out := &ABACListItem{}
	return out, s.client.do(ctx, "PATCH", "/v1/abac_policies/"+url.PathEscape(id), nil, params, out, opts...)
}

// Delete: Delete an ABAC policy and all its versions.
// DELETE /v1/abac_policies/{id}.
func (s *ABACService) Delete(ctx context.Context, id string, opts ...RequestOption) error {
	return s.client.do(ctx, "DELETE", "/v1/abac_policies/"+url.PathEscape(id), nil, nil, nil, opts...)
}

// Versions: List every saved version of an ABAC policy, newest first.
// GET /v1/abac_policies/{id}/versions.
func (s *ABACService) Versions(ctx context.Context, id string, params ListParams) (*CursorPage[ABACVersionsItem], error) {
	out := &CursorPage[ABACVersionsItem]{}
	return out, s.client.do(ctx, "GET", "/v1/abac_policies/"+url.PathEscape(id)+"/versions", params.values(), nil, out)
}

// Test: Run test cases against a policy version (default: the current one), or against a draft
// `source` and `tests` sent in the body, without saving anything. Each test is a request plus the
// expected decision; the policy is evaluated on its own, not with the rest of the set. The
// response also carries `coverage`: which rules and `when`/`unless` clauses the tests exercised (a
// clause no test saw both true and false is listed as a gap), with line numbers.
// POST /v1/abac_policies/{id}/test.
func (s *ABACService) Test(ctx context.Context, id string, params ABACTestParams, opts ...RequestOption) (*ABACTestResult, error) {
	out := &ABACTestResult{}
	return out, s.client.do(ctx, "POST", "/v1/abac_policies/"+url.PathEscape(id)+"/test", nil, params, out, opts...)
}

// Evaluate: Policy decision point: ask whether `principal` may perform `action` on `resource`
// given `context` (and optional extra `entities` for hierarchy). All enabled policies are
// evaluated together with Cedar semantics: a matching forbid wins, otherwise a matching permit
// allows, otherwise deny. Each decision is written to the event feed (type authz.decision), so log
// streams carry it.
// POST /v1/abac/evaluate.
func (s *ABACService) Evaluate(ctx context.Context, params ABACEvaluateParams, opts ...RequestOption) (*ABACEvaluateResult, error) {
	out := &ABACEvaluateResult{}
	return out, s.client.do(ctx, "POST", "/v1/abac/evaluate", nil, params, out, opts...)
}

// PartialEvaluate: Partial evaluation (data filtering): ask what is left of the decision when an
// entity is unknown. With a known principal, an action and a resource TYPE, the response is a
// residual `filter` over the resource attributes (or constant `true`/`false`) that is equivalent
// to evaluating the policies on each resource. `unknowns: ["principal"]` answers "who may do this
// on that resource". Relationship conditions (`fga.check`) are resolved to id lists from the
// policy’s FGA store unless `resolve_relations` is false. `output` asks for a ready-made
// parameterised SQL WHERE (`sql`: dialect and a field-to-column map) and/or a Prisma where object
// (`prisma`: a field map). Policies that build sets from unknown attributes cannot be expressed as
// a filter and are refused with a message naming the policy.
// POST /v1/abac/partial_evaluate.
func (s *ABACService) PartialEvaluate(ctx context.Context, params ABACPartialEvaluateParams, opts ...RequestOption) (*ABACPartialEvaluateResult, error) {
	out := &ABACPartialEvaluateResult{}
	return out, s.client.do(ctx, "POST", "/v1/abac/partial_evaluate", nil, params, out, opts...)
}

// AccessibleResources: List the resources of a type a principal may perform an action on, paged
// (`limit`, `starting_after`; the response carries `has_more` and `next_cursor`). Candidates are
// the Atlas resources of that type (their metadata are the attributes) or the `candidates` you
// send. The policies are reduced to one filter and applied to every candidate; `method` says
// whether that worked or each candidate was evaluated in full.
// POST /v1/abac/accessible_resources.
func (s *ABACService) AccessibleResources(ctx context.Context, params ABACAccessibleResourcesParams, opts ...RequestOption) (*ABACAccessibleResourcesResult, error) {
	out := &ABACAccessibleResourcesResult{}
	return out, s.client.do(ctx, "POST", "/v1/abac/accessible_resources", nil, params, out, opts...)
}

// ABACDiffQuery holds the query parameters of ABACService.Diff.
type ABACDiffQuery struct {
	// The older version. Default: the one before `to`.
	From int64
	// The newer version. Default: the current version.
	To int64
	// false skips the request enumeration and returns only the text diff. Default true.
	Semantic *bool
	// Requests to compare (the enumeration is sampled beyond this). Default 5000.
	MaxRequests int64
	// Changed requests to list. Default 50.
	MaxChanges int64
}

func (q ABACDiffQuery) values() url.Values {
	v := url.Values{}
	if q.From != 0 {
		v.Set("from", strconv.FormatInt(q.From, 10))
	}
	if q.To != 0 {
		v.Set("to", strconv.FormatInt(q.To, 10))
	}
	if q.Semantic != nil {
		v.Set("semantic", strconv.FormatBool(*q.Semantic))
	}
	if q.MaxRequests != 0 {
		v.Set("max_requests", strconv.FormatInt(q.MaxRequests, 10))
	}
	if q.MaxChanges != 0 {
		v.Set("max_changes", strconv.FormatInt(q.MaxChanges, 10))
	}
	return v
}

// Diff: Compare two versions of a policy: a line diff of the source and, unless `semantic=false`,
// the requests whose decision changes. The semantic part enumerates a bounded set of requests
// built from the attributes, groups and actions the policies test (from the entity schema when one
// is set), and lists those that come out differently, with newly-allowed and newly-denied counts
// per action. `exhaustive` says whether every request in the space was compared or the space was
// sampled.
// GET /v1/abac_policies/{id}/diff.
func (s *ABACService) Diff(ctx context.Context, id string, query ABACDiffQuery) (*ABACDiffResult, error) {
	out := &ABACDiffResult{}
	return out, s.client.do(ctx, "GET", "/v1/abac_policies/"+url.PathEscape(id)+"/diff", query.values(), nil, out)
}

// DiffSources: The same comparison for two policy sources you send (a draft against the saved
// version, or two templates), without saving anything.
// POST /v1/abac/diff.
func (s *ABACService) DiffSources(ctx context.Context, params ABACDiffSourcesParams, opts ...RequestOption) (*ABACDiffResult, error) {
	out := &ABACDiffResult{}
	return out, s.client.do(ctx, "POST", "/v1/abac/diff", nil, params, out, opts...)
}

// AuthzenEvaluation: AuthZEN Access Evaluation: `{subject, resource, action, context}` →
// `{decision: boolean}`. Entity types map to PascalCase policy types.
// POST /v1/authzen/access/v1/evaluation.
func (s *ABACService) AuthzenEvaluation(ctx context.Context, params ABACAuthzenEvaluationParams, opts ...RequestOption) (*ABACAuthzenEvaluationResult, error) {
	out := &ABACAuthzenEvaluationResult{}
	return out, s.client.do(ctx, "POST", "/v1/authzen/access/v1/evaluation", nil, params, out, opts...)
}

// AuthzenEvaluations: AuthZEN Access Evaluations (batch, up to 100): shared defaults plus an
// `evaluations` array, with `options.evaluations_semantic` of execute_all (default),
// deny_on_first_deny or permit_on_first_permit.
// POST /v1/authzen/access/v1/evaluations.
func (s *ABACService) AuthzenEvaluations(ctx context.Context, params ABACAuthzenEvaluationParams, opts ...RequestOption) (*ABACAuthzenEvaluationsResult, error) {
	out := &ABACAuthzenEvaluationsResult{}
	return out, s.client.do(ctx, "POST", "/v1/authzen/access/v1/evaluations", nil, params, out, opts...)
}

// AuthzenSearchSubject: AuthZEN Subject Search: which subjects of `subject.type` may perform
// `action` on `resource` (give the resource a `type` and `id`). Answers from the same ABAC
// policies as an evaluation, reduced once by partial evaluation and applied to the candidates
// Atlas knows: your users (type `user`, their public metadata as attributes) and the users in the
// FGA stores the policies consult. `page.limit` and `page.token` page the result; the response
// carries `page.next_token` (empty on the last page), `count` and `total`.
// POST /v1/authzen/access/v1/search/subject.
func (s *ABACService) AuthzenSearchSubject(ctx context.Context, params ABACAuthzenSearchSubjectParams, opts ...RequestOption) (*ABACAuthzenSearchSubjectResult, error) {
	out := &ABACAuthzenSearchSubjectResult{}
	return out, s.client.do(ctx, "POST", "/v1/authzen/access/v1/search/subject", nil, params, out, opts...)
}

// AuthzenSearchResource: AuthZEN Resource Search: which resources of `resource.type` the `subject`
// may perform `action` on. Candidates are your synced Atlas resources of that type (their metadata
// are the attributes) and the objects of that type in the FGA stores the policies consult. Paged
// with `page.limit` and `page.token`.
// POST /v1/authzen/access/v1/search/resource.
func (s *ABACService) AuthzenSearchResource(ctx context.Context, params ABACAuthzenSearchResourceParams, opts ...RequestOption) (*ABACAuthzenSearchSubjectResult, error) {
	out := &ABACAuthzenSearchSubjectResult{}
	return out, s.client.do(ctx, "POST", "/v1/authzen/access/v1/search/resource", nil, params, out, opts...)
}

// AuthzenSearchAction: AuthZEN Action Search: which actions the `subject` may perform on the
// `resource`. The actions considered are the ones the policies name (and the entity schema
// declares), each evaluated in full; the result lists the permitted action names.
// POST /v1/authzen/access/v1/search/action.
func (s *ABACService) AuthzenSearchAction(ctx context.Context, params ABACAuthzenSearchActionParams, opts ...RequestOption) (*ABACAuthzenSearchActionResult, error) {
	out := &ABACAuthzenSearchActionResult{}
	return out, s.client.do(ctx, "POST", "/v1/authzen/access/v1/search/action", nil, params, out, opts...)
}

// ABACTemplatesService is the abac templates group of ABACService.
type ABACTemplatesService struct {
	client *Client
}

// List: List the ABAC policy templates, with their slots and how many links each has.
// GET /v1/abac_templates.
func (s *ABACTemplatesService) List(ctx context.Context, params ListParams) (*CursorPage[ABACTemplatesListItem], error) {
	out := &CursorPage[ABACTemplatesListItem]{}
	return out, s.client.do(ctx, "GET", "/v1/abac_templates", params.values(), nil, out)
}

// Create: Create a policy template: policy source whose scope uses the slots `?principal` and/or
// `?resource` (`principal == ?principal`, `resource in ?resource`, `resource is Doc in
// ?resource`). Slots are filled by a link. With an entity schema set, the template is type-checked
// on save (a slot stands for any entity type).
// POST /v1/abac_templates.
func (s *ABACTemplatesService) Create(ctx context.Context, params ABACTemplatesCreateParams, opts ...RequestOption) (*ABACTemplatesListItem, error) {
	out := &ABACTemplatesListItem{}
	return out, s.client.do(ctx, "POST", "/v1/abac_templates", nil, params, out, opts...)
}

// Get: Read one policy template.
// GET /v1/abac_templates/{id}.
func (s *ABACTemplatesService) Get(ctx context.Context, id string) (*ABACTemplatesListItem, error) {
	out := &ABACTemplatesListItem{}
	return out, s.client.do(ctx, "GET", "/v1/abac_templates/"+url.PathEscape(id), nil, nil, out)
}

// Update: Change a template. A new `source` bumps `version` and takes effect on every link at once
// (`links_updated` counts them). It is refused, with one error per problem and the link named, if
// any link could no longer be filled in or would fail the entity schema.
// PATCH /v1/abac_templates/{id}.
func (s *ABACTemplatesService) Update(ctx context.Context, id string, params ABACTemplatesUpdateParams, opts ...RequestOption) (*ABACTemplatesListItem, error) {
	out := &ABACTemplatesListItem{}
	return out, s.client.do(ctx, "PATCH", "/v1/abac_templates/"+url.PathEscape(id), nil, params, out, opts...)
}

// ABACTemplatesDeleteQuery holds the query parameters of ABACTemplatesService.Delete.
type ABACTemplatesDeleteQuery struct {
	// Delete the template together with its links.
	Force *bool
}

func (q ABACTemplatesDeleteQuery) values() url.Values {
	v := url.Values{}
	if q.Force != nil {
		v.Set("force", strconv.FormatBool(*q.Force))
	}
	return v
}

// Delete: Delete a template. A template with links is refused with 409 unless `force=true`, which
// deletes the links too.
// DELETE /v1/abac_templates/{id}.
func (s *ABACTemplatesService) Delete(ctx context.Context, id string, query ABACTemplatesDeleteQuery, opts ...RequestOption) error {
	return s.client.do(ctx, "DELETE", "/v1/abac_templates/"+url.PathEscape(id), query.values(), nil, nil, opts...)
}

// ABACLinksService is the abac links group of ABACService.
type ABACLinksService struct {
	client *Client
}

// ABACLinksListQuery holds the query parameters of ABACLinksService.List.
type ABACLinksListQuery struct {
	// Only the links of this template.
	TemplateID string
	// Page size, 1-500. Without limit (and without starting_after) the whole list is returned.
	Limit int64
	// Cursor: return only items after this one. Pass the previous page's `next_cursor` (the last
	// item's id). An unknown cursor is a 400.
	StartingAfter string
}

func (q ABACLinksListQuery) values() url.Values {
	v := url.Values{}
	if q.TemplateID != "" {
		v.Set("template_id", q.TemplateID)
	}
	if q.Limit != 0 {
		v.Set("limit", strconv.FormatInt(q.Limit, 10))
	}
	if q.StartingAfter != "" {
		v.Set("starting_after", q.StartingAfter)
	}
	return v
}

// List: List template links: a template with its slots filled by entities. Each link’s `source` is
// what the policy engine evaluates.
// GET /v1/abac_policy_links.
func (s *ABACLinksService) List(ctx context.Context, query ABACLinksListQuery) (*CursorPage[ABACLinksListItem], error) {
	out := &CursorPage[ABACLinksListItem]{}
	return out, s.client.do(ctx, "GET", "/v1/abac_policy_links", query.values(), nil, out)
}

// Create: Link a template to entities. Every slot the template uses needs its entity (`principal`
// for `?principal`, `resource` for `?resource`); one it does not use is refused. The link is
// evaluated together with the other enabled policies, always from the template’s current source,
// and is type-checked against the entity schema when one is set.
// POST /v1/abac_policy_links.
func (s *ABACLinksService) Create(ctx context.Context, params ABACLinksCreateParams, opts ...RequestOption) (*ABACLinksListItem, error) {
	out := &ABACLinksListItem{}
	return out, s.client.do(ctx, "POST", "/v1/abac_policy_links", nil, params, out, opts...)
}

// Get: Read one template link.
// GET /v1/abac_policy_links/{id}.
func (s *ABACLinksService) Get(ctx context.Context, id string) (*ABACLinksListItem, error) {
	out := &ABACLinksListItem{}
	return out, s.client.do(ctx, "GET", "/v1/abac_policy_links/"+url.PathEscape(id), nil, nil, out)
}

// Update: Rename, enable or disable a link, or point its slots at other entities.
// PATCH /v1/abac_policy_links/{id}.
func (s *ABACLinksService) Update(ctx context.Context, id string, params ABACLinksUpdateParams, opts ...RequestOption) (*ABACLinksListItem, error) {
	out := &ABACLinksListItem{}
	return out, s.client.do(ctx, "PATCH", "/v1/abac_policy_links/"+url.PathEscape(id), nil, params, out, opts...)
}

// Delete: Delete a link; the template stays.
// DELETE /v1/abac_policy_links/{id}.
func (s *ABACLinksService) Delete(ctx context.Context, id string, opts ...RequestOption) error {
	return s.client.do(ctx, "DELETE", "/v1/abac_policy_links/"+url.PathEscape(id), nil, nil, nil, opts...)
}

// ABACSchemaService is the abac schema group of ABACService.
type ABACSchemaService struct {
	client *Client
}

// Get: The instance’s ABAC entity schema (`schema` is null and `version` 0 when none is set).
// GET /v1/abac_schema.
func (s *ABACSchemaService) Get(ctx context.Context) (*ABACSchemaGetResult, error) {
	out := &ABACSchemaGetResult{}
	return out, s.client.do(ctx, "GET", "/v1/abac_schema", nil, nil, out)
}

// Set: Set the ABAC entity schema: `entity_types` (attributes with `boolean`, `long`, `string`,
// `set`, `entity` and `record` types, `required: false` for optional ones, and `member_of`) and
// `actions` (`applies_to` principal and resource types and a `context`). Every problem is reported
// with its path. Once set, policies and templates are type-checked when saved: unknown attributes,
// optional attributes read without a `has` guard, wrong operand types, unknown entity types and
// actions, and actions that do not apply to the policy’s principal and resource types. The
// response lists the errors the schema would give the policies and links already stored.
// PUT /v1/abac_schema.
func (s *ABACSchemaService) Set(ctx context.Context, params ABACSchemaSetParams, opts ...RequestOption) (*ABACSchemaGetResult, error) {
	out := &ABACSchemaGetResult{}
	return out, s.client.do(ctx, "PUT", "/v1/abac_schema", nil, params, out, opts...)
}

// Delete: Remove the entity schema; policies are no longer type-checked.
// DELETE /v1/abac_schema.
func (s *ABACSchemaService) Delete(ctx context.Context, opts ...RequestOption) error {
	return s.client.do(ctx, "DELETE", "/v1/abac_schema", nil, nil, nil, opts...)
}

// Validate: Type-check policy (or, with `template: true`, template) source against the saved
// schema, or one sent as `schema`, without saving anything. Returns every issue with its policy
// number, clause, character offset, line and column. A syntax error is reported as an issue too.
// POST /v1/abac_schema/validate.
func (s *ABACSchemaService) Validate(ctx context.Context, params ABACSchemaValidateParams, opts ...RequestOption) (*ABACSchemaValidateResult, error) {
	out := &ABACSchemaValidateResult{}
	return out, s.client.do(ctx, "POST", "/v1/abac_schema/validate", nil, params, out, opts...)
}
