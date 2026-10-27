package atlas

// ABACAccessibleResourcesParams is a typed model of the Backend API.
type ABACAccessibleResourcesParams struct {
	Principal ABACPartialEvaluateParamsPrincipal `json:"principal"`
	Action    string                             `json:"action"`
	// The Atlas resource type key (the policy type is its PascalCase form).
	ResourceType string                                        `json:"resource_type"`
	Context      map[string]interface{}                        `json:"context,omitempty"`
	Entities     []ABACPartialEvaluateParamsPrincipal          `json:"entities,omitempty"`
	Candidates   []ABACAccessibleResourcesParamsCandidatesItem `json:"candidates,omitempty"`
	PolicyIDs    []string                                      `json:"policy_ids,omitempty"`
	// Default 100.
	Limit         *int64 `json:"limit,omitempty"`
	StartingAfter string `json:"starting_after,omitempty"`
}

// ABACAccessibleResourcesParamsCandidatesItem is a typed model of the Backend API.
type ABACAccessibleResourcesParamsCandidatesItem struct {
	ID         string                 `json:"id"`
	Attributes map[string]interface{} `json:"attributes,omitempty"`
	Parents    []string               `json:"parents,omitempty"`
}

// ABACAccessibleResourcesResult is a typed model of the Backend API.
type ABACAccessibleResourcesResult struct {
	Object  string                                  `json:"object"`
	Data    []ABACAccessibleResourcesResultDataItem `json:"data"`
	HasMore bool                                    `json:"has_more"`
	// Pass as `starting_after` for the next page.
	NextCursor *string `json:"next_cursor"`
	// All resources the principal may act on.
	Total int64 `json:"total"`
	// Candidate resources examined.
	Evaluated int64 `json:"evaluated"`
	// `residual` when one filter was applied to every candidate; `per_resource` when the policies had
	// to be evaluated candidate by candidate. One of: residual, per_resource.
	Method string `json:"method"`
}

// ABACAccessibleResourcesResultDataItem is a typed model of the Backend API.
type ABACAccessibleResourcesResultDataItem struct {
	Object string `json:"object"`
	Type   string `json:"type"`
	ID     string `json:"id"`
}

// ABACAuthzenEvaluationParams is a typed model of the Backend API.
type ABACAuthzenEvaluationParams struct {
	Subject     map[string]interface{}   `json:"subject,omitempty"`
	Resource    map[string]interface{}   `json:"resource,omitempty"`
	Action      map[string]interface{}   `json:"action,omitempty"`
	Context     map[string]interface{}   `json:"context,omitempty"`
	Evaluations []map[string]interface{} `json:"evaluations,omitempty"`
	Options     map[string]interface{}   `json:"options,omitempty"`
}

// ABACAuthzenEvaluationResult is a typed model of the Backend API.
type ABACAuthzenEvaluationResult struct {
	// true = allowed.
	Decision bool                               `json:"decision"`
	Context  ABACAuthzenEvaluationResultContext `json:"context"`
}

// ABACAuthzenEvaluationResultContext is a typed model of the Backend API.
type ABACAuthzenEvaluationResultContext struct {
	// Names of the policies that decided it.
	Reasons []string `json:"reasons"`
}

// ABACAuthzenEvaluationsResult is `evaluations` (one decision per evaluation sent, in order;
// shorter when an evaluations_semantic stops early), or a single `decision` when no evaluations
// array was sent.
type ABACAuthzenEvaluationsResult struct {
	Evaluations []ABACAuthzenEvaluationsResultEvaluationsItem `json:"evaluations"`
	Decision    bool                                          `json:"decision"`
}

// ABACAuthzenEvaluationsResultEvaluationsItem is a typed model of the Backend API.
type ABACAuthzenEvaluationsResultEvaluationsItem struct {
	Decision bool `json:"decision"`
}

// ABACAuthzenSearchActionParams is a typed model of the Backend API.
type ABACAuthzenSearchActionParams struct {
	Subject  ABACAuthzenSearchSubjectParamsResource `json:"subject"`
	Resource ABACAuthzenSearchSubjectParamsResource `json:"resource"`
	Context  map[string]interface{}                 `json:"context,omitempty"`
	Page     *ABACAuthzenSearchSubjectParamsPage    `json:"page,omitempty"`
}

// ABACAuthzenSearchActionResult is a typed model of the Backend API.
type ABACAuthzenSearchActionResult struct {
	Results []ABACAuthzenSearchActionResultResultsItem `json:"results"`
	Page    ABACAuthzenSearchSubjectResultPage         `json:"page"`
}

// ABACAuthzenSearchActionResultResultsItem is a typed model of the Backend API.
type ABACAuthzenSearchActionResultResultsItem struct {
	Name string `json:"name"`
}

// ABACAuthzenSearchResourceParams is a typed model of the Backend API.
type ABACAuthzenSearchResourceParams struct {
	Subject  ABACAuthzenSearchSubjectParamsResource `json:"subject"`
	Action   ABACAuthzenSearchSubjectParamsAction   `json:"action"`
	Resource ABACAuthzenSearchSubjectParamsSubject  `json:"resource"`
	Context  map[string]interface{}                 `json:"context,omitempty"`
	Page     *ABACAuthzenSearchSubjectParamsPage    `json:"page,omitempty"`
}

// ABACAuthzenSearchSubjectParams is a typed model of the Backend API.
type ABACAuthzenSearchSubjectParams struct {
	Subject  ABACAuthzenSearchSubjectParamsSubject  `json:"subject"`
	Action   ABACAuthzenSearchSubjectParamsAction   `json:"action"`
	Resource ABACAuthzenSearchSubjectParamsResource `json:"resource"`
	Context  map[string]interface{}                 `json:"context,omitempty"`
	Page     *ABACAuthzenSearchSubjectParamsPage    `json:"page,omitempty"`
}

// ABACAuthzenSearchSubjectParamsAction is a typed model of the Backend API.
type ABACAuthzenSearchSubjectParamsAction struct {
	Name       string                 `json:"name"`
	Properties map[string]interface{} `json:"properties,omitempty"`
}

// ABACAuthzenSearchSubjectParamsPage is a typed model of the Backend API.
type ABACAuthzenSearchSubjectParamsPage struct {
	// Default 100.
	Limit *int64 `json:"limit,omitempty"`
	// The `next_token` of the previous page.
	Token string `json:"token,omitempty"`
}

// ABACAuthzenSearchSubjectParamsResource is a typed model of the Backend API.
type ABACAuthzenSearchSubjectParamsResource struct {
	Type       string                 `json:"type"`
	ID         string                 `json:"id"`
	Properties map[string]interface{} `json:"properties,omitempty"`
}

// ABACAuthzenSearchSubjectParamsSubject is a typed model of the Backend API.
type ABACAuthzenSearchSubjectParamsSubject struct {
	Type       string                 `json:"type"`
	ID         string                 `json:"id,omitempty"`
	Properties map[string]interface{} `json:"properties,omitempty"`
}

// ABACAuthzenSearchSubjectResult is a typed model of the Backend API.
type ABACAuthzenSearchSubjectResult struct {
	Results []OpenFGAListUsersResultUsersItemObject `json:"results"`
	Page    ABACAuthzenSearchSubjectResultPage      `json:"page"`
}

// ABACAuthzenSearchSubjectResultPage is a typed model of the Backend API.
type ABACAuthzenSearchSubjectResultPage struct {
	// Empty on the last page.
	NextToken string `json:"next_token"`
	Count     int64  `json:"count"`
	// All matches, not just this page.
	Total int64 `json:"total"`
}

// ABACCreateParams is a typed model of the Backend API.
type ABACCreateParams struct {
	Name        string                   `json:"name,omitempty"`
	Description *string                  `json:"description,omitempty"`
	Enabled     *bool                    `json:"enabled,omitempty"`
	FGAStoreID  *string                  `json:"fga_store_id,omitempty"`
	Source      string                   `json:"source,omitempty"`
	Tests       []map[string]interface{} `json:"tests,omitempty"`
}

// ABACDiffResult is a typed model of the Backend API.
type ABACDiffResult struct {
	Object   string             `json:"object"`
	PolicyID string             `json:"policy_id"`
	From     int64              `json:"from"`
	To       int64              `json:"to"`
	Text     ABACDiffResultText `json:"text"`
	// The requests whose decision changes. Null when `semantic` was false.
	Semantic *ABACDiffResultSemantic `json:"semantic"`
}

// ABACDiffResultSemantic is the requests whose decision changes. Null when `semantic` was false.
type ABACDiffResultSemantic struct {
	// Requests compared.
	Enumerated int64 `json:"enumerated"`
	// Size of the request space the policies define.
	Space int64 `json:"space"`
	// false when the space was sampled rather than enumerated.
	Exhaustive   bool                                           `json:"exhaustive"`
	Changed      int64                                          `json:"changed"`
	NewlyAllowed int64                                          `json:"newly_allowed"`
	NewlyDenied  int64                                          `json:"newly_denied"`
	ByAction     map[string]ABACDiffResultSemanticByActionValue `json:"by_action"`
	// More changes exist than are listed.
	Truncated bool                                `json:"truncated"`
	Changes   []ABACDiffResultSemanticChangesItem `json:"changes"`
}

// ABACDiffResultSemanticByActionValue is a typed model of the Backend API.
type ABACDiffResultSemanticByActionValue struct {
	NewlyAllowed int64 `json:"newly_allowed"`
	NewlyDenied  int64 `json:"newly_denied"`
}

// ABACDiffResultSemanticChangesItem is a typed model of the Backend API.
type ABACDiffResultSemanticChangesItem struct {
	Request map[string]interface{} `json:"request"`
	// One of: allow, deny.
	Before string `json:"before"`
	// One of: allow, deny.
	After string `json:"after"`
	// Present when a version uses `fga.check`: the assumption the change holds under.
	Assuming ABACDiffResultSemanticChangesItemAssuming `json:"assuming"`
}

// ABACDiffResultSemanticChangesItemAssuming is present when a version uses `fga.check`: the
// assumption the change holds under.
type ABACDiffResultSemanticChangesItemAssuming struct {
	FGACheck bool `json:"fga_check"`
}

// ABACDiffResultText is a typed model of the Backend API.
type ABACDiffResultText struct {
	Identical bool                          `json:"identical"`
	Added     int64                         `json:"added"`
	Removed   int64                         `json:"removed"`
	Lines     []ABACDiffResultTextLinesItem `json:"lines"`
}

// ABACDiffResultTextLinesItem is a typed model of the Backend API.
type ABACDiffResultTextLinesItem struct {
	// One of: context, add, remove.
	Type       string `json:"type"`
	Text       string `json:"text"`
	BeforeLine int64  `json:"before_line"`
	AfterLine  int64  `json:"after_line"`
}

// ABACDiffSourcesParams is a typed model of the Backend API.
type ABACDiffSourcesParams struct {
	Before      string `json:"before"`
	After       string `json:"after"`
	Semantic    *bool  `json:"semantic,omitempty"`
	MaxRequests *int64 `json:"max_requests,omitempty"`
	MaxChanges  *int64 `json:"max_changes,omitempty"`
}

// ABACEvaluateParams is a typed model of the Backend API.
type ABACEvaluateParams struct {
	Principal map[string]interface{}   `json:"principal,omitempty"`
	Action    string                   `json:"action,omitempty"`
	Resource  map[string]interface{}   `json:"resource,omitempty"`
	Context   map[string]interface{}   `json:"context,omitempty"`
	Entities  []map[string]interface{} `json:"entities,omitempty"`
	PolicyIDs []string                 `json:"policy_ids,omitempty"`
}

// ABACEvaluateResult is a typed model of the Backend API.
type ABACEvaluateResult struct {
	Object string `json:"object"`
	// One of: allow, deny.
	Decision string `json:"decision"`
	// Names of the policies that decided it.
	Reasons []string `json:"reasons"`
	// Policies skipped because they errored while evaluating.
	Errors []string `json:"errors"`
}

// ABACLinksCreateParams is a typed model of the Backend API.
type ABACLinksCreateParams struct {
	TemplateID string `json:"template_id"`
	// Shown as the deciding policy in decisions.
	Name string `json:"name"`
	// An entity such as `{ "type": "User", "id": "alice" }`.
	Principal *ABACLinksCreateParamsPrincipal `json:"principal,omitempty"`
	// An entity such as `{ "type": "User", "id": "alice" }`.
	Resource *ABACLinksCreateParamsPrincipal `json:"resource,omitempty"`
	Enabled  *bool                           `json:"enabled,omitempty"`
}

// ABACLinksCreateParamsPrincipal is an entity such as `{ "type": "User", "id": "alice" }`.
type ABACLinksCreateParamsPrincipal struct {
	Type string `json:"type,omitempty"`
	ID   string `json:"id,omitempty"`
}

// ABACLinksListItem is a typed model of the Backend API.
type ABACLinksListItem struct {
	Object string `json:"object"`
	ID     string `json:"id"`
	// Shown as the deciding policy in decisions.
	Name         string  `json:"name"`
	TemplateID   string  `json:"template_id"`
	TemplateName *string `json:"template_name"`
	// The template version the link currently follows (always the latest).
	TemplateVersion *int64                                 `json:"template_version"`
	Principal       *OpenFGAListUsersResultUsersItemObject `json:"principal"`
	Resource        *OpenFGAListUsersResultUsersItemObject `json:"resource"`
	Enabled         bool                                   `json:"enabled"`
	// The policy source the link evaluates: the template with its slots filled.
	Source string `json:"source"`
	// Created (epoch ms).
	CreatedAt int64 `json:"created_at"`
	// Last updated (epoch ms).
	UpdatedAt int64 `json:"updated_at"`
}

// ABACLinksUpdateParams is a typed model of the Backend API.
type ABACLinksUpdateParams struct {
	TemplateID string `json:"template_id,omitempty"`
	// Shown as the deciding policy in decisions.
	Name string `json:"name,omitempty"`
	// An entity such as `{ "type": "User", "id": "alice" }`.
	Principal *ABACLinksCreateParamsPrincipal `json:"principal,omitempty"`
	// An entity such as `{ "type": "User", "id": "alice" }`.
	Resource *ABACLinksCreateParamsPrincipal `json:"resource,omitempty"`
	Enabled  *bool                           `json:"enabled,omitempty"`
}

// ABACListItem is a typed model of the Backend API.
type ABACListItem struct {
	Object         string  `json:"object"`
	ID             string  `json:"id"`
	Name           string  `json:"name"`
	Description    *string `json:"description"`
	Enabled        bool    `json:"enabled"`
	CurrentVersion int64   `json:"current_version"`
	// The FGA store `fga.check(...)` consults.
	FGAStoreID *string `json:"fga_store_id"`
	// The current version’s policy source.
	Source string                  `json:"source"`
	Tests  []ABACListItemTestsItem `json:"tests"`
	// Created (epoch ms).
	CreatedAt int64 `json:"created_at"`
	// Last updated (epoch ms).
	UpdatedAt int64 `json:"updated_at"`
}

// ABACListItemTestsItem is a typed model of the Backend API.
type ABACListItemTestsItem struct {
	Name string `json:"name"`
	// principal, action, resource, context and optional entities.
	Request map[string]interface{} `json:"request"`
	// One of: allow, deny.
	Expect string `json:"expect"`
}

// ABACPartialEvaluateParams is a typed model of the Backend API.
type ABACPartialEvaluateParams struct {
	Principal ABACPartialEvaluateParamsPrincipal `json:"principal"`
	Action    string                             `json:"action"`
	Resource  ABACPartialEvaluateParamsPrincipal `json:"resource"`
	Context   map[string]interface{}             `json:"context,omitempty"`
	// Other entities the policies reference (hierarchy and attributes).
	Entities []ABACPartialEvaluateParamsPrincipal `json:"entities,omitempty"`
	// Only these policies (default: every enabled one).
	PolicyIDs []string `json:"policy_ids,omitempty"`
	// Which entity’s attributes are unknown. Default ["resource"].
	Unknowns []string `json:"unknowns,omitempty"`
	// Replace relationship conditions with the ids the FGA store returns. Default true.
	ResolveRelations *bool                            `json:"resolve_relations,omitempty"`
	Output           *ABACPartialEvaluateParamsOutput `json:"output,omitempty"`
}

// ABACPartialEvaluateParamsOutput is a typed model of the Backend API.
type ABACPartialEvaluateParamsOutput struct {
	SQL    *ABACPartialEvaluateParamsOutputSQL    `json:"sql,omitempty"`
	Prisma *ABACPartialEvaluateParamsOutputPrisma `json:"prisma,omitempty"`
}

// ABACPartialEvaluateParamsOutputPrisma is a typed model of the Backend API.
type ABACPartialEvaluateParamsOutputPrisma struct {
	Fields map[string]string `json:"fields,omitempty"`
}

// ABACPartialEvaluateParamsOutputSQL is a typed model of the Backend API.
type ABACPartialEvaluateParamsOutputSQL struct {
	// One of: postgres, mysql, sqlite.
	Dialect string `json:"dialect,omitempty"`
	// Field to column: a name, or `{ column, kind: "array"|"json", json: "a.b" }`.
	Columns map[string]interface{} `json:"columns"`
	// Postgres: the number the first `$n` placeholder gets.
	ParamOffset *int64 `json:"param_offset,omitempty"`
}

// ABACPartialEvaluateParamsPrincipal is a typed model of the Backend API.
type ABACPartialEvaluateParamsPrincipal struct {
	Type string `json:"type"`
	// Required for a known entity; ignored for an unknown one.
	ID         string                 `json:"id,omitempty"`
	Attributes map[string]interface{} `json:"attributes,omitempty"`
	// `Type::id` uids the entity is a member of.
	Parents []string `json:"parents,omitempty"`
}

// ABACPartialEvaluateResult is a typed model of the Backend API.
type ABACPartialEvaluateResult struct {
	Object string `json:"object"`
	// `allow`/`deny` when the filter is constant; `conditional` otherwise. One of: allow, deny,
	// conditional.
	Decision string `json:"decision"`
	// A residual-policy condition over fields of the unknown entity (`resource.department`,
	// `principal.level`; reserved `<var>.$id` and `<var>.$ancestors`). Leaves are total booleans (a
	// missing field is false) and there is no `not`. `and`/`or` carry `args`; `eq|ne|lt|lte|gt|gte`
	// carry `field` with a `valu
	Filter ABACPartialEvaluateResultFilter `json:"filter"`
	// A residual-policy condition over fields of the unknown entity (`resource.department`,
	// `principal.level`; reserved `<var>.$id` and `<var>.$ancestors`). Leaves are total booleans (a
	// missing field is false) and there is no `not`. `and`/`or` carry `args`; `eq|ne|lt|lte|gt|gte`
	// carry `field` with a `valu
	Permit ABACPartialEvaluateResultFilter `json:"permit"`
	// A residual-policy condition over fields of the unknown entity (`resource.department`,
	// `principal.level`; reserved `<var>.$id` and `<var>.$ancestors`). Leaves are total booleans (a
	// missing field is false) and there is no `not`. `and`/`or` carry `args`; `eq|ne|lt|lte|gt|gte`
	// carry `field` with a `valu
	Forbid   ABACPartialEvaluateResultFilter `json:"forbid"`
	Unknowns []string                        `json:"unknowns"`
	// true when relationship conditions were replaced by id lists from the FGA store.
	RelationsResolved bool                         `json:"relations_resolved"`
	SQL               ABACPartialEvaluateResultSQL `json:"sql"`
	// A Prisma `where` object.
	Prisma map[string]interface{} `json:"prisma"`
}

// ABACPartialEvaluateResultFilter is a residual-policy condition over fields of the unknown entity
// (`resource.department`, `principal.level`; reserved `<var>.$id` and `<var>.$ancestors`). Leaves
// are total booleans (a missing field is false) and there is no `not`. `and`/`or` carry `args`;
// `eq|ne|lt|lte|gt|gte` carry `field` with a `valu
type ABACPartialEvaluateResultFilter struct {
	Op      string        `json:"op"`
	Field   string        `json:"field"`
	Value   interface{}   `json:"value"`
	Ref     string        `json:"ref"`
	Args    []interface{} `json:"args"`
	Values  []interface{} `json:"values"`
	Pattern string        `json:"pattern"`
}

// ABACPartialEvaluateResultSQL is a typed model of the Backend API.
type ABACPartialEvaluateResultSQL struct {
	// A parameterised boolean expression for WHERE.
	Text   string        `json:"text"`
	Params []interface{} `json:"params"`
}

// ABACSchemaGetResult is a typed model of the Backend API.
type ABACSchemaGetResult struct {
	Object string `json:"object"`
	// The entity schema: `entity_types` and `actions`. Null when none is set.
	Schema map[string]interface{} `json:"schema"`
	// 0 when none is set.
	Version   int64  `json:"version"`
	UpdatedAt *int64 `json:"updated_at"`
	// On a save: the errors this schema would give the policies and links already stored (the schema
	// is saved anyway; they must be fixed before those are edited).
	PolicyIssues []ABACSchemaGetResultPolicyIssuesItem `json:"policy_issues"`
}

// ABACSchemaGetResultPolicyIssuesItem is a typed model of the Backend API.
type ABACSchemaGetResultPolicyIssuesItem struct {
	// One of: error, warning.
	Severity string `json:"severity"`
	// 1-based position of the policy in the source (0 for a syntax error).
	Policy int64 `json:"policy"`
	// One of: permit, forbid.
	Rule    string                                    `json:"rule"`
	Clause  ABACSchemaGetResultPolicyIssuesItemClause `json:"clause"`
	Message string                                    `json:"message"`
	// Character offset in the source.
	Offset int64 `json:"offset"`
	Line   int64 `json:"line"`
	Column int64 `json:"column"`
	// With `policy_issues`: the stored policy or link the issue belongs to.
	SourceName string `json:"source_name"`
}

// ABACSchemaGetResultPolicyIssuesItemClause is a typed model of the Backend API.
type ABACSchemaGetResultPolicyIssuesItemClause struct {
	// One of: when, unless.
	Kind  string `json:"kind"`
	Index int64  `json:"index"`
}

// ABACSchemaSetParams is a typed model of the Backend API.
type ABACSchemaSetParams struct {
	Schema map[string]interface{} `json:"schema"`
}

// ABACSchemaValidateParams is a typed model of the Backend API.
type ABACSchemaValidateParams struct {
	Source   string                 `json:"source"`
	Schema   map[string]interface{} `json:"schema,omitempty"`
	Template *bool                  `json:"template,omitempty"`
}

// ABACSchemaValidateResult is a typed model of the Backend API.
type ABACSchemaValidateResult struct {
	Object string `json:"object"`
	// false when there is any error (warnings do not count).
	Valid bool `json:"valid"`
	// false when no schema was set or the source did not parse.
	SchemaChecked bool                                  `json:"schema_checked"`
	Issues        []ABACSchemaGetResultPolicyIssuesItem `json:"issues"`
}

// ABACTemplatesCreateParams is a typed model of the Backend API.
type ABACTemplatesCreateParams struct {
	Name        string  `json:"name"`
	Description *string `json:"description,omitempty"`
	// Policy source with `?principal` and/or `?resource` slots in the scope, e.g. `permit (principal
	// == ?principal, action == Action::"read", resource in ?resource);`.
	Source string `json:"source"`
	// The FGA store `fga.check(...)` in the source consults.
	FGAStoreID *string `json:"fga_store_id,omitempty"`
}

// ABACTemplatesListItem is a typed model of the Backend API.
type ABACTemplatesListItem struct {
	Object      string  `json:"object"`
	ID          string  `json:"id"`
	Name        string  `json:"name"`
	Description *string `json:"description"`
	// Policy source with `?principal` / `?resource` slots in the scope.
	Source string `json:"source"`
	// Increases each time `source` changes; every link follows it.
	Version    int64    `json:"version"`
	Slots      []string `json:"slots"`
	FGAStoreID *string  `json:"fga_store_id"`
	LinkCount  int64    `json:"link_count"`
	// On an update that changed `source`: the links that now evaluate the new source.
	LinksUpdated int64 `json:"links_updated"`
	// Created (epoch ms).
	CreatedAt int64 `json:"created_at"`
	// Last updated (epoch ms).
	UpdatedAt int64 `json:"updated_at"`
}

// ABACTemplatesUpdateParams is a typed model of the Backend API.
type ABACTemplatesUpdateParams struct {
	Name        string  `json:"name,omitempty"`
	Description *string `json:"description,omitempty"`
	// Policy source with `?principal` and/or `?resource` slots in the scope, e.g. `permit (principal
	// == ?principal, action == Action::"read", resource in ?resource);`.
	Source string `json:"source,omitempty"`
	// The FGA store `fga.check(...)` in the source consults.
	FGAStoreID *string `json:"fga_store_id,omitempty"`
}

// ABACTestParams is a typed model of the Backend API.
type ABACTestParams struct {
	Version *int64                   `json:"version,omitempty"`
	Source  string                   `json:"source,omitempty"`
	Tests   []map[string]interface{} `json:"tests,omitempty"`
}

// ABACTestResult is a typed model of the Backend API.
type ABACTestResult struct {
	Object string `json:"object"`
	Passed bool   `json:"passed"`
	// Which rules and `when`/`unless` clauses the test cases exercised.
	Coverage ABACTestResultCoverage      `json:"coverage"`
	Results  []ABACTestResultResultsItem `json:"results"`
}

// ABACTestResultCoverage is which rules and `when`/`unless` clauses the test cases exercised.
type ABACTestResultCoverage struct {
	Object string `json:"object"`
	// Test cases run.
	Tests   int64                             `json:"tests"`
	Rules   []ABACTestResultCoverageRulesItem `json:"rules"`
	Summary ABACTestResultCoverageSummary     `json:"summary"`
	// What to add a test for, one sentence each.
	Gaps []string `json:"gaps"`
}

// ABACTestResultCoverageRulesItem is a typed model of the Backend API.
type ABACTestResultCoverageRulesItem struct {
	// 1-based position of the rule in the source.
	Rule int64 `json:"rule"`
	// One of: permit, forbid.
	Effect string `json:"effect"`
	Line   *int64 `json:"line"`
	// Tests whose principal, action and resource fell in the rule’s scope.
	InScope int64 `json:"in_scope"`
	// Tests in which the rule matched.
	Matched int64 `json:"matched"`
	// One of: covered, partial, untouched.
	Status  string                                       `json:"status"`
	Clauses []ABACTestResultCoverageRulesItemClausesItem `json:"clauses"`
}

// ABACTestResultCoverageRulesItemClausesItem is a typed model of the Backend API.
type ABACTestResultCoverageRulesItemClausesItem struct {
	// One of: when, unless.
	Kind  string `json:"kind"`
	Index int64  `json:"index"`
	Line  *int64 `json:"line"`
	True  int64  `json:"true"`
	False int64  `json:"false"`
	Error int64  `json:"error"`
}

// ABACTestResultCoverageSummary is a typed model of the Backend API.
type ABACTestResultCoverageSummary struct {
	Rules           int64 `json:"rules"`
	Reached         int64 `json:"reached"`
	Matched         int64 `json:"matched"`
	Clauses         int64 `json:"clauses"`
	ClausesBothWays int64 `json:"clauses_both_ways"`
	// Rules reached, as a whole percentage.
	Percent int64 `json:"percent"`
}

// ABACTestResultResultsItem is a typed model of the Backend API.
type ABACTestResultResultsItem struct {
	Name   string `json:"name"`
	Expect string `json:"expect"`
	Actual string `json:"actual"`
	Passed bool   `json:"passed"`
}

// ABACUpdateParams is a typed model of the Backend API.
type ABACUpdateParams struct {
	Name           string                   `json:"name,omitempty"`
	Description    *string                  `json:"description,omitempty"`
	Enabled        *bool                    `json:"enabled,omitempty"`
	FGAStoreID     *string                  `json:"fga_store_id,omitempty"`
	Source         string                   `json:"source,omitempty"`
	Tests          []map[string]interface{} `json:"tests,omitempty"`
	CurrentVersion *int64                   `json:"current_version,omitempty"`
}

// ABACVersionsItem is a typed model of the Backend API.
type ABACVersionsItem struct {
	Object   string                  `json:"object"`
	PolicyID string                  `json:"policy_id"`
	Version  int64                   `json:"version"`
	Source   string                  `json:"source"`
	Tests    []ABACListItemTestsItem `json:"tests"`
	Current  bool                    `json:"current"`
	// Created (epoch ms).
	CreatedAt int64 `json:"created_at"`
}

// AccessPoliciesCreateParams is a typed model of the Backend API.
type AccessPoliciesCreateParams struct {
	Name        string                   `json:"name,omitempty"`
	Description *string                  `json:"description,omitempty"`
	Enabled     *bool                    `json:"enabled,omitempty"`
	Priority    *int64                   `json:"priority,omitempty"`
	Stages      []string                 `json:"stages,omitempty"`
	Conditions  map[string]interface{}   `json:"conditions,omitempty"`
	Grants      []map[string]interface{} `json:"grants,omitempty"`
}

// AccessPoliciesListItem is a typed model of the Backend API.
type AccessPoliciesListItem struct {
	Object      string  `json:"object"`
	ID          string  `json:"id"`
	Name        string  `json:"name"`
	Description *string `json:"description"`
	Enabled     bool    `json:"enabled"`
	// Lower evaluates first.
	Priority int64 `json:"priority"`
	// Empty = every stage.
	Stages []string `json:"stages"`
	// All present conditions must match.
	Conditions map[string]interface{}             `json:"conditions"`
	Grants     []AccessPoliciesListItemGrantsItem `json:"grants"`
	// Created (epoch ms).
	CreatedAt int64 `json:"created_at"`
	// Last updated (epoch ms).
	UpdatedAt int64 `json:"updated_at"`
}

// AccessPoliciesListItemGrantsItem is a typed model of the Backend API.
type AccessPoliciesListItemGrantsItem struct {
	// One of: allow, block, require_mfa, require_acr, require_policy_acceptance, require_action.
	Type  string `json:"type"`
	Value string `json:"value"`
}

// AccessPoliciesSimulateParams is a typed model of the Backend API.
type AccessPoliciesSimulateParams struct {
	PolicyID      string   `json:"policy_id,omitempty"`
	Stage         string   `json:"stage,omitempty"`
	IP            string   `json:"ip,omitempty"`
	ApplicationID string   `json:"application_id,omitempty"`
	UserID        string   `json:"user_id,omitempty"`
	Groups        []string `json:"groups,omitempty"`
	Orgs          []string `json:"orgs,omitempty"`
	Roles         []string `json:"roles,omitempty"`
	Country       string   `json:"country,omitempty"`
	// One of: low, medium, high.
	RiskLevel string `json:"risk_level,omitempty"`
	// One of: trusted, untrusted, unknown.
	DeviceTrust string   `json:"device_trust,omitempty"`
	AuthMethods []string `json:"auth_methods,omitempty"`
	MFAVerified *bool    `json:"mfa_verified,omitempty"`
	Acr         []string `json:"acr,omitempty"`
	Now         *int64   `json:"now,omitempty"`
}

// AccessPoliciesSimulateResult is a typed model of the Backend API.
type AccessPoliciesSimulateResult struct {
	Object string `json:"object"`
	// One of: allow, block, step_up.
	Decision     string                                   `json:"decision"`
	Matched      []string                                 `json:"matched"`
	BlockedBy    *string                                  `json:"blocked_by"`
	Requirements AccessPoliciesSimulateResultRequirements `json:"requirements"`
	Unmet        []string                                 `json:"unmet"`
}

// AccessPoliciesSimulateResultRequirements is a typed model of the Backend API.
type AccessPoliciesSimulateResultRequirements struct {
	MFA              bool     `json:"mfa"`
	Acr              []string `json:"acr"`
	PolicyAcceptance []string `json:"policy_acceptance"`
	Actions          []string `json:"actions"`
}

// ActionsCallsResult is a typed model of the Backend API.
type ActionsCallsResult struct {
	Object     string                       `json:"object"`
	Data       []ActionsCallsResultDataItem `json:"data"`
	HasMore    bool                         `json:"has_more"`
	NextCursor *string                      `json:"next_cursor"`
	// Real (non-test) calls in the last 24 hours.
	Stats ActionsCallsResultStats `json:"stats"`
}

// ActionsCallsResultDataItem is a typed model of the Backend API.
type ActionsCallsResultDataItem struct {
	Object   string  `json:"object"`
	ID       string  `json:"id"`
	ActionID string  `json:"action_id"`
	Trigger  string  `json:"trigger"`
	UserID   *string `json:"user_id"`
	// A dry-run test call, kept out of the stats.
	Test bool `json:"test"`
	// One of: ok, denied, timeout, error, invalid_response.
	Status     string  `json:"status"`
	HTTPStatus *int64  `json:"http_status"`
	LatencyMs  *int64  `json:"latency_ms"`
	Error      *string `json:"error"`
	// What the endpoint answered with, reduced to the names it set (never claim values).
	Answer map[string]interface{} `json:"answer"`
	// Called (epoch ms).
	CreatedAt int64 `json:"created_at"`
}

// ActionsCallsResultStats is real (non-test) calls in the last 24 hours.
type ActionsCallsResultStats struct {
	Calls24h     int64  `json:"calls_24h"`
	Denied24h    int64  `json:"denied_24h"`
	Failed24h    int64  `json:"failed_24h"`
	Timeouts24h  int64  `json:"timeouts_24h"`
	P95LatencyMs *int64 `json:"p95_latency_ms"`
	LastFailedAt *int64 `json:"last_failed_at"`
}

// AgentAccessRequestsApproveParams is a typed model of the Backend API.
type AgentAccessRequestsApproveParams struct {
	ExpiresInSeconds *int64 `json:"expires_in_seconds,omitempty"`
	DecidedBy        string `json:"decided_by,omitempty"`
}

// AgentAccessRequestsDenyParams is a typed model of the Backend API.
type AgentAccessRequestsDenyParams struct {
	DecidedBy string `json:"decided_by,omitempty"`
}

// AgentRegistrationGetResult is a typed model of the Backend API.
type AgentRegistrationGetResult struct {
	Object           string                                           `json:"object"`
	Enabled          bool                                             `json:"enabled"`
	AllowAnonymous   bool                                             `json:"allow_anonymous"`
	AllowServiceAuth bool                                             `json:"allow_service_auth"`
	AllowRefresh     bool                                             `json:"allow_refresh"`
	UntrustedScopes  []string                                         `json:"untrusted_scopes"`
	TrustedScopes    []string                                         `json:"trusted_scopes"`
	ClaimTTLSeconds  int64                                            `json:"claim_ttl_seconds"`
	AutoApproveRules []AgentRegistrationGetResultAutoApproveRulesItem `json:"auto_approve_rules"`
}

// AgentRegistrationGetResultAutoApproveRulesItem is a typed model of the Backend API.
type AgentRegistrationGetResultAutoApproveRulesItem struct {
	// One of: tool, connection.
	Kind     string `json:"kind"`
	Resource string `json:"resource"`
}

// AgentRegistrationReplaceParams is a typed model of the Backend API.
type AgentRegistrationReplaceParams struct {
	Enabled          *bool    `json:"enabled,omitempty"`
	AllowAnonymous   *bool    `json:"allow_anonymous,omitempty"`
	AllowServiceAuth *bool    `json:"allow_service_auth,omitempty"`
	AllowRefresh     *bool    `json:"allow_refresh,omitempty"`
	UntrustedScopes  []string `json:"untrusted_scopes,omitempty"`
	TrustedScopes    []string `json:"trusted_scopes,omitempty"`
	ClaimTTLSeconds  *int64   `json:"claim_ttl_seconds,omitempty"`
	// Access requests from a trusted agent matching a rule are approved automatically.
	AutoApproveRules []AgentRegistrationReplaceParamsAutoApproveRulesItem `json:"auto_approve_rules,omitempty"`
}

// AgentRegistrationReplaceParamsAutoApproveRulesItem is a typed model of the Backend API.
type AgentRegistrationReplaceParamsAutoApproveRulesItem struct {
	// One of: tool, connection.
	Kind string `json:"kind"`
	// Exact name, or a prefix ending in *.
	Resource string `json:"resource"`
}

// AgentsClaimParams is a typed model of the Backend API.
type AgentsClaimParams struct {
	UserID string `json:"user_id"`
}

// AgentsGetResult is a typed model of the Backend API.
type AgentsGetResult map[string]interface{}

// AgentsListResult is a typed model of the Backend API.
type AgentsListResult struct {
	Object  string                   `json:"object"`
	Data    []map[string]interface{} `json:"data"`
	HasMore bool                     `json:"has_more"`
}

// AgentsRevokeAccessParams is a typed model of the Backend API.
type AgentsRevokeAccessParams struct {
	Disable *bool `json:"disable,omitempty"`
}

// AgentsSetOwnerParams is a typed model of the Backend API.
type AgentsSetOwnerParams struct {
	UserID *string `json:"user_id"`
}

// AnalyticsActiveUsersResult is a typed model of the Backend API.
type AnalyticsActiveUsersResult struct {
	Object string                               `json:"object"`
	Window AnalyticsFunnelResultWindow          `json:"window"`
	Dau    int64                                `json:"dau"`
	Wau    int64                                `json:"wau"`
	Mau    int64                                `json:"mau"`
	Data   []AnalyticsActiveUsersResultDataItem `json:"data"`
}

// AnalyticsActiveUsersResultDataItem is a typed model of the Backend API.
type AnalyticsActiveUsersResultDataItem struct {
	Bucket         string `json:"bucket"`
	ActiveUsers    int64  `json:"active_users"`
	NewUsers       int64  `json:"new_users"`
	ReturningUsers int64  `json:"returning_users"`
	SignIns        int64  `json:"sign_ins"`
}

// AnalyticsAlertRulesCreateParams is a typed model of the Backend API.
type AnalyticsAlertRulesCreateParams struct {
	Name string `json:"name"`
	// Percent metrics are 0-100; failed_sign_ins is a count; sign_in_p95_seconds is seconds;
	// api_usage_spike is the ratio of a key or organization's request rate in the window to its
	// average hourly rate over the 7 days before (for example 10 = ten times its usual volume), and
	// min_sample is the fewest requ One of: sign_in_success_rate, failed_passkey_ratio,
	// failed_sign_ins, sign_in_p95_seconds, api_us...
	Metric string `json:"metric"`
	// One of: lt, gt.
	Comparator string  `json:"comparator"`
	Threshold  float64 `json:"threshold"`
	// Trailing window, 5 to 1440 (default 60).
	WindowMinutes *int64 `json:"window_minutes,omitempty"`
	// Ratios and latency are not evaluated on fewer observations (default 20).
	MinSample *int64 `json:"min_sample,omitempty"`
	// Minimum minutes between notifications while the rule stays firing (default 60).
	CooldownMinutes *int64   `json:"cooldown_minutes,omitempty"`
	EmailContacts   []string `json:"email_contacts,omitempty"`
	// A public HTTPS endpoint. The body is signed like any Atlas webhook; the signing secret is
	// returned once, on create.
	WebhookURL *string `json:"webhook_url,omitempty"`
	Enabled    *bool   `json:"enabled,omitempty"`
	// api_usage_spike only: watch secret keys, end-user API keys or organizations (null = all). One
	// of: api_key, end_user_api_key, organization, .
	SubjectType *string `json:"subject_type,omitempty"`
	// api_usage_spike only: watch one key or organization (needs subject_type).
	SubjectID *string `json:"subject_id,omitempty"`
	// Also raise a Shared Signals event (an opaque subject naming the key or organization) on every
	// enabled stream that asks for it.
	SSF *bool `json:"ssf,omitempty"`
}

// AnalyticsAlertRulesListResult is a typed model of the Backend API.
type AnalyticsAlertRulesListResult struct {
	Object string                                  `json:"object"`
	Data   []AnalyticsAlertRulesListResultDataItem `json:"data"`
	// Whether another page follows the cursor.
	HasMore bool `json:"has_more"`
	// The cursor to pass as `starting_after` for the next page on a keyset-paginated list; null on the
	// last page (and absent on lists that are not cursor-paginated).
	NextCursor *string                `json:"next_cursor"`
	Metrics    map[string]interface{} `json:"metrics"`
}

// AnalyticsAlertRulesListResultDataItem is a typed model of the Backend API.
type AnalyticsAlertRulesListResultDataItem struct {
	Object string `json:"object"`
	ID     string `json:"id"`
	Name   string `json:"name"`
	// One of: sign_in_success_rate, failed_passkey_ratio, failed_sign_ins, sign_in_p95_seconds,
	// api_usage_spike.
	Metric string `json:"metric"`
	// One of: lt, gt.
	Comparator       string   `json:"comparator"`
	Threshold        float64  `json:"threshold"`
	WindowMinutes    int64    `json:"window_minutes"`
	MinSample        int64    `json:"min_sample"`
	CooldownMinutes  int64    `json:"cooldown_minutes"`
	EmailContacts    []string `json:"email_contacts"`
	WebhookURL       *string  `json:"webhook_url"`
	HasWebhookSecret bool     `json:"has_webhook_secret"`
	Enabled          bool     `json:"enabled"`
	SubjectType      *string  `json:"subject_type"`
	SubjectID        *string  `json:"subject_id"`
	SSF              bool     `json:"ssf"`
	// One of: ok, firing.
	State           string   `json:"state"`
	LastValue       *float64 `json:"last_value"`
	LastEvaluatedAt *int64   `json:"last_evaluated_at"`
	LastTriggeredAt *int64   `json:"last_triggered_at"`
	LastError       *string  `json:"last_error"`
	CreatedAt       int64    `json:"created_at"`
}

// AnalyticsAlertRulesTestParams is a typed model of the Backend API.
type AnalyticsAlertRulesTestParams struct {
	Notify *bool `json:"notify,omitempty"`
}

// AnalyticsAlertRulesTestResult is a typed model of the Backend API.
type AnalyticsAlertRulesTestResult struct {
	Object   string                           `json:"object"`
	Value    *float64                         `json:"value"`
	Sample   int64                            `json:"sample"`
	Subject  *AnalyticsAPIUsageResultDataItem `json:"subject"`
	Notified bool                             `json:"notified"`
	Error    *string                          `json:"error"`
}

// AnalyticsAlertRulesUpdateParams is a typed model of the Backend API.
type AnalyticsAlertRulesUpdateParams struct {
	Name string `json:"name,omitempty"`
	// Percent metrics are 0-100; failed_sign_ins is a count; sign_in_p95_seconds is seconds;
	// api_usage_spike is the ratio of a key or organization's request rate in the window to its
	// average hourly rate over the 7 days before (for example 10 = ten times its usual volume), and
	// min_sample is the fewest requ One of: sign_in_success_rate, failed_passkey_ratio,
	// failed_sign_ins, sign_in_p95_seconds, api_us...
	Metric string `json:"metric,omitempty"`
	// One of: lt, gt.
	Comparator string   `json:"comparator,omitempty"`
	Threshold  *float64 `json:"threshold,omitempty"`
	// Trailing window, 5 to 1440 (default 60).
	WindowMinutes *int64 `json:"window_minutes,omitempty"`
	// Ratios and latency are not evaluated on fewer observations (default 20).
	MinSample *int64 `json:"min_sample,omitempty"`
	// Minimum minutes between notifications while the rule stays firing (default 60).
	CooldownMinutes *int64   `json:"cooldown_minutes,omitempty"`
	EmailContacts   []string `json:"email_contacts,omitempty"`
	// A public HTTPS endpoint. The body is signed like any Atlas webhook; the signing secret is
	// returned once, on create.
	WebhookURL *string `json:"webhook_url,omitempty"`
	Enabled    *bool   `json:"enabled,omitempty"`
	// api_usage_spike only: watch secret keys, end-user API keys or organizations (null = all). One
	// of: api_key, end_user_api_key, organization, .
	SubjectType *string `json:"subject_type,omitempty"`
	// api_usage_spike only: watch one key or organization (needs subject_type).
	SubjectID *string `json:"subject_id,omitempty"`
	// Also raise a Shared Signals event (an opaque subject naming the key or organization) on every
	// enabled stream that asks for it.
	SSF *bool `json:"ssf,omitempty"`
}

// AnalyticsAPIUsageResult is a typed model of the Backend API.
type AnalyticsAPIUsageResult struct {
	Object        string                            `json:"object"`
	WindowMinutes int64                             `json:"window_minutes"`
	BaselineHours int64                             `json:"baseline_hours"`
	GeneratedAt   int64                             `json:"generated_at"`
	Data          []AnalyticsAPIUsageResultDataItem `json:"data"`
}

// AnalyticsAPIUsageResultDataItem is a typed model of the Backend API.
type AnalyticsAPIUsageResultDataItem struct {
	// One of: api_key, end_user_api_key, organization.
	Type            string  `json:"type"`
	ID              string  `json:"id"`
	Current         int64   `json:"current"`
	CurrentPerHour  float64 `json:"current_per_hour"`
	BaselinePerHour float64 `json:"baseline_per_hour"`
	Ratio           float64 `json:"ratio"`
	ErrorRate       float64 `json:"error_rate"`
}

// AnalyticsBreakdownResult is a typed model of the Backend API.
type AnalyticsBreakdownResult struct {
	Object    string                             `json:"object"`
	Window    AnalyticsFunnelResultWindow        `json:"window"`
	Dimension string                             `json:"dimension"`
	Total     int64                              `json:"total"`
	Data      []AnalyticsBreakdownResultDataItem `json:"data"`
}

// AnalyticsBreakdownResultDataItem is a typed model of the Backend API.
type AnalyticsBreakdownResultDataItem struct {
	Value string  `json:"value"`
	Count int64   `json:"count"`
	Share float64 `json:"share"`
}

// AnalyticsFailuresResult is a typed model of the Backend API.
type AnalyticsFailuresResult struct {
	Object string                            `json:"object"`
	Window AnalyticsFunnelResultWindow       `json:"window"`
	Total  int64                             `json:"total"`
	Data   []AnalyticsFailuresResultDataItem `json:"data"`
}

// AnalyticsFailuresResultDataItem is a typed model of the Backend API.
type AnalyticsFailuresResultDataItem struct {
	Phase  string  `json:"phase"`
	Reason string  `json:"reason"`
	Method string  `json:"method"`
	Count  int64   `json:"count"`
	Share  float64 `json:"share"`
}

// AnalyticsFunnelResult is a typed model of the Backend API.
type AnalyticsFunnelResult struct {
	Object string                          `json:"object"`
	Window AnalyticsFunnelResultWindow     `json:"window"`
	Data   []AnalyticsFunnelResultDataItem `json:"data"`
}

// AnalyticsFunnelResultDataItem is a typed model of the Backend API.
type AnalyticsFunnelResultDataItem struct {
	Method                 string  `json:"method"`
	Started                int64   `json:"started"`
	Completed              int64   `json:"completed"`
	Abandoned              int64   `json:"abandoned"`
	InProgress             int64   `json:"in_progress"`
	NeedsFirstFactor       int64   `json:"needs_first_factor"`
	NeedsSecondFactor      int64   `json:"needs_second_factor"`
	NeedsEmailVerification int64   `json:"needs_email_verification"`
	CompletionRate         float64 `json:"completion_rate"`
}

// AnalyticsFunnelResultWindow is a typed model of the Backend API.
type AnalyticsFunnelResultWindow struct {
	From           int64   `json:"from"`
	To             int64   `json:"to"`
	Granularity    string  `json:"granularity"`
	OrganizationID *string `json:"organization_id"`
}

// AnalyticsJourneyFunnelResult is a typed model of the Backend API.
type AnalyticsJourneyFunnelResult struct {
	Object      string                                 `json:"object"`
	Window      AnalyticsFunnelResultWindow            `json:"window"`
	JourneyID   string                                 `json:"journey_id"`
	JourneyName string                                 `json:"journey_name"`
	Data        []AnalyticsJourneyFunnelResultDataItem `json:"data"`
}

// AnalyticsJourneyFunnelResultDataItem is a typed model of the Backend API.
type AnalyticsJourneyFunnelResultDataItem struct {
	Step           string  `json:"step"`
	Held           int64   `json:"held"`
	Completed      int64   `json:"completed"`
	Applied        int64   `json:"applied"`
	Denied         int64   `json:"denied"`
	CompletionRate float64 `json:"completion_rate"`
}

// AnalyticsPasskeyAdoptionResult is a typed model of the Backend API.
type AnalyticsPasskeyAdoptionResult struct {
	Object           string                                   `json:"object"`
	Window           AnalyticsFunnelResultWindow              `json:"window"`
	Users            int64                                    `json:"users"`
	UsersWithPasskey int64                                    `json:"users_with_passkey"`
	AdoptionRate     float64                                  `json:"adoption_rate"`
	Data             []AnalyticsPasskeyAdoptionResultDataItem `json:"data"`
}

// AnalyticsPasskeyAdoptionResultDataItem is a typed model of the Backend API.
type AnalyticsPasskeyAdoptionResultDataItem struct {
	Bucket         string  `json:"bucket"`
	PasskeySignIns int64   `json:"passkey_sign_ins"`
	SignIns        int64   `json:"sign_ins"`
	PasskeyShare   float64 `json:"passkey_share"`
}

// AnalyticsReportsAccessByAppResult is a typed model of the Backend API.
type AnalyticsReportsAccessByAppResult struct {
	Object string                                      `json:"object"`
	Window AnalyticsFunnelResultWindow                 `json:"window"`
	Data   []AnalyticsReportsAccessByAppResultDataItem `json:"data"`
}

// AnalyticsReportsAccessByAppResultDataItem is a typed model of the Backend API.
type AnalyticsReportsAccessByAppResultDataItem struct {
	ClientID      string `json:"client_id"`
	Name          string `json:"name"`
	Users         int64  `json:"users"`
	ActiveGrants  int64  `json:"active_grants"`
	UsersInWindow int64  `json:"users_in_window"`
}

// AnalyticsReportsInactiveUsersResult is a typed model of the Backend API.
type AnalyticsReportsInactiveUsersResult struct {
	Object       string                                        `json:"object"`
	Window       AnalyticsFunnelResultWindow                   `json:"window"`
	InactiveDays int64                                         `json:"inactive_days"`
	Cutoff       string                                        `json:"cutoff"`
	HasMore      bool                                          `json:"has_more"`
	NextCursor   *string                                       `json:"next_cursor"`
	Data         []AnalyticsReportsInactiveUsersResultDataItem `json:"data"`
}

// AnalyticsReportsInactiveUsersResultDataItem is a typed model of the Backend API.
type AnalyticsReportsInactiveUsersResultDataItem struct {
	UserID       string  `json:"user_id"`
	Email        *string `json:"email"`
	LastSignInAt *string `json:"last_sign_in_at"`
	CreatedAt    string  `json:"created_at"`
}

// AnalyticsReportsMFACoverageResult is a typed model of the Backend API.
type AnalyticsReportsMFACoverageResult struct {
	Object     string                                      `json:"object"`
	Window     AnalyticsFunnelResultWindow                 `json:"window"`
	TotalUsers int64                                       `json:"total_users"`
	Data       []AnalyticsReportsMFACoverageResultDataItem `json:"data"`
}

// AnalyticsReportsMFACoverageResultDataItem is a typed model of the Backend API.
type AnalyticsReportsMFACoverageResultDataItem struct {
	Protection string  `json:"protection"`
	Users      int64   `json:"users"`
	Share      float64 `json:"share"`
}

// AppCatalogInstalledResult is a typed model of the Backend API.
type AppCatalogInstalledResult struct {
	Object string                              `json:"object"`
	Data   []AppCatalogInstalledResultDataItem `json:"data"`
}

// AppCatalogInstalledResultDataItem is a typed model of the Backend API.
type AppCatalogInstalledResultDataItem struct {
	Object string `json:"object"`
	ID     string `json:"id"`
	// One of: saml, oidc.
	Protocol            string   `json:"protocol"`
	Name                string   `json:"name"`
	PresetID            *string  `json:"preset_id"`
	EntityID            *string  `json:"entity_id"`
	AcsURL              *string  `json:"acs_url"`
	ClientID            *string  `json:"client_id"`
	LaunchURL           *string  `json:"launch_url"`
	AllowedEmailDomains []string `json:"allowed_email_domains"`
	// Who may open the app. mode everyone (default) or assigned; with assigned, only the listed users,
	// members of the listed instance groups (id or slug, inherited), members of the listed
	// organizations or holders of the listed organization roles. allowed_email_domains applies on top.
	Assignment AppCatalogInstalledResultDataItemAssignment `json:"assignment"`
}

// AppCatalogInstalledResultDataItemAssignment is who may open the app. mode everyone (default) or
// assigned; with assigned, only the listed users, members of the listed instance groups (id or
// slug, inherited), members of the listed organizations or holders of the listed organization
// roles. allowed_email_domains applies on top.
type AppCatalogInstalledResultDataItemAssignment struct {
	// One of: everyone, assigned.
	Mode          string   `json:"mode"`
	UserIDs       []string `json:"user_ids"`
	Groups        []string `json:"groups"`
	Organizations []string `json:"organizations"`
	Roles         []string `json:"roles"`
}

// AppCatalogInstallParams is a typed model of the Backend API.
type AppCatalogInstallParams struct {
	// The preset's parameters (GET /v1/app_catalog lists them).
	Params map[string]string `json:"params,omitempty"`
	// 1-64 letters, digits, - or _. Defaults to the preset id.
	InstalledID         string   `json:"installed_id,omitempty"`
	Name                string   `json:"name,omitempty"`
	AllowedEmailDomains []string `json:"allowed_email_domains,omitempty"`
	// Who may open the app. mode everyone (default) or assigned; with assigned, only the listed users,
	// members of the listed instance groups (id or slug, inherited), members of the listed
	// organizations or holders of the listed organization roles. allowed_email_domains applies on top.
	Assignment *AppCatalogInstallParamsAssignment `json:"assignment,omitempty"`
}

// AppCatalogInstallParamsAssignment is who may open the app. mode everyone (default) or assigned;
// with assigned, only the listed users, members of the listed instance groups (id or slug,
// inherited), members of the listed organizations or holders of the listed organization roles.
// allowed_email_domains applies on top.
type AppCatalogInstallParamsAssignment struct {
	// One of: everyone, assigned.
	Mode          string   `json:"mode,omitempty"`
	UserIDs       []string `json:"user_ids,omitempty"`
	Groups        []string `json:"groups,omitempty"`
	Organizations []string `json:"organizations,omitempty"`
	Roles         []string `json:"roles,omitempty"`
}

// AppCatalogPresetsResult is a typed model of the Backend API.
type AppCatalogPresetsResult struct {
	Object string                            `json:"object"`
	Data   []AppCatalogPresetsResultDataItem `json:"data"`
}

// AppCatalogPresetsResultDataItem is a typed model of the Backend API.
type AppCatalogPresetsResultDataItem struct {
	Object string `json:"object"`
	ID     string `json:"id"`
	// One of: saml, oidc.
	Protocol   string `json:"protocol"`
	Name       string `json:"name"`
	Category   string `json:"category"`
	IconDomain string `json:"icon_domain"`
	// False: the values could not be confirmed in the vendor's SSO documentation; check them against
	// the app's SSO settings.
	Verified  bool                                        `json:"verified"`
	SourceURL *string                                     `json:"source_url"`
	Params    []AppCatalogPresetsResultDataItemParamsItem `json:"params"`
}

// AppCatalogPresetsResultDataItemParamsItem is a typed model of the Backend API.
type AppCatalogPresetsResultDataItemParamsItem struct {
	Key   string `json:"key"`
	Label string `json:"label"`
}

// AppCatalogUpdateParams is a typed model of the Backend API.
type AppCatalogUpdateParams struct {
	Name                string   `json:"name,omitempty"`
	AllowedEmailDomains []string `json:"allowed_email_domains,omitempty"`
	// Who may open the app. mode everyone (default) or assigned; with assigned, only the listed users,
	// members of the listed instance groups (id or slug, inherited), members of the listed
	// organizations or holders of the listed organization roles. allowed_email_domains applies on top.
	Assignment *AppCatalogInstallParamsAssignment `json:"assignment,omitempty"`
}

// AttackProtectionSetAppAttestationSecretParams is a typed model of the Backend API.
type AttackProtectionSetAppAttestationSecretParams struct {
	Secret string `json:"secret,omitempty"`
	// One of: play_integrity, devicecheck.
	Kind string `json:"kind,omitempty"`
}

// AuditEventSchemasListItem is a typed model of the Backend API.
type AuditEventSchemasListItem struct {
	Object      string  `json:"object"`
	ID          string  `json:"id"`
	Action      string  `json:"action"`
	Version     int64   `json:"version"`
	Description *string `json:"description"`
	// Allowed target.type values; empty = any.
	TargetTypes []string `json:"target_types"`
	// Allowed actor.type values; empty = any.
	ActorTypes []string `json:"actor_types"`
	// A JSON Schema the event metadata must satisfy (type, required, properties, additionalProperties,
	// enum, minimum/maximum, minLength/maxLength, pattern, format, items, minItems/maxItems).
	MetadataSchema map[string]interface{} `json:"metadata_schema"`
	// One of: active, deprecated.
	Status    string `json:"status"`
	CreatedAt int64  `json:"created_at"`
}

// AuditEventSchemasRedactionsItem is a typed model of the Backend API.
type AuditEventSchemasRedactionsItem struct {
	Object     string   `json:"object"`
	ID         string   `json:"id"`
	EventID    string   `json:"event_id"`
	Fields     []string `json:"fields"`
	Reason     string   `json:"reason"`
	RedactedBy *string  `json:"redacted_by"`
	CreatedAt  int64    `json:"created_at"`
}

// AuditEventSchemasRedactParams is a typed model of the Backend API.
type AuditEventSchemasRedactParams struct {
	Fields []string `json:"fields"`
	Reason string   `json:"reason"`
}

// AuditEventSchemasRedactResult is a typed model of the Backend API.
type AuditEventSchemasRedactResult struct {
	Object    string   `json:"object"`
	EventID   string   `json:"event_id"`
	Redacted  []string `json:"redacted"`
	Unchanged []string `json:"unchanged"`
	Reason    string   `json:"reason"`
}

// AuditEventSchemasRegisterParams is a typed model of the Backend API.
type AuditEventSchemasRegisterParams struct {
	// e.g. invoice.sent
	Action         string                 `json:"action"`
	Version        *int64                 `json:"version,omitempty"`
	Description    string                 `json:"description,omitempty"`
	TargetTypes    []string               `json:"target_types,omitempty"`
	ActorTypes     []string               `json:"actor_types,omitempty"`
	MetadataSchema map[string]interface{} `json:"metadata_schema,omitempty"`
}

// AuditEventSchemasUpdateParams is a typed model of the Backend API.
type AuditEventSchemasUpdateParams struct {
	Description *string `json:"description,omitempty"`
	// One of: active, deprecated.
	Status string `json:"status,omitempty"`
}

// AuthzDecisionsListItem is one logged authorization decision. `input` is redacted per the capture
// settings (null when capture is off).
type AuthzDecisionsListItem struct {
	Object string `json:"object"`
	ID     string `json:"id"`
	// One of: abac, authzen, fga, access_policy, mcp_gateway.
	Source string `json:"source"`
	// One of: allow, deny.
	Decision string `json:"decision"`
	// Who asked: `Type::id` (ABAC / AuthZEN), the FGA user, or the user id (access policies).
	Principal *string `json:"principal"`
	// The action, the FGA relation, or the access-policy stage.
	Action   *string `json:"action"`
	Resource *string `json:"resource"`
	// The request as kept by `input_mode`: identifiers only, or the whole request with the configured
	// paths blanked.
	Input map[string]interface{} `json:"input"`
	// Reasons (policy names), matched policies, error counts, FGA `allowed` and whether it was served
	// from cache.
	Result map[string]interface{} `json:"result"`
	// The signed-bundle revision in force when this was decided (`rev_…`); access-policy decisions
	// carry an `ap_…` digest instead.
	PolicyRevision *string `json:"policy_revision"`
	// The exact policy versions or FGA model that evaluated.
	PolicyVersion map[string]interface{} `json:"policy_version"`
	LatencyMs     float64                `json:"latency_ms"`
	// The probability this decision was kept at; divide counts by it to estimate the true volume.
	SampleRate float64 `json:"sample_rate"`
	ActorID    *string `json:"actor_id"`
	// Decided (epoch ms).
	CreatedAt int64 `json:"created_at"`
}

// AuthzDecisionsSettingsGetResult is a typed model of the Backend API.
type AuthzDecisionsSettingsGetResult struct {
	Object string `json:"object"`
	// Record decisions. Off by default.
	Enabled bool `json:"enabled"`
	// Probability an allow is recorded.
	SampleRateAllow float64 `json:"sample_rate_allow"`
	// Probability a deny is recorded.
	SampleRateDeny float64 `json:"sample_rate_deny"`
	// `ids` keeps only identifiers; `full` keeps the request minus the `redact` paths; `none` keeps no
	// input. One of: ids, full, none.
	InputMode string `json:"input_mode"`
	// Dotted paths blanked in `full` mode; `*` matches one segment (`context.ip`,
	// `principal.attributes.*`).
	Redact []string `json:"redact"`
	// Also emit each recorded decision as an `authz.decision` event, so log streams, webhooks and
	// event destinations receive it.
	ShipToEvents bool `json:"ship_to_events"`
	// Days to keep decisions; null keeps them.
	RetentionDays *int64 `json:"retention_days"`
}

// AuthzDecisionsSettingsUpdateParams is a typed model of the Backend API.
type AuthzDecisionsSettingsUpdateParams struct {
	Enabled         *bool    `json:"enabled,omitempty"`
	SampleRateAllow *float64 `json:"sample_rate_allow,omitempty"`
	SampleRateDeny  *float64 `json:"sample_rate_deny,omitempty"`
	// One of: ids, full, none.
	InputMode     string   `json:"input_mode,omitempty"`
	Redact        []string `json:"redact,omitempty"`
	ShipToEvents  *bool    `json:"ship_to_events,omitempty"`
	RetentionDays *int64   `json:"retention_days,omitempty"`
}

// AuthzDecisionsStatsResult is a typed model of the Backend API.
type AuthzDecisionsStatsResult struct {
	Object   string `json:"object"`
	Since    int64  `json:"since"`
	Until    int64  `json:"until"`
	Recorded int64  `json:"recorded"`
	// Recorded decisions scaled back up by their sample rates.
	EstimatedTotal int64                                             `json:"estimated_total"`
	BySource       map[string]AuthzDecisionsStatsResultBySourceValue `json:"by_source"`
	LatencyMs      AuthzDecisionsStatsResultLatencyMs                `json:"latency_ms"`
}

// AuthzDecisionsStatsResultBySourceValue is a typed model of the Backend API.
type AuthzDecisionsStatsResultBySourceValue struct {
	Allow          int64 `json:"allow"`
	Deny           int64 `json:"deny"`
	EstimatedAllow int64 `json:"estimated_allow"`
	EstimatedDeny  int64 `json:"estimated_deny"`
}

// AuthzDecisionsStatsResultLatencyMs is a typed model of the Backend API.
type AuthzDecisionsStatsResultLatencyMs struct {
	P50 *float64 `json:"p50"`
	P95 *float64 `json:"p95"`
	P99 *float64 `json:"p99"`
	Max *float64 `json:"max"`
}

// ConnectionsConnectParams is a typed model of the Backend API.
type ConnectionsConnectParams struct {
	// Where the owner lands after the provider returns. Must be an allowed origin of the instance.
	RedirectURL string `json:"redirect_url"`
	// Values that fill the provider's host templates for this one connection, for example
	// {"subdomain":"acme"} (Zendesk), {"shop":"acme"} (Shopify), {"domain":"acme.my.salesforce.com"}
	// (Salesforce My Domain), {"data_center":"eu"} (Zoho), {"tenant":"contoso.onmicrosoft.com"}
	// (Microsoft), {"host":"git.examp
	HostParams map[string]string `json:"host_params,omitempty"`
	// The provider environment the credential belongs to. sandbox selects the provider's test hosts
	// (Salesforce test.salesforce.com, PayPal and QuickBooks sandboxes, DocuSign demo...). One of:
	// production, sandbox.
	Environment interface{} `json:"environment,omitempty"`
	// Scopes to ask for on top of the provider defaults, the owner client's scopes and config.scopes.
	AdditionalScopes []string `json:"additional_scopes,omitempty"`
	LoginHint        string   `json:"login_hint,omitempty"`
	// popup completes through postMessage like a popup sign-in. One of: redirect, popup.
	Display interface{} `json:"display,omitempty"`
	// When the provider returns a different account than the one this connection already holds, create
	// a sibling connection for it instead of answering 409.
	CreateIfNew *bool `json:"create_if_new,omitempty"`
	// Informational: the user who is connecting (stored as authorized_by_user_id).
	ConnectUserID string `json:"connect_user_id,omitempty"`
}

// ConnectionsConnectResult is a typed model of the Backend API.
type ConnectionsConnectResult struct {
	Object       string `json:"object"`
	ConnectionID string `json:"connection_id"`
	// Send the owner here. The provider returns to Atlas, the tokens are stored on the connection, and
	// the owner lands on your redirect_url with `__atlas_status=connected` and `__atlas_connection=<id
	// of the connection that was written>`.
	AuthorizationURL string `json:"authorization_url"`
	AttemptID        string `json:"attempt_id"`
}

// ConnectionsCreateParams is a typed model of the Backend API.
type ConnectionsCreateParams struct {
	Owner ConnectionsCreateParamsOwner `json:"owner"`
	// One of: oauth, api_key, client_credentials, bearer, basic, custom_header, hmac_secret,
	// jwt_bearer, oauth1, github_app_installation, admin_consent.
	Kind interface{} `json:"kind"`
	// A built-in or custom OAuth provider key for oauth; any short key otherwise.
	Provider string `json:"provider"`
	Name     string `json:"name,omitempty"`
	// Hostnames, or *.example.com wildcards (1 to 20).
	AllowedHosts []string `json:"allowed_hosts"`
	// api_key: placement (header or query), name, scheme. custom_header: name. hmac_secret: algorithm,
	// encoding, signature_header, prefix, timestamp_header. client_credentials: token_url, client_id,
	// scopes, auth_style, grant_type, account_id, audience, resource, extra_params, request_format,
	// token_header.
	Config map[string]interface{} `json:"config,omitempty"`
	// Relay verbs allowed for this connection (default GET, HEAD, POST).
	AllowedMethods []interface{} `json:"allowed_methods,omitempty"`
	// The provider environment the credential belongs to. sandbox selects the provider's test hosts
	// (Salesforce test.salesforce.com, PayPal and QuickBooks sandboxes, DocuSign demo...). One of:
	// production, sandbox.
	Environment interface{} `json:"environment,omitempty"`
	// Values that fill the provider's host templates for this one connection, for example
	// {"subdomain":"acme"} (Zendesk), {"shop":"acme"} (Shopify), {"domain":"acme.my.salesforce.com"}
	// (Salesforce My Domain), {"data_center":"eu"} (Zoho), {"tenant":"contoso.onmicrosoft.com"}
	// (Microsoft), {"host":"git.examp
	HostParams map[string]string `json:"host_params,omitempty"`
	// Only data is accepted. A sign-in link is an external account.
	Purpose string `json:"purpose,omitempty"`
}

// ConnectionsCreateParamsOwner is a typed model of the Backend API.
type ConnectionsCreateParamsOwner struct {
	// One of: organization, user.
	Type interface{} `json:"type"`
	ID   string      `json:"id"`
}

// ConnectionsCreateResult is a typed model of the Backend API.
type ConnectionsCreateResult struct {
	Object string                       `json:"object"`
	ID     string                       `json:"id"`
	Owner  ConnectionsCreateParamsOwner `json:"owner"`
	// oauth, github_app_installation, admin_consent and a three-legged oauth1 are authorized by a
	// browser step; client_credentials and jwt_bearer mint tokens from a credential Atlas holds;
	// api_key, bearer, basic, custom_header and hmac_secret are typed secrets the owner enters. One
	// of: oauth, api_key, client_credentials, bearer, basic, custom_header, hmac_secret, jwt_bearer,
	// oauth1, github_app_instal...
	Kind     interface{} `json:"kind"`
	Provider string      `json:"provider"`
	// Your label for this account, for example "Support inbox".
	Name string `json:"name"`
	// The only hosts the relay may call with this connection.
	AllowedHosts []string `json:"allowed_hosts"`
	// Non-secret settings of the kind (api_key placement and name, token_url, client_id, scopes,
	// issuer, audience, public_jwk, signature_method, realm, installation_id, tenant...). Never a
	// secret.
	Config map[string]interface{} `json:"config"`
	// needs_reauth: the token expired or was refused and cannot be refreshed. revoked: disconnected on
	// purpose. One of: connected, needs_reauth, revoked, error, not_connected.
	Status interface{} `json:"status"`
	// A connection is never a sign-in method: connecting one adds no way to sign in, counts toward no
	// only-method rule and needs no step-up.
	Purpose string `json:"purpose"`
	// The provider environment the credential belongs to. sandbox selects the provider's test hosts
	// (Salesforce test.salesforce.com, PayPal and QuickBooks sandboxes, DocuSign demo...). One of:
	// production, sandbox.
	Environment interface{} `json:"environment"`
	// True when environment is sandbox.
	Sandbox bool `json:"sandbox"`
	// The provider-side account this connection covers (a QuickBooks realm, a Slack workspace, a
	// HubSpot hub, the authorizing user's id at the provider). Several connections of one provider
	// coexist by it; null until connected.
	ExternalID *string `json:"external_id"`
	// Values that fill the provider's host templates for this one connection, for example
	// {"subdomain":"acme"} (Zendesk), {"shop":"acme"} (Shopify), {"domain":"acme.my.salesforce.com"}
	// (Salesforce My Domain), {"data_center":"eu"} (Zoho), {"tenant":"contoso.onmicrosoft.com"}
	// (Microsoft), {"host":"git.examp
	HostParams map[string]string `json:"host_params"`
	// The owner OAuth client that issued the stored token, or null when the instance client did.
	OAuthClientID *string `json:"oauth_client_id"`
	// The scopes the provider granted.
	Scopes []string `json:"scopes"`
	// When the access token expires, epoch milliseconds. Refreshed automatically on read.
	ExpiresAt *int64 `json:"expires_at"`
	// Non-secret provider handles captured with the token (instance_url, realmId, hub_id, tenant_id,
	// team_id...).
	Metadata map[string]string `json:"metadata"`
	// Who connected it. Informational only: the connection does not depend on that user, who may be
	// deleted.
	AuthorizedByUserID *string `json:"authorized_by_user_id"`
	// Epoch milliseconds.
	ConnectedAt *int64 `json:"connected_at"`
	// Epoch milliseconds.
	LastRefreshedAt *int64 `json:"last_refreshed_at"`
	// Epoch milliseconds.
	StatusChangedAt *int64 `json:"status_changed_at"`
	// Why the connection left connected, or why the last refresh failed.
	LastError interface{} `json:"last_error"`
	// Consecutive failed refreshes; 0 when healthy. A provider outage is retried with backoff and
	// announced (connection.refresh_failed) after 3.
	RefreshFailures int64 `json:"refresh_failures"`
	// When the keep-alive worker next refreshes this connection (epoch milliseconds), null when there
	// is nothing to keep alive.
	NextRefreshAt *int64 `json:"next_refresh_at"`
	// Deprecated, always null: a connection owns its tokens and no longer rides a user's linked
	// account.
	ExternalAccountID interface{} `json:"external_account_id"`
	// Whether a credential is stored. The credential itself is never returned by this object.
	HasSecret bool `json:"has_secret"`
	// When the entered credential expires (epoch ms). connection.secret_expiring reminders go out 30,
	// 7 and 1 days before.
	SecretExpiresAt *int64 `json:"secret_expires_at"`
	// While a rotation's overlap window is open: when the replaced version stops being accepted (epoch
	// ms).
	PreviousValidUntil *int64 `json:"previous_valid_until"`
	// The relay verbs this connection may use. GET, HEAD and POST unless set.
	AllowedMethods []interface{} `json:"allowed_methods"`
	// When the connection was created (epoch ms).
	CreatedAt int64 `json:"created_at"`
	// When the connection last changed (epoch ms).
	UpdatedAt int64 `json:"updated_at"`
}

// ConnectionsExportConnectionsParams is a typed model of the Backend API.
type ConnectionsExportConnectionsParams struct {
	// One of: organization, user.
	OwnerType interface{} `json:"owner_type,omitempty"`
	OwnerID   string      `json:"owner_id,omitempty"`
	Provider  string      `json:"provider,omitempty"`
	// The provider environment the credential belongs to. sandbox selects the provider's test hosts
	// (Salesforce test.salesforce.com, PayPal and QuickBooks sandboxes, DocuSign demo...). One of:
	// production, sandbox.
	Environment interface{} `json:"environment,omitempty"`
	// One of: connected, needs_reauth, revoked, error, not_connected.
	Status         interface{} `json:"status,omitempty"`
	Limit          *int64      `json:"limit,omitempty"`
	StartingAfter  string      `json:"starting_after,omitempty"`
	IncludeSecrets *bool       `json:"include_secrets,omitempty"`
	// Required with include_secrets: a PUBLIC JWK. A key with private parameters is refused.
	RecipientPublicKey map[string]interface{} `json:"recipient_public_key,omitempty"`
}

// ConnectionsExportConnectionsResult is a typed model of the Backend API.
type ConnectionsExportConnectionsResult struct {
	Object string `json:"object"`
	// True when the tokens are included, sealed in `bundle`.
	Sealed     bool    `json:"sealed"`
	Count      int64   `json:"count"`
	HasMore    bool    `json:"has_more"`
	NextCursor *string `json:"next_cursor"`
	// Present when sealed is false.
	Connections []map[string]interface{} `json:"connections"`
	// The thumbprint of the key the bundle is sealed to.
	RecipientKeyID string `json:"recipient_key_id"`
	// Present when sealed is true: a compact JWE (RSA-OAEP-256 or ECDH-ES+A256KW with A256GCM) of
	// {version, exported_at, connections}.
	Bundle string `json:"bundle"`
}

// ConnectionsImportConnectionsParams is a typed model of the Backend API.
type ConnectionsImportConnectionsParams struct {
	Connections []ConnectionsImportConnectionsParamsConnectionsItem `json:"connections"`
	// Spend each refresh token against the provider and store what it issues.
	Validate *bool `json:"validate,omitempty"`
	DryRun   *bool `json:"dry_run,omitempty"`
}

// ConnectionsImportConnectionsParamsConnectionsItem is a typed model of the Backend API.
type ConnectionsImportConnectionsParamsConnectionsItem struct {
	Provider     string                       `json:"provider"`
	Owner        ConnectionsCreateParamsOwner `json:"owner"`
	ExternalID   string                       `json:"external_id"`
	RefreshToken string                       `json:"refresh_token,omitempty"`
	AccessToken  string                       `json:"access_token,omitempty"`
	// Epoch milliseconds or ISO 8601.
	ExpiresAt interface{}            `json:"expires_at,omitempty"`
	Scopes    []string               `json:"scopes,omitempty"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
	// The provider environment the credential belongs to. sandbox selects the provider's test hosts
	// (Salesforce test.salesforce.com, PayPal and QuickBooks sandboxes, DocuSign demo...). One of:
	// production, sandbox.
	Environment interface{} `json:"environment,omitempty"`
	// Values that fill the provider's host templates for this one connection, for example
	// {"subdomain":"acme"} (Zendesk), {"shop":"acme"} (Shopify), {"domain":"acme.my.salesforce.com"}
	// (Salesforce My Domain), {"data_center":"eu"} (Zoho), {"tenant":"contoso.onmicrosoft.com"}
	// (Microsoft), {"host":"git.examp
	HostParams   map[string]string `json:"host_params,omitempty"`
	Name         string            `json:"name,omitempty"`
	AllowedHosts []string          `json:"allowed_hosts,omitempty"`
}

// ConnectionsImportConnectionsResult is a typed model of the Backend API.
type ConnectionsImportConnectionsResult struct {
	Object string `json:"object"`
	Total  int64  `json:"total"`
	DryRun bool   `json:"dry_run"`
	// Whether refresh tokens were checked against the provider.
	Validated   bool                                         `json:"validated"`
	Created     int64                                        `json:"created"`
	Updated     int64                                        `json:"updated"`
	WouldCreate int64                                        `json:"would_create"`
	WouldUpdate int64                                        `json:"would_update"`
	Failed      int64                                        `json:"failed"`
	Data        []ConnectionsImportConnectionsResultDataItem `json:"data"`
}

// ConnectionsImportConnectionsResultDataItem is a typed model of the Backend API.
type ConnectionsImportConnectionsResultDataItem struct {
	Index int64 `json:"index"`
	// One of: created, updated, would_create, would_update, failed.
	Status       interface{} `json:"status"`
	ConnectionID *string     `json:"connection_id"`
	Validated    bool        `json:"validated"`
	Refreshed    bool        `json:"refreshed"`
	Error        interface{} `json:"error"`
}

// ConnectionsOauth1SignParams is a typed model of the Backend API.
type ConnectionsOauth1SignParams struct {
	// Default GET.
	Method string `json:"method,omitempty"`
	URL    string `json:"url"`
	// The request body, to sign when it is form-encoded.
	Body        string `json:"body,omitempty"`
	ContentType string `json:"content_type,omitempty"`
}

// ConnectionsOauth1SignResult is a typed model of the Backend API.
type ConnectionsOauth1SignResult struct {
	Object       string `json:"object"`
	ConnectionID string `json:"connection_id"`
	// The `Authorization: OAuth ...` header value to send. It is valid for this method, URL and body
	// only.
	Authorization string `json:"authorization"`
	Method        string `json:"method"`
	URL           string `json:"url"`
}

// ConnectionsOAuthClientsSetParams is a typed model of the Backend API.
type ConnectionsOAuthClientsSetParams struct {
	Owner    *ConnectionsCreateParamsOwner `json:"owner,omitempty"`
	Provider string                        `json:"provider"`
	// The provider environment the credential belongs to. sandbox selects the provider's test hosts
	// (Salesforce test.salesforce.com, PayPal and QuickBooks sandboxes, DocuSign demo...). One of:
	// production, sandbox.
	Environment interface{} `json:"environment,omitempty"`
	ClientID    string      `json:"client_id"`
	// Write-only. Required when the client is first created; omit it to keep the stored secret.
	ClientSecret string   `json:"client_secret,omitempty"`
	Scopes       []string `json:"scopes,omitempty"`
	// Values that fill the provider's host templates for this one connection, for example
	// {"subdomain":"acme"} (Zendesk), {"shop":"acme"} (Shopify), {"domain":"acme.my.salesforce.com"}
	// (Salesforce My Domain), {"data_center":"eu"} (Zoho), {"tenant":"contoso.onmicrosoft.com"}
	// (Microsoft), {"host":"git.examp
	HostParams map[string]string `json:"host_params,omitempty"`
	Enabled    *bool             `json:"enabled,omitempty"`
}

// ConnectionsOAuthClientsSetResult is a typed model of the Backend API.
type ConnectionsOAuthClientsSetResult struct {
	Object   string                       `json:"object"`
	ID       string                       `json:"id"`
	Owner    ConnectionsCreateParamsOwner `json:"owner"`
	Provider string                       `json:"provider"`
	// The provider environment the credential belongs to. sandbox selects the provider's test hosts
	// (Salesforce test.salesforce.com, PayPal and QuickBooks sandboxes, DocuSign demo...). One of:
	// production, sandbox.
	Environment interface{} `json:"environment"`
	ClientID    string      `json:"client_id"`
	// The client secret is write-only; it is sealed in the vault and never returned.
	HasSecret bool     `json:"has_secret"`
	Scopes    []string `json:"scopes"`
	// Values that fill the provider's host templates for this one connection, for example
	// {"subdomain":"acme"} (Zendesk), {"shop":"acme"} (Shopify), {"domain":"acme.my.salesforce.com"}
	// (Salesforce My Domain), {"data_center":"eu"} (Zoho), {"tenant":"contoso.onmicrosoft.com"}
	// (Microsoft), {"host":"git.examp
	HostParams map[string]string `json:"host_params"`
	Enabled    bool              `json:"enabled"`
	// The redirect URI to register on this client at the provider.
	CallbackURL string `json:"callback_url"`
	// When the client was added (epoch ms).
	CreatedAt int64 `json:"created_at"`
	// When the client last changed (epoch ms).
	UpdatedAt int64 `json:"updated_at"`
}

// ConnectionsRefreshTokenParams is a typed model of the Backend API.
type ConnectionsRefreshTokenParams struct {
	// Why you are refreshing; recorded in the audit log. One of: provider_401, expired, manual.
	Reason interface{} `json:"reason,omitempty"`
	// SHA-256 (hex) of the access token the provider refused.
	StaleTokenHash string `json:"stale_token_hash,omitempty"`
}

// ConnectionsRelayParams is a typed model of the Backend API.
type ConnectionsRelayParams struct {
	// Must be in the connection's allowed_methods. One of: GET, HEAD, POST, PUT, PATCH, DELETE.
	Method string `json:"method,omitempty"`
	// Absolute https URL on an allowed host.
	URL string `json:"url"`
	// Extra request headers. Authorization, Cookie and Host cannot be set.
	Headers map[string]string `json:"headers,omitempty"`
	// POST, PUT, PATCH or DELETE: a string, or an object sent as JSON (up to 256 KiB).
	Body interface{} `json:"body,omitempty"`
	// Where the provider returns after authorizing, to receive meta.authorize_url on a 402.
	RedirectURL string `json:"redirect_url,omitempty"`
	// The user the authorization link is for (organization-owned connections).
	ConnectUserID string `json:"connect_user_id,omitempty"`
}

// ConnectionsRelayResult is a typed model of the Backend API.
type ConnectionsRelayResult struct {
	Object       string `json:"object"`
	ConnectionID string `json:"connection_id"`
	// The provider's HTTP status.
	Status int64 `json:"status"`
	// A small allow-list of response headers (content-type, etag, retry-after, link and a few more).
	Headers map[string]string `json:"headers"`
	// The provider's response body as text (up to 1 MiB).
	Body      string `json:"body"`
	Truncated bool   `json:"truncated"`
}

// ConnectionsRotateCredentialsParams is the new credential fields of the connection's kind, plus
// overlap_seconds and expires_at.
type ConnectionsRotateCredentialsParams struct {
	OverlapSeconds *int64 `json:"overlap_seconds,omitempty"`
	// Epoch milliseconds or an ISO date.
	ExpiresAt interface{} `json:"expires_at,omitempty"`
}

// ConnectionsSecretVersionsResult is a typed model of the Backend API.
type ConnectionsSecretVersionsResult struct {
	Object string                                    `json:"object"`
	Data   []ConnectionsSecretVersionsResultDataItem `json:"data"`
	// Whether another page follows the cursor.
	HasMore bool `json:"has_more"`
	// The cursor to pass as `starting_after` for the next page on a keyset-paginated list; null on the
	// last page (and absent on lists that are not cursor-paginated).
	NextCursor         *string `json:"next_cursor"`
	ConnectionID       string  `json:"connection_id"`
	CurrentVersion     *int64  `json:"current_version"`
	PreviousValidUntil *int64  `json:"previous_valid_until"`
}

// ConnectionsSecretVersionsResultDataItem is a typed model of the Backend API.
type ConnectionsSecretVersionsResultDataItem struct {
	Object  string `json:"object"`
	Version int64  `json:"version"`
	Current bool   `json:"current"`
	// True for the replaced version while a rotation's overlap window is open.
	Previous bool `json:"previous"`
	// When this version was written (epoch ms).
	CreatedAt int64 `json:"created_at"`
	// For the previous version: when it stops being accepted, epoch ms.
	ValidUntil *int64 `json:"valid_until"`
}

// ConnectionsSetCredentialsParams is the fields of the connection's kind. Write-only: stored in
// the vault (the tenant's own KMS key when one is set) and never returned. The kind's non-secret
// settings (see config on POST /v1/connections: preset, issuer, subject, audience, auth_style,
// grant_type, account_id, mode, signature_method, realm
type ConnectionsSetCredentialsParams struct {
	// api_key.
	APIKey string `json:"api_key,omitempty"`
	// bearer; or the token of a tba/three-legged oauth1 credential.
	Token string `json:"token,omitempty"`
	// basic (no colon).
	Username string `json:"username,omitempty"`
	// basic.
	Password string `json:"password,omitempty"`
	// custom_header.
	Value string `json:"value,omitempty"`
	// hmac_secret.
	Secret string `json:"secret,omitempty"`
	// client_credentials, or the app client id of a jwt_bearer with Basic client authentication.
	ClientID string `json:"client_id,omitempty"`
	// client_credentials / jwt_bearer client authentication.
	ClientSecret string `json:"client_secret,omitempty"`
	// https token endpoint (client_credentials, jwt_bearer); `{name}` placeholders are filled from
	// host_params.
	TokenURL string   `json:"token_url,omitempty"`
	Scopes   []string `json:"scopes,omitempty"`
	// jwt_bearer / github_app_installation: a PEM private key (RSA or P-256). Held in the vault; never
	// returned.
	PrivateKey string `json:"private_key,omitempty"`
	// jwt_bearer: have Atlas generate the key pair; the public JWK is returned in config.public_jwk
	// for you to register at the provider.
	GenerateKey *bool `json:"generate_key,omitempty"`
	// jwt_bearer: a Google service-account JSON key (a string or the parsed object).
	ServiceAccountJSON interface{} `json:"service_account_json,omitempty"`
	// jwt_bearer with a provider-issued JWT credential (RingCentral).
	Assertion string `json:"assertion,omitempty"`
	// oauth1.
	ConsumerKey string `json:"consumer_key,omitempty"`
	// oauth1.
	ConsumerSecret string `json:"consumer_secret,omitempty"`
	// oauth1.
	TokenSecret string `json:"token_secret,omitempty"`
	// Non-secret settings to merge (same keys as the connection config).
	Config map[string]interface{} `json:"config,omitempty"`
	// When this credential expires: epoch milliseconds or an ISO date. Reminders are sent at 30, 7 and
	// 1 days before.
	ExpiresAt interface{} `json:"expires_at,omitempty"`
}

// ConnectionsTokenResult is a typed model of the Backend API.
type ConnectionsTokenResult struct {
	Object       string `json:"object"`
	ConnectionID string `json:"connection_id"`
	// A live access token (refreshed first when it was expired or about to be).
	AccessToken string `json:"access_token"`
	// Epoch milliseconds, null when the provider did not say.
	ExpiresAt *int64   `json:"expires_at"`
	Scopes    []string `json:"scopes"`
	// Non-secret provider handles (instance_url, realmId, hub_id, team_id, cloud_id, tenant_id...).
	Metadata map[string]string `json:"metadata"`
	// The provider's token response without secret fields, plus fields looked up after the exchange
	// (Xero `tenants`, Atlassian `accessible_resources`).
	TokenResponse map[string]interface{} `json:"token_response"`
	// Further credentials held by the same connection, by name. Slack: `user` is the installing user's
	// token next to the bot token in `access_token`.
	Credentials map[string]ConnectionsTokenResultCredentialsValue `json:"credentials"`
	ExternalID  *string                                           `json:"external_id"`
	// The provider environment the credential belongs to. sandbox selects the provider's test hosts
	// (Salesforce test.salesforce.com, PayPal and QuickBooks sandboxes, DocuSign demo...). One of:
	// production, sandbox.
	Environment interface{} `json:"environment"`
	// Values that fill the provider's host templates for this one connection, for example
	// {"subdomain":"acme"} (Zendesk), {"shop":"acme"} (Shopify), {"domain":"acme.my.salesforce.com"}
	// (Salesforce My Domain), {"data_center":"eu"} (Zoho), {"tenant":"contoso.onmicrosoft.com"}
	// (Microsoft), {"host":"git.examp
	HostParams map[string]string `json:"host_params"`
	// True when this read refreshed (or minted) the token.
	Refreshed bool `json:"refreshed"`
	// jwt_bearer: the user the token acts as (domain-wide delegation), when one was asked for.
	Subject string `json:"subject"`
}

// ConnectionsTokenResultCredentialsValue is a typed model of the Backend API.
type ConnectionsTokenResultCredentialsValue struct {
	AccessToken string   `json:"access_token"`
	ExpiresAt   *int64   `json:"expires_at"`
	Scopes      []string `json:"scopes"`
}

// ConnectionsTokensItem is a typed model of the Backend API.
type ConnectionsTokensItem struct {
	ID string `json:"id"`
	// One of: ok, error.
	Status interface{} `json:"status"`
	// Present when status is ok: the same body as GET /v1/connections/{id}/token.
	Token ConnectionsTokenResult     `json:"token"`
	Error ConnectionsTokensItemError `json:"error"`
}

// ConnectionsTokensItemError is a typed model of the Backend API.
type ConnectionsTokensItemError struct {
	// One of: connection_required, not_found.
	Code interface{} `json:"code"`
	// One of: not_connected, needs_reauth, revoked, refresh_failed, unknown_connection.
	Reason interface{} `json:"reason"`
}

// ConnectionsTokensParams is a typed model of the Backend API.
type ConnectionsTokensParams struct {
	// Connection ids (duplicates are read once).
	IDs           []string `json:"ids"`
	MinTTLSeconds *int64   `json:"min_ttl_seconds,omitempty"`
}

// ConnectionsUpdateParams is a typed model of the Backend API.
type ConnectionsUpdateParams struct {
	Name           string                 `json:"name,omitempty"`
	AllowedHosts   []string               `json:"allowed_hosts,omitempty"`
	Config         map[string]interface{} `json:"config,omitempty"`
	SharedByUserID string                 `json:"shared_by_user_id,omitempty"`
	// Transfer the connection to another organization or user of this instance. Its tokens move with
	// it; nobody reconnects.
	Owner *ConnectionsCreateParamsOwner `json:"owner,omitempty"`
	// The provider environment the credential belongs to. sandbox selects the provider's test hosts
	// (Salesforce test.salesforce.com, PayPal and QuickBooks sandboxes, DocuSign demo...). One of:
	// production, sandbox.
	Environment interface{} `json:"environment,omitempty"`
	// Values that fill the provider's host templates for this one connection, for example
	// {"subdomain":"acme"} (Zendesk), {"shop":"acme"} (Shopify), {"domain":"acme.my.salesforce.com"}
	// (Salesforce My Domain), {"data_center":"eu"} (Zoho), {"tenant":"contoso.onmicrosoft.com"}
	// (Microsoft), {"host":"git.examp
	HostParams     map[string]string `json:"host_params,omitempty"`
	AllowedMethods []interface{}     `json:"allowed_methods,omitempty"`
}

// ConnectionsWebhooksCreateEndpointParams is a typed model of the Backend API.
type ConnectionsWebhooksCreateEndpointParams struct {
	// One of: hubspot_v3, shopify_hmac, intercom, zoom, slack_v0, calendly, stripe,
	// generic_hmac_sha256.
	Scheme interface{} `json:"scheme"`
	// https URL that receives verified deliveries as Atlas-signed webhooks.
	ForwardURL string `json:"forward_url"`
	// Write-only. The provider's signing secret for this endpoint (Slack signing secret, Zoom secret
	// token, Calendly signing key...). Without it, the connection's hmac_secret credential or its
	// OAuth client secret is used.
	SigningSecret string `json:"signing_secret,omitempty"`
	// generic_hmac_sha256 only: signature_header, encoding (hex or base64), prefix, algorithm.
	Options map[string]string `json:"options,omitempty"`
	Enabled *bool             `json:"enabled,omitempty"`
}

// ConnectionsWebhooksCreateEndpointResult is a typed model of the Backend API.
type ConnectionsWebhooksCreateEndpointResult struct {
	Object       string `json:"object"`
	ID           string `json:"id"`
	ConnectionID string `json:"connection_id"`
	// One of: hubspot_v3, shopify_hmac, intercom, zoom, slack_v0, calendly, stripe,
	// generic_hmac_sha256.
	Scheme     interface{} `json:"scheme"`
	ForwardURL string      `json:"forward_url"`
	// Give this URL to the provider as the webhook target.
	IngressURL string            `json:"ingress_url"`
	Options    map[string]string `json:"options"`
	// Whether the endpoint has its own provider signing secret (never returned).
	HasSigningSecret bool   `json:"has_signing_secret"`
	Enabled          bool   `json:"enabled"`
	LastDeliveryAt   *int64 `json:"last_delivery_at"`
	// When the endpoint was created (epoch ms).
	CreatedAt int64 `json:"created_at"`
	// When the endpoint last changed (epoch ms).
	UpdatedAt int64 `json:"updated_at"`
	// Only in the create response, once: verifies the Atlas-signed deliveries sent to forward_url
	// (atlas-signature, as for any Atlas webhook).
	ForwardSecret string `json:"forward_secret"`
}

// ConnectionsWebhooksUpdateEndpointParams is a typed model of the Backend API.
type ConnectionsWebhooksUpdateEndpointParams struct {
	// One of: hubspot_v3, shopify_hmac, intercom, zoom, slack_v0, calendly, stripe,
	// generic_hmac_sha256.
	Scheme interface{} `json:"scheme,omitempty"`
	// https URL that receives verified deliveries as Atlas-signed webhooks.
	ForwardURL string `json:"forward_url,omitempty"`
	// Write-only. The provider's signing secret for this endpoint (Slack signing secret, Zoom secret
	// token, Calendly signing key...). Without it, the connection's hmac_secret credential or its
	// OAuth client secret is used.
	SigningSecret string `json:"signing_secret,omitempty"`
	// generic_hmac_sha256 only: signature_header, encoding (hex or base64), prefix, algorithm.
	Options map[string]string `json:"options,omitempty"`
	Enabled *bool             `json:"enabled,omitempty"`
}

// ConnectionsWebhooksVerifyParams is a typed model of the Backend API.
type ConnectionsWebhooksVerifyParams struct {
	// One of: hubspot_v3, shopify_hmac, intercom, zoom, slack_v0, calendly, stripe,
	// generic_hmac_sha256.
	Scheme interface{} `json:"scheme"`
	// The delivery's headers.
	Headers map[string]string `json:"headers"`
	// The body exactly as received (up to 1 MiB).
	RawBody string `json:"raw_body"`
	// One of: utf8, base64.
	RawBodyEncoding interface{} `json:"raw_body_encoding,omitempty"`
	// hubspot_v3: the HTTP method of the delivery (default POST).
	Method string `json:"method,omitempty"`
	// hubspot_v3: the full URL the provider posted to.
	URL string `json:"url,omitempty"`
	// Use this webhook endpoint's signing secret and options.
	EndpointID       string `json:"endpoint_id,omitempty"`
	ToleranceSeconds *int64 `json:"tolerance_seconds,omitempty"`
	// generic_hmac_sha256: signature_header, encoding, prefix, algorithm.
	Options map[string]string `json:"options,omitempty"`
	// Set false to check without remembering the delivery (default true).
	RecordReplay *bool `json:"record_replay,omitempty"`
}

// ConnectionsWebhooksVerifyResult is a typed model of the Backend API.
type ConnectionsWebhooksVerifyResult struct {
	Object       string `json:"object"`
	ConnectionID string `json:"connection_id"`
	// One of: hubspot_v3, shopify_hmac, intercom, zoom, slack_v0, calendly, stripe,
	// generic_hmac_sha256.
	Scheme interface{} `json:"scheme"`
	// True only for a genuine, fresh, first-time delivery.
	Valid bool `json:"valid"`
	// One of: missing_signature, missing_timestamp, malformed_signature, stale_timestamp,
	// bad_signature, url_required, replayed, .
	Reason *string `json:"reason"`
	// The same delivery id (or signature) verified before on this connection.
	Replayed bool `json:"replayed"`
	// The signed timestamp, epoch seconds, for schemes that sign one.
	Timestamp *int64 `json:"timestamp"`
	// The provider's delivery id when the scheme carries one (Shopify).
	DeliveryID *string `json:"delivery_id"`
	// Zoom endpoint.url_validation ({plainToken, encryptedToken}) or Slack url_verification
	// ({challenge}): answer the provider with this body.
	Handshake map[string]string `json:"handshake"`
}

// DeliveryHealthGetResult is a typed model of the Backend API.
type DeliveryHealthGetResult struct {
	Object string `json:"object"`
	// One of: webhook_endpoint, referral_connection, backchannel_receiver, integration.
	Kind     string  `json:"kind"`
	TargetID string  `json:"target_id"`
	URL      *string `json:"url"`
	Label    *string `json:"label"`
	// One of: healthy, failing, disabled.
	State               string                 `json:"state"`
	FailingSince        *int64                 `json:"failing_since"`
	DisabledAt          *int64                 `json:"disabled_at"`
	LastSuccessAt       *int64                 `json:"last_success_at"`
	LastFailure         map[string]interface{} `json:"last_failure"`
	ConsecutiveFailures int64                  `json:"consecutive_failures"`
	SuccessRate24h      *float64               `json:"success_rate_24h"`
	Attempts24h         map[string]interface{} `json:"attempts_24h"`
	AlertContacts       []string               `json:"alert_contacts"`
	Alerts              map[string]interface{} `json:"alerts"`
}

// DesktopMFACreateEnrolmentCodeParams is a typed model of the Backend API.
type DesktopMFACreateEnrolmentCodeParams struct {
	UserID           string   `json:"user_id,omitempty"`
	ExpiresInMinutes *float64 `json:"expires_in_minutes,omitempty"`
}

// DesktopMFACreateEnrolmentCodeResult is a typed model of the Backend API.
type DesktopMFACreateEnrolmentCodeResult struct {
	Object string `json:"object"`
	// Shown once. Single use.
	Code string `json:"code"`
	// Expires (epoch ms).
	ExpiresAt int64  `json:"expires_at"`
	UserID    string `json:"user_id"`
}

// DesktopMFAGetDeviceResult is a typed model of the Backend API.
type DesktopMFAGetDeviceResult struct {
	Object string `json:"object"`
	ID     string `json:"id"`
	UserID string `json:"user_id"`
	// The device key the workstation signs with.
	DeviceKeyID string  `json:"device_key_id"`
	Hostname    *string `json:"hostname"`
	// One of: windows, macos, linux.
	Platform     string  `json:"platform"`
	AgentVersion *string `json:"agent_version"`
	// One of: active, revoked.
	Status        string `json:"status"`
	OfflinePinSet bool   `json:"offline_pin_set"`
	// Raised to void every offline verifier issued so far.
	BundleGeneration int64 `json:"bundle_generation"`
	// Last authenticated call (epoch ms).
	LastSeenAt *int64 `json:"last_seen_at"`
	RevokedAt  *int64 `json:"revoked_at"`
	// Enrolled (epoch ms).
	CreatedAt int64 `json:"created_at"`
	// The most recent offline verifiers issued to the workstation.
	OfflineBundles []DesktopMFAGetDeviceResultOfflineBundlesItem `json:"offline_bundles"`
}

// DesktopMFAGetDeviceResultOfflineBundlesItem is a typed model of the Backend API.
type DesktopMFAGetDeviceResultOfflineBundlesItem struct {
	ID         string `json:"id"`
	Generation int64  `json:"generation"`
	// Issued (epoch ms).
	IssuedAt int64 `json:"issued_at"`
	// Expires (epoch ms).
	ExpiresAt int64  `json:"expires_at"`
	RevokedAt *int64 `json:"revoked_at"`
}

// DesktopMFAGetPolicyResult is a typed model of the Backend API.
type DesktopMFAGetPolicyResult struct {
	Object string `json:"object"`
	// Workstation agents ask for a second factor at OS login.
	Enabled bool `json:"enabled"`
	// `selected` limits it to `user_ids` and members of `org_ids`. One of: all, selected.
	AppliesTo string   `json:"applies_to"`
	UserIDs   []string `json:"user_ids"`
	OrgIDs    []string `json:"org_ids"`
	// Factors an agent may start: push (with number matching), totp, passkey.
	AllowedFactors []string `json:"allowed_factors"`
	// Agents may cache a sealed offline verifier and unlock without reaching Atlas.
	OfflineEnabled bool `json:"offline_enabled"`
	// How long a cached verifier stays usable without a refresh.
	OfflineGraceHours int64 `json:"offline_grace_hours"`
	// Offline unlock needs the user's PIN as well as the one-time code.
	OfflinePinRequired bool `json:"offline_pin_required"`
}

// DesktopMFAListDevicesItem is a typed model of the Backend API.
type DesktopMFAListDevicesItem struct {
	Object string `json:"object"`
	ID     string `json:"id"`
	UserID string `json:"user_id"`
	// The device key the workstation signs with.
	DeviceKeyID string  `json:"device_key_id"`
	Hostname    *string `json:"hostname"`
	// One of: windows, macos, linux.
	Platform     string  `json:"platform"`
	AgentVersion *string `json:"agent_version"`
	// One of: active, revoked.
	Status        string `json:"status"`
	OfflinePinSet bool   `json:"offline_pin_set"`
	// Raised to void every offline verifier issued so far.
	BundleGeneration int64 `json:"bundle_generation"`
	// Last authenticated call (epoch ms).
	LastSeenAt *int64 `json:"last_seen_at"`
	RevokedAt  *int64 `json:"revoked_at"`
	// Enrolled (epoch ms).
	CreatedAt int64 `json:"created_at"`
}

// DesktopMFAUpdatePolicyParams is a typed model of the Backend API.
type DesktopMFAUpdatePolicyParams struct {
	Enabled            *bool    `json:"enabled,omitempty"`
	AppliesTo          string   `json:"applies_to,omitempty"`
	UserIDs            []string `json:"user_ids,omitempty"`
	OrgIDs             []string `json:"org_ids,omitempty"`
	AllowedFactors     []string `json:"allowed_factors,omitempty"`
	OfflineEnabled     *bool    `json:"offline_enabled,omitempty"`
	OfflineGraceHours  *float64 `json:"offline_grace_hours,omitempty"`
	OfflinePinRequired *bool    `json:"offline_pin_required,omitempty"`
}

// DevicesIngestPostureParams is a typed model of the Backend API.
type DevicesIngestPostureParams struct {
	Devices []map[string]interface{} `json:"devices,omitempty"`
}

// DevicesListItem is a typed model of the Backend API.
type DevicesListItem struct {
	Object     string                 `json:"object"`
	ID         string                 `json:"id"`
	UserID     *string                `json:"user_id"`
	Source     string                 `json:"source"`
	ExternalID string                 `json:"external_id"`
	Name       *string                `json:"name"`
	Platform   *string                `json:"platform"`
	Managed    bool                   `json:"managed"`
	Compliant  bool                   `json:"compliant"`
	Posture    map[string]interface{} `json:"posture"`
	// Last posture report (epoch ms).
	LastReportedAt int64 `json:"last_reported_at"`
	// Created (epoch ms).
	CreatedAt int64 `json:"created_at"`
}

// DevicesReportParams is a typed model of the Backend API.
type DevicesReportParams struct {
	ExternalID string                 `json:"external_id,omitempty"`
	Source     string                 `json:"source,omitempty"`
	UserID     *string                `json:"user_id,omitempty"`
	UserEmail  string                 `json:"user_email,omitempty"`
	Name       *string                `json:"name,omitempty"`
	Platform   *string                `json:"platform,omitempty"`
	Managed    *bool                  `json:"managed,omitempty"`
	Compliant  *bool                  `json:"compliant,omitempty"`
	Posture    map[string]interface{} `json:"posture,omitempty"`
}

// DirectoryPullSourcesCreateParams is a typed model of the Backend API.
type DirectoryPullSourcesCreateParams struct {
	OrganizationID string `json:"organization_id"`
	Name           string `json:"name"`
	// One of: entra, google_workspace, bamboohr, hibob, personio, csv, rest_json.
	Provider string `json:"provider"`
	// One of: active, paused.
	Status string                 `json:"status,omitempty"`
	Config map[string]interface{} `json:"config,omitempty"`
	// Write-only.
	Credentials   map[string]interface{} `json:"credentials,omitempty"`
	DefaultRoleID *string                `json:"default_role_id,omitempty"`
	// Schedule, role mappings and disable-on-removal.
	Settings map[string]interface{} `json:"settings,omitempty"`
}

// DirectoryPullSourcesListResult is a typed model of the Backend API.
type DirectoryPullSourcesListResult struct {
	Object  string                                   `json:"object"`
	Data    []DirectoryPullSourcesListResultDataItem `json:"data"`
	HasMore bool                                     `json:"has_more"`
}

// DirectoryPullSourcesListResultDataItem is a typed model of the Backend API.
type DirectoryPullSourcesListResultDataItem struct {
	Object         string `json:"object"`
	ID             string `json:"id"`
	OrganizationID string `json:"organization_id"`
	Name           string `json:"name"`
	// One of: entra, google_workspace, bamboohr, hibob, personio, csv, rest_json.
	Provider string `json:"provider"`
	// One of: active, paused.
	Status         string                 `json:"status"`
	Config         map[string]interface{} `json:"config"`
	Settings       map[string]interface{} `json:"settings"`
	DefaultRoleID  *string                `json:"default_role_id"`
	HasCredentials bool                   `json:"has_credentials"`
	HasUploadedCSV bool                   `json:"has_uploaded_csv"`
	NextSyncAt     *int64                 `json:"next_sync_at"`
	CreatedAt      int64                  `json:"created_at"`
	UpdatedAt      int64                  `json:"updated_at"`
}

// DirectoryPullSourcesSetCSVParams is a typed model of the Backend API.
type DirectoryPullSourcesSetCSVParams struct {
	CSV string `json:"csv,omitempty"`
}

// DirectoryPullSourcesSyncRunsCreateResult is a typed model of the Backend API.
type DirectoryPullSourcesSyncRunsCreateResult struct {
	Object         string                 `json:"object"`
	ID             string                 `json:"id"`
	SourceID       string                 `json:"source_id"`
	OrganizationID string                 `json:"organization_id"`
	Trigger        string                 `json:"trigger"`
	Status         string                 `json:"status"`
	Stats          map[string]interface{} `json:"stats"`
	Error          *string                `json:"error"`
	CreatedAt      int64                  `json:"created_at"`
	StartedAt      *int64                 `json:"started_at"`
	FinishedAt     *int64                 `json:"finished_at"`
}

// DirectoryPullSourcesSyncRunsListResult is a typed model of the Backend API.
type DirectoryPullSourcesSyncRunsListResult struct {
	Object  string                                     `json:"object"`
	Data    []DirectoryPullSourcesSyncRunsCreateResult `json:"data"`
	HasMore bool                                       `json:"has_more"`
}

// DirectoryPullSourcesUpdateParams is a typed model of the Backend API.
type DirectoryPullSourcesUpdateParams struct {
	OrganizationID string `json:"organization_id,omitempty"`
	Name           string `json:"name,omitempty"`
	// One of: entra, google_workspace, bamboohr, hibob, personio, csv, rest_json.
	Provider string `json:"provider,omitempty"`
	// One of: active, paused.
	Status string                 `json:"status,omitempty"`
	Config map[string]interface{} `json:"config,omitempty"`
	// Write-only.
	Credentials   map[string]interface{} `json:"credentials,omitempty"`
	DefaultRoleID *string                `json:"default_role_id,omitempty"`
	// Schedule, role mappings and disable-on-removal.
	Settings map[string]interface{} `json:"settings,omitempty"`
}

// FGAListUsersParams is a typed model of the Backend API.
type FGAListUsersParams struct {
	Object               interface{}                         `json:"object,omitempty"`
	Relation             string                              `json:"relation,omitempty"`
	UserFilters          []FGAListUsersParamsUserFiltersItem `json:"user_filters,omitempty"`
	AuthorizationModelID string                              `json:"authorization_model_id,omitempty"`
	ContextualTuples     interface{}                         `json:"contextual_tuples,omitempty"`
	Context              map[string]interface{}              `json:"context,omitempty"`
	PageSize             *int64                              `json:"page_size,omitempty"`
	ContinuationToken    string                              `json:"continuation_token,omitempty"`
	// One of: UNSPECIFIED, MINIMIZE_LATENCY, HIGHER_CONSISTENCY.
	Consistency      string `json:"consistency,omitempty"`
	ConsistencyToken string `json:"consistency_token,omitempty"`
}

// FGAListUsersParamsUserFiltersItem is a typed model of the Backend API.
type FGAListUsersParamsUserFiltersItem struct {
	Type     string `json:"type"`
	Relation string `json:"relation,omitempty"`
}

// FGAListUsersResult is a typed model of the Backend API.
type FGAListUsersResult struct {
	Object string `json:"object"`
	// Members as `type:id`, `type:id#relation` (relation filter), or `type:*` for a public wildcard.
	Users []string `json:"users"`
	// Users a wildcard in `users` does NOT cover.
	ExcludedUsers []string `json:"excluded_users"`
	// Pass back to fetch the next page; null on the last page.
	ContinuationToken    *string `json:"continuation_token"`
	AuthorizationModelID string  `json:"authorization_model_id"`
	// Opaque consistency token (zookie). Pass it back as `consistency_token` on a later read to
	// require it be evaluated at least this fresh.
	ConsistencyToken string `json:"consistency_token"`
}

// FGAReadChangesResult is a typed model of the Backend API.
type FGAReadChangesResult struct {
	Object  string                         `json:"object"`
	Data    []FGAReadChangesResultDataItem `json:"data"`
	HasMore bool                           `json:"has_more"`
	// Position of the last change returned; pass it back to receive only newer changes.
	ContinuationToken string `json:"continuation_token"`
}

// FGAReadChangesResultDataItem is a typed model of the Backend API.
type FGAReadChangesResultDataItem struct {
	Object string `json:"object"`
	// One of: write, delete.
	Operation string `json:"operation"`
	User      string `json:"user"`
	Relation  string `json:"relation"`
	Target    string `json:"target"`
	// A model condition bound to a tuple: the tuple grants only while the CEL expression holds.
	Condition FGAReadChangesResultDataItemCondition `json:"condition"`
	// The consistency token of the write that made this change.
	ConsistencyToken string `json:"consistency_token"`
	// When the change was recorded (epoch ms).
	CreatedAt int64 `json:"created_at"`
}

// FGAReadChangesResultDataItemCondition is a model condition bound to a tuple: the tuple grants
// only while the CEL expression holds.
type FGAReadChangesResultDataItemCondition struct {
	// A condition defined in the authorization model.
	Name string `json:"name"`
	// Values for the condition parameters fixed on this tuple.
	Context map[string]interface{} `json:"context"`
}

// FlagsAssignOrganizationEntitlementsParams is a typed model of the Backend API.
type FlagsAssignOrganizationEntitlementsParams struct {
	Plan     *string          `json:"plan,omitempty"`
	Features []string         `json:"features,omitempty"`
	Limits   map[string]int64 `json:"limits,omitempty"`
	// Unix ms or ISO 8601; null = no expiry.
	ExpiresAt interface{} `json:"expires_at,omitempty"`
}

// FlagsAssignOrganizationEntitlementsResult is a typed model of the Backend API.
type FlagsAssignOrganizationEntitlementsResult struct {
	Object string `json:"object"`
	// One of: user, org.
	SubjectType string                 `json:"subject_type"`
	SubjectID   string                 `json:"subject_id"`
	Plan        *string                `json:"plan"`
	Features    []string               `json:"features"`
	Limits      map[string]interface{} `json:"limits"`
	// Epoch milliseconds.
	ExpiresAt *int64 `json:"expires_at"`
}

// FlagsCreateParams is a typed model of the Backend API.
type FlagsCreateParams struct {
	// Lowercase letters, digits, - and _.
	Key string `json:"key"`
	// One of: boolean, string, int, json.
	Type        string  `json:"type"`
	Description *string `json:"description,omitempty"`
	Enabled     *bool   `json:"enabled,omitempty"`
	// A boolean, string, integer or JSON value matching the flag `type`.
	DefaultValue interface{} `json:"default_value"`
	// A boolean, string, integer or JSON value matching the flag `type`.
	OffValue interface{} `json:"off_value,omitempty"`
	// Ordered targeting rules; the first match wins.
	Rules []FlagsCreateParamsRulesItem `json:"rules,omitempty"`
}

// FlagsCreateParamsRulesItem is a typed model of the Backend API.
type FlagsCreateParamsRulesItem struct {
	// A boolean, string, integer or JSON value matching the flag `type`.
	Value interface{} `json:"value,omitempty"`
}

// FlagsCreateResult is a typed model of the Backend API.
type FlagsCreateResult struct {
	Object string `json:"object"`
	ID     string `json:"id"`
	// Unique within the instance (an instance is one environment).
	Key string `json:"key"`
	// One of: boolean, string, int, json.
	Type        string  `json:"type"`
	Description *string `json:"description"`
	// The kill switch: while false, every subject gets `off_value`.
	Enabled bool `json:"enabled"`
	// A boolean, string, integer or JSON value matching the flag `type`.
	DefaultValue interface{} `json:"default_value"`
	// A boolean, string, integer or JSON value matching the flag `type`.
	OffValue interface{} `json:"off_value"`
	// Evaluated in order; the first rule that matches (and whose percentage bucket includes the
	// subject) supplies the value.
	Rules []FlagsCreateResultRulesItem `json:"rules"`
	// When the flag was created (epoch ms).
	CreatedAt int64 `json:"created_at"`
	// When the flag last changed (epoch ms).
	UpdatedAt int64 `json:"updated_at"`
}

// FlagsCreateResultRulesItem is a typed model of the Backend API.
type FlagsCreateResultRulesItem struct {
	// Every given list must contain the subject's value. An empty match applies to everyone.
	Match FlagsCreateResultRulesItemMatch `json:"match"`
	// Stable rollout share, bucketed by user id (else org id).
	Percentage float64 `json:"percentage"`
	// A boolean, string, integer or JSON value matching the flag `type`.
	Value interface{} `json:"value"`
}

// FlagsCreateResultRulesItemMatch is every given list must contain the subject's value. An empty
// match applies to everyone.
type FlagsCreateResultRulesItemMatch struct {
	UserIDs []string `json:"user_ids"`
	OrgIDs  []string `json:"org_ids"`
	Plans   []string `json:"plans"`
}

// FlagsDeleteResult is a typed model of the Backend API.
type FlagsDeleteResult struct {
	Object  string `json:"object"`
	ID      string `json:"id"`
	Key     string `json:"key"`
	Deleted bool   `json:"deleted"`
}

// FlagsEvaluateParams is a typed model of the Backend API.
type FlagsEvaluateParams struct {
	UserID string   `json:"user_id,omitempty"`
	OrgID  string   `json:"org_id,omitempty"`
	Plan   string   `json:"plan,omitempty"`
	Keys   []string `json:"keys,omitempty"`
}

// FlagsEvaluateResult is a typed model of the Backend API.
type FlagsEvaluateResult struct {
	Object  string                                   `json:"object"`
	Subject map[string]interface{}                   `json:"subject"`
	Flags   map[string]FlagsEvaluateResultFlagsValue `json:"flags"`
}

// FlagsEvaluateResultFlagsValue is a typed model of the Backend API.
type FlagsEvaluateResultFlagsValue struct {
	// A boolean, string, integer or JSON value matching the flag `type`.
	Value  interface{} `json:"value"`
	Reason string      `json:"reason"`
}

// FlagsUpdateParams is a typed model of the Backend API.
type FlagsUpdateParams struct {
	Description *string `json:"description,omitempty"`
	Enabled     *bool   `json:"enabled,omitempty"`
	// A boolean, string, integer or JSON value matching the flag `type`.
	DefaultValue interface{} `json:"default_value,omitempty"`
	// A boolean, string, integer or JSON value matching the flag `type`.
	OffValue interface{} `json:"off_value,omitempty"`
	// Ordered targeting rules; the first match wins.
	Rules []FlagsCreateParamsRulesItem `json:"rules,omitempty"`
}

// GroupsAddMembersParams is a typed model of the Backend API.
type GroupsAddMembersParams struct {
	UserIDs []string `json:"user_ids"`
}

// GroupsCreateParams is a typed model of the Backend API.
type GroupsCreateParams struct {
	// Lowercase letters, digits, - and _ (max 63). Unique per instance; usable in place of the id in
	// paths.
	Slug        string  `json:"slug"`
	Name        string  `json:"name"`
	Description *string `json:"description,omitempty"`
	// Nest under another group (up to 8 levels, no cycles). Members of a child are also members of its
	// ancestors for the token claim and role mapping.
	ParentID *string `json:"parent_id,omitempty"`
	// Free attributes (max 8 KB).
	Attributes map[string]interface{} `json:"attributes,omitempty"`
	// App roles every member (and member of a descendant) holds, merged into app_roles /
	// app_permissions on the token.
	AppRoleKeys []string `json:"app_role_keys,omitempty"`
	// Add the slug to the `groups` token claim (default true).
	IncludeInToken *bool `json:"include_in_token,omitempty"`
	// A user-search filter tree. POST …/reapply (and each SSO sign-in) makes membership match it.
	DynamicFilter map[string]interface{} `json:"dynamic_filter,omitempty"`
	// { claim, equals | contains | matches }: join at SSO sign-in when the IdP claim (a string or
	// list, e.g. "groups") matches; leave when it stops matching.
	SSOMatch map[string]interface{} `json:"sso_match,omitempty"`
}

// GroupsListItem is a typed model of the Backend API.
type GroupsListItem struct {
	Object         string                 `json:"object"`
	ID             string                 `json:"id"`
	Slug           string                 `json:"slug"`
	Name           string                 `json:"name"`
	Description    *string                `json:"description"`
	ParentID       *string                `json:"parent_id"`
	Attributes     map[string]interface{} `json:"attributes"`
	AppRoleKeys    []string               `json:"app_role_keys"`
	IncludeInToken bool                   `json:"include_in_token"`
	DynamicFilter  map[string]interface{} `json:"dynamic_filter"`
	SSOMatch       map[string]interface{} `json:"sso_match"`
	MemberCount    int64                  `json:"member_count"`
	// GET /v1/users/:id/groups only: how the user joined.
	Source string `json:"source"`
	// Created (epoch ms).
	CreatedAt int64 `json:"created_at"`
	// Updated (epoch ms).
	UpdatedAt int64 `json:"updated_at"`
}

// GroupsListMembersItem is a typed model of the Backend API.
type GroupsListMembersItem struct {
	Object  string `json:"object"`
	GroupID string `json:"group_id"`
	UserID  string `json:"user_id"`
	// How the user joined. One of: manual, dynamic, sso, rule.
	Source string `json:"source"`
	// The rule or connection that added the user, when not manual.
	SourceRef *string `json:"source_ref"`
	// Joined (epoch ms).
	CreatedAt int64 `json:"created_at"`
}

// GroupsReapplyResult is a typed model of the Backend API.
type GroupsReapplyResult struct {
	Object  string `json:"object"`
	GroupID string `json:"group_id"`
	// Users the dynamic filter matches now.
	Matched int64 `json:"matched"`
	// Members added by this run.
	Added int64 `json:"added"`
	// Members removed because they no longer match.
	Removed int64 `json:"removed"`
}

// GroupsRulesApplyAllItem is a typed model of the Backend API.
type GroupsRulesApplyAllItem struct {
	Object string `json:"object"`
	RuleID string `json:"rule_id"`
	// Users the rule condition matches.
	Matched       int64 `json:"matched"`
	GroupsAdded   int64 `json:"groups_added"`
	GroupsRemoved int64 `json:"groups_removed"`
	RolesGranted  int64 `json:"roles_granted"`
	TraitsSet     int64 `json:"traits_set"`
}

// GroupsRulesCreateParams is a typed model of the Backend API.
type GroupsRulesCreateParams struct {
	Name    string `json:"name"`
	Enabled *bool  `json:"enabled,omitempty"`
	// Lower runs first (default 100).
	Priority *int64 `json:"priority,omitempty"`
	// A user-search filter tree (see POST /v1/users/search).
	Condition map[string]interface{}               `json:"condition"`
	Actions   []GroupsRulesCreateParamsActionsItem `json:"actions"`
}

// GroupsRulesCreateParamsActionsItem is add_to_group { group } (declarative: removed when the user
// stops matching) · add_app_role { role } and set_trait { key, value } (additive).
type GroupsRulesCreateParamsActionsItem struct {
	// One of: add_to_group, add_app_role, set_trait.
	Type  string `json:"type"`
	Group string `json:"group,omitempty"`
	Role  string `json:"role,omitempty"`
	Key   string `json:"key,omitempty"`
	// set_trait only: any JSON value (under 2000 bytes), written to public_metadata[key].
	Value interface{} `json:"value,omitempty"`
}

// GroupsRulesListItem is a typed model of the Backend API.
type GroupsRulesListItem struct {
	Object    string                   `json:"object"`
	ID        string                   `json:"id"`
	Name      string                   `json:"name"`
	Enabled   bool                     `json:"enabled"`
	Priority  int64                    `json:"priority"`
	Condition map[string]interface{}   `json:"condition"`
	Actions   []map[string]interface{} `json:"actions"`
	CreatedBy *string                  `json:"created_by"`
	// Created (epoch ms).
	CreatedAt int64 `json:"created_at"`
	// Updated (epoch ms).
	UpdatedAt int64 `json:"updated_at"`
}

// GroupsRulesUpdateParams is a typed model of the Backend API.
type GroupsRulesUpdateParams struct {
	Name    string `json:"name,omitempty"`
	Enabled *bool  `json:"enabled,omitempty"`
	// Lower runs first (default 100).
	Priority *int64 `json:"priority,omitempty"`
	// A user-search filter tree (see POST /v1/users/search).
	Condition map[string]interface{}               `json:"condition,omitempty"`
	Actions   []GroupsRulesCreateParamsActionsItem `json:"actions,omitempty"`
}

// GroupsUpdateParams is a typed model of the Backend API.
type GroupsUpdateParams struct {
	// Lowercase letters, digits, - and _ (max 63). Unique per instance; usable in place of the id in
	// paths.
	Slug        string  `json:"slug,omitempty"`
	Name        string  `json:"name,omitempty"`
	Description *string `json:"description,omitempty"`
	// Nest under another group (up to 8 levels, no cycles). Members of a child are also members of its
	// ancestors for the token claim and role mapping.
	ParentID *string `json:"parent_id,omitempty"`
	// Free attributes (max 8 KB).
	Attributes map[string]interface{} `json:"attributes,omitempty"`
	// App roles every member (and member of a descendant) holds, merged into app_roles /
	// app_permissions on the token.
	AppRoleKeys []string `json:"app_role_keys,omitempty"`
	// Add the slug to the `groups` token claim (default true).
	IncludeInToken *bool `json:"include_in_token,omitempty"`
	// A user-search filter tree. POST …/reapply (and each SSO sign-in) makes membership match it.
	DynamicFilter map[string]interface{} `json:"dynamic_filter,omitempty"`
	// { claim, equals | contains | matches }: join at SSO sign-in when the IdP claim (a string or
	// list, e.g. "groups") matches; leave when it stops matching.
	SSOMatch map[string]interface{} `json:"sso_match,omitempty"`
}

// IdentityVerificationDecideParams is a typed model of the Backend API.
type IdentityVerificationDecideParams struct {
	// One of: approved, declined.
	Decision string `json:"decision,omitempty"`
	Reason   string `json:"reason,omitempty"`
}

// IdentityVerificationListItem is a typed model of the Backend API.
type IdentityVerificationListItem struct {
	Object string `json:"object"`
	ID     string `json:"id"`
	UserID string `json:"user_id"`
	// One of: persona, onfido, veriff, stripe_identity.
	Provider string `json:"provider"`
	// One of: pending, approved, declined, needs_review.
	Status string `json:"status"`
	// The service's short reason for a decline or review.
	Reason *string `json:"reason"`
	// The service's hosted verification page, while the check is pending.
	URL *string `json:"url"`
	// Who decided a review by hand.
	DecidedBy *string `json:"decided_by"`
	// Started (epoch ms).
	CreatedAt int64 `json:"created_at"`
	// When the check was approved or declined (epoch ms).
	CompletedAt *int64 `json:"completed_at"`
}

// IdentityVerificationSettingsResult is a typed model of the Backend API.
type IdentityVerificationSettingsResult struct {
	Object  string `json:"object"`
	Enabled bool   `json:"enabled"`
	// The service connector (Persona, Onfido, Veriff or Stripe Identity) that does the checking.
	ConnectorID *string `json:"connector_id"`
	// Offer a verified identity as the custom second step of sign-in.
	AsChallenge bool `json:"as_challenge"`
	// The URL to give the verification service for verdict webhooks (set the service's webhook secret
	// on the connector as `webhook_secret`; Veriff uses its shared secret).
	WebhookURL *string `json:"webhook_url"`
}

// IdentityVerificationStartParams is a typed model of the Backend API.
type IdentityVerificationStartParams struct {
	RedirectURL string `json:"redirect_url,omitempty"`
}

// IdentityVerificationUpdateSettingsParams is a typed model of the Backend API.
type IdentityVerificationUpdateSettingsParams struct {
	Enabled     *bool   `json:"enabled,omitempty"`
	ConnectorID *string `json:"connector_id,omitempty"`
	AsChallenge *bool   `json:"as_challenge,omitempty"`
}

// IGACampaignsCreateParams is a typed model of the Backend API.
type IGACampaignsCreateParams struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	// One of: all, entitlement, app, role, group, org.
	ScopeType string   `json:"scope_type,omitempty"`
	ScopeIDs  []string `json:"scope_ids,omitempty"`
	// One of: manager, owner, named.
	ReviewerType string   `json:"reviewer_type,omitempty"`
	ReviewerIDs  []string `json:"reviewer_ids,omitempty"`
	DueAt        *int64   `json:"due_at,omitempty"`
	ReminderDays []int64  `json:"reminder_days,omitempty"`
	AutoRevoke   *bool    `json:"auto_revoke,omitempty"`
}

// IGACampaignsDecideParams is a typed model of the Backend API.
type IGACampaignsDecideParams struct {
	// One of: certify, revoke.
	Decision       string `json:"decision"`
	Comment        string `json:"comment,omitempty"`
	ReviewerUserID string `json:"reviewer_user_id,omitempty"`
}

// IGACampaignsEvidenceResult is a typed model of the Backend API.
type IGACampaignsEvidenceResult struct {
	Object      string                                `json:"object"`
	Campaign    IGACampaignsListItem                  `json:"campaign"`
	Progress    IGACampaignsProgressResult            `json:"progress"`
	GeneratedAt string                                `json:"generated_at"`
	Items       []IGACampaignsEvidenceResultItemsItem `json:"items"`
}

// IGACampaignsEvidenceResultItemsItem is a typed model of the Backend API.
type IGACampaignsEvidenceResultItemsItem struct {
	ItemID          string  `json:"item_id"`
	UserID          string  `json:"user_id"`
	UserErased      bool    `json:"user_erased"`
	UserEmailMasked *string `json:"user_email_masked"`
	EntitlementKey  *string `json:"entitlement_key"`
	EntitlementName *string `json:"entitlement_name"`
	RiskLevel       *string `json:"risk_level"`
	ReviewerUserID  *string `json:"reviewer_user_id"`
	Decision        string  `json:"decision"`
	DecidedBy       *string `json:"decided_by"`
	DecidedAt       *string `json:"decided_at"`
	RevokedApplied  bool    `json:"revoked_applied"`
}

// IGACampaignsItemsItem is a typed model of the Backend API.
type IGACampaignsItemsItem struct {
	Object         string  `json:"object"`
	ID             string  `json:"id"`
	CampaignID     string  `json:"campaign_id"`
	GrantID        string  `json:"grant_id"`
	UserID         string  `json:"user_id"`
	EntitlementID  string  `json:"entitlement_id"`
	ReviewerUserID *string `json:"reviewer_user_id"`
	// One of: pending, certified, revoked.
	Decision       string  `json:"decision"`
	DecidedBy      *string `json:"decided_by"`
	DecidedAt      *int64  `json:"decided_at"`
	Comment        *string `json:"comment"`
	RevokedApplied bool    `json:"revoked_applied"`
}

// IGACampaignsListItem is a typed model of the Backend API.
type IGACampaignsListItem struct {
	Object      string  `json:"object"`
	ID          string  `json:"id"`
	Name        string  `json:"name"`
	Description *string `json:"description"`
	// One of: all, entitlement, app, role, group, org.
	ScopeType string   `json:"scope_type"`
	ScopeIDs  []string `json:"scope_ids"`
	// One of: manager, owner, named.
	ReviewerType string   `json:"reviewer_type"`
	ReviewerIDs  []string `json:"reviewer_ids"`
	// One of: draft, active, closed.
	Status       string  `json:"status"`
	DueAt        *int64  `json:"due_at"`
	ReminderDays []int64 `json:"reminder_days"`
	AutoRevoke   bool    `json:"auto_revoke"`
	LaunchedAt   *int64  `json:"launched_at"`
	ClosedAt     *int64  `json:"closed_at"`
	// Created (epoch ms).
	CreatedAt int64 `json:"created_at"`
}

// IGACampaignsProgressResult is a typed model of the Backend API.
type IGACampaignsProgressResult struct {
	Object     string `json:"object"`
	CampaignID string `json:"campaign_id"`
	// One of: draft, active, closed.
	Status          string                                    `json:"status"`
	Total           int64                                     `json:"total"`
	Pending         int64                                     `json:"pending"`
	Certified       int64                                     `json:"certified"`
	Revoked         int64                                     `json:"revoked"`
	PercentComplete int64                                     `json:"percent_complete"`
	Overdue         bool                                      `json:"overdue"`
	Reviewers       []IGACampaignsProgressResultReviewersItem `json:"reviewers"`
}

// IGACampaignsProgressResultReviewersItem is a typed model of the Backend API.
type IGACampaignsProgressResultReviewersItem struct {
	ReviewerUserID *string `json:"reviewer_user_id"`
	Total          int64   `json:"total"`
	Decided        int64   `json:"decided"`
}

// IGADelegationsCreateParams is a typed model of the Backend API.
type IGADelegationsCreateParams struct {
	DelegatorUserID string `json:"delegator_user_id"`
	DelegateUserID  string `json:"delegate_user_id"`
	StartsAt        *int64 `json:"starts_at,omitempty"`
	EndsAt          int64  `json:"ends_at"`
}

// IGADelegationsListItem is a typed model of the Backend API.
type IGADelegationsListItem struct {
	Object          string `json:"object"`
	ID              string `json:"id"`
	DelegatorUserID string `json:"delegator_user_id"`
	DelegateUserID  string `json:"delegate_user_id"`
	// Starts (epoch ms).
	StartsAt int64 `json:"starts_at"`
	// Ends (epoch ms).
	EndsAt int64 `json:"ends_at"`
	// Created (epoch ms).
	CreatedAt int64 `json:"created_at"`
}

// IGAEntitlementsCreateParams is a typed model of the Backend API.
type IGAEntitlementsCreateParams struct {
	Key         string  `json:"key"`
	Name        string  `json:"name"`
	Description *string `json:"description,omitempty"`
	// One of: role, org_membership, group, resource_role, app_assignment, custom.
	Kind        string                 `json:"kind"`
	Target      map[string]interface{} `json:"target"`
	OwnerUserID *string                `json:"owner_user_id,omitempty"`
	// One of: low, medium, high, critical.
	RiskLevel            string                                    `json:"risk_level,omitempty"`
	ApprovalRules        *IGAEntitlementsCreateParamsApprovalRules `json:"approval_rules,omitempty"`
	MaxDurationSeconds   *int64                                    `json:"max_duration_seconds,omitempty"`
	Requestable          *bool                                     `json:"requestable,omitempty"`
	RequireJustification *bool                                     `json:"require_justification,omitempty"`
}

// IGAEntitlementsCreateParamsApprovalRules is a typed model of the Backend API.
type IGAEntitlementsCreateParamsApprovalRules struct {
	// Up to five steps, run in order. No steps = approved at once.
	Steps []IGAEntitlementsCreateParamsApprovalRulesStepsItem `json:"steps"`
}

// IGAEntitlementsCreateParamsApprovalRulesStepsItem is a typed model of the Backend API.
type IGAEntitlementsCreateParamsApprovalRulesStepsItem struct {
	// One of: manager, owner, group, users.
	Type string   `json:"type"`
	IDs  []string `json:"ids,omitempty"`
	// `any` approver decides the step; `all` must approve. One of: any, all.
	Mode string `json:"mode,omitempty"`
	// After this long without a decision the step escalates (60 s to a year).
	TimeoutSeconds *int64                                                       `json:"timeout_seconds,omitempty"`
	EscalateTo     *IGAEntitlementsCreateParamsApprovalRulesStepsItemEscalateTo `json:"escalate_to,omitempty"`
}

// IGAEntitlementsCreateParamsApprovalRulesStepsItemEscalateTo is a typed model of the Backend API.
type IGAEntitlementsCreateParamsApprovalRulesStepsItemEscalateTo struct {
	// One of: manager, owner, group, users.
	Type string `json:"type"`
	// A group slug (type group) or user ids (type users).
	IDs []string `json:"ids,omitempty"`
}

// IGAEntitlementsListItem is a typed model of the Backend API.
type IGAEntitlementsListItem struct {
	Object      string  `json:"object"`
	ID          string  `json:"id"`
	Key         string  `json:"key"`
	Name        string  `json:"name"`
	Description *string `json:"description"`
	// One of: role, org_membership, group, resource_role, app_assignment, custom.
	Kind string `json:"kind"`
	// What the entitlement points at, by kind: role {role_key}, org_membership {organization_id,
	// role}, group {group}, resource_role {resource_id, role}, app_assignment {app_id}, custom
	// (free-form).
	Target      map[string]interface{} `json:"target"`
	OwnerUserID *string                `json:"owner_user_id"`
	// One of: low, medium, high, critical.
	RiskLevel            string                               `json:"risk_level"`
	ApprovalRules        IGAEntitlementsListItemApprovalRules `json:"approval_rules"`
	MaxDurationSeconds   *int64                               `json:"max_duration_seconds"`
	Requestable          bool                                 `json:"requestable"`
	RequireJustification bool                                 `json:"require_justification"`
	// Created (epoch ms).
	CreatedAt int64 `json:"created_at"`
	// Updated (epoch ms).
	UpdatedAt int64 `json:"updated_at"`
}

// IGAEntitlementsListItemApprovalRules is a typed model of the Backend API.
type IGAEntitlementsListItemApprovalRules struct {
	// Up to five steps, run in order. No steps = approved at once.
	Steps []IGAEntitlementsListItemApprovalRulesStepsItem `json:"steps"`
}

// IGAEntitlementsListItemApprovalRulesStepsItem is a typed model of the Backend API.
type IGAEntitlementsListItemApprovalRulesStepsItem struct {
	// One of: manager, owner, group, users.
	Type string   `json:"type"`
	IDs  []string `json:"ids"`
	// `any` approver decides the step; `all` must approve. One of: any, all.
	Mode string `json:"mode"`
	// After this long without a decision the step escalates (60 s to a year).
	TimeoutSeconds int64                                                   `json:"timeout_seconds"`
	EscalateTo     IGAEntitlementsListItemApprovalRulesStepsItemEscalateTo `json:"escalate_to"`
}

// IGAEntitlementsListItemApprovalRulesStepsItemEscalateTo is a typed model of the Backend API.
type IGAEntitlementsListItemApprovalRulesStepsItemEscalateTo struct {
	// One of: manager, owner, group, users.
	Type string `json:"type"`
	// A group slug (type group) or user ids (type users).
	IDs []string `json:"ids"`
}

// IGAEntitlementsUpdateParams is a typed model of the Backend API.
type IGAEntitlementsUpdateParams struct {
	Key         string  `json:"key,omitempty"`
	Name        string  `json:"name,omitempty"`
	Description *string `json:"description,omitempty"`
	// One of: role, org_membership, group, resource_role, app_assignment, custom.
	Kind        string                 `json:"kind,omitempty"`
	Target      map[string]interface{} `json:"target,omitempty"`
	OwnerUserID *string                `json:"owner_user_id,omitempty"`
	// One of: low, medium, high, critical.
	RiskLevel            string                                    `json:"risk_level,omitempty"`
	ApprovalRules        *IGAEntitlementsCreateParamsApprovalRules `json:"approval_rules,omitempty"`
	MaxDurationSeconds   *int64                                    `json:"max_duration_seconds,omitempty"`
	Requestable          *bool                                     `json:"requestable,omitempty"`
	RequireJustification *bool                                     `json:"require_justification,omitempty"`
}

// IGAGrantsCreateParams is a typed model of the Backend API.
type IGAGrantsCreateParams struct {
	Entitlement    string `json:"entitlement"`
	UserID         string `json:"user_id"`
	ExpiresAt      *int64 `json:"expires_at,omitempty"`
	OverrideReason string `json:"override_reason,omitempty"`
}

// IGAGrantsListItem is a typed model of the Backend API.
type IGAGrantsListItem struct {
	Object        string  `json:"object"`
	ID            string  `json:"id"`
	UserID        string  `json:"user_id"`
	EntitlementID string  `json:"entitlement_id"`
	RequestID     *string `json:"request_id"`
	// One of: request, admin, birthright, existing.
	Source string `json:"source"`
	// One of: active, revoked, expired.
	Status string `json:"status"`
	// Granted (epoch ms).
	GrantedAt     int64   `json:"granted_at"`
	ExpiresAt     *int64  `json:"expires_at"`
	RevokedAt     *int64  `json:"revoked_at"`
	RevokedReason *string `json:"revoked_reason"`
	RevokedBy     *string `json:"revoked_by"`
	// The access existed before governance took it over. An expiry or a birthright change leaves
	// adopted access in place; an administrator or reviewer revoke removes it.
	Adopted bool `json:"adopted"`
}

// IGAGrantsRevokeParams is a typed model of the Backend API.
type IGAGrantsRevokeParams struct {
	Reason string `json:"reason,omitempty"`
}

// IGALifecycleCreateBirthrightRuleParams is a typed model of the Backend API.
type IGALifecycleCreateBirthrightRuleParams struct {
	Name            string                                      `json:"name"`
	Match           IGALifecycleCreateBirthrightRuleParamsMatch `json:"match"`
	EntitlementIDs  []string                                    `json:"entitlement_ids"`
	RevokeOnUnmatch *bool                                       `json:"revoke_on_unmatch,omitempty"`
	Enabled         *bool                                       `json:"enabled,omitempty"`
}

// IGALifecycleCreateBirthrightRuleParamsMatch is a typed model of the Backend API.
type IGALifecycleCreateBirthrightRuleParamsMatch struct {
	Group          string `json:"group,omitempty"`
	OrganizationID string `json:"organization_id,omitempty"`
	OrgRole        string `json:"org_role,omitempty"`
	AppRole        string `json:"app_role,omitempty"`
	EmailDomain    string `json:"email_domain,omitempty"`
}

// IGALifecycleListBirthrightRulesItem is a typed model of the Backend API.
type IGALifecycleListBirthrightRulesItem struct {
	Object          string                                   `json:"object"`
	ID              string                                   `json:"id"`
	Name            string                                   `json:"name"`
	Match           IGALifecycleListBirthrightRulesItemMatch `json:"match"`
	EntitlementIDs  []string                                 `json:"entitlement_ids"`
	RevokeOnUnmatch bool                                     `json:"revoke_on_unmatch"`
	Enabled         bool                                     `json:"enabled"`
	// Created (epoch ms).
	CreatedAt int64 `json:"created_at"`
}

// IGALifecycleListBirthrightRulesItemMatch is a typed model of the Backend API.
type IGALifecycleListBirthrightRulesItemMatch struct {
	Group          string `json:"group"`
	OrganizationID string `json:"organization_id"`
	OrgRole        string `json:"org_role"`
	AppRole        string `json:"app_role"`
	EmailDomain    string `json:"email_domain"`
}

// IGALifecycleOffboardParams is a typed model of the Backend API.
type IGALifecycleOffboardParams struct {
	CloseAccount *bool  `json:"close_account,omitempty"`
	GraceSeconds *int64 `json:"grace_seconds,omitempty"`
	Reason       string `json:"reason,omitempty"`
}

// IGALifecycleOffboardResult is a typed model of the Backend API.
type IGALifecycleOffboardResult struct {
	Object            string      `json:"object"`
	UserID            string      `json:"user_id"`
	RevokedGrants     int64       `json:"revoked_grants"`
	CancelledRequests int64       `json:"cancelled_requests"`
	AccountClosure    interface{} `json:"account_closure"`
}

// IGALifecycleReconcileResult is a typed model of the Backend API.
type IGALifecycleReconcileResult struct {
	Object  string   `json:"object"`
	UserID  string   `json:"user_id"`
	Granted []string `json:"granted"`
	Revoked []string `json:"revoked"`
}

// IGALifecycleSettingsResult is a typed model of the Backend API.
type IGALifecycleSettingsResult struct {
	Object     string `json:"object"`
	JMLEnabled bool   `json:"jml_enabled"`
	// One of: revoke, revoke_and_close.
	LeaverAction            string `json:"leaver_action"`
	LeaverCloseGraceSeconds *int64 `json:"leaver_close_grace_seconds"`
}

// IGALifecycleUpdateBirthrightRuleParams is a typed model of the Backend API.
type IGALifecycleUpdateBirthrightRuleParams struct {
	Name            string                                       `json:"name,omitempty"`
	Match           *IGALifecycleCreateBirthrightRuleParamsMatch `json:"match,omitempty"`
	EntitlementIDs  []string                                     `json:"entitlement_ids,omitempty"`
	RevokeOnUnmatch *bool                                        `json:"revoke_on_unmatch,omitempty"`
	Enabled         *bool                                        `json:"enabled,omitempty"`
}

// IGALifecycleUpdateSettingsParams is a typed model of the Backend API.
type IGALifecycleUpdateSettingsParams struct {
	JMLEnabled *bool `json:"jml_enabled,omitempty"`
	// One of: revoke, revoke_and_close.
	LeaverAction            string `json:"leaver_action,omitempty"`
	LeaverCloseGraceSeconds *int64 `json:"leaver_close_grace_seconds,omitempty"`
}

// IGARequestsCreateParams is a typed model of the Backend API.
type IGARequestsCreateParams struct {
	Entitlement     string `json:"entitlement"`
	UserID          string `json:"user_id"`
	RequesterUserID string `json:"requester_user_id,omitempty"`
	Justification   string `json:"justification,omitempty"`
	DurationSeconds *int64 `json:"duration_seconds,omitempty"`
}

// IGARequestsDecideParams is a typed model of the Backend API.
type IGARequestsDecideParams struct {
	// One of: approve, deny.
	Decision       string `json:"decision"`
	Comment        string `json:"comment,omitempty"`
	ApproverUserID string `json:"approver_user_id,omitempty"`
}

// IGARequestsListItem is a typed model of the Backend API.
type IGARequestsListItem struct {
	Object            string  `json:"object"`
	ID                string  `json:"id"`
	EntitlementID     string  `json:"entitlement_id"`
	RequesterUserID   *string `json:"requester_user_id"`
	BeneficiaryUserID string  `json:"beneficiary_user_id"`
	// One of: self, admin.
	Source          string  `json:"source"`
	Justification   *string `json:"justification"`
	DurationSeconds *int64  `json:"duration_seconds"`
	// One of: pending, approved, denied, cancelled, fulfilled, failed.
	Status      string                             `json:"status"`
	CurrentStep *int64                             `json:"current_step"`
	Steps       []IGARequestsListItemStepsItem     `json:"steps"`
	SOD         []IGARequestsListItemSODItem       `json:"sod"`
	Approvals   []IGARequestsListItemApprovalsItem `json:"approvals"`
	Failure     *string                            `json:"failure"`
	DecidedAt   *int64                             `json:"decided_at"`
	// Filed (epoch ms).
	CreatedAt int64 `json:"created_at"`
}

// IGARequestsListItemApprovalsItem is a typed model of the Backend API.
type IGARequestsListItemApprovalsItem struct {
	Step            int64   `json:"step"`
	ApproverUserID  string  `json:"approver_user_id"`
	ActingForUserID *string `json:"acting_for_user_id"`
	// One of: approve, deny.
	Decision string  `json:"decision"`
	Comment  *string `json:"comment"`
	// Decided (epoch ms).
	DecidedAt int64 `json:"decided_at"`
}

// IGARequestsListItemSODItem is a typed model of the Backend API.
type IGARequestsListItemSODItem struct {
	RuleID   string `json:"rule_id"`
	RuleName string `json:"rule_name"`
	// One of: block, require_approval.
	Mode                     string `json:"mode"`
	ConflictingEntitlementID string `json:"conflicting_entitlement_id"`
}

// IGARequestsListItemStepsItem is a typed model of the Backend API.
type IGARequestsListItemStepsItem struct {
	Index     int64    `json:"index"`
	Type      string   `json:"type"`
	Mode      string   `json:"mode"`
	Approvers []string `json:"approvers"`
	// One of: pending, approved, denied.
	Status         string  `json:"status"`
	Escalated      bool    `json:"escalated"`
	TimeoutSeconds *int64  `json:"timeout_seconds"`
	SODRuleID      *string `json:"sod_rule_id"`
}

// IGASODCreateRuleParams is a typed model of the Backend API.
type IGASODCreateRuleParams struct {
	Name         string `json:"name"`
	Description  string `json:"description,omitempty"`
	EntitlementA string `json:"entitlement_a"`
	EntitlementB string `json:"entitlement_b"`
	// One of: block, require_approval.
	Mode     string                                             `json:"mode,omitempty"`
	Approver *IGAEntitlementsCreateParamsApprovalRulesStepsItem `json:"approver,omitempty"`
	Enabled  *bool                                              `json:"enabled,omitempty"`
}

// IGASODListRulesItem is a typed model of the Backend API.
type IGASODListRulesItem struct {
	Object       string  `json:"object"`
	ID           string  `json:"id"`
	Name         string  `json:"name"`
	Description  *string `json:"description"`
	EntitlementA string  `json:"entitlement_a"`
	EntitlementB string  `json:"entitlement_b"`
	// One of: block, require_approval.
	Mode     string      `json:"mode"`
	Approver interface{} `json:"approver"`
	Enabled  bool        `json:"enabled"`
	// Created (epoch ms).
	CreatedAt int64 `json:"created_at"`
	// Updated (epoch ms).
	UpdatedAt int64 `json:"updated_at"`
}

// IGASODScanResult is a typed model of the Backend API.
type IGASODScanResult struct {
	Object   string `json:"object"`
	Found    int64  `json:"found"`
	Resolved int64  `json:"resolved"`
}

// IGASODUpdateRuleParams is a typed model of the Backend API.
type IGASODUpdateRuleParams struct {
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
	// One of: block, require_approval.
	Mode     string                                             `json:"mode,omitempty"`
	Approver *IGAEntitlementsCreateParamsApprovalRulesStepsItem `json:"approver,omitempty"`
	Enabled  *bool                                              `json:"enabled,omitempty"`
}

// IGASODViolationsItem is a typed model of the Backend API.
type IGASODViolationsItem struct {
	Object   string  `json:"object"`
	ID       string  `json:"id"`
	RuleID   string  `json:"rule_id"`
	RuleName *string `json:"rule_name"`
	Mode     *string `json:"mode"`
	UserID   string  `json:"user_id"`
	// One of: open, accepted, resolved.
	Status string `json:"status"`
	// One of: request, assignment, scan.
	Source    string  `json:"source"`
	RequestID *string `json:"request_id"`
	Note      *string `json:"note"`
	// Detected (epoch ms).
	DetectedAt int64  `json:"detected_at"`
	ResolvedAt *int64 `json:"resolved_at"`
}

// InstanceIntegrationsRotateEventsSecretParams is a typed model of the Backend API.
type InstanceIntegrationsRotateEventsSecretParams struct {
	// How long the previous secret keeps signing deliveries (default 0 = stop now).
	OverlapSeconds *int64 `json:"overlap_seconds,omitempty"`
}

// InstanceIntegrationsRotateEventsSecretResult is a typed model of the Backend API.
type InstanceIntegrationsRotateEventsSecretResult struct {
	Object      string `json:"object"`
	Integration string `json:"integration"`
	EndpointID  string `json:"endpoint_id"`
	URL         string `json:"url"`
	// The new signing secret. Shown once.
	Secret         string `json:"secret"`
	OverlapSeconds int64  `json:"overlap_seconds"`
	// Epoch ms when the old secret stops signing; null when it already has.
	PreviousSecretExpiresAt *int64 `json:"previous_secret_expires_at"`
	// What happens to the old secret, said plainly.
	Warning string `json:"warning"`
}

// IntegrationsRunCardActionParams is a typed model of the Backend API.
type IntegrationsRunCardActionParams struct {
	Sub string `json:"sub"`
	Iss string `json:"iss,omitempty"`
	// Who pressed the button in the integrated service (recorded in the audit log).
	Agent *IntegrationsRunCardActionParamsAgent `json:"agent,omitempty"`
}

// IntegrationsRunCardActionParamsAgent is who pressed the button in the integrated service
// (recorded in the audit log).
type IntegrationsRunCardActionParamsAgent struct {
	ID    string `json:"id,omitempty"`
	Name  string `json:"name,omitempty"`
	Email string `json:"email,omitempty"`
}

// IntegrationsRunCardActionResult is a typed model of the Backend API.
type IntegrationsRunCardActionResult struct {
	Object          string `json:"object"`
	Integration     string `json:"integration"`
	Action          string `json:"action"`
	Ok              bool   `json:"ok"`
	SessionsRevoked int64  `json:"sessions_revoked"`
}

// JourneysActivateParams is a typed model of the Backend API.
type JourneysActivateParams struct {
	Version int64 `json:"version"`
}

// JourneysCreateParams is a typed model of the Backend API.
type JourneysCreateParams struct {
	Name        string  `json:"name"`
	Description *string `json:"description,omitempty"`
	// The journey for every sign-in without an application-specific one (only one is default).
	IsDefault *bool `json:"is_default,omitempty"`
	// OAuth client ids whose sign-ins use this journey instead of the default.
	Applications []string                       `json:"applications,omitempty"`
	Enabled      *bool                          `json:"enabled,omitempty"`
	Definition   JourneysCreateParamsDefinition `json:"definition"`
	// Make the new version active (default true).
	Activate *bool `json:"activate,omitempty"`
}

// JourneysCreateParamsDefinition is a typed model of the Backend API.
type JourneysCreateParamsDefinition struct {
	Steps []JourneysCreateParamsDefinitionStepsItem `json:"steps"`
}

// JourneysCreateParamsDefinitionStepsItem is a typed model of the Backend API.
type JourneysCreateParamsDefinitionStepsItem struct {
	// 1-48 lowercase letters, digits, _ or -; unique in the journey.
	ID string `json:"id"`
	// One of: require_method, require_mfa, required_action, profile_prompt, policy_acceptance, action,
	// set_claim, redirect, deny, form, subflow.
	Type string `json:"type"`
	// Conditions (the access-policy condition language: applications, userIds, groups, orgs, roles,
	// networkZones, countries, riskLevels, deviceTrust, authMethods, timeWindow). The step runs only
	// when they all match.
	When map[string]interface{} `json:"when,omitempty"`
	// require_method: accepted methods, or the families oauth and enterprise_sso.
	Methods []string `json:"methods,omitempty"`
	// required_action: what the user must do before the session is issued. One of: update_password,
	// verify_email, configure_mfa, update_profile, accept_policy, identity_verification, custom.
	Action string `json:"action,omitempty"`
	// required_action custom: where the user is sent; redirect: where the user goes after signing in
	// (https).
	URL string `json:"url,omitempty"`
	// action: an Action with the workflow_step trigger; it may refuse the sign-in.
	ActionID string `json:"action_id,omitempty"`
	// set_claim: the session claim to set (not a protocol or Atlas-managed claim).
	Claim string `json:"claim,omitempty"`
	// set_claim: the value (at most 1 KB of JSON).
	Value interface{} `json:"value,omitempty"`
	// deny / require_*: the message the user sees when the step refuses.
	Message string `json:"message,omitempty"`
	// form: the heading the hosted pages and SDKs show.
	Title string `json:"title,omitempty"`
	// form: a line of text under the heading.
	Intro string `json:"intro,omitempty"`
	// form: the fields to ask for (values are saved to public_metadata under each key).
	Fields []JourneysCreateParamsDefinitionStepsItemFieldsItem `json:"fields,omitempty"`
	// form: ask only while a required field is still empty (default true).
	Once *bool `json:"once,omitempty"`
	// subflow: the journey whose active steps run here (its own conditions apply on top). At most five
	// deep; cycles are refused.
	FlowID string `json:"flow_id,omitempty"`
}

// JourneysCreateParamsDefinitionStepsItemFieldsItem is a typed model of the Backend API.
type JourneysCreateParamsDefinitionStepsItemFieldsItem struct {
	Key   string `json:"key"`
	Label string `json:"label"`
	// One of: text, email, number, date, select, checkbox, textarea.
	Type        string `json:"type"`
	Required    *bool  `json:"required,omitempty"`
	Placeholder string `json:"placeholder,omitempty"`
	// select: the allowed values.
	Options []string `json:"options,omitempty"`
}

// JourneysListResult is a typed model of the Backend API.
type JourneysListResult struct {
	Object  string                       `json:"object"`
	Data    []JourneysListResultDataItem `json:"data"`
	HasMore bool                         `json:"has_more"`
}

// JourneysListResultDataItem is a typed model of the Backend API.
type JourneysListResultDataItem struct {
	Object        string                                `json:"object"`
	ID            string                                `json:"id"`
	Name          string                                `json:"name"`
	Description   *string                               `json:"description"`
	IsDefault     bool                                  `json:"is_default"`
	Applications  []string                              `json:"applications"`
	Enabled       bool                                  `json:"enabled"`
	ActiveVersion *int64                                `json:"active_version"`
	LatestVersion int64                                 `json:"latest_version"`
	Definition    *JourneysListResultDataItemDefinition `json:"definition"`
	CreatedAt     int64                                 `json:"created_at"`
	UpdatedAt     int64                                 `json:"updated_at"`
}

// JourneysListResultDataItemDefinition is a typed model of the Backend API.
type JourneysListResultDataItemDefinition struct {
	Steps []JourneysListResultDataItemDefinitionStepsItem `json:"steps"`
}

// JourneysListResultDataItemDefinitionStepsItem is a typed model of the Backend API.
type JourneysListResultDataItemDefinitionStepsItem struct {
	// 1-48 lowercase letters, digits, _ or -; unique in the journey.
	ID string `json:"id"`
	// One of: require_method, require_mfa, required_action, profile_prompt, policy_acceptance, action,
	// set_claim, redirect, deny, form, subflow.
	Type string `json:"type"`
	// Conditions (the access-policy condition language: applications, userIds, groups, orgs, roles,
	// networkZones, countries, riskLevels, deviceTrust, authMethods, timeWindow). The step runs only
	// when they all match.
	When map[string]interface{} `json:"when"`
	// require_method: accepted methods, or the families oauth and enterprise_sso.
	Methods []string `json:"methods"`
	// required_action: what the user must do before the session is issued. One of: update_password,
	// verify_email, configure_mfa, update_profile, accept_policy, identity_verification, custom.
	Action string `json:"action"`
	// required_action custom: where the user is sent; redirect: where the user goes after signing in
	// (https).
	URL string `json:"url"`
	// action: an Action with the workflow_step trigger; it may refuse the sign-in.
	ActionID string `json:"action_id"`
	// set_claim: the session claim to set (not a protocol or Atlas-managed claim).
	Claim string `json:"claim"`
	// set_claim: the value (at most 1 KB of JSON).
	Value interface{} `json:"value"`
	// deny / require_*: the message the user sees when the step refuses.
	Message string `json:"message"`
	// form: the heading the hosted pages and SDKs show.
	Title string `json:"title"`
	// form: a line of text under the heading.
	Intro string `json:"intro"`
	// form: the fields to ask for (values are saved to public_metadata under each key).
	Fields []JourneysListResultDataItemDefinitionStepsItemFieldsItem `json:"fields"`
	// form: ask only while a required field is still empty (default true).
	Once bool `json:"once"`
	// subflow: the journey whose active steps run here (its own conditions apply on top). At most five
	// deep; cycles are refused.
	FlowID string `json:"flow_id"`
}

// JourneysListResultDataItemDefinitionStepsItemFieldsItem is a typed model of the Backend API.
type JourneysListResultDataItemDefinitionStepsItemFieldsItem struct {
	Key   string `json:"key"`
	Label string `json:"label"`
	// One of: text, email, number, date, select, checkbox, textarea.
	Type        string `json:"type"`
	Required    bool   `json:"required"`
	Placeholder string `json:"placeholder"`
	// select: the allowed values.
	Options []string `json:"options"`
}

// JourneysSimulateParams is a typed model of the Backend API.
type JourneysSimulateParams struct {
	UserID        string `json:"user_id"`
	Method        string `json:"method,omitempty"`
	MFAVerified   *bool  `json:"mfa_verified,omitempty"`
	IP            string `json:"ip,omitempty"`
	ApplicationID string `json:"application_id,omitempty"`
	Version       *int64 `json:"version,omitempty"`
}

// JourneysSimulateResult is a typed model of the Backend API.
type JourneysSimulateResult struct {
	Object    string `json:"object"`
	JourneyID string `json:"journey_id"`
	Version   int64  `json:"version"`
	// One of: allowed, held, refused.
	Outcome string                            `json:"outcome"`
	Effects []map[string]interface{}          `json:"effects"`
	Trace   []JourneysSimulateResultTraceItem `json:"trace"`
}

// JourneysSimulateResultTraceItem is a typed model of the Backend API.
type JourneysSimulateResultTraceItem struct {
	Step    string `json:"step"`
	Type    string `json:"type"`
	Matched bool   `json:"matched"`
	// One of: skipped, passed, effect, stopped.
	Outcome string `json:"outcome"`
}

// JourneysUpdateParams is a typed model of the Backend API.
type JourneysUpdateParams struct {
	Name        string  `json:"name,omitempty"`
	Description *string `json:"description,omitempty"`
	// The journey for every sign-in without an application-specific one (only one is default).
	IsDefault *bool `json:"is_default,omitempty"`
	// OAuth client ids whose sign-ins use this journey instead of the default.
	Applications []string                        `json:"applications,omitempty"`
	Enabled      *bool                           `json:"enabled,omitempty"`
	Definition   *JourneysCreateParamsDefinition `json:"definition,omitempty"`
	// Make the new version active (default true).
	Activate *bool `json:"activate,omitempty"`
}

// JourneysVersionsResult is a typed model of the Backend API.
type JourneysVersionsResult struct {
	Object string                           `json:"object"`
	Data   []JourneysVersionsResultDataItem `json:"data"`
}

// JourneysVersionsResultDataItem is a typed model of the Backend API.
type JourneysVersionsResultDataItem struct {
	Object     string                               `json:"object"`
	Version    int64                                `json:"version"`
	Definition JourneysListResultDataItemDefinition `json:"definition"`
	CreatedBy  *string                              `json:"created_by"`
	CreatedAt  int64                                `json:"created_at"`
}

// LDAPServerClientsCreateParams is a typed model of the Backend API.
type LDAPServerClientsCreateParams struct {
	Name string `json:"name"`
	// e.g. dc=acme,dc=com
	BaseDN string `json:"base_dn"`
	// The service account cn under base_dn.
	BindCn string `json:"bind_cn"`
	// Source networks allowed to bind (empty = anywhere).
	AllowedCIDRs  []string `json:"allowed_cidrs,omitempty"`
	AllowUserBind *bool    `json:"allow_user_bind,omitempty"`
	SizeLimit     *int64   `json:"size_limit,omitempty"`
	// One of: active, disabled.
	Status string `json:"status,omitempty"`
}

// LDAPServerClientsListResult is a typed model of the Backend API.
type LDAPServerClientsListResult struct {
	Object  string                                `json:"object"`
	Data    []LDAPServerClientsListResultDataItem `json:"data"`
	HasMore bool                                  `json:"has_more"`
}

// LDAPServerClientsListResultDataItem is a typed model of the Backend API.
type LDAPServerClientsListResultDataItem struct {
	Object         string   `json:"object"`
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	BaseDN         string   `json:"base_dn"`
	BindDN         string   `json:"bind_dn"`
	UserDNTemplate string   `json:"user_dn_template"`
	AllowedCIDRs   []string `json:"allowed_cidrs"`
	AllowUserBind  bool     `json:"allow_user_bind"`
	SizeLimit      int64    `json:"size_limit"`
	// One of: active, disabled.
	Status       string `json:"status"`
	SecretPrefix string `json:"secret_prefix"`
	LastBindAt   *int64 `json:"last_bind_at"`
	CreatedAt    int64  `json:"created_at"`
	// On create and rotate only: the bind password, shown once.
	Secret string `json:"secret"`
}

// LDAPServerClientsUpdateParams is a typed model of the Backend API.
type LDAPServerClientsUpdateParams struct {
	Name string `json:"name,omitempty"`
	// e.g. dc=acme,dc=com
	BaseDN string `json:"base_dn,omitempty"`
	// The service account cn under base_dn.
	BindCn string `json:"bind_cn,omitempty"`
	// Source networks allowed to bind (empty = anywhere).
	AllowedCIDRs  []string `json:"allowed_cidrs,omitempty"`
	AllowUserBind *bool    `json:"allow_user_bind,omitempty"`
	SizeLimit     *int64   `json:"size_limit,omitempty"`
	// One of: active, disabled.
	Status string `json:"status,omitempty"`
}

// LeastPrivilegeApplyParams is a typed model of the Backend API.
type LeastPrivilegeApplyParams struct {
	// One of: api_key, oauth_client, mcp_gateway, agent.
	SubjectType            string `json:"subject_type,omitempty"`
	SubjectID              string `json:"subject_id,omitempty"`
	Digest                 string `json:"digest,omitempty"`
	Days                   *int64 `json:"days,omitempty"`
	AcknowledgeShortWindow *bool  `json:"acknowledge_short_window,omitempty"`
}

// LeastPrivilegeApplyResult is a typed model of the Backend API.
type LeastPrivilegeApplyResult struct {
	Object      string                                                    `json:"object"`
	SubjectType string                                                    `json:"subject_type"`
	SubjectID   string                                                    `json:"subject_id"`
	Applied     bool                                                      `json:"applied"`
	Summary     string                                                    `json:"summary"`
	Changes     []LeastPrivilegeReportResultDataItemSuggestionChangesItem `json:"changes"`
}

// LeastPrivilegeReportResult is a typed model of the Backend API.
type LeastPrivilegeReportResult struct {
	Object      string                               `json:"object"`
	GeneratedAt int64                                `json:"generated_at"`
	WindowDays  int64                                `json:"window_days"`
	Summary     LeastPrivilegeReportResultSummary    `json:"summary"`
	Data        []LeastPrivilegeReportResultDataItem `json:"data"`
}

// LeastPrivilegeReportResultDataItem is a typed model of the Backend API.
type LeastPrivilegeReportResultDataItem struct {
	Object string `json:"object"`
	// One of: api_key, oauth_client, mcp_gateway, agent.
	SubjectType string  `json:"subject_type"`
	SubjectID   string  `json:"subject_id"`
	Name        *string `json:"name"`
	WindowDays  int64   `json:"window_days"`
	// How many of the window's days the usage data covers. Use is recorded from the day the feature
	// reached the instance; gateway tool calls come from the audit trail.
	ObservedDays int64 `json:"observed_days"`
	// `low` when the data covers less than the window: a permission used once a month can look unused.
	// One of: high, low.
	Confidence string                                          `json:"confidence"`
	Granted    []LeastPrivilegeReportResultDataItemGrantedItem `json:"granted"`
	Used       []LeastPrivilegeReportResultDataItemUsedItem    `json:"used"`
	Unused     []LeastPrivilegeReportResultDataItemUnusedItem  `json:"unused"`
	// The narrower grant. It only ever removes permissions.
	Suggestion *LeastPrivilegeReportResultDataItemSuggestion `json:"suggestion"`
	// The suggestion can be applied with one call.
	Applicable bool   `json:"applicable"`
	Note       string `json:"note"`
}

// LeastPrivilegeReportResultDataItemGrantedItem is a typed model of the Backend API.
type LeastPrivilegeReportResultDataItemGrantedItem struct {
	// A scope, `tool:<name>`, `<kind>:<resource>` for an agent grant, or `default_policy:allow`.
	Permission string `json:"permission"`
	// One of: scope, tool, grant, default_policy, wildcard.
	Kind   string `json:"kind"`
	Detail string `json:"detail"`
}

// LeastPrivilegeReportResultDataItemSuggestion is the narrower grant. It only ever removes
// permissions.
type LeastPrivilegeReportResultDataItemSuggestion struct {
	Summary string                                                    `json:"summary"`
	Changes []LeastPrivilegeReportResultDataItemSuggestionChangesItem `json:"changes"`
	// Pass it to POST /v1/least_privilege/apply so what you previewed is what is applied.
	Digest string `json:"digest"`
}

// LeastPrivilegeReportResultDataItemSuggestionChangesItem is a typed model of the Backend API.
type LeastPrivilegeReportResultDataItemSuggestionChangesItem struct {
	Field string `json:"field"`
	// A list of scopes, a tool policy map, a default policy, or a list of grant ids, depending on the
	// field.
	Before interface{} `json:"before"`
	// A list of scopes, a tool policy map, a default policy, or a list of grant ids, depending on the
	// field.
	After interface{} `json:"after"`
}

// LeastPrivilegeReportResultDataItemUnusedItem is a typed model of the Backend API.
type LeastPrivilegeReportResultDataItemUnusedItem struct {
	// A scope, `tool:<name>`, `<kind>:<resource>` for an agent grant, or `default_policy:allow`.
	Permission string `json:"permission"`
	// One of: scope, tool, grant, default_policy, wildcard.
	Kind       string      `json:"kind"`
	Detail     string      `json:"detail"`
	LastUsedAt interface{} `json:"last_used_at"`
}

// LeastPrivilegeReportResultDataItemUsedItem is a typed model of the Backend API.
type LeastPrivilegeReportResultDataItemUsedItem struct {
	Permission string `json:"permission"`
	Uses       int64  `json:"uses"`
	LastUsedAt int64  `json:"last_used_at"`
}

// LeastPrivilegeReportResultSummary is a typed model of the Backend API.
type LeastPrivilegeReportResultSummary struct {
	Subjects              int64 `json:"subjects"`
	WithUnused            int64 `json:"with_unused"`
	UnusedPermissions     int64 `json:"unused_permissions"`
	ApplicableSuggestions int64 `json:"applicable_suggestions"`
}

// ListenCreateSessionParams is a typed model of the Backend API.
type ListenCreateSessionParams struct {
	// Event types or patterns to forward, such as `user.created` or `user.*`. Omit for every event.
	Events []string `json:"events,omitempty"`
	// How long the session lives. Default 3600.
	TTLSeconds *int64 `json:"ttl_seconds,omitempty"`
}

// ListenCreateSessionResult is a typed model of the Backend API.
type ListenCreateSessionResult struct {
	// One of: listen_session.
	Object string `json:"object"`
	ID     string `json:"id"`
	// Verify forwarded deliveries with this secret, exactly like a webhook signing secret.
	Secret string   `json:"secret"`
	Events []string `json:"events"`
	// Epoch milliseconds.
	ExpiresAt int64  `json:"expires_at"`
	StreamURL string `json:"stream_url"`
}

// ManagedGrantsListResult is a typed model of the Backend API.
type ManagedGrantsListResult struct {
	Object string                            `json:"object"`
	Data   []ManagedGrantsListResultDataItem `json:"data"`
}

// ManagedGrantsListResultDataItem is a typed model of the Backend API.
type ManagedGrantsListResultDataItem struct {
	Object string `json:"object"`
	// The `grant_id` returned in token responses.
	ID             string  `json:"id"`
	ClientID       *string `json:"client_id"`
	UserID         string  `json:"user_id"`
	OrganizationID *string `json:"organization_id"`
	// One of: active, revoked.
	Status string   `json:"status"`
	Scopes []string `json:"scopes"`
	// The API (resource server identifier) the grant covers, or null.
	Resource             *string                  `json:"resource"`
	AuthorizationDetails []map[string]interface{} `json:"authorization_details"`
	// Bumped by every merge, replace and narrowing.
	Revision  int64  `json:"revision"`
	CreatedAt int64  `json:"created_at"`
	UpdatedAt int64  `json:"updated_at"`
	RevokedAt *int64 `json:"revoked_at"`
	// One of: client, user, admin, system, .
	RevokedBy *string `json:"revoked_by"`
}

// ManagedGrantsNarrowParams is a typed model of the Backend API.
type ManagedGrantsNarrowParams struct {
	Scopes               []string                 `json:"scopes,omitempty"`
	AuthorizationDetails []map[string]interface{} `json:"authorization_details,omitempty"`
}

// ManagedGrantsRevokeResult is a typed model of the Backend API.
type ManagedGrantsRevokeResult struct {
	Object      string `json:"object"`
	ID          string `json:"id"`
	Deleted     bool   `json:"deleted"`
	TokensEnded int64  `json:"tokens_ended"`
}

// MarketingGetSettingsResult is a typed model of the Backend API.
type MarketingGetSettingsResult struct {
	Object  string                            `json:"object"`
	Capture MarketingGetSettingsResultCapture `json:"capture"`
	Scripts MarketingGetSettingsResultScripts `json:"scripts"`
}

// MarketingGetSettingsResultCapture is a typed model of the Backend API.
type MarketingGetSettingsResultCapture struct {
	Enabled         bool     `json:"enabled"`
	Params          []string `json:"params"`
	DefaultParams   []string `json:"default_params"`
	ConsentCategory string   `json:"consent_category"`
}

// MarketingGetSettingsResultScripts is a typed model of the Backend API.
type MarketingGetSettingsResultScripts struct {
	Ga4MeasurementID *string `json:"ga4_measurement_id"`
	GtmContainerID   *string `json:"gtm_container_id"`
	HotjarSiteID     *int64  `json:"hotjar_site_id"`
	ConsentCategory  string  `json:"consent_category"`
}

// MarketingListLeadsItem is a typed model of the Backend API.
type MarketingListLeadsItem struct {
	ID         string                 `json:"id"`
	Email      string                 `json:"email"`
	Name       *string                `json:"name"`
	Form       string                 `json:"form"`
	Consent    bool                   `json:"consent"`
	FirstTouch map[string]interface{} `json:"first_touch"`
	CreatedAt  int64                  `json:"created_at"`
}

// MarketingUpdateSettingsParams is a typed model of the Backend API.
type MarketingUpdateSettingsParams struct {
	Capture *MarketingUpdateSettingsParamsCapture `json:"capture,omitempty"`
	Scripts *MarketingUpdateSettingsParamsScripts `json:"scripts,omitempty"`
}

// MarketingUpdateSettingsParamsCapture is a typed model of the Backend API.
type MarketingUpdateSettingsParamsCapture struct {
	Enabled         *bool    `json:"enabled,omitempty"`
	Params          []string `json:"params,omitempty"`
	ConsentCategory string   `json:"consent_category,omitempty"`
}

// MarketingUpdateSettingsParamsScripts is a typed model of the Backend API.
type MarketingUpdateSettingsParamsScripts struct {
	// G-XXXXXXXX, or null to remove.
	Ga4MeasurementID *string `json:"ga4_measurement_id,omitempty"`
	// GTM-XXXXXXX, or null to remove.
	GtmContainerID  *string `json:"gtm_container_id,omitempty"`
	HotjarSiteID    *int64  `json:"hotjar_site_id,omitempty"`
	ConsentCategory string  `json:"consent_category,omitempty"`
}

// MCPGatewaysBudgetsCreateParams is a typed model of the Backend API.
type MCPGatewaysBudgetsCreateParams struct {
	Name string `json:"name,omitempty"`
	// One of: agent, session.
	Scope string `json:"scope,omitempty"`
	// One of: calls, cost, rate.
	Metric string `json:"metric,omitempty"`
	// The ceiling, in calls or cost units.
	Limit *float64 `json:"limit,omitempty"`
	// Fixed window length in seconds; null never resets. Required for rate.
	WindowSeconds *int64  `json:"window_seconds,omitempty"`
	AgentID       *string `json:"agent_id,omitempty"`
	Tool          *string `json:"tool,omitempty"`
	// cost: what one call costs when cost_arg is not set. Default 1.
	CostPerCall *float64 `json:"cost_per_call,omitempty"`
	// cost: dot path to a number in the call arguments that is the cost of the call.
	CostArg *string `json:"cost_arg,omitempty"`
	Enabled *bool   `json:"enabled,omitempty"`
}

// MCPGatewaysBudgetsListResult is a typed model of the Backend API.
type MCPGatewaysBudgetsListResult struct {
	Object  string                                 `json:"object"`
	Data    []MCPGatewaysBudgetsListResultDataItem `json:"data"`
	HasMore bool                                   `json:"has_more"`
}

// MCPGatewaysBudgetsListResultDataItem is a typed model of the Backend API.
type MCPGatewaysBudgetsListResultDataItem struct {
	Object    string `json:"object"`
	ID        string `json:"id"`
	GatewayID string `json:"gateway_id"`
	Name      string `json:"name"`
	// One of: agent, session.
	Scope   string  `json:"scope"`
	AgentID *string `json:"agent_id"`
	Tool    *string `json:"tool"`
	// One of: calls, cost, rate.
	Metric        string  `json:"metric"`
	Limit         float64 `json:"limit"`
	WindowSeconds *int64  `json:"window_seconds"`
	CostPerCall   float64 `json:"cost_per_call"`
	CostArg       *string `json:"cost_arg"`
	Enabled       bool    `json:"enabled"`
	CreatedAt     int64   `json:"created_at"`
}

// MCPGatewaysBudgetsUsageResult is a typed model of the Backend API.
type MCPGatewaysBudgetsUsageResult struct {
	Object    string  `json:"object"`
	BudgetID  string  `json:"budget_id"`
	AgentID   string  `json:"agent_id"`
	Used      float64 `json:"used"`
	Limit     float64 `json:"limit"`
	Remaining float64 `json:"remaining"`
	ResetsAt  *int64  `json:"resets_at"`
}

// MCPGatewaysCreateParams is a typed model of the Backend API.
type MCPGatewaysCreateParams struct {
	Name                  string `json:"name"`
	UpstreamURL           string `json:"upstream_url"`
	UpstreamAuthorization string `json:"upstream_authorization,omitempty"`
	// One of: allow, deny.
	DefaultPolicy string `json:"default_policy,omitempty"`
	Enabled       *bool  `json:"enabled,omitempty"`
	// Authorize every tool call through the ABAC policy engine as well as the tool policy. The
	// principal is the agent (type Agent, with name, tier, owner_user_id, organization_id, scopes,
	// data), the action is the tool name, and the resource is the tool (type McpTool, with gateway_id,
	// gateway_name, tool an
	ABAC *MCPGatewaysCreateParamsABAC `json:"abac,omitempty"`
	// Tool name to { allow?, scopes?, conditions?: [{ arg, op: eq|neq|lte|gte|in|not_in|present, value
	// }], approval?, mask?: { fields?, presets?: email|card|ssn|phone } }.
	Tools map[string]interface{} `json:"tools,omitempty"`
}

// MCPGatewaysCreateParamsABAC is authorize every tool call through the ABAC policy engine as well
// as the tool policy. The principal is the agent (type Agent, with name, tier, owner_user_id,
// organization_id, scopes, data), the action is the tool name, and the resource is the tool (type
// McpTool, with gateway_id, gateway_name, tool an
type MCPGatewaysCreateParamsABAC struct {
	Enabled   *bool    `json:"enabled,omitempty"`
	PolicyIDs []string `json:"policy_ids,omitempty"`
}

// MCPGatewaysUpdateParams is a typed model of the Backend API.
type MCPGatewaysUpdateParams struct {
	// Authorize every tool call through the ABAC policy engine as well as the tool policy. The
	// principal is the agent (type Agent, with name, tier, owner_user_id, organization_id, scopes,
	// data), the action is the tool name, and the resource is the tool (type McpTool, with gateway_id,
	// gateway_name, tool an
	ABAC *MCPGatewaysCreateParamsABAC `json:"abac,omitempty"`
}

// MFAFactorsDuoHealthCheckResult is a typed model of the Backend API.
type MFAFactorsDuoHealthCheckResult struct {
	Object  string `json:"object"`
	Ok      bool   `json:"ok"`
	Message string `json:"message"`
}

// MFAFactorsRemoveYubicoSecretResult is a typed model of the Backend API.
type MFAFactorsRemoveYubicoSecretResult struct {
	Object  string `json:"object"`
	Deleted bool   `json:"deleted"`
}

// MFAFactorsResetSecurityQuestionsResult is a typed model of the Backend API.
type MFAFactorsResetSecurityQuestionsResult struct {
	Object  string `json:"object"`
	UserID  string `json:"user_id"`
	Deleted bool   `json:"deleted"`
}

// MFAFactorsSetDuoSecretParams is a typed model of the Backend API.
type MFAFactorsSetDuoSecretParams struct {
	// Duo client secret.
	Secret string `json:"secret"`
}

// MFAFactorsSetSmartCardSecretParams is a typed model of the Backend API.
type MFAFactorsSetSmartCardSecretParams struct {
	// Random shared secret, 24 characters or more.
	Secret string `json:"secret"`
}

// MFAFactorsSetYubicoSecretParams is a typed model of the Backend API.
type MFAFactorsSetYubicoSecretParams struct {
	// Base64 secret key.
	Secret string `json:"secret"`
}

// MFAFactorsSetYubicoSecretResult is a typed model of the Backend API.
type MFAFactorsSetYubicoSecretResult struct {
	Object string `json:"object"`
	Set    bool   `json:"set"`
}

// MFAFactorsSmartCardMappingsAddParams is a typed model of the Backend API.
type MFAFactorsSmartCardMappingsAddParams struct {
	// One of: san_email, san_upn, subject_cn, serial, fingerprint.
	Kind  string `json:"kind"`
	Value string `json:"value"`
	// Issuer DN. Required for kind "serial".
	Issuer string `json:"issuer,omitempty"`
	Label  string `json:"label,omitempty"`
}

// MFAFactorsSmartCardMappingsListResult is a typed model of the Backend API.
type MFAFactorsSmartCardMappingsListResult struct {
	Object string                                          `json:"object"`
	Data   []MFAFactorsSmartCardMappingsListResultDataItem `json:"data"`
}

// MFAFactorsSmartCardMappingsListResultDataItem is a typed model of the Backend API.
type MFAFactorsSmartCardMappingsListResultDataItem struct {
	Object string `json:"object"`
	ID     string `json:"id"`
	UserID string `json:"user_id"`
	// One of: san_email, san_upn, subject_cn, serial, fingerprint.
	Kind string `json:"kind"`
	// The normalised value: lowercase; fingerprint 64 hex; serial as "<issuer DN>#<serial hex>".
	Value      string  `json:"value"`
	Label      *string `json:"label"`
	LastUsedAt *int64  `json:"last_used_at"`
	CreatedAt  int64   `json:"created_at"`
}

// MFAFactorsYubikeysListResult is a typed model of the Backend API.
type MFAFactorsYubikeysListResult struct {
	Object string                                 `json:"object"`
	Data   []MFAFactorsYubikeysListResultDataItem `json:"data"`
}

// MFAFactorsYubikeysListResultDataItem is a typed model of the Backend API.
type MFAFactorsYubikeysListResultDataItem struct {
	Object   string  `json:"object"`
	ID       string  `json:"id"`
	PublicID string  `json:"public_id"`
	Label    *string `json:"label"`
	// The user the key belongs to, once assigned or enrolled.
	UserID       *string `json:"user_id"`
	HasPrivateID bool    `json:"has_private_id"`
	// The highest use/session counter accepted so far (replay guard).
	LastCounter *int64 `json:"last_counter"`
	CreatedAt   int64  `json:"created_at"`
}

// MFAFactorsYubikeysRegisterParams is a typed model of the Backend API.
type MFAFactorsYubikeysRegisterParams struct {
	// Modhex prefix printed on the key (2 to 16 characters).
	PublicID string `json:"public_id"`
	// 32 hex characters.
	AESKey string `json:"aes_key"`
	// Optional 12 hex characters; when given the decrypted token must carry it.
	PrivateID string `json:"private_id,omitempty"`
	Label     string `json:"label,omitempty"`
	UserID    string `json:"user_id,omitempty"`
}

// MigrationsDeleteBridgeResult is a typed model of the Backend API.
type MigrationsDeleteBridgeResult struct {
	Object  string `json:"object"`
	Source  string `json:"source"`
	Deleted bool   `json:"deleted"`
}

// MigrationsExchangeParams is a typed model of the Backend API.
type MigrationsExchangeParams struct {
	// The old session token (JWT or opaque), as the middleware extracted it.
	Token string `json:"token"`
	// false records a browser-session (non-persistent) session. Default true.
	Remember *bool `json:"remember,omitempty"`
}

// MigrationsExchangeResult is object "session" (cookie delivery), "session_tokens" (body delivery)
// or "sign_in_attempt" (a second factor is still owed).
type MigrationsExchangeResult struct {
	// One of: session, session_tokens, sign_in_attempt.
	Object    string `json:"object"`
	ID        string `json:"id"`
	SessionID string `json:"session_id"`
	UserID    string `json:"user_id"`
	JWT       string `json:"jwt"`
	// Body delivery only.
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
	// One of: needs_second_factor, needs_mfa_enrollment, needs_policy_acceptance.
	Status                string      `json:"status"`
	Identifier            *string     `json:"identifier"`
	SupportedFirstFactors []string    `json:"supported_first_factors"`
	CreatedSessionID      interface{} `json:"created_session_id"`
	ExpiresAt             int64       `json:"expires_at"`
}

// MigrationsGetBridgeResult is a typed model of the Backend API.
type MigrationsGetBridgeResult struct {
	Object  string `json:"object"`
	Source  string `json:"source"`
	Enabled bool   `json:"enabled"`
	// End of the migration window, or null (Unix milliseconds).
	EndsAt *int64 `json:"ends_at"`
	// One of: jwt, session_table, remote.
	Mode                string            `json:"mode"`
	Preset              *string           `json:"preset"`
	PresetVars          map[string]string `json:"preset_vars"`
	Issuer              *string           `json:"issuer"`
	JWKSURL             *string           `json:"jwks_url"`
	Audience            []string          `json:"audience"`
	Algorithms          []string          `json:"algorithms"`
	ClaimMap            map[string]string `json:"claim_map"`
	ExpiredGraceSeconds int64             `json:"expired_grace_seconds"`
	CookieNames         []string          `json:"cookie_names"`
	CreateUsers         bool              `json:"create_users"`
	// Whether an HS256 secret is stored — never the secret.
	HasSharedSecret bool `json:"has_shared_secret"`
	// The Frontend API path the SDKs call.
	ExchangePath string                         `json:"exchange_path"`
	Stats        MigrationsGetBridgeResultStats `json:"stats"`
	// Created, or null when never configured (Unix milliseconds).
	CreatedAt *int64 `json:"created_at"`
	// Updated, or null when never configured (Unix milliseconds).
	UpdatedAt *int64 `json:"updated_at"`
}

// MigrationsGetBridgeResultStats is a typed model of the Backend API.
type MigrationsGetBridgeResultStats struct {
	Exchanged  int64 `json:"exchanged"`
	FromImport int64 `json:"from_import"`
	FromJWT    int64 `json:"from_jwt"`
}

// MigrationsImportsApplyParams is a typed model of the Backend API.
type MigrationsImportsApplyParams struct {
	ConfirmConflicts *bool `json:"confirm_conflicts,omitempty"`
}

// MigrationsImportsCreateParams is a typed model of the Backend API.
type MigrationsImportsCreateParams struct {
	// What the import does. Every field is optional; an unknown field is refused. A `better_auth`
	// import takes the Better Auth options (see /v1/better_auth_imports); every other source takes
	// these.
	Options *MigrationsImportsCreateParamsOptions `json:"options,omitempty"`
}

// MigrationsImportsCreateParamsOptions is what the import does. Every field is optional; an
// unknown field is refused. A `better_auth` import takes the Better Auth options (see
// /v1/better_auth_imports); every other source takes these.
type MigrationsImportsCreateParamsOptions struct {
	// Only these canonical models. Default: all.
	Models []string `json:"models,omitempty"`
	// A user whose verified email belongs to an Atlas user from elsewhere: skip it (reported as a
	// conflict) or merge into that user. One of: skip, link.
	OnEmailConflict string `json:"on_email_conflict,omitempty"`
	// Create an Atlas app role for each source app role that has none.
	CreateAppRoles *bool `json:"create_app_roles,omitempty"`
	// Carry identities' access and refresh tokens (re-encrypted under the instance key).
	ImportOAuthTokens *bool `json:"import_oauth_tokens,omitempty"`
	// Passkeys registered for another relying-party id than the instance's. One of: skip, import.
	PasskeysOnRPMismatch string `json:"passkeys_on_rp_mismatch,omitempty"`
	// Import still-valid sessions (token hashes) for the zero-logout bridge.
	ImportSessions *bool `json:"import_sessions,omitempty"`
	// Publish the source's JWT public keys in the instance JWKS for the cutover.
	ImportJWKS      *bool  `json:"import_jwks,omitempty"`
	JWKSCutoverDays *int64 `json:"jwks_cutover_days,omitempty"`
	// Source provider name → Atlas provider key, for providers the source names differently (e.g.
	// {"oauth_custom_acme": "acme"}).
	ProviderMap map[string]string `json:"provider_map,omitempty"`
	// Hash parameters that live outside the export, per algorithm id, merged into every password of
	// that algorithm (e.g. {"scrypt_firebase": {"signer_key": "…", "salt_separator": "Bw==", "rounds":
	// 8, "mem_cost": 14}}).
	PasswordHashParams map[string]map[string]interface{} `json:"password_hash_params,omitempty"`
	// Keep the sealed bundle after a successful apply (it is deleted by default).
	RetainBundle *bool `json:"retain_bundle,omitempty"`
}

// MigrationsImportsCreateResult is a typed model of the Backend API.
type MigrationsImportsCreateResult struct {
	Object string `json:"object"`
	ID     string `json:"id"`
	Source string `json:"source"`
	// One of: atlas-migration-bundle, atlas-better-auth-bundle.
	Format string `json:"format"`
	// One of: uploading, analyzing, ready, invalid, queued, applying, completed, failed.
	Status       string                 `json:"status"`
	KeyID        *string                `json:"key_id"`
	Parts        int64                  `json:"parts"`
	Bytes        int64                  `json:"bytes"`
	BundleSHA256 *string                `json:"bundle_sha256"`
	BundlePurged bool                   `json:"bundle_purged"`
	Options      map[string]interface{} `json:"options"`
	// What the exporter reported about the source.
	Manifest *MigrationsImportsCreateResultManifest `json:"manifest"`
	Total    int64                                  `json:"total"`
	Progress *MigrationsImportsCreateResultProgress `json:"progress"`
	// The dry run: what an apply would do.
	Report         *MigrationsImportsCreateResultReport `json:"report"`
	Result         *MigrationsImportsCreateResultResult `json:"result"`
	Error          *MigrationsImportsCreateResultError  `json:"error"`
	CreatedAt      int64                                `json:"created_at"`
	UpdatedAt      int64                                `json:"updated_at"`
	AnalyzedAt     *int64                               `json:"analyzed_at"`
	ApplyStartedAt *int64                               `json:"apply_started_at"`
	CompletedAt    *int64                               `json:"completed_at"`
}

// MigrationsImportsCreateResultError is a typed model of the Backend API.
type MigrationsImportsCreateResultError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// MigrationsImportsCreateResultManifest is what the exporter reported about the source.
type MigrationsImportsCreateResultManifest struct {
	ExportedAt string                                        `json:"exported_at"`
	Exporter   MigrationsImportsCreateResultManifestExporter `json:"exporter"`
	// Tenant domain / project / user pool the data came from.
	Origin        *string  `json:"origin"`
	SourceVersion *string  `json:"source_version"`
	Models        []string `json:"models"`
	Providers     []string `json:"providers"`
	RPID          *string  `json:"rp_id"`
	Warnings      []string `json:"warnings"`
}

// MigrationsImportsCreateResultManifestExporter is a typed model of the Backend API.
type MigrationsImportsCreateResultManifestExporter struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// MigrationsImportsCreateResultProgress is a typed model of the Backend API.
type MigrationsImportsCreateResultProgress struct {
	Total     int64 `json:"total"`
	Processed int64 `json:"processed"`
	Succeeded int64 `json:"succeeded"`
	Failed    int64 `json:"failed"`
	Percent   int64 `json:"percent"`
}

// MigrationsImportsCreateResultReport is the dry run: what an apply would do.
type MigrationsImportsCreateResultReport struct {
	Models []MigrationsImportsCreateResultReportModelsItem `json:"models"`
	// Users per password-hash algorithm (weak ones are re-hashed on first sign-in).
	PasswordAlgorithms map[string]int64                                     `json:"password_algorithms"`
	Skipped            []MigrationsImportsCreateResultReportSkippedItem     `json:"skipped"`
	SkippedTotal       int64                                                `json:"skipped_total"`
	SkippedByCode      map[string]int64                                     `json:"skipped_by_code"`
	Conflicts          []MigrationsImportsCreateResultReportConflictsItem   `json:"conflicts"`
	ConflictsTotal     int64                                                `json:"conflicts_total"`
	ActionItems        []MigrationsImportsCreateResultReportActionItemsItem `json:"action_items"`
	Warnings           []string                                             `json:"warnings"`
	Notes              map[string]interface{}                               `json:"notes"`
}

// MigrationsImportsCreateResultReportActionItemsItem is a typed model of the Backend API.
type MigrationsImportsCreateResultReportActionItemsItem struct {
	Code string `json:"code"`
	// One of: required, recommended, info.
	Severity string   `json:"severity"`
	Message  string   `json:"message"`
	Count    int64    `json:"count"`
	Items    []string `json:"items"`
}

// MigrationsImportsCreateResultReportConflictsItem is a typed model of the Backend API.
type MigrationsImportsCreateResultReportConflictsItem struct {
	Model   string  `json:"model"`
	RowID   *string `json:"row_id"`
	Code    string  `json:"code"`
	Message string  `json:"message"`
	// One of: merge, skip.
	Resolution string  `json:"resolution"`
	ExistingID *string `json:"existing_id"`
}

// MigrationsImportsCreateResultReportModelsItem is a typed model of the Backend API.
type MigrationsImportsCreateResultReportModelsItem struct {
	Model      string `json:"model"`
	Label      string `json:"label"`
	Found      int64  `json:"found"`
	WillCreate int64  `json:"will_create"`
	WillUpdate int64  `json:"will_update"`
	WillSkip   int64  `json:"will_skip"`
}

// MigrationsImportsCreateResultReportSkippedItem is a typed model of the Backend API.
type MigrationsImportsCreateResultReportSkippedItem struct {
	Model      string  `json:"model"`
	RowID      *string `json:"row_id"`
	ReasonCode string  `json:"reason_code"`
	Reason     string  `json:"reason"`
}

// MigrationsImportsCreateResultResult is a typed model of the Backend API.
type MigrationsImportsCreateResultResult struct {
	Models         []MigrationsImportsCreateResultResultModelsItem      `json:"models"`
	CompletedAt    *int64                                               `json:"completed_at"`
	Skipped        []MigrationsImportsCreateResultReportSkippedItem     `json:"skipped"`
	SkippedTotal   int64                                                `json:"skipped_total"`
	SkippedByCode  map[string]int64                                     `json:"skipped_by_code"`
	Conflicts      []MigrationsImportsCreateResultReportConflictsItem   `json:"conflicts"`
	ConflictsTotal int64                                                `json:"conflicts_total"`
	ActionItems    []MigrationsImportsCreateResultReportActionItemsItem `json:"action_items"`
	Warnings       []string                                             `json:"warnings"`
	Notes          map[string]interface{}                               `json:"notes"`
}

// MigrationsImportsCreateResultResultModelsItem is a typed model of the Backend API.
type MigrationsImportsCreateResultResultModelsItem struct {
	Model     string `json:"model"`
	Label     string `json:"label"`
	Found     int64  `json:"found"`
	Created   int64  `json:"created"`
	Updated   int64  `json:"updated"`
	Unchanged int64  `json:"unchanged"`
	Skipped   int64  `json:"skipped"`
	Failed    int64  `json:"failed"`
}

// MigrationsImportsGetPublicKeyResult is a typed model of the Backend API.
type MigrationsImportsGetPublicKeyResult struct {
	Object string `json:"object"`
	Kid    string `json:"kid"`
	// base64url raw X25519 public key. One key serves every source.
	PublicKey string `json:"public_key"`
	Alg       string `json:"alg"`
	// One of: active, retired.
	Status string `json:"status"`
	// SHA-256 of the raw key, first 16 bytes as hex pairs: compare it with what the exporter prints.
	Fingerprint string `json:"fingerprint"`
	// The `kid:public_key` form the exporters accept.
	Compact   string `json:"compact"`
	CreatedAt int64  `json:"created_at"`
	RetiredAt *int64 `json:"retired_at"`
}

// MigrationsImportsPutPartParams is a typed model of the Backend API.
type MigrationsImportsPutPartParams struct {
	// Lines of the sealed bundle file.
	Data string `json:"data"`
}

// MigrationsImportsPutPartResult is a typed model of the Backend API.
type MigrationsImportsPutPartResult struct {
	Object   string `json:"object"`
	ImportID string `json:"import_id"`
	Part     int64  `json:"part"`
	Bytes    int64  `json:"bytes"`
	SHA256   string `json:"sha256"`
}

// MigrationsSetBridgeParams is a typed model of the Backend API.
type MigrationsSetBridgeParams struct {
	// Whether the exchange accepts old sessions. Default false.
	Enabled *bool `json:"enabled,omitempty"`
	// End of the migration window (ISO-8601 or Unix ms); null = open until disabled.
	EndsAt interface{} `json:"ends_at,omitempty"`
	// jwt: the old session is a vendor JWT. session_table: an opaque token matched against imported
	// sessions. remote: the vendor is asked about the token with the preset's call (vendors whose
	// sessions only they can check; needs a preset with a remote check). Default: the preset's. One
	// of: jwt, session_table, remote.
	Mode string `json:"mode,omitempty"`
	// A bridge preset (GET /v1/migrations/sources lists them): fills issuer, keys URL, audience,
	// algorithms, claims and cookie names from preset_vars.
	Preset *string `json:"preset,omitempty"`
	// The preset's variables, e.g. {"domain": "acme.us.auth0.com"} or {"region": "us-east-1",
	// "user_pool_id": "…", "client_id": "…"}.
	PresetVars map[string]string `json:"preset_vars,omitempty"`
	// Override: the `iss` the old tokens carry.
	Issuer *string `json:"issuer,omitempty"`
	// Override: where the old signing keys are (public https on production).
	JWKSURL *string `json:"jwks_url,omitempty"`
	// Override: accepted `aud` values; null = unchecked.
	Audience   []string                           `json:"audience,omitempty"`
	Algorithms []string                           `json:"algorithms,omitempty"`
	ClaimMap   *MigrationsSetBridgeParamsClaimMap `json:"claim_map,omitempty"`
	// Accept a validly signed token this long past exp (still single use). For vendors whose cookie
	// token is refreshed by their client SDK only.
	ExpiredGraceSeconds *int64 `json:"expired_grace_seconds,omitempty"`
	// Where the SDK middleware finds the token (* wildcards). Default: the preset's.
	CookieNames []string `json:"cookie_names,omitempty"`
	// Create an Atlas user for a valid token whose subject was never imported (needs a verified email
	// claim). Default false.
	CreateUsers *bool `json:"create_users,omitempty"`
	// Write-only HS256 secret, for vendors that sign with one (Supabase legacy JWT secret). Omit to
	// keep, null to clear.
	SharedSecret *string `json:"shared_secret,omitempty"`
}

// MigrationsSetBridgeParamsClaimMap is a typed model of the Backend API.
type MigrationsSetBridgeParamsClaimMap struct {
	// Claim holding the source user id (default sub).
	Subject       string `json:"subject,omitempty"`
	Email         string `json:"email,omitempty"`
	EmailVerified string `json:"email_verified,omitempty"`
	Name          string `json:"name,omitempty"`
	// Claim spent in the single-use ledger (jti / sid); the whole token when absent.
	SessionKey string `json:"session_key,omitempty"`
	// amr:mfa | acr:<value> | claim:<name>.
	MFA string `json:"mfa,omitempty"`
}

// MigrationsSourcesItem is a typed model of the Backend API.
type MigrationsSourcesItem struct {
	Object string   `json:"object"`
	Source string   `json:"source"`
	Label  string   `json:"label"`
	Models []string `json:"models"`
	// export: hashes are exported and verified by Atlas. ticket: only through the vendor's support.
	// lazy: never exported, use the lazy-migration preset. none: passwordless. One of: export, ticket,
	// lazy, none.
	Passwords     string                              `json:"passwords"`
	ExportVia     []string                            `json:"export_via"`
	Bridge        MigrationsSourcesItemBridge         `json:"bridge"`
	LazyMigration *MigrationsSourcesItemLazyMigration `json:"lazy_migration"`
	// Hash algorithm ids Atlas verifies (the registry).
	PasswordAlgorithms []string `json:"password_algorithms"`
	Limits             *string  `json:"limits"`
}

// MigrationsSourcesItemBridge is a typed model of the Backend API.
type MigrationsSourcesItemBridge struct {
	// One of: jwt, session_table, remote, none.
	Mode   string  `json:"mode"`
	Preset *string `json:"preset"`
	// Variable → hint.
	Vars    map[string]string `json:"vars"`
	Cookies []string          `json:"cookies"`
}

// MigrationsSourcesItemLazyMigration is a typed model of the Backend API.
type MigrationsSourcesItemLazyMigration struct {
	Preset string `json:"preset"`
	// Setting → { label, required }.
	Config map[string]interface{}                    `json:"config"`
	Secret *MigrationsSourcesItemLazyMigrationSecret `json:"secret"`
}

// MigrationsSourcesItemLazyMigrationSecret is a typed model of the Backend API.
type MigrationsSourcesItemLazyMigrationSecret struct {
	Label    string `json:"label"`
	Required bool   `json:"required"`
}

// NetworkZonesCheckParams is a typed model of the Backend API.
type NetworkZonesCheckParams struct {
	IP string `json:"ip,omitempty"`
}

// NetworkZonesCheckResult is a typed model of the Backend API.
type NetworkZonesCheckResult struct {
	Object string `json:"object"`
	ZoneID string `json:"zone_id"`
	// The address checked, normalised.
	IP string `json:"ip"`
	// Whether the address falls inside the zone (always false while the zone is disabled).
	Matches bool `json:"matches"`
	// What Atlas knows about the address; null where it has no data.
	Facts NetworkZonesCheckResultFacts `json:"facts"`
}

// NetworkZonesCheckResultFacts is what Atlas knows about the address; null where it has no data.
type NetworkZonesCheckResultFacts struct {
	// ISO 3166-1 alpha-2 country code.
	Country *string `json:"country"`
	// Autonomous system number.
	ASN *int64 `json:"asn"`
	// A Tor exit node.
	Tor *bool `json:"tor"`
	// A hosting or datacenter range.
	Datacenter *bool `json:"datacenter"`
}

// NetworkZonesCreateParams is a typed model of the Backend API.
type NetworkZonesCreateParams struct {
	Name        string   `json:"name,omitempty"`
	Description *string  `json:"description,omitempty"`
	CIDRs       []string `json:"cidrs,omitempty"`
	Countries   []string `json:"countries,omitempty"`
	Asns        []int64  `json:"asns,omitempty"`
	Anonymizers []string `json:"anonymizers,omitempty"`
	Enabled     *bool    `json:"enabled,omitempty"`
}

// NetworkZonesListItem is a typed model of the Backend API.
type NetworkZonesListItem struct {
	Object      string   `json:"object"`
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description *string  `json:"description"`
	CIDRs       []string `json:"cidrs"`
	// ISO 3166-1 alpha-2, upper case.
	Countries   []string `json:"countries"`
	Asns        []int64  `json:"asns"`
	Anonymizers []string `json:"anonymizers"`
	Enabled     bool     `json:"enabled"`
	// Created (epoch ms).
	CreatedAt int64 `json:"created_at"`
	// Last updated (epoch ms).
	UpdatedAt int64 `json:"updated_at"`
}

// OAuthClientProfilesListItem is a typed model of the Backend API.
type OAuthClientProfilesListItem struct {
	Object      string  `json:"object"`
	Name        string  `json:"name"`
	Builtin     bool    `json:"builtin"`
	Description *string `json:"description"`
	RequirePKCE bool    `json:"require_pkce"`
	// Authorization requests must be pushed (RFC 9126).
	RequirePar bool `json:"require_par"`
	// The token request must prove DPoP, mutual TLS, or either (any). One of: none, dpop, mtls, any.
	SenderConstraint string `json:"sender_constraint"`
	// Authorization requests must be a signed request object (RFC 9101), pushed or direct.
	RequireSignedRequest bool `json:"require_signed_request"`
	// Allowed client authentication methods; null = any.
	TokenEndpointAuthMethods []string `json:"token_endpoint_auth_methods"`
	// JWS algorithms accepted for request objects and client assertions; null = any asymmetric.
	SigningAlgs        []string `json:"signing_algs"`
	HttpsRedirectsOnly bool     `json:"https_redirects_only"`
	// Claim names a `claims` request may ask for; null = any.
	AllowedClaims []string `json:"allowed_claims"`
}

// OAuthClientProfilesSetParams is a typed model of the Backend API.
type OAuthClientProfilesSetParams struct {
	Description *string `json:"description,omitempty"`
	RequirePKCE *bool   `json:"require_pkce,omitempty"`
	// Authorization requests must be pushed (RFC 9126).
	RequirePar *bool `json:"require_par,omitempty"`
	// The token request must prove DPoP, mutual TLS, or either (any). One of: none, dpop, mtls, any.
	SenderConstraint string `json:"sender_constraint,omitempty"`
	// Authorization requests must be a signed request object (RFC 9101), pushed or direct.
	RequireSignedRequest *bool `json:"require_signed_request,omitempty"`
	// Allowed client authentication methods; null = any.
	TokenEndpointAuthMethods []string `json:"token_endpoint_auth_methods,omitempty"`
	// JWS algorithms accepted for request objects and client assertions; null = any asymmetric.
	SigningAlgs        []string `json:"signing_algs,omitempty"`
	HttpsRedirectsOnly *bool    `json:"https_redirects_only,omitempty"`
	// Claim names a `claims` request may ask for; null = any.
	AllowedClaims []string `json:"allowed_claims,omitempty"`
}

// OAuthClientsAppSettingsGetResult is a typed model of the Backend API.
type OAuthClientsAppSettingsGetResult struct {
	Object   string `json:"object"`
	ClientID string `json:"client_id"`
	// The sign-in methods a session must have used for this app: password, email_code, email_link,
	// passkey, phone_code, siwe, siws, siwf, a provider such as oauth_google, or the families oauth
	// (any social provider) and enterprise_sso (any enterprise connection). The hosted pages offer
	// only these when the
	AllowedSignInMethods []string `json:"allowed_sign_in_methods"`
	// The heading, sub-heading, logo and primary colour of the hosted sign-in and sign-up pages when
	// the sign-in is for this app.
	Branding *OAuthClientsAppSettingsGetResultBranding `json:"branding"`
	// The user claims this app receives in its ID token and from userinfo (for example email, name,
	// org_id). Protocol claims (iss, sub, aud, exp, iat, nonce, auth_time, acr, amr, azp, sid) always
	// pass. [] = protocol claims only.
	ClaimsAllowlist []string `json:"claims_allowlist"`
	// The identity traits a session that came from this app (a native app that exchanged its token for
	// a session) may change through PATCH /v1/client/me. Others are refused with 403.
	WritableTraits []string `json:"writable_traits"`
	// Overrides of the instance's riskBasedMfa for sign-ins to this app (a sign-in started from this
	// app's /oauth2/authorize request). A field left null keeps the instance value; weights, signals
	// and reputation feeds stay instance-wide.
	Risk *OAuthClientsAppSettingsGetResultRisk `json:"risk"`
}

// OAuthClientsAppSettingsGetResultBranding is the heading, sub-heading, logo and primary colour of
// the hosted sign-in and sign-up pages when the sign-in is for this app.
type OAuthClientsAppSettingsGetResultBranding struct {
	Heading    *string `json:"heading"`
	Subheading *string `json:"subheading"`
	// An https URL.
	LogoURL *string `json:"logo_url"`
	// A hex, rgb() or named CSS colour.
	PrimaryColor *string `json:"primary_color"`
}

// OAuthClientsAppSettingsGetResultRisk is overrides of the instance's riskBasedMfa for sign-ins to
// this app (a sign-in started from this app's /oauth2/authorize request). A field left null keeps
// the instance value; weights, signals and reputation feeds stay instance-wide.
type OAuthClientsAppSettingsGetResultRisk struct {
	// Turn risk-based MFA on or off for sign-ins to this app.
	Enabled *bool `json:"enabled"`
	// audit scores and records sign-ins without changing them. One of: enforce, audit, .
	Mode interface{} `json:"mode"`
	// One of: low, medium, high, .
	StepUpThreshold interface{} `json:"step_up_threshold"`
	// One of: allow, block, require_enroll, .
	OnHighRiskNoFactor interface{}                                       `json:"on_high_risk_no_factor"`
	LevelActions       *OAuthClientsAppSettingsGetResultRiskLevelActions `json:"level_actions"`
	// The refresh-time check for sessions that came from this app (its native token exchange).
	MidSession *OAuthClientsAppSettingsGetResultRiskMidSession `json:"mid_session"`
}

// OAuthClientsAppSettingsGetResultRiskLevelActions is a typed model of the Backend API.
type OAuthClientsAppSettingsGetResultRiskLevelActions struct {
	// One of: default, allow, notify, mfa, block, .
	Medium interface{} `json:"medium"`
	// One of: default, allow, notify, mfa, block, .
	High interface{} `json:"high"`
}

// OAuthClientsAppSettingsGetResultRiskMidSession is the refresh-time check for sessions that came
// from this app (its native token exchange).
type OAuthClientsAppSettingsGetResultRiskMidSession struct {
	Enabled *bool `json:"enabled"`
	// One of: revoke, notify, audit, .
	Action interface{} `json:"action"`
}

// OAuthClientsAppSettingsUpdateParams is a typed model of the Backend API.
type OAuthClientsAppSettingsUpdateParams struct {
	// The sign-in methods a session must have used for this app: password, email_code, email_link,
	// passkey, phone_code, siwe, siws, siwf, a provider such as oauth_google, or the families oauth
	// (any social provider) and enterprise_sso (any enterprise connection). The hosted pages offer
	// only these when the
	AllowedSignInMethods []string `json:"allowed_sign_in_methods,omitempty"`
	// The heading, sub-heading, logo and primary colour of the hosted sign-in and sign-up pages when
	// the sign-in is for this app.
	Branding *OAuthClientsAppSettingsUpdateParamsBranding `json:"branding,omitempty"`
	// The user claims this app receives in its ID token and from userinfo (for example email, name,
	// org_id). Protocol claims (iss, sub, aud, exp, iat, nonce, auth_time, acr, amr, azp, sid) always
	// pass. [] = protocol claims only.
	ClaimsAllowlist []string `json:"claims_allowlist,omitempty"`
	// The identity traits a session that came from this app (a native app that exchanged its token for
	// a session) may change through PATCH /v1/client/me. Others are refused with 403.
	WritableTraits []string `json:"writable_traits,omitempty"`
	// Overrides of the instance's riskBasedMfa for sign-ins to this app (a sign-in started from this
	// app's /oauth2/authorize request). A field left null keeps the instance value; weights, signals
	// and reputation feeds stay instance-wide.
	Risk *OAuthClientsAppSettingsUpdateParamsRisk `json:"risk,omitempty"`
}

// OAuthClientsAppSettingsUpdateParamsBranding is the heading, sub-heading, logo and primary colour
// of the hosted sign-in and sign-up pages when the sign-in is for this app.
type OAuthClientsAppSettingsUpdateParamsBranding struct {
	Heading    *string `json:"heading,omitempty"`
	Subheading *string `json:"subheading,omitempty"`
	// An https URL.
	LogoURL *string `json:"logo_url,omitempty"`
	// A hex, rgb() or named CSS colour.
	PrimaryColor *string `json:"primary_color,omitempty"`
}

// OAuthClientsAppSettingsUpdateParamsRisk is overrides of the instance's riskBasedMfa for sign-ins
// to this app (a sign-in started from this app's /oauth2/authorize request). A field left null
// keeps the instance value; weights, signals and reputation feeds stay instance-wide.
type OAuthClientsAppSettingsUpdateParamsRisk struct {
	// Turn risk-based MFA on or off for sign-ins to this app.
	Enabled *bool `json:"enabled,omitempty"`
	// audit scores and records sign-ins without changing them. One of: enforce, audit, .
	Mode interface{} `json:"mode,omitempty"`
	// One of: low, medium, high, .
	StepUpThreshold interface{} `json:"step_up_threshold,omitempty"`
	// One of: allow, block, require_enroll, .
	OnHighRiskNoFactor interface{}                                          `json:"on_high_risk_no_factor,omitempty"`
	LevelActions       *OAuthClientsAppSettingsUpdateParamsRiskLevelActions `json:"level_actions,omitempty"`
	// The refresh-time check for sessions that came from this app (its native token exchange).
	MidSession *OAuthClientsAppSettingsUpdateParamsRiskMidSession `json:"mid_session,omitempty"`
}

// OAuthClientsAppSettingsUpdateParamsRiskLevelActions is a typed model of the Backend API.
type OAuthClientsAppSettingsUpdateParamsRiskLevelActions struct {
	// One of: default, allow, notify, mfa, block, .
	Medium interface{} `json:"medium,omitempty"`
	// One of: default, allow, notify, mfa, block, .
	High interface{} `json:"high,omitempty"`
}

// OAuthClientsAppSettingsUpdateParamsRiskMidSession is the refresh-time check for sessions that
// came from this app (its native token exchange).
type OAuthClientsAppSettingsUpdateParamsRiskMidSession struct {
	Enabled *bool `json:"enabled,omitempty"`
	// One of: revoke, notify, audit, .
	Action interface{} `json:"action,omitempty"`
}

// OAuthClientsConsentRequestsAcceptParams is a typed model of the Backend API.
type OAuthClientsConsentRequestsAcceptParams struct {
	// The scopes to grant: a subset of requested_scope that includes openid. Default: all requested.
	GrantScope []string `json:"grant_scope,omitempty"`
	// Record the consent so the user is not asked again. Default true.
	Remember *bool `json:"remember,omitempty"`
}

// OAuthClientsConsentRequestsGetResult is a typed model of the Backend API.
type OAuthClientsConsentRequestsGetResult struct {
	Object string `json:"object"`
	// The signed-in Atlas user id.
	Subject              string                                   `json:"subject"`
	Client               OAuthClientsLoginRequestsGetResultClient `json:"client"`
	RequestedScope       []string                                 `json:"requested_scope"`
	Audience             *string                                  `json:"audience"`
	AuthorizationDetails []map[string]interface{}                 `json:"authorization_details"`
	OrganizationID       *string                                  `json:"organization_id"`
	RedirectURI          string                                   `json:"redirect_uri"`
	// The challenge expires (epoch ms).
	ExpiresAt int64 `json:"expires_at"`
}

// OAuthClientsGetExchangePolicyResult is a typed model of the Backend API.
type OAuthClientsGetExchangePolicyResult struct {
	Object string `json:"object"`
	// The OAuth client row id (oac_…).
	ClientID string `json:"client_id"`
	// Resource server identifiers the client may exchange for; null = any it holds a client grant on.
	AllowedAudiences []string `json:"allowed_audiences"`
	// Scope ceiling applied on top of the client grant; null = no extra limit.
	AllowedScopes []string `json:"allowed_scopes"`
	// Resource authorization server issuers this client may request an ID-JAG (Cross App Access) for;
	// null = none.
	IDJagAudiences []string `json:"id_jag_audiences"`
	// false = the client must present an actor_token (delegation only).
	AllowImpersonation bool `json:"allow_impersonation"`
	// true = delegation needs a subject token carrying may_act.
	RequireMayAct bool `json:"require_may_act"`
	// Deepest act chain the client may produce (1 to 10).
	MaxDelegationDepth int64 `json:"max_delegation_depth"`
	// false = these are the defaults; no policy row exists.
	Configured bool `json:"configured"`
}

// OAuthClientsLoginRequestsAcceptParams is a typed model of the Backend API.
type OAuthClientsLoginRequestsAcceptParams struct {
	// The Atlas user id the visitor authenticated as.
	Subject string `json:"subject"`
	// Keep the Atlas session across browser restarts.
	Remember *bool `json:"remember,omitempty"`
	// Authentication methods used, recorded on the session and echoed in the id_token.
	Amr []string `json:"amr,omitempty"`
	// Authentication context class reached.
	Acr string `json:"acr,omitempty"`
}

// OAuthClientsLoginRequestsAcceptResult is a typed model of the Backend API.
type OAuthClientsLoginRequestsAcceptResult struct {
	Object string `json:"object"`
	// Send the end user’s browser here next.
	RedirectTo string `json:"redirect_to"`
}

// OAuthClientsLoginRequestsGetResult is a typed model of the Backend API.
type OAuthClientsLoginRequestsGetResult struct {
	Object         string                                   `json:"object"`
	Client         OAuthClientsLoginRequestsGetResultClient `json:"client"`
	RequestedScope []string                                 `json:"requested_scope"`
	Audience       *string                                  `json:"audience"`
	// sign-up when the application asked for prompt=create. One of: sign-in, sign-up.
	Page string `json:"page"`
	// The Atlas user already signed in on this browser, if any.
	SessionSubject *string `json:"session_subject"`
	UILocales      *string `json:"ui_locales"`
	LoginHint      *string `json:"login_hint"`
	// The challenge expires (epoch ms).
	ExpiresAt int64 `json:"expires_at"`
}

// OAuthClientsLoginRequestsGetResultClient is a typed model of the Backend API.
type OAuthClientsLoginRequestsGetResultClient struct {
	ID         string `json:"id"`
	ClientID   string `json:"client_id"`
	Name       string `json:"name"`
	FirstParty bool   `json:"first_party"`
}

// OAuthClientsLoginRequestsRejectParams is a typed model of the Backend API.
type OAuthClientsLoginRequestsRejectParams struct {
	// The OAuth error returned to the application. Default access_denied. One of: access_denied,
	// login_required, interaction_required, consent_required, account_selection_required,
	// unauthorized_client, temporarily_unavailable, server_error.
	Error            string `json:"error,omitempty"`
	ErrorDescription string `json:"error_description,omitempty"`
}

// OAuthClientsSetDelegatedUIParams is a typed model of the Backend API.
type OAuthClientsSetDelegatedUIParams struct {
	// https URL of your sign-in page; null clears it. Omit to leave unchanged.
	LoginURL *string `json:"login_url,omitempty"`
	// https URL of your consent page; null clears it. Omit to leave unchanged.
	ConsentURL *string `json:"consent_url,omitempty"`
}

// OAuthClientsSetDelegatedUIResult is a typed model of the Backend API.
type OAuthClientsSetDelegatedUIResult struct {
	Object     string  `json:"object"`
	ClientID   string  `json:"client_id"`
	LoginURL   *string `json:"login_url"`
	ConsentURL *string `json:"consent_url"`
}

// OAuthClientsSetExchangePolicyParams is a typed model of the Backend API.
type OAuthClientsSetExchangePolicyParams struct {
	AllowedAudiences   []string `json:"allowed_audiences,omitempty"`
	AllowedScopes      []string `json:"allowed_scopes,omitempty"`
	IDJagAudiences     []string `json:"id_jag_audiences,omitempty"`
	AllowImpersonation *bool    `json:"allow_impersonation,omitempty"`
	RequireMayAct      *bool    `json:"require_may_act,omitempty"`
	MaxDelegationDepth *int64   `json:"max_delegation_depth,omitempty"`
}

// OAuthClientsSetProfileParams is a typed model of the Backend API.
type OAuthClientsSetProfileParams struct {
	// A built-in or custom profile name; null clears.
	Profile *string `json:"profile"`
}

// OAuthClientsSetProfileResult is a typed model of the Backend API.
type OAuthClientsSetProfileResult struct {
	Object   string  `json:"object"`
	ClientID string  `json:"client_id"`
	Profile  *string `json:"profile"`
}

// OAuthClientsTrustedIssuersCreateParams is a typed model of the Backend API.
type OAuthClientsTrustedIssuersCreateParams struct {
	Issuer string `json:"issuer"`
	// Inline JWK Set. Provide exactly one of jwks or jwks_uri.
	JWKS map[string]interface{} `json:"jwks,omitempty"`
	// https URL of the issuer JWK Set. Provide exactly one of jwks or jwks_uri.
	JWKSURI string `json:"jwks_uri,omitempty"`
	// One of: user_id, external_id, email.
	SubjectMapping string `json:"subject_mapping,omitempty"`
	// Fills in issuer and jwks_uri for github_actions, gcp and azure when you omit them. One of:
	// generic, spiffe, kubernetes, github_actions, gcp, azure.
	WorkloadKind string `json:"workload_kind,omitempty"`
	// Required for workload_kind azure (without an explicit issuer).
	TenantID string `json:"tenant_id,omitempty"`
	// One of: user_assertion, client_auth, both.
	Purpose string `json:"purpose,omitempty"`
	// Required when purpose is client_auth or both. A glob with * wildcards; a bare * is refused.
	SubjectPattern string `json:"subject_pattern,omitempty"`
	// Extra claims that must match exactly.
	RequiredClaims map[string]string `json:"required_claims,omitempty"`
	// Accepted aud values. Defaults to the token endpoint, the PAR endpoint and the issuer.
	Audiences []string `json:"audiences,omitempty"`
}

// OAuthClientsTrustedIssuersListItem is a typed model of the Backend API.
type OAuthClientsTrustedIssuersListItem struct {
	Object string `json:"object"`
	ID     string `json:"id"`
	// The OAuth client row id (oac_…) that trusts this issuer.
	ClientID string `json:"client_id"`
	// The `iss` its JWTs carry.
	Issuer string `json:"issuer"`
	// Inline JWK Set, or null when jwks_uri is used.
	JWKS    map[string]interface{} `json:"jwks"`
	JWKSURI *string                `json:"jwks_uri"`
	// How the JWT `sub` names an Atlas user. One of: user_id, external_id, email.
	SubjectMapping string `json:"subject_mapping"`
	// The kind of workload platform issuing the tokens; it only supplies defaults. One of: generic,
	// spiffe, kubernetes, github_actions, gcp, azure.
	WorkloadKind string `json:"workload_kind"`
	// Whether the issuer asserts users (jwt-bearer grant), authenticates the client itself
	// (workload_jwt), or both. One of: user_assertion, client_auth, both.
	Purpose string `json:"purpose"`
	// Glob (* wildcard) the workload token `sub` must match.
	SubjectPattern *string `json:"subject_pattern"`
	// Claims that must equal these string values.
	RequiredClaims map[string]interface{} `json:"required_claims"`
	// Accepted `aud` values for a workload token; null means the token endpoint and the issuer.
	Audiences []string `json:"audiences"`
	// Created (epoch ms).
	CreatedAt int64 `json:"created_at"`
}

// OAuthClientsWorkloadIdentityCloudTrustResult is a typed model of the Backend API.
type OAuthClientsWorkloadIdentityCloudTrustResult struct {
	Object string `json:"object"`
	// One of: aws, gcp, azure.
	Provider string   `json:"provider"`
	Steps    []string `json:"steps"`
	// AWS IAM role trust policy.
	TrustPolicy map[string]interface{} `json:"trust_policy"`
	// GCP workload identity pool provider settings.
	ProviderConfig map[string]interface{} `json:"provider_config"`
	// GCP principal to grant roles/iam.workloadIdentityUser.
	Principal string `json:"principal"`
	// Azure federated identity credential.
	FederatedCredential map[string]interface{} `json:"federated_credential"`
	TokenEndpoint       string                 `json:"token_endpoint"`
}

// OAuthClientsWorkloadIdentityPresetsItem is a typed model of the Backend API.
type OAuthClientsWorkloadIdentityPresetsItem struct {
	Object         string  `json:"object"`
	Kind           string  `json:"kind"`
	Title          string  `json:"title"`
	Issuer         *string `json:"issuer"`
	JWKSURI        *string `json:"jwks_uri"`
	SubjectExample string  `json:"subject_example"`
	Notes          string  `json:"notes"`
}

// OpenFGAListUsersParams is a typed model of the Backend API.
type OpenFGAListUsersParams struct {
	Object OpenFGAListUsersParamsObject `json:"object"`
	// e.g. viewer
	Relation             string                                  `json:"relation"`
	UserFilters          []OpenFGAListUsersParamsUserFiltersItem `json:"user_filters"`
	AuthorizationModelID string                                  `json:"authorization_model_id,omitempty"`
	// The OpenFGA tuple-list wrapper.
	ContextualTuples *OpenFGAListUsersParamsContextualTuples `json:"contextual_tuples,omitempty"`
	// Request-time values for tuple-condition parameters. A tuple's own context wins on a clash.
	Context map[string]interface{} `json:"context,omitempty"`
	// MINIMIZE_LATENCY (and UNSPECIFIED) may be answered from a short-lived result cache;
	// HIGHER_CONSISTENCY bypasses it and reads the primary. One of: UNSPECIFIED, MINIMIZE_LATENCY,
	// HIGHER_CONSISTENCY.
	Consistency string `json:"consistency,omitempty"`
	// A token returned by a write (or any read): evaluate at least that fresh, so a check can never be
	// answered from before that write. Also accepted as the `Atlas-Consistency-Token` request header.
	ConsistencyToken string `json:"consistency_token,omitempty"`
	// Defaults to 1000.
	PageSize *int64 `json:"page_size,omitempty"`
	// The `continuation_token` of the previous page.
	ContinuationToken string `json:"continuation_token,omitempty"`
}

// OpenFGAListUsersParamsContextualTuples is the OpenFGA tuple-list wrapper.
type OpenFGAListUsersParamsContextualTuples struct {
	TupleKeys []OpenFGAListUsersParamsContextualTuplesTupleKeysItem `json:"tuple_keys"`
}

// OpenFGAListUsersParamsContextualTuplesTupleKeysItem is a typed model of the Backend API.
type OpenFGAListUsersParamsContextualTuplesTupleKeysItem struct {
	// The subject: `user:alice`, a userset `group:eng#member`, or a wildcard `user:*`.
	User string `json:"user"`
	// The relation, e.g. `viewer`.
	Relation string `json:"relation"`
	// The object, e.g. `document:roadmap`.
	Object string `json:"object"`
	// A model condition bound to a tuple: the tuple grants only while the CEL expression holds.
	Condition *OpenFGAListUsersParamsContextualTuplesTupleKeysItemCondition `json:"condition,omitempty"`
}

// OpenFGAListUsersParamsContextualTuplesTupleKeysItemCondition is a model condition bound to a
// tuple: the tuple grants only while the CEL expression holds.
type OpenFGAListUsersParamsContextualTuplesTupleKeysItemCondition struct {
	// A condition defined in the authorization model.
	Name string `json:"name"`
	// Values for the condition parameters fixed on this tuple.
	Context map[string]interface{} `json:"context,omitempty"`
}

// OpenFGAListUsersParamsObject is a typed model of the Backend API.
type OpenFGAListUsersParamsObject struct {
	// e.g. document
	Type string `json:"type"`
	// e.g. roadmap
	ID string `json:"id"`
}

// OpenFGAListUsersParamsUserFiltersItem is a typed model of the Backend API.
type OpenFGAListUsersParamsUserFiltersItem struct {
	// The user type to return, e.g. user.
	Type string `json:"type"`
	// Return `type:id#relation` usersets instead of concrete users.
	Relation string `json:"relation,omitempty"`
}

// OpenFGAListUsersResult is a typed model of the Backend API.
type OpenFGAListUsersResult struct {
	Users         []OpenFGAListUsersResultUsersItem         `json:"users"`
	ExcludedUsers []OpenFGAListUsersResultExcludedUsersItem `json:"excluded_users"`
	// Empty on the last page.
	ContinuationToken string `json:"continuation_token"`
}

// OpenFGAListUsersResultExcludedUsersItem is a typed model of the Backend API.
type OpenFGAListUsersResultExcludedUsersItem struct {
	Object OpenFGAListUsersResultUsersItemObject `json:"object"`
}

// OpenFGAListUsersResultUsersItem is a typed model of the Backend API.
type OpenFGAListUsersResultUsersItem struct {
	Object   OpenFGAListUsersResultUsersItemObject   `json:"object"`
	Userset  OpenFGAListUsersResultUsersItemUserset  `json:"userset"`
	Wildcard OpenFGAListUsersResultUsersItemWildcard `json:"wildcard"`
}

// OpenFGAListUsersResultUsersItemObject is a typed model of the Backend API.
type OpenFGAListUsersResultUsersItemObject struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

// OpenFGAListUsersResultUsersItemUserset is a typed model of the Backend API.
type OpenFGAListUsersResultUsersItemUserset struct {
	Type     string `json:"type"`
	ID       string `json:"id"`
	Relation string `json:"relation"`
}

// OpenFGAListUsersResultUsersItemWildcard is a typed model of the Backend API.
type OpenFGAListUsersResultUsersItemWildcard struct {
	Type string `json:"type"`
}

// OpenFGAReadChangesResult is a typed model of the Backend API.
type OpenFGAReadChangesResult struct {
	Changes           []OpenFGAReadChangesResultChangesItem `json:"changes"`
	ContinuationToken string                                `json:"continuation_token"`
}

// OpenFGAReadChangesResultChangesItem is a typed model of the Backend API.
type OpenFGAReadChangesResultChangesItem struct {
	TupleKey OpenFGAReadChangesResultChangesItemTupleKey `json:"tuple_key"`
	// One of: TUPLE_OPERATION_WRITE, TUPLE_OPERATION_DELETE.
	Operation string `json:"operation"`
	Timestamp string `json:"timestamp"`
}

// OpenFGAReadChangesResultChangesItemTupleKey is a typed model of the Backend API.
type OpenFGAReadChangesResultChangesItemTupleKey struct {
	// The subject: `user:alice`, a userset `group:eng#member`, or a wildcard `user:*`.
	User string `json:"user"`
	// The relation, e.g. `viewer`.
	Relation string `json:"relation"`
	// The object, e.g. `document:roadmap`.
	Object string `json:"object"`
	// A model condition bound to a tuple: the tuple grants only while the CEL expression holds.
	Condition FGAReadChangesResultDataItemCondition `json:"condition"`
}

// OrganizationsGetConnectionSecretResult is a typed model of the Backend API.
type OrganizationsGetConnectionSecretResult struct {
	Object       string `json:"object"`
	ConnectionID string `json:"connection_id"`
	// One of: api_key, bearer, basic, custom_header, hmac_secret.
	Kind interface{} `json:"kind"`
	// The vault version that was read.
	Version int64 `json:"version"`
	// The credential's fields. api_key: {api_key}. bearer: {token}. basic: {username, password}.
	// custom_header: {value}. hmac_secret: {secret}.
	Secret map[string]string `json:"secret"`
	// The non-secret settings (placement, header name, algorithm...) needed to apply it.
	Config map[string]interface{} `json:"config"`
	// When the credential expires, epoch ms.
	ExpiresAt *int64 `json:"expires_at"`
}

// OrganizationsListConnectedAppsItem is a typed model of the Backend API.
type OrganizationsListConnectedAppsItem struct {
	Object string `json:"object"`
	// The grant id; pass it to DELETE to revoke.
	ID             string  `json:"id"`
	OrganizationID string  `json:"organization_id"`
	UserID         string  `json:"user_id"`
	ClientID       *string `json:"client_id"`
	ClientName     *string `json:"client_name"`
	Scope          string  `json:"scope"`
	// Connected (epoch ms).
	ConnectedAt int64 `json:"connected_at"`
}

// OrganizationsWebhookEndpointsCreateParams is a typed model of the Backend API.
type OrganizationsWebhookEndpointsCreateParams struct {
	// The HTTPS receiver (any public URL that answers 2xx).
	URL string `json:"url,omitempty"`
	// Event types to receive, or ["*"]. Only events that belong to this organization are ever
	// delivered.
	EnabledEvents []string `json:"enabled_events,omitempty"`
	// A label, up to 500 characters.
	Description *string `json:"description,omitempty"`
	// Set false to pause deliveries.
	Active *bool `json:"active,omitempty"`
}

// OrganizationsWebhookEndpointsDeliveriesItem is a typed model of the Backend API.
type OrganizationsWebhookEndpointsDeliveriesItem struct {
	Object  string `json:"object"`
	ID      string `json:"id"`
	EventID string `json:"event_id"`
	// The name the event was delivered as (the canonical name, or the deprecated spelling the endpoint
	// subscribed to), or null once the event has passed its retention.
	EventType *string `json:"event_type"`
	// How long the receiver took to answer.
	LatencyMs *int64 `json:"latency_ms"`
	// The W3C trace-id the delivery carried in its traceparent; every retry repeats it.
	TraceID       *string `json:"trace_id"`
	AttemptNumber int64   `json:"attempt_number"`
	MaxAttempts   int64   `json:"max_attempts"`
	// The event payload that was sent (null once the event has passed its retention).
	Payload interface{} `json:"payload"`
	// One of: pending, success, failed.
	Status     string `json:"status"`
	HTTPStatus *int64 `json:"http_status"`
	// Why the attempt failed, as a code: `webhook_redirect_not_followed` (the endpoint answered 3xx;
	// Atlas never follows redirects, see `location`), `webhook_http_error`, `webhook_timeout`,
	// `webhook_network_error` or `webhook_url_blocked`. Null on success or while pending.
	Error *string `json:"error"`
	// The `Location` header of a 3xx answer, resolved to an absolute URL. Not followed.
	Location        *string `json:"location"`
	ResponseSnippet *string `json:"response_snippet"`
	// When the next attempt is due; null once the delivery succeeded or no attempt is owed.
	NextRetryAt *int64 `json:"next_retry_at"`
	DeliveredAt *int64 `json:"delivered_at"`
	// Created (epoch ms).
	CreatedAt int64 `json:"created_at"`
}

// OrganizationsWebhookEndpointsListItem is a typed model of the Backend API.
type OrganizationsWebhookEndpointsListItem struct {
	Object string `json:"object"`
	ID     string `json:"id"`
	// The HTTPS receiver; for an event destination, a descriptor such as
	// aws-eventbridge://us-east-1/default.
	URL           string   `json:"url"`
	Description   *string  `json:"description"`
	EnabledEvents []string `json:"enabled_events"`
	// Which names `*` delivers under: canonical, or the pre-convention spellings (endpoints created
	// before the canonical catalogue). One of: canonical, legacy.
	EventNaming string `json:"event_naming"`
	Active      bool   `json:"active"`
	// A third-party receiver: preflight does not flag its host as off-origin.
	External          bool     `json:"external"`
	SignatureVersions []string `json:"signature_versions"`
	// Where deliveries go: { type: "https" } or an event destination with its non-secret settings.
	// Credentials are never returned (credentials_set says whether they are stored).
	Destination OrganizationsWebhookEndpointsListItemDestination `json:"destination"`
	// One of: healthy, failing, disabled.
	Health string `json:"health"`
	// Start of the current failure streak (epoch ms), or null when the last delivery succeeded.
	FailingSince *int64 `json:"failing_since"`
	// Start of the failure streak that preceded the last re-enable (epoch ms); what replay resolves
	// since=failing_since to once the live streak is cleared.
	LastFailingSince *int64 `json:"last_failing_since"`
	// When the endpoint was switched off after repeated failures (epoch ms), or null.
	DisabledAt          *int64                                            `json:"disabled_at"`
	LastSuccessAt       *int64                                            `json:"last_success_at"`
	LastFailure         *OrganizationsWebhookEndpointsListItemLastFailure `json:"last_failure"`
	ConsecutiveFailures int64                                             `json:"consecutive_failures"`
	// Share of attempts in the last 24 hours that succeeded (0–1), null with no attempts.
	SuccessRate24h *float64                                         `json:"success_rate_24h"`
	Attempts24h    OrganizationsWebhookEndpointsListItemAttempts24h `json:"attempts_24h"`
	// Who is emailed when it fails; null = the owners of the account.
	AlertContacts []string `json:"alert_contacts"`
	// Alerts sent for the current streak: first (1 hour), second (24 hours) and the disabled notice
	// (epoch ms or null).
	AlertsSent  OrganizationsWebhookEndpointsListItemAlertsSent  `json:"alerts_sent"`
	AutoDisable OrganizationsWebhookEndpointsListItemAutoDisable `json:"auto_disable"`
	// While a secret rotation overlap is open: when the previous secret stops signing deliveries
	// (epoch ms). Until then every delivery carries two signatures. Null otherwise.
	PreviousSecretExpiresAt *int64 `json:"previous_secret_expires_at"`
	// On an update that re-enabled the endpoint: the call that replays what it missed.
	Replay *OrganizationsWebhookEndpointsListItemReplay `json:"replay"`
	// On create and PUT by_url: whether this call created the endpoint.
	Created bool `json:"created"`
	// Created (epoch ms).
	CreatedAt int64 `json:"created_at"`
	// Last changed (epoch ms).
	UpdatedAt int64 `json:"updated_at"`
}

// OrganizationsWebhookEndpointsListItemAlertsSent is alerts sent for the current streak: first (1
// hour), second (24 hours) and the disabled notice (epoch ms or null).
type OrganizationsWebhookEndpointsListItemAlertsSent struct {
	FirstSentAt    *int64 `json:"first_sent_at"`
	SecondSentAt   *int64 `json:"second_sent_at"`
	DisabledSentAt *int64 `json:"disabled_sent_at"`
}

// OrganizationsWebhookEndpointsListItemAttempts24h is a typed model of the Backend API.
type OrganizationsWebhookEndpointsListItemAttempts24h struct {
	Succeeded int64 `json:"succeeded"`
	Failed    int64 `json:"failed"`
}

// OrganizationsWebhookEndpointsListItemAutoDisable is a typed model of the Backend API.
type OrganizationsWebhookEndpointsListItemAutoDisable struct {
	// Disabled after failing this long (72 hours).
	AfterFailingMs int64 `json:"after_failing_ms"`
	// Or after this many failed attempts in a row…
	AfterConsecutiveFailures int64 `json:"after_consecutive_failures"`
	// …once it has been failing at least this long (24 hours).
	ConsecutiveFailuresMinFailingMs int64  `json:"consecutive_failures_min_failing_ms"`
	Description                     string `json:"description"`
}

// OrganizationsWebhookEndpointsListItemDestination is where deliveries go: { type: "https" } or an
// event destination with its non-secret settings. Credentials are never returned (credentials_set
// says whether they are stored).
type OrganizationsWebhookEndpointsListItemDestination struct {
	// One of: https, aws_eventbridge, gcp_pubsub, cloudflare_queue, segment, ga4, mixpanel, posthog,
	// amplitude, customerio, slack.
	Type           string `json:"type"`
	CredentialsSet bool   `json:"credentials_set"`
}

// OrganizationsWebhookEndpointsListItemLastFailure is a typed model of the Backend API.
type OrganizationsWebhookEndpointsListItemLastFailure struct {
	At     int64   `json:"at"`
	Status *int64  `json:"status"`
	Error  *string `json:"error"`
}

// OrganizationsWebhookEndpointsListItemReplay is on an update that re-enabled the endpoint: the
// call that replays what it missed.
type OrganizationsWebhookEndpointsListItemReplay struct {
	Since  int64  `json:"since"`
	Method string `json:"method"`
	Path   string `json:"path"`
	Note   string `json:"note"`
}

// OrganizationsWebhookEndpointsRotateSecretResult is a typed model of the Backend API.
type OrganizationsWebhookEndpointsRotateSecretResult struct {
	Object string `json:"object"`
	// The new signing secret. Returned exactly once.
	Secret                  string `json:"secret"`
	OverlapSeconds          int64  `json:"overlap_seconds"`
	PreviousSecretExpiresAt *int64 `json:"previous_secret_expires_at"`
}

// OrgLDAPConnectionsGetRelayResult is a typed model of the Backend API.
type OrgLDAPConnectionsGetRelayResult struct {
	Object  string  `json:"object"`
	AgentID *string `json:"agent_id"`
}

// OrgLDAPConnectionsGetSyncResult is a typed model of the Backend API.
type OrgLDAPConnectionsGetSyncResult struct {
	Object string `json:"object"`
}

// OrgLDAPConnectionsSetRelayParams is a typed model of the Backend API.
type OrgLDAPConnectionsSetRelayParams struct {
	AgentID *string `json:"agent_id,omitempty"`
}

// OrgLDAPConnectionsSetSyncParams is a typed model of the Backend API.
type OrgLDAPConnectionsSetSyncParams struct {
	Enabled              *bool                                             `json:"enabled,omitempty"`
	IntervalMinutes      *float64                                          `json:"intervalMinutes,omitempty"`
	PageSize             *float64                                          `json:"pageSize,omitempty"`
	IDAttribute          string                                            `json:"idAttribute,omitempty"`
	UserFilter           *string                                           `json:"userFilter,omitempty"`
	GroupBaseDN          *string                                           `json:"groupBaseDN,omitempty"`
	GroupFilter          string                                            `json:"groupFilter,omitempty"`
	GroupMemberAttribute string                                            `json:"groupMemberAttribute,omitempty"`
	GroupNameAttribute   string                                            `json:"groupNameAttribute,omitempty"`
	SyncGroups           *bool                                             `json:"syncGroups,omitempty"`
	RoleMappings         []OrgLDAPConnectionsSetSyncParamsRoleMappingsItem `json:"roleMappings,omitempty"`
	DisableOnRemoval     *bool                                             `json:"disableOnRemoval,omitempty"`
	DeltaAttribute       string                                            `json:"deltaAttribute,omitempty"`
}

// OrgLDAPConnectionsSetSyncParamsRoleMappingsItem is a typed model of the Backend API.
type OrgLDAPConnectionsSetSyncParamsRoleMappingsItem struct {
	Group string `json:"group"`
	Role  string `json:"role"`
}

// OrgLDAPConnectionsSyncRunsCreateParams is a typed model of the Backend API.
type OrgLDAPConnectionsSyncRunsCreateParams struct {
	Kind string `json:"kind,omitempty"`
}

// OrgLDAPConnectionsSyncRunsListResult is a typed model of the Backend API.
type OrgLDAPConnectionsSyncRunsListResult struct {
	Object  string                                         `json:"object"`
	Data    []OrgLDAPConnectionsSyncRunsListResultDataItem `json:"data"`
	HasMore bool                                           `json:"has_more"`
}

// OrgLDAPConnectionsSyncRunsListResultDataItem is a typed model of the Backend API.
type OrgLDAPConnectionsSyncRunsListResultDataItem struct {
	Object         string                 `json:"object"`
	ID             string                 `json:"id"`
	ConnectionID   string                 `json:"connection_id"`
	OrganizationID string                 `json:"organization_id"`
	Kind           string                 `json:"kind"`
	Trigger        string                 `json:"trigger"`
	Status         string                 `json:"status"`
	Stats          map[string]interface{} `json:"stats"`
	Error          *string                `json:"error"`
	CreatedAt      int64                  `json:"created_at"`
	StartedAt      *int64                 `json:"started_at"`
	FinishedAt     *int64                 `json:"finished_at"`
}

// OrgRoleGrantsCreateParams is a typed model of the Backend API.
type OrgRoleGrantsCreateParams struct {
	GrantorOrgID string   `json:"grantor_org_id,omitempty"`
	GranteeOrgID string   `json:"grantee_org_id,omitempty"`
	RoleKeys     []string `json:"role_keys,omitempty"`
}

// OrgRoleGrantsDelegateParams is a typed model of the Backend API.
type OrgRoleGrantsDelegateParams struct {
	UserID  string `json:"user_id,omitempty"`
	RoleKey string `json:"role_key,omitempty"`
}

// OrgRoleGrantsEffectiveItem is a typed model of the Backend API.
type OrgRoleGrantsEffectiveItem struct {
	// The grantor organization the role applies in.
	OrganizationID string `json:"organization_id"`
	// The cross-organization grant the role comes through.
	GrantID string `json:"grant_id"`
	RoleKey string `json:"role_key"`
	// The permissions the role carries.
	Permissions []string `json:"permissions"`
}

// OrgRoleGrantsListDelegationsItem is a typed model of the Backend API.
type OrgRoleGrantsListDelegationsItem struct {
	Object  string `json:"object"`
	ID      string `json:"id"`
	GrantID string `json:"grant_id"`
	UserID  string `json:"user_id"`
	RoleKey string `json:"role_key"`
	// Created (epoch ms).
	CreatedAt int64 `json:"created_at"`
}

// OrgRoleGrantsListItem is a typed model of the Backend API.
type OrgRoleGrantsListItem struct {
	Object       string   `json:"object"`
	ID           string   `json:"id"`
	GrantorOrgID string   `json:"grantor_org_id"`
	GranteeOrgID string   `json:"grantee_org_id"`
	RoleKeys     []string `json:"role_keys"`
	// One of: active, revoked.
	Status string `json:"status"`
	// Created (epoch ms).
	CreatedAt int64  `json:"created_at"`
	RevokedAt *int64 `json:"revoked_at"`
}

// OrgRoleGrantsUpdateParams is a typed model of the Backend API.
type OrgRoleGrantsUpdateParams struct {
	RoleKeys []string `json:"role_keys,omitempty"`
}

// PageTemplatesListItem is a typed model of the Backend API.
type PageTemplatesListItem struct {
	Object string `json:"object"`
	// One of: sign-in, sign-up, user-profile.
	Page string `json:"page"`
	// The template the hosted page renders: `{ version, updated_at, definition }`.
	Live map[string]interface{} `json:"live"`
	// The unpublished template, visible only behind a preview link.
	Draft map[string]interface{} `json:"draft"`
}

// PageTemplatesPreviewResult is a typed model of the Backend API.
type PageTemplatesPreviewResult struct {
	Object string `json:"object"`
	Page   string `json:"page"`
	URL    string `json:"url"`
	// Link expires (epoch ms).
	ExpiresAt int64 `json:"expires_at"`
}

// PageTemplatesSaveDraftParams is a typed model of the Backend API.
type PageTemplatesSaveDraftParams struct {
	Definition *PageTemplatesSaveDraftParamsDefinition `json:"definition,omitempty"`
}

// PageTemplatesSaveDraftParamsDefinition is a typed model of the Backend API.
type PageTemplatesSaveDraftParamsDefinition struct {
	Version *float64                                       `json:"version,omitempty"`
	Regions *PageTemplatesSaveDraftParamsDefinitionRegions `json:"regions,omitempty"`
}

// PageTemplatesSaveDraftParamsDefinitionRegions is a typed model of the Backend API.
type PageTemplatesSaveDraftParamsDefinitionRegions struct {
	Header    []map[string]interface{} `json:"header,omitempty"`
	AboveForm []map[string]interface{} `json:"above_form,omitempty"`
	BelowForm []map[string]interface{} `json:"below_form,omitempty"`
	Footer    []map[string]interface{} `json:"footer,omitempty"`
}

// PasskeyAPILoginFinalizeParams is a typed model of the Backend API.
type PasskeyAPILoginFinalizeParams struct {
	Handle            string `json:"handle"`
	Challenge         string `json:"challenge"`
	CredentialID      string `json:"credential_id"`
	AuthenticatorData string `json:"authenticator_data"`
	ClientDataJSON    string `json:"client_data_json"`
	Signature         string `json:"signature"`
	// Your own user id. Atlas stores it with the passkey and never needs a matching Atlas user.
	UserID string `json:"user_id,omitempty"`
}

// PasskeyAPILoginFinalizeResult is a typed model of the Backend API.
type PasskeyAPILoginFinalizeResult struct {
	Object       string `json:"object"`
	Verified     bool   `json:"verified"`
	UserID       string `json:"user_id"`
	CredentialID string `json:"credential_id"`
	PasskeyID    string `json:"passkey_id"`
	UserVerified bool   `json:"user_verified"`
	// The signature counter went backwards: possible cloned authenticator.
	ClonedWarning bool `json:"cloned_warning"`
}

// PasskeyAPILoginInitParams is a typed model of the Backend API.
type PasskeyAPILoginInitParams struct {
	// Your own user id. Atlas stores it with the passkey and never needs a matching Atlas user.
	UserID string `json:"user_id,omitempty"`
}

// PasskeyAPIRegistrationFinalizeParams is a typed model of the Backend API.
type PasskeyAPIRegistrationFinalizeParams struct {
	// Your own user id. Atlas stores it with the passkey and never needs a matching Atlas user.
	UserID    string `json:"user_id"`
	Challenge string `json:"challenge"`
	// base64url.
	AttestationObject string `json:"attestation_object"`
	// base64url.
	ClientDataJSON string   `json:"client_data_json"`
	Name           string   `json:"name,omitempty"`
	Transports     []string `json:"transports,omitempty"`
}

// PasskeyAPIRegistrationFinalizeResult is a typed model of the Backend API.
type PasskeyAPIRegistrationFinalizeResult struct {
	Object       string   `json:"object"`
	ID           string   `json:"id"`
	UserID       string   `json:"user_id"`
	CredentialID string   `json:"credential_id"`
	Name         *string  `json:"name"`
	AAGUID       *string  `json:"aaguid"`
	BackedUp     bool     `json:"backed_up"`
	Transports   []string `json:"transports"`
	// Last successful login (epoch ms).
	LastUsedAt *int64 `json:"last_used_at"`
	// Registered (epoch ms).
	CreatedAt int64 `json:"created_at"`
}

// PasskeyAPIRegistrationInitParams is a typed model of the Backend API.
type PasskeyAPIRegistrationInitParams struct {
	// Your own user id. Atlas stores it with the passkey and never needs a matching Atlas user.
	UserID string `json:"user_id"`
	// Shown by the authenticator. Defaults to user_id.
	Username    string `json:"username,omitempty"`
	DisplayName string `json:"display_name,omitempty"`
}

// PasskeyAPIRegistrationInitResult is a typed model of the Backend API.
type PasskeyAPIRegistrationInitResult struct {
	Object string `json:"object"`
	// Login only: send back to finalize with the browser response.
	Handle string `json:"handle"`
	// Pass to navigator.credentials.create() / get() in the user’s browser (challenge is base64url).
	Options map[string]interface{} `json:"options"`
}

// PasskeyAPIUsageResult is a typed model of the Backend API.
type PasskeyAPIUsageResult struct {
	Object   string `json:"object"`
	Passkeys int64  `json:"passkeys"`
}

// PolicyBundlesCurrentResult is a typed model of the Backend API.
type PolicyBundlesCurrentResult struct {
	Object   string `json:"object"`
	Revision string `json:"revision"`
}

// PolicyBundlesImportParams is a typed model of the Backend API.
type PolicyBundlesImportParams struct {
	// The bundle (tar.gz), base64-encoded.
	Bundle string `json:"bundle"`
	// The detached compact JWS (`header..signature`) over the archive bytes.
	Signature string `json:"signature"`
	// Public keys to trust IN ADDITION to this instance's own, as a JWKS — for a bundle signed by
	// another instance (promote staging to production). Private key material is rejected.
	TrustedJWKS *PolicyBundlesVerifyParamsTrustedJWKS `json:"trusted_jwks,omitempty"`
	// Return the diff and apply nothing.
	DryRun *bool `json:"dry_run,omitempty"`
	// Also delete ABAC policies absent from the bundle.
	Prune *bool `json:"prune,omitempty"`
}

// PolicyBundlesImportResult is a typed model of the Backend API.
type PolicyBundlesImportResult struct {
	Object   string `json:"object"`
	DryRun   bool   `json:"dry_run"`
	Applied  bool   `json:"applied"`
	Prune    bool   `json:"prune"`
	Revision string `json:"revision"`
	// What importing a bundle would change.
	Diff PolicyBundlesImportResultDiff `json:"diff"`
}

// PolicyBundlesImportResultDiff is what importing a bundle would change.
type PolicyBundlesImportResultDiff struct {
	ABACPolicies  PolicyBundlesImportResultDiffABACPolicies  `json:"abac_policies"`
	FGAStores     PolicyBundlesImportResultDiffFGAStores     `json:"fga_stores"`
	ABACTemplates PolicyBundlesImportResultDiffABACTemplates `json:"abac_templates"`
	ABACLinks     PolicyBundlesImportResultDiffABACPolicies  `json:"abac_links"`
	// The ABAC entity schema: `absent` means the instance has one and the bundle does not (removed
	// only with `prune`). One of: create, update, absent, unchanged.
	ABACSchema string `json:"abac_schema"`
	// True when nothing would be created or updated.
	Identical bool `json:"identical"`
}

// PolicyBundlesImportResultDiffABACPolicies is a typed model of the Backend API.
type PolicyBundlesImportResultDiffABACPolicies struct {
	Create []string                                              `json:"create"`
	Update []PolicyBundlesImportResultDiffABACPoliciesUpdateItem `json:"update"`
	// On the instance but not in the bundle; deleted only with `prune`.
	Absent    []string `json:"absent"`
	Unchanged int64    `json:"unchanged"`
}

// PolicyBundlesImportResultDiffABACPoliciesUpdateItem is a typed model of the Backend API.
type PolicyBundlesImportResultDiffABACPoliciesUpdateItem struct {
	Name    string   `json:"name"`
	Changed []string `json:"changed"`
}

// PolicyBundlesImportResultDiffABACTemplates is a typed model of the Backend API.
type PolicyBundlesImportResultDiffABACTemplates struct {
	Create []string                                              `json:"create"`
	Update []PolicyBundlesImportResultDiffABACPoliciesUpdateItem `json:"update"`
	// On the instance but not in the bundle; deleted (with their links) only with `prune`.
	Absent    []string `json:"absent"`
	Unchanged int64    `json:"unchanged"`
}

// PolicyBundlesImportResultDiffFGAStores is a typed model of the Backend API.
type PolicyBundlesImportResultDiffFGAStores struct {
	Create []string                                              `json:"create"`
	Update []PolicyBundlesImportResultDiffABACPoliciesUpdateItem `json:"update"`
	// Never deleted by an import: a store holds relationship data.
	Absent    []string `json:"absent"`
	Unchanged int64    `json:"unchanged"`
}

// PolicyBundlesListResult is a typed model of the Backend API.
type PolicyBundlesListResult struct {
	Object  string                            `json:"object"`
	Data    []PolicyBundlesListResultDataItem `json:"data"`
	HasMore bool                              `json:"has_more"`
}

// PolicyBundlesListResultDataItem is a typed model of the Backend API.
type PolicyBundlesListResultDataItem struct {
	Object string `json:"object"`
	// A digest of the bundle CONTENT (`rev_…`): the same policy has the same revision on every
	// instance.
	Revision string `json:"revision"`
	// SHA-256 of the archive bytes.
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
	// The instance signing key id (`kid`), published in the JWKS.
	KeyID string `json:"key_id"`
	// One of: RS256, ES256.
	Algorithm string `json:"algorithm"`
	// A detached compact JWS (`header..signature`) over the archive bytes.
	Signature string `json:"signature"`
	// One of: export, import.
	Origin string `json:"origin"`
	// format, format_version, revision, created_at, contents and the SHA-256 of every file.
	Manifest map[string]interface{} `json:"manifest"`
	// The tar.gz, base64-encoded. Present on create and get; omitted from lists.
	Bundle    string `json:"bundle"`
	MediaType string `json:"media_type"`
	// Created (epoch ms).
	CreatedAt int64 `json:"created_at"`
}

// PolicyBundlesVerifyParams is a typed model of the Backend API.
type PolicyBundlesVerifyParams struct {
	// The bundle (tar.gz), base64-encoded.
	Bundle string `json:"bundle"`
	// The detached compact JWS (`header..signature`) over the archive bytes.
	Signature string `json:"signature"`
	// Public keys to trust IN ADDITION to this instance's own, as a JWKS — for a bundle signed by
	// another instance (promote staging to production). Private key material is rejected.
	TrustedJWKS *PolicyBundlesVerifyParamsTrustedJWKS `json:"trusted_jwks,omitempty"`
}

// PolicyBundlesVerifyParamsTrustedJWKS is public keys to trust IN ADDITION to this instance's own,
// as a JWKS — for a bundle signed by another instance (promote staging to production). Private key
// material is rejected.
type PolicyBundlesVerifyParamsTrustedJWKS struct {
	Keys []map[string]interface{} `json:"keys,omitempty"`
}

// PolicyBundlesVerifyResult is a typed model of the Backend API.
type PolicyBundlesVerifyResult struct {
	Object string `json:"object"`
	// Signature AND integrity both check out.
	Valid     bool                               `json:"valid"`
	Signature PolicyBundlesVerifyResultSignature `json:"signature"`
	// Every manifest digest matches, nothing is added or missing, and the revision recomputed from the
	// content equals the manifest. `code`: invalid_archive, invalid_manifest, digest_mismatch,
	// unlisted_file, missing_file, revision_mismatch, invalid_content, unsupported_version.
	Integrity PolicyBundlesVerifyResultIntegrity `json:"integrity"`
	Revision  *string                            `json:"revision"`
	Manifest  map[string]interface{}             `json:"manifest"`
}

// PolicyBundlesVerifyResultIntegrity is every manifest digest matches, nothing is added or
// missing, and the revision recomputed from the content equals the manifest. `code`:
// invalid_archive, invalid_manifest, digest_mismatch, unlisted_file, missing_file,
// revision_mismatch, invalid_content, unsupported_version.
type PolicyBundlesVerifyResultIntegrity struct {
	Valid bool   `json:"valid"`
	Code  string `json:"code"`
	Error string `json:"error"`
}

// PolicyBundlesVerifyResultSignature is a typed model of the Backend API.
type PolicyBundlesVerifyResultSignature struct {
	Valid     bool    `json:"valid"`
	KeyID     *string `json:"key_id"`
	Algorithm *string `json:"algorithm"`
	Error     string  `json:"error"`
}

// ProxyAppsCreateParams is a typed model of the Backend API.
type ProxyAppsCreateParams struct {
	Name        string `json:"name"`
	Hostname    string `json:"hostname"`
	UpstreamURL string `json:"upstream_url"`
	// Path / method rules requiring a role, permission or entitlement.
	Rules         []map[string]interface{} `json:"rules,omitempty"`
	PublicPaths   []string                 `json:"public_paths,omitempty"`
	InjectHeaders *bool                    `json:"inject_headers,omitempty"`
	InjectToken   *bool                    `json:"inject_token,omitempty"`
	// Also let an active agent through with its machine token (for example to front an MCP gateway).
	// Its scopes count as the permissions rules check. Default false.
	AllowAgentTokens *bool `json:"allow_agent_tokens,omitempty"`
	Enabled          *bool `json:"enabled,omitempty"`
}

// ProxyAppsListResult is a typed model of the Backend API.
type ProxyAppsListResult struct {
	Object  string                        `json:"object"`
	Data    []ProxyAppsListResultDataItem `json:"data"`
	HasMore bool                          `json:"has_more"`
}

// ProxyAppsListResultDataItem is a typed model of the Backend API.
type ProxyAppsListResultDataItem struct {
	Object           string                   `json:"object"`
	ID               string                   `json:"id"`
	Name             string                   `json:"name"`
	Hostname         string                   `json:"hostname"`
	UpstreamURL      string                   `json:"upstream_url"`
	Rules            []map[string]interface{} `json:"rules"`
	PublicPaths      []string                 `json:"public_paths"`
	InjectHeaders    bool                     `json:"inject_headers"`
	InjectToken      bool                     `json:"inject_token"`
	AllowAgentTokens bool                     `json:"allow_agent_tokens"`
	Enabled          bool                     `json:"enabled"`
	CreatedAt        int64                    `json:"created_at"`
	UpdatedAt        int64                    `json:"updated_at"`
}

// ProxyAppsUpdateParams is a typed model of the Backend API.
type ProxyAppsUpdateParams struct {
	Name        string `json:"name,omitempty"`
	Hostname    string `json:"hostname,omitempty"`
	UpstreamURL string `json:"upstream_url,omitempty"`
	// Path / method rules requiring a role, permission or entitlement.
	Rules         []map[string]interface{} `json:"rules,omitempty"`
	PublicPaths   []string                 `json:"public_paths,omitempty"`
	InjectHeaders *bool                    `json:"inject_headers,omitempty"`
	InjectToken   *bool                    `json:"inject_token,omitempty"`
	// Also let an active agent through with its machine token (for example to front an MCP gateway).
	// Its scopes count as the permissions rules check. Default false.
	AllowAgentTokens *bool `json:"allow_agent_tokens,omitempty"`
	Enabled          *bool `json:"enabled,omitempty"`
}

// RelayAgentsCreateParams is a typed model of the Backend API.
type RelayAgentsCreateParams struct {
	Name           string  `json:"name"`
	OrganizationID *string `json:"organization_id,omitempty"`
	// One of: active, revoked.
	Status string `json:"status,omitempty"`
	// host:port destinations the agent may reach.
	AllowedDestinations []string `json:"allowed_destinations,omitempty"`
	// Client-certificate pins.
	CertFingerprints []string `json:"cert_fingerprints,omitempty"`
}

// RelayAgentsListResult is a typed model of the Backend API.
type RelayAgentsListResult struct {
	Object  string                          `json:"object"`
	Data    []RelayAgentsListResultDataItem `json:"data"`
	HasMore bool                            `json:"has_more"`
}

// RelayAgentsListResultDataItem is a typed model of the Backend API.
type RelayAgentsListResultDataItem struct {
	Object         string  `json:"object"`
	ID             string  `json:"id"`
	Name           string  `json:"name"`
	OrganizationID *string `json:"organization_id"`
	// One of: active, revoked.
	Status              string   `json:"status"`
	AllowedDestinations []string `json:"allowed_destinations"`
	CertFingerprints    []string `json:"cert_fingerprints"`
	SecretPrefix        string   `json:"secret_prefix"`
	Online              bool     `json:"online"`
	LastSeenAt          *int64   `json:"last_seen_at"`
	LastIP              *string  `json:"last_ip"`
	AgentVersion        *string  `json:"agent_version"`
	CreatedAt           int64    `json:"created_at"`
	// On create and rotate only: the agent token, shown once.
	Token string `json:"token"`
}

// RelayAgentsUpdateParams is a typed model of the Backend API.
type RelayAgentsUpdateParams struct {
	Name           string  `json:"name,omitempty"`
	OrganizationID *string `json:"organization_id,omitempty"`
	// One of: active, revoked.
	Status string `json:"status,omitempty"`
	// host:port destinations the agent may reach.
	AllowedDestinations []string `json:"allowed_destinations,omitempty"`
	// Client-certificate pins.
	CertFingerprints []string `json:"cert_fingerprints,omitempty"`
}

// ResourcesAccessibleParams is a typed model of the Backend API.
type ResourcesAccessibleParams struct {
	Subject       map[string]interface{} `json:"subject,omitempty"`
	Permission    string                 `json:"permission,omitempty"`
	Type          string                 `json:"type,omitempty"`
	Groups        []string               `json:"groups,omitempty"`
	Limit         *int64                 `json:"limit,omitempty"`
	StartingAfter string                 `json:"starting_after,omitempty"`
}

// ResourcesAssignmentsAssignParams is a typed model of the Backend API.
type ResourcesAssignmentsAssignParams struct {
	Resource map[string]interface{} `json:"resource,omitempty"`
	Subject  map[string]interface{} `json:"subject,omitempty"`
	Role     string                 `json:"role,omitempty"`
	Inherit  *bool                  `json:"inherit,omitempty"`
}

// ResourcesAssignmentsListItem is a typed model of the Backend API.
type ResourcesAssignmentsListItem struct {
	Object     string                              `json:"object"`
	ID         string                              `json:"id"`
	ResourceID string                              `json:"resource_id"`
	Subject    ResourcesAssignmentsListItemSubject `json:"subject"`
	Role       string                              `json:"role"`
	Inherit    bool                                `json:"inherit"`
	// Created (epoch ms).
	CreatedAt int64 `json:"created_at"`
}

// ResourcesAssignmentsListItemSubject is a typed model of the Backend API.
type ResourcesAssignmentsListItemSubject struct {
	// One of: user, group, org.
	Type string `json:"type"`
	ID   string `json:"id"`
}

// ResourcesCheckBatchParams is a typed model of the Backend API.
type ResourcesCheckBatchParams struct {
	Checks []map[string]interface{} `json:"checks,omitempty"`
}

// ResourcesCheckParams is a typed model of the Backend API.
type ResourcesCheckParams struct {
	Subject    map[string]interface{} `json:"subject,omitempty"`
	Permission string                 `json:"permission,omitempty"`
	Resource   map[string]interface{} `json:"resource,omitempty"`
	Groups     []string               `json:"groups,omitempty"`
}

// ResourcesCheckResult is a typed model of the Backend API.
type ResourcesCheckResult struct {
	Object     string `json:"object"`
	Allowed    bool   `json:"allowed"`
	ResourceID string `json:"resource_id"`
	// The assignments that allow it (single checks only).
	Grants []ResourcesCheckResultGrantsItem `json:"grants"`
}

// ResourcesCheckResultGrantsItem is a typed model of the Backend API.
type ResourcesCheckResultGrantsItem struct {
	ResourceID string `json:"resource_id"`
	Role       string `json:"role"`
	Subject    string `json:"subject"`
	Inherited  bool   `json:"inherited"`
}

// ResourcesListItem is a typed model of the Backend API.
type ResourcesListItem struct {
	Object string `json:"object"`
	ID     string `json:"id"`
	Type   string `json:"type"`
	// Your own identifier for the resource.
	ExternalID string                 `json:"external_id"`
	Name       *string                `json:"name"`
	ParentID   *string                `json:"parent_id"`
	Metadata   map[string]interface{} `json:"metadata"`
	// Created (epoch ms).
	CreatedAt int64 `json:"created_at"`
	// Last updated (epoch ms).
	UpdatedAt int64 `json:"updated_at"`
}

// ResourcesSyncParams is a typed model of the Backend API.
type ResourcesSyncParams struct {
	Resources []map[string]interface{} `json:"resources,omitempty"`
}

// ResourcesTypesCreateParams is a typed model of the Backend API.
type ResourcesTypesCreateParams struct {
	Key         string                   `json:"key,omitempty"`
	Name        string                   `json:"name,omitempty"`
	Description *string                  `json:"description,omitempty"`
	ParentType  *string                  `json:"parent_type,omitempty"`
	Inherit     *bool                    `json:"inherit,omitempty"`
	Roles       []map[string]interface{} `json:"roles,omitempty"`
}

// ResourcesTypesListItem is a typed model of the Backend API.
type ResourcesTypesListItem struct {
	Object      string  `json:"object"`
	Key         string  `json:"key"`
	Name        string  `json:"name"`
	Description *string `json:"description"`
	// The type a resource of this type nests under.
	ParentType *string `json:"parent_type"`
	// Whether assignments on a parent resource flow down to resources of this type.
	Inherit bool                              `json:"inherit"`
	Roles   []ResourcesTypesListItemRolesItem `json:"roles"`
	// Created (epoch ms).
	CreatedAt int64 `json:"created_at"`
	// Last updated (epoch ms).
	UpdatedAt int64 `json:"updated_at"`
}

// ResourcesTypesListItemRolesItem is a typed model of the Backend API.
type ResourcesTypesListItemRolesItem struct {
	Key  string `json:"key"`
	Name string `json:"name"`
	// `*` grants every permission.
	Permissions []string `json:"permissions"`
	// Other roles of the same type this role also grants.
	Includes []string `json:"includes"`
}

// ResourcesTypesUpdateParams is a typed model of the Backend API.
type ResourcesTypesUpdateParams struct {
	Name        string                   `json:"name,omitempty"`
	Description *string                  `json:"description,omitempty"`
	ParentType  *string                  `json:"parent_type,omitempty"`
	Inherit     *bool                    `json:"inherit,omitempty"`
	Roles       []map[string]interface{} `json:"roles,omitempty"`
}

// ResourcesUpsertParams is a typed model of the Backend API.
type ResourcesUpsertParams struct {
	Type       string                 `json:"type,omitempty"`
	ExternalID string                 `json:"external_id,omitempty"`
	Name       *string                `json:"name,omitempty"`
	Parent     map[string]interface{} `json:"parent,omitempty"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
}

// RiskBasedMFARemoveReputationSecretResult is a typed model of the Backend API.
type RiskBasedMFARemoveReputationSecretResult struct {
	Object   string `json:"object"`
	Provider string `json:"provider"`
	Deleted  bool   `json:"deleted"`
}

// RiskBasedMFASetReputationSecretParams is a typed model of the Backend API.
type RiskBasedMFASetReputationSecretParams struct {
	Secret   string `json:"secret,omitempty"`
	Provider string `json:"provider,omitempty"`
}

// RiskBasedMFASetReputationSecretResult is a typed model of the Backend API.
type RiskBasedMFASetReputationSecretResult struct {
	Object   string `json:"object"`
	Provider string `json:"provider"`
	Set      bool   `json:"set"`
}

// SCIMProvisioningPresetsListResult is a typed model of the Backend API.
type SCIMProvisioningPresetsListResult struct {
	Object  string                                      `json:"object"`
	Data    []SCIMProvisioningPresetsListResultDataItem `json:"data"`
	HasMore bool                                        `json:"has_more"`
}

// SCIMProvisioningPresetsListResultDataItem is a typed model of the Backend API.
type SCIMProvisioningPresetsListResultDataItem struct {
	ID                string                                      `json:"id"`
	Name              string                                      `json:"name"`
	BaseURLTemplate   string                                      `json:"base_url_template"`
	Params            []AppCatalogPresetsResultDataItemParamsItem `json:"params"`
	DeprovisionAction string                                      `json:"deprovision_action"`
	TokenHint         *string                                     `json:"token_hint"`
}

// ServiceConnectorsCatalogItem is a typed model of the Backend API.
type ServiceConnectorsCatalogItem struct {
	Object string `json:"object"`
	Kind   string `json:"kind"`
	Name   string `json:"name"`
	// One of: messaging, crm, analytics, fraud, idv, http.
	Category string `json:"category"`
	Summary  string `json:"summary"`
	// Secret fields, stored in the vault.
	Credentials []ServiceConnectorsCatalogItemCredentialsItem `json:"credentials"`
	Config      []ServiceConnectorsCatalogItemCredentialsItem `json:"config"`
	Operations  []ServiceConnectorsCatalogItemOperationsItem  `json:"operations"`
}

// ServiceConnectorsCatalogItemCredentialsItem is a typed model of the Backend API.
type ServiceConnectorsCatalogItemCredentialsItem struct {
	Key      string   `json:"key"`
	Label    string   `json:"label"`
	Required bool     `json:"required"`
	Type     string   `json:"type"`
	Enum     []string `json:"enum"`
	Default  string   `json:"default"`
}

// ServiceConnectorsCatalogItemOperationsItem is a typed model of the Backend API.
type ServiceConnectorsCatalogItemOperationsItem struct {
	Operation string                                        `json:"operation"`
	Summary   string                                        `json:"summary"`
	Input     []ServiceConnectorsCatalogItemCredentialsItem `json:"input"`
}

// ServiceConnectorsCreateParams is a typed model of the Backend API.
type ServiceConnectorsCreateParams struct {
	Name        string            `json:"name,omitempty"`
	Kind        string            `json:"kind,omitempty"`
	Config      map[string]string `json:"config,omitempty"`
	Credentials map[string]string `json:"credentials,omitempty"`
}

// ServiceConnectorsInvokeParams is a typed model of the Backend API.
type ServiceConnectorsInvokeParams struct {
	Operation string                 `json:"operation,omitempty"`
	Input     map[string]interface{} `json:"input,omitempty"`
}

// ServiceConnectorsInvokeResult is a typed model of the Backend API.
type ServiceConnectorsInvokeResult struct {
	Object    string  `json:"object"`
	Operation *string `json:"operation"`
	// The operation's normalized result; see the catalog entry.
	Result map[string]interface{} `json:"result"`
}

// ServiceConnectorsListItem is a typed model of the Backend API.
type ServiceConnectorsListItem struct {
	Object string `json:"object"`
	ID     string `json:"id"`
	// Unique within the instance; what Actions and flows call it by.
	Name string `json:"name"`
	// The catalog entry, e.g. `twilio`, `segment`, `persona`, `http`.
	Kind string `json:"kind"`
	// One of: messaging, crm, analytics, fraud, idv, http, .
	Category *string `json:"category"`
	// The non-secret settings. Credentials are never returned.
	Config  map[string]string `json:"config"`
	Enabled bool              `json:"enabled"`
	// When an operation last ran (epoch ms).
	LastUsedAt *int64 `json:"last_used_at"`
	// One of: ok, error, .
	LastStatus *string `json:"last_status"`
	// Created (epoch ms).
	CreatedAt int64 `json:"created_at"`
	// Updated (epoch ms).
	UpdatedAt int64 `json:"updated_at"`
}

// ServiceConnectorsUpdateParams is a typed model of the Backend API.
type ServiceConnectorsUpdateParams struct {
	Name        string            `json:"name,omitempty"`
	Enabled     *bool             `json:"enabled,omitempty"`
	Config      map[string]string `json:"config,omitempty"`
	Credentials map[string]string `json:"credentials,omitempty"`
}

// SSFReceiversCreateParams is a typed model of the Backend API.
type SSFReceiversCreateParams struct {
	Name     string            `json:"name,omitempty"`
	Issuer   string            `json:"issuer,omitempty"`
	JWKSURI  string            `json:"jwks_uri,omitempty"`
	Audience string            `json:"audience,omitempty"`
	Actions  map[string]string `json:"actions,omitempty"`
}

// SSFReceiversUpdateParams is a typed model of the Backend API.
type SSFReceiversUpdateParams struct {
	Name     string            `json:"name,omitempty"`
	JWKSURI  string            `json:"jwks_uri,omitempty"`
	Audience string            `json:"audience,omitempty"`
	Actions  map[string]string `json:"actions,omitempty"`
	Enabled  *bool             `json:"enabled,omitempty"`
}

// SSFStreamsCreateParams is a typed model of the Backend API.
type SSFStreamsCreateParams struct {
	// One of: push, poll.
	DeliveryMethod      string   `json:"delivery_method,omitempty"`
	EndpointURL         string   `json:"endpoint_url,omitempty"`
	AuthorizationHeader string   `json:"authorization_header,omitempty"`
	Audience            string   `json:"audience,omitempty"`
	Description         string   `json:"description,omitempty"`
	EventsRequested     []string `json:"events_requested,omitempty"`
}

// SSFStreamsUpdateParams is a typed model of the Backend API.
type SSFStreamsUpdateParams struct {
	EndpointURL         string   `json:"endpoint_url,omitempty"`
	AuthorizationHeader string   `json:"authorization_header,omitempty"`
	Description         string   `json:"description,omitempty"`
	EventsRequested     []string `json:"events_requested,omitempty"`
	// One of: enabled, paused, disabled.
	Status string `json:"status,omitempty"`
}

// SSFStreamsUpdateStatusParams is a typed model of the Backend API.
type SSFStreamsUpdateStatusParams struct {
	// One of: enabled, paused, disabled.
	Status string `json:"status,omitempty"`
}

// SSFStreamsVerifyParams is a typed model of the Backend API.
type SSFStreamsVerifyParams struct {
	State string `json:"state,omitempty"`
}

// UsersCreateLinkParams is a typed model of the Backend API.
type UsersCreateLinkParams struct {
	// One of: password_reset, email_verification.
	Type string `json:"type"`
	// One of the user's addresses. Default: the primary address.
	EmailAddressID string `json:"email_address_id,omitempty"`
	// Default 3600.
	ExpiresInSeconds *int64 `json:"expires_in_seconds,omitempty"`
}

// UsersCreateLinkResult is a verification or reset proof minted for a user without sending it. A
// credential: handle it like a password.
type UsersCreateLinkResult struct {
	Object string `json:"object"`
	// One of: password_reset, email_verification.
	Type           string `json:"type"`
	UserID         string `json:"user_id"`
	EmailAddressID string `json:"email_address_id"`
	EmailAddress   string `json:"email_address"`
	// Present when the instance delivers this proof as a link.
	URL string `json:"url"`
	// Present when the instance delivers this proof as a code (always, for email_verification).
	Code string `json:"code"`
	// password_reset only: the reset attempt the link and code belong to.
	AttemptID string `json:"attempt_id"`
	// Expires (epoch ms).
	ExpiresAt int64 `json:"expires_at"`
}

// UsersDeleteDeviceKeyResult is a typed model of the Backend API.
type UsersDeleteDeviceKeyResult struct {
	Object  string `json:"object"`
	ID      string `json:"id"`
	Deleted bool   `json:"deleted"`
}

// UsersGuardiansApproveParams is a typed model of the Backend API.
type UsersGuardiansApproveParams struct {
	// How consent was obtained (kept on the link).
	Note string `json:"note,omitempty"`
}

// UsersGuardiansRequestParams is a typed model of the Backend API.
type UsersGuardiansRequestParams struct {
	// The guardian's email address.
	Email string `json:"email,omitempty"`
	// A user of this application who is the guardian.
	GuardianUserID string `json:"guardian_user_id,omitempty"`
	// Free label such as mother or legal guardian.
	Relationship string `json:"relationship,omitempty"`
	// Email the consent link to the guardian (default false).
	SendEmail *bool `json:"send_email,omitempty"`
}

// UsersGuardiansRequestResult is a typed model of the Backend API.
type UsersGuardiansRequestResult struct {
	Object         string  `json:"object"`
	ID             string  `json:"id"`
	ChildUserID    string  `json:"child_user_id"`
	GuardianUserID *string `json:"guardian_user_id"`
	GuardianEmail  *string `json:"guardian_email"`
	Relationship   *string `json:"relationship"`
	// One of: pending, active, declined, revoked, expired.
	Status string `json:"status"`
	// When a pending consent link stops working (Unix ms).
	ExpiresAt *int64 `json:"expires_at"`
	// One of: email_link, admin, .
	ConsentMethod *string `json:"consent_method"`
	ConsentedAt   *int64  `json:"consented_at"`
	CreatedAt     int64   `json:"created_at"`
	ConsentURL    string  `json:"consent_url"`
	Emailed       bool    `json:"emailed"`
}

// UsersHistoryItem is a typed model of the Backend API.
type UsersHistoryItem struct {
	Object string `json:"object"`
	ID     string `json:"id"`
	UserID string `json:"user_id"`
	// For example user.updated, user.metadata_replaced, user.password_updated, user.banned,
	// user.unbanned, user.locked, user.unlocked, user.directive_imposed, user.directive_lifted.
	Action  string                        `json:"action"`
	Actor   UsersHistoryItemActor         `json:"actor"`
	Changes []UsersHistoryItemChangesItem `json:"changes"`
	Reason  *string                       `json:"reason"`
	// When a timed ban or lock lifts by itself (Unix ms).
	ExpiresAt *int64 `json:"expires_at"`
	// Recorded (epoch ms).
	CreatedAt int64 `json:"created_at"`
}

// UsersHistoryItemActor is a typed model of the Backend API.
type UsersHistoryItemActor struct {
	// One of: api_key, dashboard_user, user, system.
	Type string  `json:"type"`
	ID   *string `json:"id"`
}

// UsersHistoryItemChangesItem is a typed model of the Backend API.
type UsersHistoryItemChangesItem struct {
	// A profile field (first_name, username, ...), a metadata key (public_metadata.plan), password,
	// banned, ban_reason or locked_until.
	Field string `json:"field"`
	// The value before the change (absent when redacted).
	Before interface{} `json:"before"`
	// The value after the change (absent when redacted).
	After interface{} `json:"after"`
	// True for a password or a private_metadata value: only the field name is kept.
	Redacted bool `json:"redacted"`
}

// UsersListDeviceKeysItem is a typed model of the Backend API.
type UsersListDeviceKeysItem struct {
	Object string  `json:"object"`
	ID     string  `json:"id"`
	Label  *string `json:"label"`
	// ios, android or other.
	Platform       *string `json:"platform"`
	BiometricBound bool    `json:"biometric_bound"`
	LastUsedAt     *int64  `json:"last_used_at"`
	// Created (epoch ms).
	CreatedAt int64 `json:"created_at"`
}

// UsersMinorStatusResult is a typed model of the Backend API.
type UsersMinorStatusResult struct {
	Object string `json:"object"`
	// One of: not_required, consent_required, consented, declined.
	Status          string                                `json:"status"`
	Birthdate       string                                `json:"birthdate"`
	AgeAtAssessment int64                                 `json:"age_at_assessment"`
	ConsentAge      int64                                 `json:"consent_age"`
	Jurisdiction    *string                               `json:"jurisdiction"`
	ConsentedAt     *int64                                `json:"consented_at"`
	Guardians       []UsersMinorStatusResultGuardiansItem `json:"guardians"`
}

// UsersMinorStatusResultGuardiansItem is a typed model of the Backend API.
type UsersMinorStatusResultGuardiansItem struct {
	Object         string  `json:"object"`
	ID             string  `json:"id"`
	ChildUserID    string  `json:"child_user_id"`
	GuardianUserID *string `json:"guardian_user_id"`
	GuardianEmail  *string `json:"guardian_email"`
	Relationship   *string `json:"relationship"`
	// One of: pending, active, declined, revoked, expired.
	Status string `json:"status"`
	// When a pending consent link stops working (Unix ms).
	ExpiresAt *int64 `json:"expires_at"`
	// One of: email_link, admin, .
	ConsentMethod *string `json:"consent_method"`
	ConsentedAt   *int64  `json:"consented_at"`
	CreatedAt     int64   `json:"created_at"`
}

// UsersNotesCreateParams is a typed model of the Backend API.
type UsersNotesCreateParams struct {
	// The note text.
	Body string `json:"body"`
	// Pinned notes are listed first.
	Pinned *bool `json:"pinned,omitempty"`
}

// UsersNotesListItem is a typed model of the Backend API.
type UsersNotesListItem struct {
	Object string                   `json:"object"`
	ID     string                   `json:"id"`
	UserID string                   `json:"user_id"`
	Body   string                   `json:"body"`
	Pinned bool                     `json:"pinned"`
	Author UsersNotesListItemAuthor `json:"author"`
	// Added (epoch ms).
	CreatedAt int64 `json:"created_at"`
	// Last edited (epoch ms).
	UpdatedAt int64 `json:"updated_at"`
}

// UsersNotesListItemAuthor is a typed model of the Backend API.
type UsersNotesListItemAuthor struct {
	// One of: api_key, dashboard_user.
	Type string  `json:"type"`
	ID   *string `json:"id"`
}

// UsersNotesUpdateParams is a typed model of the Backend API.
type UsersNotesUpdateParams struct {
	// The note text.
	Body string `json:"body,omitempty"`
	// Pinned notes are listed first.
	Pinned *bool `json:"pinned,omitempty"`
}

// UsersRequiredActionsBulkParams is a typed model of the Backend API.
type UsersRequiredActionsBulkParams struct {
	// One of: update_password, verify_email, accept_policy, configure_mfa, update_profile,
	// identity_verification, custom.
	Action string `json:"action"`
	// custom only: the https URL the user is sent to.
	URL    string `json:"url,omitempty"`
	Reason string `json:"reason,omitempty"`
	// Exactly one of organization_id or user_ids.
	OrganizationID string   `json:"organization_id,omitempty"`
	UserIDs        []string `json:"user_ids,omitempty"`
}

// UsersRequiredActionsRequestParams is a typed model of the Backend API.
type UsersRequiredActionsRequestParams struct {
	// One of: update_password, verify_email, accept_policy, configure_mfa, update_profile,
	// identity_verification, custom.
	Action string `json:"action"`
	// custom only: the https URL the user is sent to.
	URL string `json:"url,omitempty"`
	// Free note shown on the audit entry and the held attempt (max 500 characters).
	Reason string `json:"reason,omitempty"`
}

// UsersRequiredActionsRequestResult is a typed model of the Backend API.
type UsersRequiredActionsRequestResult struct {
	Object string `json:"object"`
	ID     string `json:"id"`
	UserID string `json:"user_id"`
	// One of: update_password, verify_email, accept_policy, configure_mfa, update_profile,
	// identity_verification, custom.
	Action string `json:"action"`
	// custom only: where the user is sent.
	URL       *string `json:"url"`
	Reason    *string `json:"reason"`
	CreatedBy *string `json:"created_by"`
	// Requested (epoch ms).
	CreatedAt int64 `json:"created_at"`
}

// UsersSearchExportParams is a typed model of the Backend API.
type UsersSearchExportParams struct {
	// A filter tree. A group is exactly one of {"and":[…]}, {"or":[…]}, {"not":{…}} (nest up to 6
	// levels, 50 conditions). A condition is {"field","op","value"}. Fields: id, username, first_name,
	// last_name, external_id, locale, email, phone, created_at, updated_at, last_sign_in_at,
	// password_updated_at, ban
	Filter *UsersSearchQueryParamsFilter `json:"filter,omitempty"`
	// Free text over id, names, username, emails and phones, ANDed with the filter.
	Query string `json:"query,omitempty"`
	// created_at (default -created_at), updated_at, last_sign_in_at; prefix - for descending.
	OrderBy        string `json:"order_by,omitempty"`
	IncludeDeleted *bool  `json:"include_deleted,omitempty"`
	// One of: csv, ndjson.
	Format string   `json:"format,omitempty"`
	Fields []string `json:"fields,omitempty"`
}

// UsersSearchQueryItem is a user as the Backend API serializes it. Never includes private/unsafe
// metadata (those are write-only here).
type UsersSearchQueryItem struct {
	Object                string                                   `json:"object"`
	ID                    string                                   `json:"id"`
	Username              *string                                  `json:"username"`
	FirstName             *string                                  `json:"first_name"`
	LastName              *string                                  `json:"last_name"`
	ImageURL              *string                                  `json:"image_url"`
	EmailAddresses        []UsersSearchQueryItemEmailAddressesItem `json:"email_addresses"`
	PrimaryEmailAddressID *string                                  `json:"primary_email_address_id"`
	// The primary address as a flat string; null until a verified primary exists.
	PrimaryEmail *string `json:"primary_email"`
	// The relying party's own id for this user, if set/imported.
	ExternalID *string `json:"external_id"`
	// Whether the account has a usable password (never the hash).
	PasswordEnabled bool                   `json:"password_enabled"`
	PublicMetadata  map[string]interface{} `json:"public_metadata"`
	MFAEnabled      bool                   `json:"mfa_enabled"`
	// Factor classes this user must always use (POL-04); empty = none.
	RequiredFactors []string `json:"required_factors"`
	// Whether this identity is still an anonymous guest.
	IsAnonymous bool    `json:"is_anonymous"`
	Banned      bool    `json:"banned"`
	BanReason   *string `json:"ban_reason"`
	BanNote     *string `json:"ban_note"`
	Locked      bool    `json:"locked"`
	// Epoch-ms; non-null once soft-deleted.
	DeletedAt *int64 `json:"deleted_at"`
	// Epoch-ms.
	LastSignInAt *int64 `json:"last_sign_in_at"`
	// Created (epoch ms).
	CreatedAt int64 `json:"created_at"`
	// Last updated (epoch ms).
	UpdatedAt int64 `json:"updated_at"`
	// Strictly increases with every change to the user. Webhook payloads carry the same value: apply
	// an update only if its version is higher than the one you hold.
	Version int64 `json:"version"`
	// How the user arrived through a referral program (referral attribution on). Null only when the
	// user was never reported to the referral platform; otherwise `status` says where attribution
	// stands (`pending` until the platform answers). Present on read, list, create and update
	// responses.
	Referral interface{} `json:"referral"`
	// The user's own referral code, when they are a referrer.
	ReferralCode *string `json:"referral_code"`
	// The user's own referral link, when they are a referrer.
	ReferralLink *string `json:"referral_link"`
}

// UsersSearchQueryItemEmailAddressesItem is a typed model of the Backend API.
type UsersSearchQueryItemEmailAddressesItem struct {
	ID           string                                             `json:"id"`
	Object       string                                             `json:"object"`
	EmailAddress string                                             `json:"email_address"`
	Verification UsersSearchQueryItemEmailAddressesItemVerification `json:"verification"`
	// Same as verification.status === "verified": the address was proven.
	Verified bool `json:"verified"`
	Primary  bool `json:"primary"`
}

// UsersSearchQueryItemEmailAddressesItemVerification is a typed model of the Backend API.
type UsersSearchQueryItemEmailAddressesItemVerification struct {
	// verified only when the address was proven (an emailed code or link, a provider that vouches for
	// it, or your backend). An address that signed up while requireEmailVerification was false is
	// unverified. One of: verified, unverified.
	Status string `json:"status"`
	// How the address was verified: email_code, email_link, oauth, admin, import, scim, lti; skipped
	// when it signed up without proof (held for sign-in, reported unverified); null when not verified.
	Strategy *string `json:"strategy"`
}

// UsersSearchQueryParams is a typed model of the Backend API.
type UsersSearchQueryParams struct {
	// A filter tree. A group is exactly one of {"and":[…]}, {"or":[…]}, {"not":{…}} (nest up to 6
	// levels, 50 conditions). A condition is {"field","op","value"}. Fields: id, username, first_name,
	// last_name, external_id, locale, email, phone, created_at, updated_at, last_sign_in_at,
	// password_updated_at, ban
	Filter *UsersSearchQueryParamsFilter `json:"filter,omitempty"`
	// Free text over id, names, username, emails and phones, ANDed with the filter.
	Query string `json:"query,omitempty"`
	// created_at (default -created_at), updated_at, last_sign_in_at; prefix - for descending.
	OrderBy           string `json:"order_by,omitempty"`
	IncludeDeleted    *bool  `json:"include_deleted,omitempty"`
	Limit             *int64 `json:"limit,omitempty"`
	StartingAfter     string `json:"starting_after,omitempty"`
	Offset            *int64 `json:"offset,omitempty"`
	IncludeTotalCount *bool  `json:"include_total_count,omitempty"`
}

// UsersSearchQueryParamsFilter is a filter tree. A group is exactly one of {"and":[…]},
// {"or":[…]}, {"not":{…}} (nest up to 6 levels, 50 conditions). A condition is
// {"field","op","value"}. Fields: id, username, first_name, last_name, external_id, locale, email,
// phone, created_at, updated_at, last_sign_in_at, password_updated_at, ban
type UsersSearchQueryParamsFilter struct {
	And   []map[string]interface{} `json:"and,omitempty"`
	Or    []map[string]interface{} `json:"or,omitempty"`
	Not   map[string]interface{}   `json:"not,omitempty"`
	Field string                   `json:"field,omitempty"`
	// One of: eq, ne, in, nin, contains, starts_with, gt, gte, lt, lte, between, exists.
	Op string `json:"op,omitempty"`
	// The value to compare with: a string, number or boolean; a list for in / nin; [from, to] for
	// between; false with exists for "absent".
	Value interface{} `json:"value,omitempty"`
}

// UsersSearchViewsCreateParams is a typed model of the Backend API.
type UsersSearchViewsCreateParams struct {
	// Unique per instance (max 100 characters).
	Name string `json:"name"`
	// A filter tree. A group is exactly one of {"and":[…]}, {"or":[…]}, {"not":{…}} (nest up to 6
	// levels, 50 conditions). A condition is {"field","op","value"}. Fields: id, username, first_name,
	// last_name, external_id, locale, email, phone, created_at, updated_at, last_sign_in_at,
	// password_updated_at, ban
	Filter *UsersSearchQueryParamsFilter `json:"filter,omitempty"`
	// One of created_at, updated_at, last_sign_in_at, optionally prefixed with - for descending.
	OrderBy *string `json:"order_by,omitempty"`
}

// UsersSearchViewsListItem is a typed model of the Backend API.
type UsersSearchViewsListItem struct {
	Object    string                 `json:"object"`
	ID        string                 `json:"id"`
	Name      string                 `json:"name"`
	Filter    map[string]interface{} `json:"filter"`
	OrderBy   *string                `json:"order_by"`
	CreatedBy *string                `json:"created_by"`
	// Created (epoch ms).
	CreatedAt int64 `json:"created_at"`
	// Updated (epoch ms).
	UpdatedAt int64 `json:"updated_at"`
}

// UsersSearchViewsUpdateParams is a typed model of the Backend API.
type UsersSearchViewsUpdateParams struct {
	// Unique per instance (max 100 characters).
	Name string `json:"name,omitempty"`
	// A filter tree. A group is exactly one of {"and":[…]}, {"or":[…]}, {"not":{…}} (nest up to 6
	// levels, 50 conditions). A condition is {"field","op","value"}. Fields: id, username, first_name,
	// last_name, external_id, locale, email, phone, created_at, updated_at, last_sign_in_at,
	// password_updated_at, ban
	Filter *UsersSearchQueryParamsFilter `json:"filter,omitempty"`
	// One of created_at, updated_at, last_sign_in_at, optionally prefixed with - for descending.
	OrderBy *string `json:"order_by,omitempty"`
}

// VaultCreateParams is a typed model of the Backend API.
type VaultCreateParams struct {
	Name       string                 `json:"name,omitempty"`
	Value      string                 `json:"value,omitempty"`
	KeyContext map[string]string      `json:"key_context,omitempty"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
}

// VaultCreateResult is a typed model of the Backend API.
type VaultCreateResult struct {
	Object string `json:"object"`
	ID     string `json:"id"`
	// Unique within the instance.
	Name string `json:"name"`
	// The mandatory labels bound into the encryption.
	KeyContext map[string]string `json:"key_context"`
	// Non-secret labels returned by list and metadata reads.
	Metadata map[string]interface{} `json:"metadata"`
	// The current version number.
	Version int64 `json:"version"`
	// `atlas` (the instance key) or the customer KMS that wraps the current version's data key
	// (`aws_kms`, `gcp_kms`, `azure_key_vault`).
	KeyProvider string `json:"key_provider"`
	// When the object was created (epoch ms).
	CreatedAt int64 `json:"created_at"`
	// When the current version was written (epoch ms).
	UpdatedAt int64 `json:"updated_at"`
}

// VaultKeyProviderGetResult is a typed model of the Backend API.
type VaultKeyProviderGetResult struct {
	Object string `json:"object"`
	ID     string `json:"id"`
	// One of: aws_kms, gcp_kms, azure_key_vault.
	Provider string `json:"provider"`
	// The non-secret settings. Credentials are never returned.
	Config map[string]interface{} `json:"config"`
	// When the settings last changed (epoch ms).
	UpdatedAt int64 `json:"updated_at"`
}

// VaultKeyProviderSetParams is a typed model of the Backend API.
type VaultKeyProviderSetParams struct {
	Provider    string                 `json:"provider,omitempty"`
	Config      map[string]interface{} `json:"config,omitempty"`
	Credentials map[string]interface{} `json:"credentials,omitempty"`
}

// VaultReadResult is a typed model of the Backend API.
type VaultReadResult struct {
	Object string `json:"object"`
	ID     string `json:"id"`
	// Unique within the instance.
	Name string `json:"name"`
	// The mandatory labels bound into the encryption.
	KeyContext map[string]string `json:"key_context"`
	// Non-secret labels returned by list and metadata reads.
	Metadata map[string]interface{} `json:"metadata"`
	// The current version number.
	Version int64 `json:"version"`
	// `atlas` (the instance key) or the customer KMS that wraps the current version's data key
	// (`aws_kms`, `gcp_kms`, `azure_key_vault`).
	KeyProvider string `json:"key_provider"`
	// When the object was created (epoch ms).
	CreatedAt int64 `json:"created_at"`
	// When the current version was written (epoch ms).
	UpdatedAt int64 `json:"updated_at"`
	// The decrypted value.
	Value string `json:"value"`
}

// VaultUpdateParams is a typed model of the Backend API.
type VaultUpdateParams struct {
	Value        string   `json:"value,omitempty"`
	VersionCheck *float64 `json:"version_check,omitempty"`
}

// VaultVersionsItem is a typed model of the Backend API.
type VaultVersionsItem struct {
	Object      string `json:"object"`
	Version     int64  `json:"version"`
	Current     bool   `json:"current"`
	KeyProvider string `json:"key_provider"`
	// When the version was written (epoch ms).
	CreatedAt int64 `json:"created_at"`
}

// VCCreateOfferParams is a typed model of the Backend API.
type VCCreateOfferParams struct {
	CredentialTypeID string `json:"credential_type_id"`
	UserID           string `json:"user_id"`
	// 4 to 8 digits the wallet must send, delivered to the user separately.
	TXCode string `json:"tx_code,omitempty"`
	// Default 600.
	ExpiresInSeconds *int64 `json:"expires_in_seconds,omitempty"`
}

// VCCreateOfferResult is a typed model of the Backend API.
type VCCreateOfferResult struct {
	Object string `json:"object"`
	ID     string `json:"id"`
	// Expires (epoch ms).
	ExpiresAt          int64                  `json:"expires_at"`
	CredentialOffer    map[string]interface{} `json:"credential_offer"`
	CredentialOfferURI string                 `json:"credential_offer_uri"`
}

// VCCredentialsListItem is a typed model of the Backend API.
type VCCredentialsListItem struct {
	Object           string `json:"object"`
	ID               string `json:"id"`
	CredentialTypeID string `json:"credential_type_id"`
	UserID           string `json:"user_id"`
	// Position in the published status list.
	StatusIdx int64 `json:"status_idx"`
	// Issued (epoch ms).
	IssuedAt int64 `json:"issued_at"`
	// Expires (epoch ms).
	ExpiresAt int64  `json:"expires_at"`
	RevokedAt *int64 `json:"revoked_at"`
}

// VCCredentialTypesCreateParams is a typed model of the Backend API.
type VCCredentialTypesCreateParams struct {
	// The credential type identifier (a URN or URL); for mso_mdoc the docType, for example
	// org.iso.18013.5.1.mDL.
	Vct string `json:"vct"`
	// Default dc+sd-jwt. mso_mdoc issues an ISO 18013-5 mdoc (ES256, holder key P-256). One of:
	// dc+sd-jwt, mso_mdoc.
	Format string `json:"format,omitempty"`
	// mso_mdoc only: the namespace the claims live in (default the docType).
	Namespace string `json:"namespace,omitempty"`
	// mso_mdoc only: PEM IACA root certificates (ISO 18013-5 Annex B). With roots set, a presentation
	// must carry an x5chain leading to one of them and the issuer signature must verify under its
	// Document Signer key; bare trusted keys are then not accepted.
	IacaRoots []string `json:"iaca_roots,omitempty"`
	// mso_mdoc only: PEM Document Signer certificate first, then intermediates, published as x5chain.
	// The first certificate must be for this instance’s mdoc signing key (the ES256 key in its key
	// set), otherwise 400.
	SignerChain []string                                  `json:"signer_chain,omitempty"`
	Name        string                                    `json:"name"`
	Claims      []VCCredentialTypesCreateParamsClaimsItem `json:"claims"`
	// Default one year.
	LifetimeSeconds          *int64 `json:"lifetime_seconds,omitempty"`
	RequireWalletAttestation *bool  `json:"require_wallet_attestation,omitempty"`
	// JWK Set of accepted wallet providers; required with require_wallet_attestation.
	WalletAttestationJWKS map[string]interface{} `json:"wallet_attestation_jwks,omitempty"`
}

// VCCredentialTypesCreateParamsClaimsItem is a typed model of the Backend API.
type VCCredentialTypesCreateParamsClaimsItem struct {
	// The claim name in the credential.
	Name string `json:"name"`
	// user_id, email, first_name, last_name, username or public_metadata.<key>.
	Source string `json:"source"`
	// Selectively disclosable (default true; SD-JWT VC only, every mdoc element is disclosable).
	Disclosable *bool `json:"disclosable,omitempty"`
	// How the value is typed in the credential. full-date is a YYYY-MM-DD date (an mdoc full-date).
	// One of: string, number, boolean, full-date.
	ValueType string `json:"value_type,omitempty"`
}

// VCCredentialTypesListItem is a typed model of the Backend API.
type VCCredentialTypesListItem struct {
	Object string `json:"object"`
	ID     string `json:"id"`
	// The credential type (SD-JWT VC) or the docType (mdoc).
	Vct string `json:"vct"`
	// One of: dc+sd-jwt, mso_mdoc.
	Format string `json:"format"`
	// mdoc namespace of the claims.
	Namespace *string `json:"namespace"`
	// mdoc: PEM IACA root certificates. When set, presentations of this type are accepted only with an
	// x5chain that leads to one of them.
	IacaRoots []string `json:"iaca_roots"`
	// mdoc: PEM Document Signer certificate (then intermediates) published as x5chain in issued mdocs.
	SignerChain              []string                              `json:"signer_chain"`
	Name                     string                                `json:"name"`
	Claims                   []VCCredentialTypesListItemClaimsItem `json:"claims"`
	LifetimeSeconds          int64                                 `json:"lifetime_seconds"`
	RequireWalletAttestation bool                                  `json:"require_wallet_attestation"`
	// Created (epoch ms).
	CreatedAt int64 `json:"created_at"`
}

// VCCredentialTypesListItemClaimsItem is a typed model of the Backend API.
type VCCredentialTypesListItemClaimsItem struct {
	// The claim name in the credential.
	Name string `json:"name"`
	// user_id, email, first_name, last_name, username or public_metadata.<key>.
	Source string `json:"source"`
	// Selectively disclosable (default true; SD-JWT VC only, every mdoc element is disclosable).
	Disclosable bool `json:"disclosable"`
	// How the value is typed in the credential. full-date is a YYYY-MM-DD date (an mdoc full-date).
	// One of: string, number, boolean, full-date.
	ValueType string `json:"value_type"`
}

// VCPresentationRequestsCreateParams is a typed model of the Backend API.
type VCPresentationRequestsCreateParams struct {
	// The vct, or the docType for mso_mdoc.
	Vct string `json:"vct"`
	// Default dc+sd-jwt. One of: dc+sd-jwt, mso_mdoc.
	Format string `json:"format,omitempty"`
	// mso_mdoc only: PEM IACA roots for this request; overrides the credential type’s. Certificate
	// chain mode only: no bare key is accepted when roots apply.
	IacaRoots []string `json:"iaca_roots,omitempty"`
	// Claims the wallet must disclose.
	Claims []string `json:"claims,omitempty"`
	// Other issuers accepted besides this instance.
	TrustedIssuers []VCPresentationRequestsCreateParamsTrustedIssuersItem `json:"trusted_issuers,omitempty"`
	// Default 600.
	ExpiresInSeconds *int64 `json:"expires_in_seconds,omitempty"`
}

// VCPresentationRequestsCreateParamsTrustedIssuersItem is a typed model of the Backend API.
type VCPresentationRequestsCreateParamsTrustedIssuersItem struct {
	Issuer string                 `json:"issuer"`
	JWKS   map[string]interface{} `json:"jwks"`
}

// VCPresentationRequestsCreateResult is a typed model of the Backend API.
type VCPresentationRequestsCreateResult struct {
	Object string `json:"object"`
	ID     string `json:"id"`
	Vct    string `json:"vct"`
	// One of: dc+sd-jwt, mso_mdoc.
	Format    string   `json:"format"`
	IacaRoots []string `json:"iaca_roots"`
	Claims    []string `json:"claims"`
	// One of: pending, verified, failed.
	Status string `json:"status"`
	// When verified: issuer, vct and the disclosed claims.
	Result map[string]interface{} `json:"result"`
	Error  *string                `json:"error"`
	// When the credential was issued by this instance: the user it was issued to.
	UserID *string `json:"user_id"`
	// Expires (epoch ms).
	ExpiresAt  int64  `json:"expires_at"`
	RequestURI string `json:"request_uri"`
	// The openid4vp:// link for a QR code or deep link.
	AuthorizationRequestURI string `json:"authorization_request_uri"`
}

// WorkflowsCreateParams is a typed model of the Backend API.
type WorkflowsCreateParams struct {
	Name        string                           `json:"name,omitempty"`
	Description *string                          `json:"description,omitempty"`
	Enabled     *bool                            `json:"enabled,omitempty"`
	Trigger     *WorkflowsCreateParamsTrigger    `json:"trigger,omitempty"`
	Steps       []WorkflowsCreateParamsStepsItem `json:"steps,omitempty"`
}

// WorkflowsCreateParamsStepsItem is a typed model of the Backend API.
type WorkflowsCreateParamsStepsItem struct {
	// One of: notify, disable, delete, invite, add_to_org, remove_from_org, add_to_team,
	// remove_from_team, call_action.
	Type           string `json:"type"`
	Subject        string `json:"subject,omitempty"`
	Body           string `json:"body,omitempty"`
	To             string `json:"to,omitempty"`
	Reason         string `json:"reason,omitempty"`
	Role           string `json:"role,omitempty"`
	OrganizationID string `json:"organization_id,omitempty"`
	TeamID         string `json:"team_id,omitempty"`
	ActionID       string `json:"action_id,omitempty"`
}

// WorkflowsCreateParamsTrigger is a typed model of the Backend API.
type WorkflowsCreateParamsTrigger struct {
	// One of: cron, user_created, inactive, membership_age, trial_end, webhook_event.
	Type           string   `json:"type"`
	Cron           string   `json:"cron,omitempty"`
	AfterMinutes   *float64 `json:"after_minutes,omitempty"`
	Days           *float64 `json:"days,omitempty"`
	DaysBefore     *float64 `json:"days_before,omitempty"`
	OrganizationID string   `json:"organization_id,omitempty"`
	EventType      string   `json:"event_type,omitempty"`
}

// WorkflowsDryRunParams is a typed model of the Backend API.
type WorkflowsDryRunParams struct {
	UserID         string `json:"user_id,omitempty"`
	OrganizationID string `json:"organization_id,omitempty"`
}

// WorkflowsDryRunResult is a typed model of the Backend API.
type WorkflowsDryRunResult struct {
	Object     string `json:"object"`
	ID         string `json:"id"`
	WorkflowID string `json:"workflow_id"`
	// What the run was for: `user:<id>`, `event:<id>`, `cron:<slot>`, `membership:<id>`,
	// `trial:<id>:<end>`, `inactive:<id>:<last>` or `manual:<ms>:<user>`.
	Subject string  `json:"subject"`
	UserID  *string `json:"user_id"`
	DryRun  bool    `json:"dry_run"`
	// One of: running, succeeded, failed.
	Status string                           `json:"status"`
	Steps  []WorkflowsDryRunResultStepsItem `json:"steps"`
	Error  *string                          `json:"error"`
	// Started (epoch ms).
	StartedAt int64 `json:"started_at"`
	// Finished, Unix ms.
	FinishedAt *int64 `json:"finished_at"`
}

// WorkflowsDryRunResultStepsItem is a typed model of the Backend API.
type WorkflowsDryRunResultStepsItem struct {
	Index int64  `json:"index"`
	Type  string `json:"type"`
	// One of: ok, failed, would_run, skipped.
	Status string `json:"status"`
	Detail string `json:"detail"`
}

// WorkflowsListItem is a typed model of the Backend API.
type WorkflowsListItem struct {
	Object      string  `json:"object"`
	ID          string  `json:"id"`
	Name        string  `json:"name"`
	Description *string `json:"description"`
	Enabled     bool    `json:"enabled"`
	// What starts a run: `cron`, `user_created`, `inactive`, `membership_age`, `trial_end` or
	// `webhook_event`, with that trigger's fields.
	Trigger map[string]interface{} `json:"trigger"`
	// The ordered steps (1 to 20): `notify`, `disable`, `delete`, `invite`, `add_to_org`,
	// `remove_from_org`, `add_to_team`, `remove_from_team`, `add_to_group`, `remove_from_group`,
	// `call_action`.
	Steps []map[string]interface{} `json:"steps"`
	// A cron workflow's next slot, Unix ms; null for any other trigger.
	NextRunAt *int64 `json:"next_run_at"`
	// Created (epoch ms).
	CreatedAt int64 `json:"created_at"`
	// Last updated (epoch ms).
	UpdatedAt int64 `json:"updated_at"`
}
