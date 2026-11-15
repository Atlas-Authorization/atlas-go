package atlas

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"sort"
	"strconv"
	"sync"
	"time"
)

// A local mirror of resource-scoped role assignments, so a "can this subject do X
// on that resource" question is answered with no network call and the SAME
// inheritance rules as POST /v1/resource_checks.
//
// It keeps the resource types (roles, includes, inherit), the resource tree (type,
// external id, parent) and the role assignments. Sync pulls the types and the
// tree, then consumes the assignment change feed from the stored cursor.
// ApplyWebhook applies resource_role_assignment.created / .deleted events between
// syncs. One difference from the server: Atlas adds the user's organizations and
// groups to the subject itself; offline you pass them in the check options.

// MirrorSubject is who is asking: type is user, group or org.
type MirrorSubject struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

// MirrorResourceRef names a resource by Atlas id, or by your own Type + ExternalID.
type MirrorResourceRef struct {
	ID         string
	Type       string
	ExternalID string
}

// MirrorRoleDef is a role of a resource type. "*" in Permissions grants every permission.
type MirrorRoleDef struct {
	Key         string   `json:"key"`
	Name        string   `json:"name,omitempty"`
	Permissions []string `json:"permissions"`
	// Includes names other roles of the same type this role also grants.
	Includes []string `json:"includes,omitempty"`
}

// MirroredResourceType is a resource type with its roles.
type MirroredResourceType struct {
	Key     string          `json:"key"`
	Inherit bool            `json:"inherit"`
	Roles   []MirrorRoleDef `json:"roles"`
}

// MirroredResource is one node of the resource tree. ParentID is "" for a root.
type MirroredResource struct {
	ID         string `json:"id"`
	Type       string `json:"type"`
	ExternalID string `json:"external_id"`
	ParentID   string `json:"parent_id"`
}

// MirroredAssignment is one role assignment.
type MirroredAssignment struct {
	ID         string `json:"id"`
	ResourceID string `json:"resource_id"`
	// Subject is "user:usr_1", "group:eng" or "org:org_1".
	Subject string `json:"subject"`
	Role    string `json:"role"`
	Inherit bool   `json:"inherit"`
}

// MirrorAssignmentChange is one entry of the assignment change feed (Change is created or deleted).
type MirrorAssignmentChange struct {
	Change     string
	Assignment MirroredAssignment
}

// ResourceRoleMirrorStore holds the mirror. Lookups return (nil, nil) when absent.
// MemoryResourceRoleMirrorStore is for tests and single-process apps.
type ResourceRoleMirrorStore interface {
	Cursor(ctx context.Context) (string, error)
	SetCursor(ctx context.Context, cursor string) error
	GetType(ctx context.Context, key string) (*MirroredResourceType, error)
	GetResource(ctx context.Context, ref MirrorResourceRef) (*MirroredResource, error)
	// AssignmentsOn returns every assignment sitting on any of these resources.
	AssignmentsOn(ctx context.Context, resourceIDs []string) ([]MirroredAssignment, error)
	// ReplaceTypes replaces the whole type registry; ReplaceResources the whole tree.
	ReplaceTypes(ctx context.Context, types []MirroredResourceType) error
	ReplaceResources(ctx context.Context, resources []MirroredResource) error
	// ApplyChanges upserts created assignments by id and removes deleted ones.
	ApplyChanges(ctx context.Context, changes []MirrorAssignmentChange) error
}

// ResourceRoleMirrorSyncClock is optional: persist the time of the last completed Sync.
type ResourceRoleMirrorSyncClock interface {
	LastSyncAt(ctx context.Context) (at int64, ok bool, err error)
	SetLastSyncAt(ctx context.Context, at int64) error
}

// MemoryResourceRoleMirrorStore is an in-memory store, safe for concurrent use.
type MemoryResourceRoleMirrorStore struct {
	mu          sync.Mutex
	assignments map[string]MirroredAssignment
	resources   map[string]MirroredResource
	types       map[string]MirroredResourceType
	cursor      string
	syncAt      int64
	synced      bool
}

// NewMemoryResourceRoleMirrorStore returns an empty store.
func NewMemoryResourceRoleMirrorStore() *MemoryResourceRoleMirrorStore {
	return &MemoryResourceRoleMirrorStore{
		assignments: map[string]MirroredAssignment{},
		resources:   map[string]MirroredResource{},
		types:       map[string]MirroredResourceType{},
	}
}

// Cursor implements ResourceRoleMirrorStore.
func (s *MemoryResourceRoleMirrorStore) Cursor(_ context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cursor, nil
}

// SetCursor implements ResourceRoleMirrorStore.
func (s *MemoryResourceRoleMirrorStore) SetCursor(_ context.Context, c string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cursor = c
	return nil
}

// GetType implements ResourceRoleMirrorStore.
func (s *MemoryResourceRoleMirrorStore) GetType(_ context.Context, key string) (*MirroredResourceType, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.types[key]
	if !ok {
		return nil, nil
	}
	return &t, nil
}

// GetResource implements ResourceRoleMirrorStore.
func (s *MemoryResourceRoleMirrorStore) GetResource(_ context.Context, ref MirrorResourceRef) (*MirroredResource, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ref.ID != "" {
		r, ok := s.resources[ref.ID]
		if !ok {
			return nil, nil
		}
		return &r, nil
	}
	for _, r := range s.resources {
		if r.Type == ref.Type && r.ExternalID == ref.ExternalID {
			c := r
			return &c, nil
		}
	}
	return nil, nil
}

// AssignmentsOn implements ResourceRoleMirrorStore.
func (s *MemoryResourceRoleMirrorStore) AssignmentsOn(_ context.Context, ids []string) ([]MirroredAssignment, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	want := map[string]bool{}
	for _, id := range ids {
		want[id] = true
	}
	out := []MirroredAssignment{}
	for _, a := range s.assignments {
		if want[a.ResourceID] {
			out = append(out, a)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// ReplaceTypes implements ResourceRoleMirrorStore.
func (s *MemoryResourceRoleMirrorStore) ReplaceTypes(_ context.Context, types []MirroredResourceType) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.types = make(map[string]MirroredResourceType, len(types))
	for _, t := range types {
		s.types[t.Key] = t
	}
	return nil
}

// ReplaceResources implements ResourceRoleMirrorStore.
func (s *MemoryResourceRoleMirrorStore) ReplaceResources(_ context.Context, resources []MirroredResource) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.resources = make(map[string]MirroredResource, len(resources))
	for _, r := range resources {
		s.resources[r.ID] = r
	}
	return nil
}

// ApplyChanges implements ResourceRoleMirrorStore.
func (s *MemoryResourceRoleMirrorStore) ApplyChanges(_ context.Context, changes []MirrorAssignmentChange) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range changes {
		if c.Change == "deleted" {
			delete(s.assignments, c.Assignment.ID)
		} else {
			s.assignments[c.Assignment.ID] = c.Assignment
		}
	}
	return nil
}

// LastSyncAt implements ResourceRoleMirrorSyncClock.
func (s *MemoryResourceRoleMirrorStore) LastSyncAt(_ context.Context) (int64, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.syncAt, s.synced, nil
}

// SetLastSyncAt implements ResourceRoleMirrorSyncClock.
func (s *MemoryResourceRoleMirrorStore) SetLastSyncAt(_ context.Context, at int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.syncAt, s.synced = at, true
	return nil
}

// ResourceRoleChange is one entry of the assignment change feed (Change is created or deleted).
type ResourceRoleChange struct {
	Change       string        `json:"change"`
	AssignmentID string        `json:"assignment_id"`
	ResourceID   string        `json:"resource_id"`
	Subject      MirrorSubject `json:"subject"`
	Role         string        `json:"role"`
	Inherit      bool          `json:"inherit"`
}

// ResourceRoleChangesPage is one page of the assignment change feed.
type ResourceRoleChangesPage struct {
	Data       []ResourceRoleChange `json:"data"`
	HasMore    bool                 `json:"has_more"`
	NextCursor string               `json:"next_cursor"`
}

// ResourceRoleResourcesPage is one page of the resource tree.
type ResourceRoleResourcesPage struct {
	Data       []MirroredResource `json:"data"`
	HasMore    bool               `json:"has_more"`
	NextCursor string             `json:"next_cursor"`
}

// ResourceRoleMirrorUpstream is the part of the Backend API the mirror talks to.
// NewResourceRoleMirrorUpstream returns the real one for a Client; tests pass a fake.
type ResourceRoleMirrorUpstream interface {
	ListTypes(ctx context.Context) ([]MirroredResourceType, error)
	ListResources(ctx context.Context, startingAfter string, limit int) (*ResourceRoleResourcesPage, error)
	AssignmentChanges(ctx context.Context, after string, limit int) (*ResourceRoleChangesPage, error)
}

type clientResourceRoleUpstream struct{ c *Client }

// NewResourceRoleMirrorUpstream returns the ResourceRoleMirrorUpstream backed by c.
func NewResourceRoleMirrorUpstream(c *Client) ResourceRoleMirrorUpstream {
	return &clientResourceRoleUpstream{c: c}
}

func (u *clientResourceRoleUpstream) ListTypes(ctx context.Context) ([]MirroredResourceType, error) {
	out := struct {
		Data []MirroredResourceType `json:"data"`
	}{}
	if err := u.c.do(ctx, "GET", "/v1/resource_types", nil, nil, &out); err != nil {
		return nil, err
	}
	return out.Data, nil
}

func (u *clientResourceRoleUpstream) ListResources(ctx context.Context, startingAfter string, limit int) (*ResourceRoleResourcesPage, error) {
	q := url.Values{}
	q.Set("limit", strconv.Itoa(limit))
	if startingAfter != "" {
		q.Set("starting_after", startingAfter)
	}
	out := &ResourceRoleResourcesPage{}
	if err := u.c.do(ctx, "GET", "/v1/resources", q, nil, out); err != nil {
		return nil, err
	}
	return out, nil
}

func (u *clientResourceRoleUpstream) AssignmentChanges(ctx context.Context, after string, limit int) (*ResourceRoleChangesPage, error) {
	q := url.Values{}
	q.Set("limit", strconv.Itoa(limit))
	if after != "" {
		q.Set("after", after)
	}
	out := &ResourceRoleChangesPage{}
	if err := u.c.do(ctx, "GET", "/v1/resource_role_assignments/changes", q, nil, out); err != nil {
		return nil, err
	}
	return out, nil
}

// ResourceRoleMirrorOptions configures a ResourceRoleMirror.
type ResourceRoleMirrorOptions struct {
	Store    ResourceRoleMirrorStore
	Upstream ResourceRoleMirrorUpstream
	// MaxStaleness: when set, Check answers "not allowed" with Code "stale" if the mirror
	// has never completed a Sync or the last one finished longer ago, because a revoked
	// assignment may not have reached it. Zero turns the check off (webhook-only mirrors).
	MaxStaleness time.Duration
	// ServeStaleFor keeps answering from the last synced data for this long after MaxStaleness
	// (the answer carries Stale), instead of refusing at once.
	ServeStaleFor time.Duration
	// OnServeStale is called each time an answer is served inside the ServeStaleFor grace.
	OnServeStale func(lastSyncAt time.Time, staleFor time.Duration)
	// TreeRefresh re-pulls the types and resource tree on a Sync only when this long has
	// passed since the last pull (zero = every Sync).
	TreeRefresh time.Duration
	// Now overrides the clock (tests).
	Now func() time.Time
}

// ResourceRoleCheckOptions adds what the server would add itself.
type ResourceRoleCheckOptions struct {
	// Orgs are organization ids the user belongs to.
	Orgs []string
	// Groups are group ids / slugs the subject belongs to.
	Groups []string
}

// MirrorGrant is one assignment that grants the permission.
type MirrorGrant struct {
	ResourceID string
	Role       string
	Subject    string
	Inherited  bool
}

// ResourceRoleMirrorCheck is the verdict and the grants behind it.
type ResourceRoleMirrorCheck struct {
	Allowed    bool
	ResourceID string
	Grants     []MirrorGrant
	// Code is "unknown_resource" (the mirror does not hold that resource) or "stale" (see MaxStaleness).
	Code string
	// Stale is true when the mirror was past MaxStaleness and this answer came from its last synced data.
	Stale bool
}

// mirrorMaxDepth is the same cap as the server's ancestor walk.
const mirrorMaxDepth = 16

// ResourceRoleMirror answers resource permission checks locally. Safe for concurrent use.
type ResourceRoleMirror struct {
	opts      ResourceRoleMirrorOptions
	clock     ResourceRoleMirrorSyncClock
	mu        sync.Mutex
	memSyncAt int64
	memSynced bool
	treeAt    int64
	treeDone  bool
}

// NewResourceRoleMirror builds a ResourceRoleMirror.
func NewResourceRoleMirror(opts ResourceRoleMirrorOptions) (*ResourceRoleMirror, error) {
	if opts.Store == nil || opts.Upstream == nil {
		return nil, errors.New("atlas: ResourceRoleMirror needs a Store and an Upstream")
	}
	m := &ResourceRoleMirror{opts: opts}
	m.clock, _ = opts.Store.(ResourceRoleMirrorSyncClock)
	return m, nil
}

func (m *ResourceRoleMirror) nowMS() int64 {
	if m.opts.Now != nil {
		return m.opts.Now().UnixMilli()
	}
	return time.Now().UnixMilli()
}

// LastSyncAt returns epoch ms of the last completed Sync; ok is false when never synced.
func (m *ResourceRoleMirror) LastSyncAt(ctx context.Context) (int64, bool, error) {
	if m.clock != nil {
		return m.clock.LastSyncAt(ctx)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.memSyncAt, m.memSynced, nil
}

// mirrorRolePermissions returns all permissions a role grants, following includes (cycle-safe).
func mirrorRolePermissions(t MirroredResourceType, roleKey string, seen map[string]bool) map[string]bool {
	out := map[string]bool{}
	if seen[roleKey] {
		return out
	}
	seen[roleKey] = true
	var role *MirrorRoleDef
	for i := range t.Roles {
		if t.Roles[i].Key == roleKey {
			role = &t.Roles[i]
			break
		}
	}
	if role == nil {
		return out
	}
	for _, p := range role.Permissions {
		out[p] = true
	}
	for _, inc := range role.Includes {
		for p := range mirrorRolePermissions(t, inc, seen) {
			out[p] = true
		}
	}
	return out
}

// MirrorChainLink is one resource of the ancestor chain with its type and assignments.
type MirrorChainLink struct {
	ResourceID  string
	Type        MirroredResourceType
	Assignments []MirrorChainAssignment
}

// MirrorChainAssignment is an assignment as ResolveMirrorGrants reads it.
type MirrorChainAssignment struct {
	Subject string
	RoleKey string
	Inherit bool
}

// ResolveMirrorGrants is the server's grant resolver over a chain of (resource,
// type, assignments), resource first: the grants (assignments whose role holds
// permission) that apply to subjects.
func ResolveMirrorGrants(chain []MirrorChainLink, subjects map[string]bool, permission string) []MirrorGrant {
	grants := []MirrorGrant{}
	for i, link := range chain {
		for _, a := range link.Assignments {
			if !subjects[a.Subject] || (i > 0 && !a.Inherit) {
				continue
			}
			perms := mirrorRolePermissions(link.Type, a.RoleKey, map[string]bool{})
			if perms[permission] || perms["*"] {
				grants = append(grants, MirrorGrant{ResourceID: link.ResourceID, Role: a.RoleKey, Subject: a.Subject, Inherited: i > 0})
			}
		}
		// The next link up is only reachable when this resource's type inherits.
		if !link.Type.Inherit {
			break
		}
	}
	return grants
}

func (m *ResourceRoleMirror) chainOf(ctx context.Context, resource *MirroredResource) ([]MirrorChainLink, error) {
	// The resource, then its ancestors (cycle-safe, depth-capped), exactly like the server:
	// ancestors dedupe among themselves only, so a cycle yields the start resource once more.
	ancestors := []*MirroredResource{}
	id := resource.ParentID
	for i := 0; i < mirrorMaxDepth && id != ""; i++ {
		row, err := m.opts.Store.GetResource(ctx, MirrorResourceRef{ID: id})
		if err != nil {
			return nil, err
		}
		if row == nil {
			break
		}
		dup := false
		for _, a := range ancestors {
			if a.ID == row.ID {
				dup = true
				break
			}
		}
		if dup {
			break
		}
		ancestors = append(ancestors, row)
		id = row.ParentID
	}
	rows := append([]*MirroredResource{resource}, ancestors...)
	ids := make([]string, len(rows))
	for i, r := range rows {
		ids[i] = r.ID
	}
	assignments, err := m.opts.Store.AssignmentsOn(ctx, ids)
	if err != nil {
		return nil, err
	}
	chain := make([]MirrorChainLink, 0, len(rows))
	for _, r := range rows {
		t, err := m.opts.Store.GetType(ctx, r.Type)
		if err != nil {
			return nil, err
		}
		typ := MirroredResourceType{Key: r.Type, Inherit: true}
		if t != nil {
			typ = *t
		}
		link := MirrorChainLink{ResourceID: r.ID, Type: typ}
		for _, a := range assignments {
			if a.ResourceID == r.ID {
				link.Assignments = append(link.Assignments, MirrorChainAssignment{Subject: a.Subject, RoleKey: a.Role, Inherit: a.Inherit})
			}
		}
		chain = append(chain, link)
	}
	return chain, nil
}

// Check returns the verdict and the grants behind it, in the shape of POST /v1/resource_checks.
func (m *ResourceRoleMirror) Check(ctx context.Context, subject MirrorSubject, permission string, resource MirrorResourceRef, opts ResourceRoleCheckOptions) (*ResourceRoleMirrorCheck, error) {
	servedStale := false
	if m.opts.MaxStaleness > 0 {
		at, ok, err := m.LastSyncAt(ctx)
		if err != nil {
			return nil, err
		}
		var behind int64
		if ok {
			behind = m.nowMS() - at - m.opts.MaxStaleness.Milliseconds()
		}
		if !ok || behind > 0 {
			if !ok || behind > m.opts.ServeStaleFor.Milliseconds() {
				return &ResourceRoleMirrorCheck{Code: "stale"}, nil
			}
			servedStale = true
			if m.opts.OnServeStale != nil {
				m.opts.OnServeStale(time.UnixMilli(at), time.Duration(behind)*time.Millisecond)
			}
		}
	}
	row, err := m.opts.Store.GetResource(ctx, resource)
	if err != nil {
		return nil, err
	}
	if row == nil {
		return &ResourceRoleMirrorCheck{Code: "unknown_resource"}, nil
	}
	if permission == "" {
		return &ResourceRoleMirrorCheck{ResourceID: row.ID}, nil
	}
	subjects := map[string]bool{subject.Type + ":" + subject.ID: true}
	for _, g := range opts.Groups {
		subjects["group:"+g] = true
	}
	for _, o := range opts.Orgs {
		subjects["org:"+o] = true
	}
	chain, err := m.chainOf(ctx, row)
	if err != nil {
		return nil, err
	}
	grants := ResolveMirrorGrants(chain, subjects, permission)
	return &ResourceRoleMirrorCheck{Allowed: len(grants) > 0, ResourceID: row.ID, Grants: grants, Stale: servedStale}, nil
}

// Can reports whether subject may hold permission on resource, answered locally.
func (m *ResourceRoleMirror) Can(ctx context.Context, subject MirrorSubject, permission string, resource MirrorResourceRef, opts ResourceRoleCheckOptions) (bool, error) {
	res, err := m.Check(ctx, subject, permission, resource, opts)
	if err != nil {
		return false, err
	}
	return res.Allowed, nil
}

// Sync pulls the types and the resource tree (when TreeRefresh has passed), then
// consumes the assignment change feed from the stored cursor. Call it on a timer
// (every few seconds to a minute) and at startup. It returns how many changes it applied.
func (m *ResourceRoleMirror) Sync(ctx context.Context) (int, error) {
	m.mu.Lock()
	refresh := !m.treeDone || m.nowMS()-m.treeAt >= m.opts.TreeRefresh.Milliseconds()
	m.mu.Unlock()
	if refresh {
		// Tree first: an assignment the feed then delivers never names a resource this mirror lacks.
		types, err := m.opts.Upstream.ListTypes(ctx)
		if err != nil {
			return 0, err
		}
		tree := []MirroredResource{}
		cursor := ""
		for {
			page, err := m.opts.Upstream.ListResources(ctx, cursor, 1000)
			if err != nil {
				return 0, err
			}
			tree = append(tree, page.Data...)
			if !page.HasMore || page.NextCursor == "" {
				break
			}
			cursor = page.NextCursor
		}
		if err := m.opts.Store.ReplaceTypes(ctx, types); err != nil {
			return 0, err
		}
		if err := m.opts.Store.ReplaceResources(ctx, tree); err != nil {
			return 0, err
		}
		m.mu.Lock()
		m.treeAt, m.treeDone = m.nowMS(), true
		m.mu.Unlock()
	}
	after, err := m.opts.Store.Cursor(ctx)
	if err != nil {
		return 0, err
	}
	applied := 0
	for {
		page, err := m.opts.Upstream.AssignmentChanges(ctx, after, 500)
		if err != nil {
			return applied, err
		}
		changes := make([]MirrorAssignmentChange, 0, len(page.Data))
		for _, c := range page.Data {
			changes = append(changes, MirrorAssignmentChange{
				Change: c.Change,
				Assignment: MirroredAssignment{
					ID: c.AssignmentID, ResourceID: c.ResourceID, Subject: c.Subject.Type + ":" + c.Subject.ID, Role: c.Role, Inherit: c.Inherit,
				},
			})
		}
		if err := m.opts.Store.ApplyChanges(ctx, changes); err != nil {
			return applied, err
		}
		applied += len(changes)
		if page.NextCursor != "" {
			after = page.NextCursor
			if err := m.opts.Store.SetCursor(ctx, after); err != nil {
				return applied, err
			}
		}
		if !page.HasMore {
			now := m.nowMS()
			m.mu.Lock()
			m.memSyncAt, m.memSynced = now, true
			m.mu.Unlock()
			if m.clock != nil {
				if err := m.clock.SetLastSyncAt(ctx, now); err != nil {
					return applied, err
				}
			}
			return applied, nil
		}
	}
}

// ApplyWebhook applies a VERIFIED resource_role_assignment.created / .deleted
// webhook (check the signature first, e.g. with VerifyWebhook). It returns whether
// the event changed the mirror.
func (m *ResourceRoleMirror) ApplyWebhook(ctx context.Context, eventType string, data json.RawMessage) (bool, error) {
	if eventType != "resource_role_assignment.created" && eventType != "resource_role_assignment.deleted" {
		return false, nil
	}
	var d struct {
		ID         string `json:"id"`
		ResourceID string `json:"resource_id"`
		Subject    struct {
			Type string `json:"type"`
			ID   string `json:"id"`
		} `json:"subject"`
		Role    string `json:"role"`
		Inherit *bool  `json:"inherit"`
	}
	if json.Unmarshal(data, &d) != nil || d.ID == "" || d.ResourceID == "" || d.Role == "" || d.Subject.Type == "" || d.Subject.ID == "" {
		return false, nil
	}
	change := "deleted"
	if eventType == "resource_role_assignment.created" {
		change = "created"
	}
	inherit := d.Inherit == nil || *d.Inherit
	err := m.opts.Store.ApplyChanges(ctx, []MirrorAssignmentChange{{
		Change:     change,
		Assignment: MirroredAssignment{ID: d.ID, ResourceID: d.ResourceID, Subject: d.Subject.Type + ":" + d.Subject.ID, Role: d.Role, Inherit: inherit},
	}})
	return err == nil, err
}
