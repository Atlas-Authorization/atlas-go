package atlas

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

type fakeRoleUpstream struct {
	types   []MirroredResourceType
	tree    []MirroredResource
	changes []MirrorAssignmentChange
}

func (f *fakeRoleUpstream) ListTypes(context.Context) ([]MirroredResourceType, error) {
	return f.types, nil
}

func (f *fakeRoleUpstream) ListResources(context.Context, string, int) (*ResourceRoleResourcesPage, error) {
	return &ResourceRoleResourcesPage{Data: f.tree}, nil
}

func (f *fakeRoleUpstream) AssignmentChanges(context.Context, string, int) (*ResourceRoleChangesPage, error) {
	page := &ResourceRoleChangesPage{}
	for _, c := range f.changes {
		typ, id, _ := strings.Cut(c.Assignment.Subject, ":")
		page.Data = append(page.Data, ResourceRoleChange{
			Change: c.Change, AssignmentID: c.Assignment.ID, ResourceID: c.Assignment.ResourceID,
			Subject: MirrorSubject{Type: typ, ID: id}, Role: c.Assignment.Role, Inherit: c.Assignment.Inherit,
		})
	}
	page.NextCursor = "c1"
	return page, nil
}

func newRoleMirrorForTest(t *testing.T) (*ResourceRoleMirror, *fakeRoleUpstream, *time.Time) {
	t.Helper()
	up := &fakeRoleUpstream{
		types: []MirroredResourceType{
			{Key: "project", Inherit: true, Roles: []MirrorRoleDef{
				{Key: "viewer", Permissions: []string{"read"}},
				{Key: "editor", Permissions: []string{"write"}, Includes: []string{"viewer"}},
				{Key: "owner", Permissions: []string{"*"}},
			}},
			{Key: "doc", Inherit: true, Roles: []MirrorRoleDef{{Key: "viewer", Permissions: []string{"read"}}}},
		},
		tree: []MirroredResource{
			{ID: "res_p", Type: "project", ExternalID: "p1"},
			{ID: "res_d", Type: "doc", ExternalID: "d1", ParentID: "res_p"},
		},
		changes: []MirrorAssignmentChange{
			{Change: "created", Assignment: MirroredAssignment{ID: "a1", ResourceID: "res_p", Subject: "user:usr_1", Role: "editor", Inherit: true}},
			{Change: "created", Assignment: MirroredAssignment{ID: "a2", ResourceID: "res_p", Subject: "group:eng", Role: "viewer", Inherit: false}},
		},
	}
	now := time.UnixMilli(2_000_000)
	m, err := NewResourceRoleMirror(ResourceRoleMirrorOptions{
		Store: NewMemoryResourceRoleMirrorStore(), Upstream: up, MaxStaleness: time.Minute, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	return m, up, &now
}

func TestResourceRoleMirrorInheritanceAndStaleness(t *testing.T) {
	m, _, now := newRoleMirrorForTest(t)
	ctx := context.Background()
	user := MirrorSubject{Type: "user", ID: "usr_1"}
	doc := MirrorResourceRef{Type: "doc", ExternalID: "d1"}

	if res, _ := m.Check(ctx, user, "read", doc, ResourceRoleCheckOptions{}); res.Allowed || res.Code != "stale" {
		t.Fatalf("never synced is stale: %+v", res)
	}
	if n, err := m.Sync(ctx); err != nil || n != 2 {
		t.Fatalf("sync: %d %v", n, err)
	}
	// editor includes viewer, and the assignment on the project flows down to the doc.
	res, err := m.Check(ctx, user, "read", doc, ResourceRoleCheckOptions{})
	if err != nil || !res.Allowed || len(res.Grants) != 1 || !res.Grants[0].Inherited || res.ResourceID != "res_d" {
		t.Fatalf("inherited read via includes: %+v %v", res, err)
	}
	if ok, _ := m.Can(ctx, user, "delete", doc, ResourceRoleCheckOptions{}); ok {
		t.Fatal("editor does not hold delete")
	}
	// The group assignment does not inherit, so it never reaches the doc.
	if ok, _ := m.Can(ctx, MirrorSubject{Type: "user", ID: "usr_9"}, "read", doc, ResourceRoleCheckOptions{Groups: []string{"eng"}}); ok {
		t.Fatal("a non-inheriting assignment stays on its own resource")
	}
	if ok, _ := m.Can(ctx, MirrorSubject{Type: "user", ID: "usr_9"}, "read", MirrorResourceRef{ID: "res_p"}, ResourceRoleCheckOptions{Groups: []string{"eng"}}); !ok {
		t.Fatal("the group viewer reads the project itself")
	}
	if res, _ = m.Check(ctx, user, "read", MirrorResourceRef{Type: "doc", ExternalID: "nope"}, ResourceRoleCheckOptions{}); res.Code != "unknown_resource" {
		t.Fatalf("unknown resource: %+v", res)
	}
	*now = now.Add(10 * time.Minute)
	if res, _ = m.Check(ctx, user, "read", doc, ResourceRoleCheckOptions{}); res.Allowed || res.Code != "stale" {
		t.Fatalf("an old sync is stale: %+v", res)
	}
}

func TestResourceRoleMirrorApplyWebhook(t *testing.T) {
	m, _, _ := newRoleMirrorForTest(t)
	ctx := context.Background()
	if _, err := m.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	user := MirrorSubject{Type: "user", ID: "usr_2"}
	proj := MirrorResourceRef{ID: "res_p"}
	created := json.RawMessage(`{"id":"a9","resource_id":"res_p","subject":{"type":"user","id":"usr_2"},"role":"owner"}`)
	if changed, err := m.ApplyWebhook(ctx, "resource_role_assignment.created", created); err != nil || !changed {
		t.Fatalf("created: %v %v", changed, err)
	}
	if ok, _ := m.Can(ctx, user, "anything", proj, ResourceRoleCheckOptions{}); !ok {
		t.Fatal("owner holds every permission")
	}
	if changed, _ := m.ApplyWebhook(ctx, "resource_role_assignment.deleted", created); !changed {
		t.Fatal("deleted")
	}
	if ok, _ := m.Can(ctx, user, "anything", proj, ResourceRoleCheckOptions{}); ok {
		t.Fatal("a deleted assignment grants nothing")
	}
	if changed, _ := m.ApplyWebhook(ctx, "user.created", created); changed {
		t.Fatal("other events are ignored")
	}
}

func TestResolveMirrorGrantsStopsAtNonInheritingType(t *testing.T) {
	leaf := MirroredResourceType{Key: "leaf", Inherit: false, Roles: []MirrorRoleDef{{Key: "r", Permissions: []string{"x"}}}}
	root := MirroredResourceType{Key: "root", Inherit: true, Roles: []MirrorRoleDef{{Key: "r", Permissions: []string{"x"}}}}
	chain := []MirrorChainLink{
		{ResourceID: "child", Type: leaf},
		{ResourceID: "parent", Type: root, Assignments: []MirrorChainAssignment{{Subject: "user:u", RoleKey: "r", Inherit: true}}},
	}
	if got := ResolveMirrorGrants(chain, map[string]bool{"user:u": true}, "x"); len(got) != 0 {
		t.Fatalf("a non-inheriting type blocks the walk: %+v", got)
	}
}
