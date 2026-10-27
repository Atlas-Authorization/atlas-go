package atlas

import (
	"context"
	"net/url"
	"strconv"
)

// DirectoryPullSourcesService is the directoryPullSources resource.
type DirectoryPullSourcesService struct {
	client   *Client
	SyncRuns *DirectoryPullSourcesSyncRunsService
}

// DirectoryPullSourcesListQuery holds the query parameters of DirectoryPullSourcesService.List.
type DirectoryPullSourcesListQuery struct {
	// Only the sources of this organization.
	OrganizationID string
	// Page size, 1-500. Without limit (and without starting_after) the whole list is returned.
	Limit int64
	// Cursor: return only items after this one. Pass the previous page's `next_cursor` (the last
	// item's id). An unknown cursor is a 400.
	StartingAfter string
}

func (q DirectoryPullSourcesListQuery) values() url.Values {
	v := url.Values{}
	if q.OrganizationID != "" {
		v.Set("organization_id", q.OrganizationID)
	}
	if q.Limit != 0 {
		v.Set("limit", strconv.FormatInt(q.Limit, 10))
	}
	if q.StartingAfter != "" {
		v.Set("starting_after", q.StartingAfter)
	}
	return v
}

// List: List HR / directory pull sources, optionally for one organization (organization_id).
// Credentials are never returned.
// GET /v1/directory_pull_sources.
func (s *DirectoryPullSourcesService) List(ctx context.Context, query DirectoryPullSourcesListQuery) (*DirectoryPullSourcesListResult, error) {
	out := &DirectoryPullSourcesListResult{}
	return out, s.client.do(ctx, "GET", "/v1/directory_pull_sources", query.values(), nil, out)
}

// Create: Create a pull source for an organization: provider (entra, google_workspace, bamboohr,
// hibob, personio, csv, rest_json), config, write-only credentials and settings (schedule, role
// mappings, disable on removal).
// POST /v1/directory_pull_sources.
func (s *DirectoryPullSourcesService) Create(ctx context.Context, params DirectoryPullSourcesCreateParams, opts ...RequestOption) (*DirectoryPullSourcesListResultDataItem, error) {
	out := &DirectoryPullSourcesListResultDataItem{}
	return out, s.client.do(ctx, "POST", "/v1/directory_pull_sources", nil, params, out, opts...)
}

// Get: Read one pull source.
// GET /v1/directory_pull_sources/{id}.
func (s *DirectoryPullSourcesService) Get(ctx context.Context, id string) (*DirectoryPullSourcesListResultDataItem, error) {
	out := &DirectoryPullSourcesListResultDataItem{}
	return out, s.client.do(ctx, "GET", "/v1/directory_pull_sources/"+url.PathEscape(id), nil, nil, out)
}

// Update: Change the source name, status (active or paused), config, credentials, default role or
// settings. Settings are merged.
// PATCH /v1/directory_pull_sources/{id}.
func (s *DirectoryPullSourcesService) Update(ctx context.Context, id string, params DirectoryPullSourcesUpdateParams, opts ...RequestOption) (*DirectoryPullSourcesListResultDataItem, error) {
	out := &DirectoryPullSourcesListResultDataItem{}
	return out, s.client.do(ctx, "PATCH", "/v1/directory_pull_sources/"+url.PathEscape(id), nil, params, out, opts...)
}

// Delete: Delete a pull source and its run log. Users it created are kept.
// DELETE /v1/directory_pull_sources/{id}.
func (s *DirectoryPullSourcesService) Delete(ctx context.Context, id string, opts ...RequestOption) error {
	return s.client.do(ctx, "DELETE", "/v1/directory_pull_sources/"+url.PathEscape(id), nil, nil, nil, opts...)
}

// SetCSV: Upload the CSV a csv source without a URL reads on its next run (up to 5 MiB).
// PUT /v1/directory_pull_sources/{id}/csv.
func (s *DirectoryPullSourcesService) SetCSV(ctx context.Context, id string, params DirectoryPullSourcesSetCSVParams, opts ...RequestOption) error {
	return s.client.do(ctx, "PUT", "/v1/directory_pull_sources/"+url.PathEscape(id)+"/csv", nil, params, nil, opts...)
}

// DirectoryPullSourcesSyncRunsService is the directoryPullSources syncRuns group of DirectoryPullSourcesService.
type DirectoryPullSourcesSyncRunsService struct {
	client *Client
}

// Create: Queue a pull now. One run at a time per source (409 otherwise); the worker executes it.
// POST /v1/directory_pull_sources/{id}/sync_runs.
func (s *DirectoryPullSourcesSyncRunsService) Create(ctx context.Context, id string, opts ...RequestOption) (*DirectoryPullSourcesSyncRunsCreateResult, error) {
	out := &DirectoryPullSourcesSyncRunsCreateResult{}
	return out, s.client.do(ctx, "POST", "/v1/directory_pull_sources/"+url.PathEscape(id)+"/sync_runs", nil, nil, out, opts...)
}

// List: List the runs of a source with counts of people seen, created, re-roled, disabled and
// re-enabled.
// GET /v1/directory_pull_sources/{id}/sync_runs.
func (s *DirectoryPullSourcesSyncRunsService) List(ctx context.Context, id string, params ListParams) (*DirectoryPullSourcesSyncRunsListResult, error) {
	out := &DirectoryPullSourcesSyncRunsListResult{}
	return out, s.client.do(ctx, "GET", "/v1/directory_pull_sources/"+url.PathEscape(id)+"/sync_runs", params.values(), nil, out)
}

// Get: Read one directory pull run with its counts and error.
// GET /v1/directory_pull_sources/{id}/sync_runs/{runId}.
func (s *DirectoryPullSourcesSyncRunsService) Get(ctx context.Context, id string, runID string) (*DirectoryPullSourcesSyncRunsCreateResult, error) {
	out := &DirectoryPullSourcesSyncRunsCreateResult{}
	return out, s.client.do(ctx, "GET", "/v1/directory_pull_sources/"+url.PathEscape(id)+"/sync_runs/"+url.PathEscape(runID), nil, nil, out)
}
