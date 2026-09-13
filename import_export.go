package atlas

import (
	"context"
	"net/url"
)

// ImportExportService is the /v1/user_imports, /v1/user_exports and /v1/jobs
// namespace — §9.3 bulk user import/export (the Auth0 jobs parity surface).
type ImportExportService struct{ client *Client }

// ExportedUser is a user as serialised into an export job's result. Never a
// secret.
type ExportedUser struct {
	Object          string   `json:"object"`
	ID              string   `json:"id"`
	Username        *string  `json:"username"`
	FirstName       *string  `json:"first_name"`
	LastName        *string  `json:"last_name"`
	ImageURL        *string  `json:"image_url"`
	PublicMetadata  Metadata `json:"public_metadata"`
	PrivateMetadata Metadata `json:"private_metadata"`
	EmailAddresses  []struct {
		ID           string `json:"id"`
		EmailAddress string `json:"email_address"`
		Verified     bool   `json:"verified"`
		Primary      bool   `json:"primary"`
	} `json:"email_addresses"`
	MFAEnabled bool  `json:"mfa_enabled"`
	Banned     bool  `json:"banned"`
	CreatedAt  int64 `json:"created_at"`
	UpdatedAt  int64 `json:"updated_at"`
}

// Job is an import/export job.
type Job struct {
	Object      string         `json:"object"`
	ID          string         `json:"id"`
	Type        string         `json:"type"`
	Status      string         `json:"status"`
	Total       int            `json:"total"`
	Processed   int            `json:"processed"`
	Succeeded   int            `json:"succeeded"`
	Failed      int            `json:"failed"`
	ErrorCount  int            `json:"error_count"`
	Result      []ExportedUser `json:"result,omitempty"`
	CreatedAt   int64          `json:"created_at"`
	UpdatedAt   int64          `json:"updated_at"`
	CompletedAt *int64         `json:"completed_at"`
}

// JobError is one recorded per-row failure inside a job's errors array.
type JobError struct {
	Index   int     `json:"index"`
	Email   *string `json:"email"`
	Code    string  `json:"code"`
	Message string  `json:"message"`
}

// ImportUserRow is one user row accepted by an import.
type ImportUserRow struct {
	EmailAddress     string      `json:"email_address,omitempty"`
	Email            string      `json:"email,omitempty"`
	Password         string      `json:"password,omitempty"`
	PasswordHash     string      `json:"password_hash,omitempty"`
	EmailVerified    *bool       `json:"email_verified,omitempty"`
	Verified         *bool       `json:"verified,omitempty"`
	FirstName        string      `json:"first_name,omitempty"`
	LastName         string      `json:"last_name,omitempty"`
	Username         string      `json:"username,omitempty"`
	PublicMetadata   interface{} `json:"public_metadata,omitempty"`
	PrivateMetadata  interface{} `json:"private_metadata,omitempty"`
	ExternalAccounts []struct {
		Provider       string `json:"provider,omitempty"`
		ProviderUserID string `json:"provider_user_id,omitempty"`
		Email          string `json:"email,omitempty"`
		EmailVerified  *bool  `json:"email_verified,omitempty"`
	} `json:"external_accounts,omitempty"`
}

// ImportUsersParams is the body of POST /v1/user_imports.
type ImportUsersParams struct {
	Users  []ImportUserRow `json:"users"`
	Upsert *bool           `json:"upsert,omitempty"`
}

// ImportUsers imports users through the same per-row path sign-up uses.
// POST /v1/user_imports.
func (s *ImportExportService) ImportUsers(ctx context.Context, params ImportUsersParams, opts ...RequestOption) (*Job, error) {
	out := &Job{}
	return out, s.client.post(ctx, "/v1/user_imports", params, out, opts...)
}

// ExportUsers exports every non-deleted user, serialised without secrets.
// POST /v1/user_exports.
func (s *ImportExportService) ExportUsers(ctx context.Context, opts ...RequestOption) (*Job, error) {
	out := &Job{}
	return out, s.client.post(ctx, "/v1/user_exports", nil, out, opts...)
}

// ListJobs polls the instance's import/export jobs, newest first. GET /v1/jobs.
func (s *ImportExportService) ListJobs(ctx context.Context, params ListParams) (*CursorPage[Job], error) {
	out := &CursorPage[Job]{}
	return out, s.client.get(ctx, "/v1/jobs", params.values(), out)
}

// GetJob returns one job. GET /v1/jobs/:id.
func (s *ImportExportService) GetJob(ctx context.Context, id string) (*Job, error) {
	out := &Job{}
	return out, s.client.get(ctx, "/v1/jobs/"+url.PathEscape(id), nil, out)
}

// GetJobErrors returns the per-row failures recorded against a job.
// GET /v1/jobs/:id/errors.
func (s *ImportExportService) GetJobErrors(ctx context.Context, id string) (*ListPage[JobError], error) {
	out := &ListPage[JobError]{}
	return out, s.client.get(ctx, "/v1/jobs/"+url.PathEscape(id)+"/errors", nil, out)
}
