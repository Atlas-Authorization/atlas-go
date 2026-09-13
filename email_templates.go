package atlas

import (
	"context"
	"net/url"
)

// EmailTemplatesService is the /v1/email_templates namespace — the transactional
// email templates, keyed by name.
type EmailTemplatesService struct{ client *Client }

// EmailTemplateBody is the customizable body of a template.
type EmailTemplateBody struct {
	Subject string `json:"subject,omitempty"`
	Text    string `json:"text,omitempty"`
}

// EmailTemplate is a list row: both the built-in default and any stored override.
type EmailTemplate struct {
	Object  string `json:"object"`
	Name    string `json:"name"`
	Default struct {
		Subject string `json:"subject"`
		Text    string `json:"text"`
	} `json:"default"`
	Override   *EmailTemplateBody `json:"override"`
	Customised bool               `json:"customised"`
}

// EmailTemplateResult is the lean shape an update/delete acknowledges with.
type EmailTemplateResult struct {
	Object     string             `json:"object"`
	Name       string             `json:"name"`
	Override   *EmailTemplateBody `json:"override"`
	Customised bool               `json:"customised"`
}

// EmailTemplatePreview is a rendered template with sample variables.
type EmailTemplatePreview struct {
	Object    string            `json:"object"`
	Template  string            `json:"template"`
	Valid     bool              `json:"valid"`
	Problem   *string           `json:"problem"`
	HTML      *string           `json:"html"`
	Variables map[string]string `json:"variables"`
}

// List returns the email templates. GET /v1/email_templates.
func (s *EmailTemplatesService) List(ctx context.Context) (*ListPage[EmailTemplate], error) {
	out := &ListPage[EmailTemplate]{}
	return out, s.client.get(ctx, "/v1/email_templates", nil, out)
}

// Preview renders an unsaved draft (if a body is given) or the stored template.
// POST /v1/email_templates/:name/preview.
func (s *EmailTemplatesService) Preview(ctx context.Context, name string, body EmailTemplateBody) (*EmailTemplatePreview, error) {
	out := &EmailTemplatePreview{}
	return out, s.client.post(ctx, "/v1/email_templates/"+url.PathEscape(name)+"/preview", body, out)
}

// Update saves an override, keyed by template name.
// PUT /v1/email_templates/:name.
func (s *EmailTemplatesService) Update(ctx context.Context, name string, body EmailTemplateBody) (*EmailTemplateResult, error) {
	out := &EmailTemplateResult{}
	return out, s.client.put(ctx, "/v1/email_templates/"+url.PathEscape(name), body, out)
}

// Delete reverts to the built-in. DELETE /v1/email_templates/:name.
func (s *EmailTemplatesService) Delete(ctx context.Context, name string) (*EmailTemplateResult, error) {
	out := &EmailTemplateResult{}
	return out, s.client.del(ctx, "/v1/email_templates/"+url.PathEscape(name), out)
}
