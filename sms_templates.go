package atlas

import (
	"context"
	"net/url"
)

// SMSTemplatesService is the /v1/sms_templates namespace — the transactional SMS
// templates, keyed by name.
type SMSTemplatesService struct{ client *Client }

// SMSTemplate is a template row: the built-in default and any stored override.
type SMSTemplate struct {
	Object     string   `json:"object"`
	Name       string   `json:"name"`
	Default    string   `json:"default"`
	Body       *string  `json:"body"`
	Enabled    bool     `json:"enabled"`
	Customised bool     `json:"customised"`
	Variables  []string `json:"variables"`
}

// CreateSMSTemplateParams is the body of POST /v1/sms_templates.
type CreateSMSTemplateParams struct {
	Name    string `json:"name"`
	Body    string `json:"body"`
	Enabled *bool  `json:"enabled,omitempty"`
}

// UpdateSMSTemplateParams is the body of PATCH /v1/sms_templates/:name.
type UpdateSMSTemplateParams struct {
	Body    string `json:"body,omitempty"`
	Enabled *bool  `json:"enabled,omitempty"`
}

// SMSTemplatePreview is a rendered body with a fixed sample code.
type SMSTemplatePreview struct {
	Object     string `json:"object"`
	Name       string `json:"name"`
	Body       string `json:"body"`
	Customised bool   `json:"customised"`
}

// List returns the SMS templates. GET /v1/sms_templates.
func (s *SMSTemplatesService) List(ctx context.Context) (*ListPage[SMSTemplate], error) {
	out := &ListPage[SMSTemplate]{}
	return out, s.client.get(ctx, "/v1/sms_templates", nil, out)
}

// Create upserts an override by name. POST /v1/sms_templates.
func (s *SMSTemplatesService) Create(ctx context.Context, params CreateSMSTemplateParams, opts ...RequestOption) (*SMSTemplate, error) {
	out := &SMSTemplate{}
	return out, s.client.post(ctx, "/v1/sms_templates", params, out, opts...)
}

// Get returns one template. GET /v1/sms_templates/:name.
func (s *SMSTemplatesService) Get(ctx context.Context, name string) (*SMSTemplate, error) {
	out := &SMSTemplate{}
	return out, s.client.get(ctx, "/v1/sms_templates/"+url.PathEscape(name), nil, out)
}

// Update patches a template. PATCH /v1/sms_templates/:name.
func (s *SMSTemplatesService) Update(ctx context.Context, name string, params UpdateSMSTemplateParams) (*SMSTemplate, error) {
	out := &SMSTemplate{}
	return out, s.client.patch(ctx, "/v1/sms_templates/"+url.PathEscape(name), params, out)
}

// Delete reverts to the built-in. DELETE /v1/sms_templates/:name.
func (s *SMSTemplatesService) Delete(ctx context.Context, name string) (*SMSTemplate, error) {
	out := &SMSTemplate{}
	return out, s.client.del(ctx, "/v1/sms_templates/"+url.PathEscape(name), out)
}

// Preview renders an unsaved draft (if a body is given) or the stored/built-in.
// POST /v1/sms_templates/:name/preview.
func (s *SMSTemplatesService) Preview(ctx context.Context, name, body string) (*SMSTemplatePreview, error) {
	out := &SMSTemplatePreview{}
	reqBody := map[string]string{}
	if body != "" {
		reqBody["body"] = body
	}
	return out, s.client.post(ctx, "/v1/sms_templates/"+url.PathEscape(name)+"/preview", reqBody, out)
}
