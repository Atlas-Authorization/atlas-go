package atlas

import (
	"context"
	"net/url"
)

// PageTemplatesService is the pageTemplates resource.
type PageTemplatesService struct {
	client *Client
}

// List: The hosted-page templates of the instance: for each page (sign-in, sign-up, user-profile)
// the live template and the draft waiting to be previewed or promoted.
// GET /v1/instance/page_templates.
func (s *PageTemplatesService) List(ctx context.Context, params ListParams) (*CursorPage[PageTemplatesListItem], error) {
	out := &CursorPage[PageTemplatesListItem]{}
	return out, s.client.do(ctx, "GET", "/v1/instance/page_templates", params.values(), nil, out)
}

// Get: Read one page's live and draft template.
// GET /v1/instance/page_templates/{page}.
func (s *PageTemplatesService) Get(ctx context.Context, page string) (*PageTemplatesListItem, error) {
	out := &PageTemplatesListItem{}
	return out, s.client.do(ctx, "GET", "/v1/instance/page_templates/"+url.PathEscape(page), nil, nil, out)
}

// SaveDraft: Save a page template as the page's draft. A template is data: components (heading,
// text, image, link, button_link, list, divider, spacer, columns) in four regions (header,
// above_form, below_form, footer). It is validated on save: no raw HTML, CSS or script, https and
// mailto links only. The live page is unchanged until you promote.
// PUT /v1/instance/page_templates/{page}.
func (s *PageTemplatesService) SaveDraft(ctx context.Context, page string, params PageTemplatesSaveDraftParams, opts ...RequestOption) (*PageTemplatesListItem, error) {
	out := &PageTemplatesListItem{}
	return out, s.client.do(ctx, "PUT", "/v1/instance/page_templates/"+url.PathEscape(page), nil, params, out, opts...)
}

// PageTemplatesDiscardQuery holds the query parameters of PageTemplatesService.Discard.
type PageTemplatesDiscardQuery struct {
	// Which slot to drop: the draft, or the live template (the page goes back to the default).
	Status string
}

func (q PageTemplatesDiscardQuery) values() url.Values {
	v := url.Values{}
	if q.Status != "" {
		v.Set("status", q.Status)
	}
	return v
}

// Discard: Drop the draft or take the live template down (`status`).
// DELETE /v1/instance/page_templates/{page}.
func (s *PageTemplatesService) Discard(ctx context.Context, page string, query PageTemplatesDiscardQuery, opts ...RequestOption) (*PageTemplatesListItem, error) {
	out := &PageTemplatesListItem{}
	return out, s.client.do(ctx, "DELETE", "/v1/instance/page_templates/"+url.PathEscape(page), query.values(), nil, out, opts...)
}

// Preview: A signed link to the hosted page with the draft template applied (valid for one hour,
// noindex, with a preview banner). 409 when the page has no template.
// POST /v1/instance/page_templates/{page}/preview.
func (s *PageTemplatesService) Preview(ctx context.Context, page string, opts ...RequestOption) (*PageTemplatesPreviewResult, error) {
	out := &PageTemplatesPreviewResult{}
	return out, s.client.do(ctx, "POST", "/v1/instance/page_templates/"+url.PathEscape(page)+"/preview", nil, nil, out, opts...)
}

// Promote: Make the draft the live template.
// POST /v1/instance/page_templates/{page}/promote.
func (s *PageTemplatesService) Promote(ctx context.Context, page string, opts ...RequestOption) (*PageTemplatesListItem, error) {
	out := &PageTemplatesListItem{}
	return out, s.client.do(ctx, "POST", "/v1/instance/page_templates/"+url.PathEscape(page)+"/promote", nil, nil, out, opts...)
}
