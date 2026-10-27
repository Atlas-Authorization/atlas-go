package atlas

import (
	"context"
	"net/url"
	"strconv"
)

// MarketingService is the marketing resource.
type MarketingService struct {
	client *Client
}

// GetSettings: The marketing settings: which UTM / ad-click-id parameters the SDK captures onto
// new users, and the GA4, GTM and Hotjar ids hosted pages load after consent.
// GET /v1/marketing_settings.
func (s *MarketingService) GetSettings(ctx context.Context) (*MarketingGetSettingsResult, error) {
	out := &MarketingGetSettingsResult{}
	return out, s.client.do(ctx, "GET", "/v1/marketing_settings", nil, nil, out)
}

// UpdateSettings: Change the marketing settings. `capture.params` empty means the standard set
// (utm_source, utm_medium, utm_campaign, utm_term, utm_content, utm_id and the common ad click
// ids). Hosted pages load a configured script only when the visitor's consent manager grants
// `scripts.consent_category` (default analytics); with no consent signal nothing loads.
// PUT /v1/marketing_settings.
func (s *MarketingService) UpdateSettings(ctx context.Context, params MarketingUpdateSettingsParams, opts ...RequestOption) (*MarketingGetSettingsResult, error) {
	out := &MarketingGetSettingsResult{}
	return out, s.client.do(ctx, "PUT", "/v1/marketing_settings", nil, params, out, opts...)
}

// MarketingListLeadsQuery holds the query parameters of MarketingService.ListLeads.
type MarketingListLeadsQuery struct {
	// Page size (default 50, at most 200).
	Limit int64
	// Cursor: the last id of the previous page.
	StartingAfter string
	// Only this form.
	Form string
	// csv returns a file.
	Format string
}

func (q MarketingListLeadsQuery) values() url.Values {
	v := url.Values{}
	if q.Limit != 0 {
		v.Set("limit", strconv.FormatInt(q.Limit, 10))
	}
	if q.StartingAfter != "" {
		v.Set("starting_after", q.StartingAfter)
	}
	if q.Form != "" {
		v.Set("form", q.Form)
	}
	if q.Format != "" {
		v.Set("format", q.Format)
	}
	return v
}

// ListLeads: The lead / subscribe form's submissions, newest first, with the first-touch
// attribution captured with each. `format=csv` exports up to 50,000.
// GET /v1/leads.
func (s *MarketingService) ListLeads(ctx context.Context, query MarketingListLeadsQuery) (*CursorPage[MarketingListLeadsItem], error) {
	out := &CursorPage[MarketingListLeadsItem]{}
	return out, s.client.do(ctx, "GET", "/v1/leads", query.values(), nil, out)
}

// DeleteLead: Delete one captured lead.
// DELETE /v1/leads/{id}.
func (s *MarketingService) DeleteLead(ctx context.Context, id string, opts ...RequestOption) (*UsersDeleteDeviceKeyResult, error) {
	out := &UsersDeleteDeviceKeyResult{}
	return out, s.client.do(ctx, "DELETE", "/v1/leads/"+url.PathEscape(id), nil, nil, out, opts...)
}
