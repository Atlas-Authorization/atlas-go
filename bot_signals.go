package atlas

import (
	"context"
	"net/url"
	"strconv"
)

// BotSignalsService is the /v1/bot_signals + /v1/bot_labels namespace — the
// anti-bot signal lake and its training labels.
type BotSignalsService struct{ client *Client }

// BotSignal is one anonymised feature vector per auth interaction.
type BotSignal struct {
	Object            string                 `json:"object"`
	ID                string                 `json:"id"`
	AttemptID         *string                `json:"attempt_id"`
	UserID            *string                `json:"user_id"`
	Kind              string                 `json:"kind"`
	Source            string                 `json:"source"`
	IPHash            *string                `json:"ip_hash"`
	IPSubnet          *string                `json:"ip_subnet"`
	ASN               *int                   `json:"asn"`
	GeoCountry        *string                `json:"geo_country"`
	GeoCity           *string                `json:"geo_city"`
	IsDatacenter      *bool                  `json:"is_datacenter"`
	IsAnonymizer      *bool                  `json:"is_anonymizer"`
	HeaderFingerprint *string                `json:"header_fingerprint"`
	AcceptLanguage    *string                `json:"accept_language"`
	DeviceID          *string                `json:"device_id"`
	DeviceFingerprint *string                `json:"device_fingerprint"`
	DeviceFeatures    map[string]interface{} `json:"device_features"`
	BehaviorFeatures  map[string]interface{} `json:"behavior_features"`
	CaptchaProvider   *string                `json:"captcha_provider"`
	CaptchaScore      *float64               `json:"captcha_score"`
	RiskLevel         *string                `json:"risk_level"`
	RiskScore         *float64               `json:"risk_score"`
	RiskSignals       map[string]interface{} `json:"risk_signals"`
	HeuristicScore    *float64               `json:"heuristic_score"`
	HeuristicReasons  []interface{}          `json:"heuristic_reasons"`
	Outcome           *string                `json:"outcome"`
	CreatedAt         int64                  `json:"created_at"`
}

// BotLabel is a supervised training label.
type BotLabel struct {
	Object      string  `json:"object"`
	ID          string  `json:"id"`
	SubjectType string  `json:"subject_type"`
	SubjectID   string  `json:"subject_id"`
	Label       string  `json:"label"`
	Source      string  `json:"source"`
	Confidence  float64 `json:"confidence"`
	Note        *string `json:"note"`
	LabeledBy   *string `json:"labeled_by"`
	CreatedAt   int64   `json:"created_at"`
}

// BotExportPage is a newest-first export page. NextBefore is the created-at
// epoch-ms cursor to pass back as Before for the next (older) page.
type BotExportPage[T any] struct {
	Object     string `json:"object"`
	Data       []T    `json:"data"`
	NextBefore *int64 `json:"next_before"`
}

// BotExportParams carries the limit (1..500) and an optional Before cursor.
type BotExportParams struct {
	Limit  int
	Before int64
}

func (p BotExportParams) values() url.Values {
	v := url.Values{}
	if p.Limit > 0 {
		v.Set("limit", strconv.Itoa(p.Limit))
	}
	if p.Before > 0 {
		v.Set("before", strconv.FormatInt(p.Before, 10))
	}
	return v
}

// CreateBotLabelParams is the body of POST /v1/bot_labels.
type CreateBotLabelParams struct {
	SubjectType string   `json:"subject_type"`
	SubjectID   string   `json:"subject_id"`
	Label       string   `json:"label"`
	Confidence  *float64 `json:"confidence,omitempty"`
	Note        string   `json:"note,omitempty"`
}

// List pages the signal lake, newest first. GET /v1/bot_signals.
func (s *BotSignalsService) List(ctx context.Context, params BotExportParams) (*BotExportPage[BotSignal], error) {
	out := &BotExportPage[BotSignal]{}
	return out, s.client.get(ctx, "/v1/bot_signals", params.values(), out)
}

// ListLabels pages the training labels, newest first. GET /v1/bot_labels.
func (s *BotSignalsService) ListLabels(ctx context.Context, params BotExportParams) (*BotExportPage[BotLabel], error) {
	out := &BotExportPage[BotLabel]{}
	return out, s.client.get(ctx, "/v1/bot_labels", params.values(), out)
}

// CreateLabel attaches a training label. POST /v1/bot_labels.
func (s *BotSignalsService) CreateLabel(ctx context.Context, params CreateBotLabelParams, opts ...RequestOption) (*BotLabel, error) {
	out := &BotLabel{}
	return out, s.client.post(ctx, "/v1/bot_labels", params, out, opts...)
}
