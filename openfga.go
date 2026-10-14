package atlas

import (
	"context"
	"net/url"
)

// OpenFGAService is the /v1/openfga namespace — the OpenFGA wire-compatible
// surface over the same relationship-based authorization engine as Client.FGA.
// Request and response shapes follow the OpenFGA HTTP API (stores, models,
// check, write, read, list-objects, expand, batch-check), so code written for an
// OpenFGA server ports over with only the base URL and credential changed.
type OpenFGAService struct{ client *Client }

// OpenFGAStore is a store as OpenFGA renders it (RFC 3339 timestamps).
type OpenFGAStore struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

// OpenFGAStoreList is the GET /v1/openfga/stores response.
type OpenFGAStoreList struct {
	Stores []OpenFGAStore `json:"stores"`
}

// OpenFGATupleKey is an OpenFGA tuple key: user, relation, object (type:id).
type OpenFGATupleKey struct {
	User     string `json:"user"`
	Relation string `json:"relation"`
	Object   string `json:"object"`
}

// OpenFGATupleKeys wraps a list of tuple keys the way OpenFGA does
// ({ "tuple_keys": [...] }) — used for writes, deletes and contextual tuples.
type OpenFGATupleKeys struct {
	TupleKeys []OpenFGATupleKey `json:"tuple_keys"`
}

// OpenFGAWriteAuthorizationModelParams is the body of
// POST /v1/openfga/stores/:store/authorization-models. Send either
// TypeDefinitions (+ SchemaVersion, default "1.1") or a DSL model string.
type OpenFGAWriteAuthorizationModelParams struct {
	TypeDefinitions []map[string]interface{} `json:"type_definitions,omitempty"`
	SchemaVersion   string                   `json:"schema_version,omitempty"`
	DSL             string                   `json:"dsl,omitempty"`
}

// OpenFGAWriteAuthorizationModelResponse carries the new model's id.
type OpenFGAWriteAuthorizationModelResponse struct {
	AuthorizationModelID string `json:"authorization_model_id"`
}

// OpenFGAAuthorizationModelSummary is one entry in a model listing.
type OpenFGAAuthorizationModelSummary struct {
	ID            string `json:"id"`
	SchemaVersion string `json:"schema_version"`
}

// OpenFGAAuthorizationModelList is the model listing response.
type OpenFGAAuthorizationModelList struct {
	AuthorizationModels []OpenFGAAuthorizationModelSummary `json:"authorization_models"`
}

// OpenFGAAuthorizationModel is one model with its type definitions (and any
// conditions) as stored.
type OpenFGAAuthorizationModel struct {
	ID              string                   `json:"id"`
	SchemaVersion   string                   `json:"schema_version"`
	TypeDefinitions []map[string]interface{} `json:"type_definitions"`
	Conditions      map[string]interface{}   `json:"conditions,omitempty"`
}

// OpenFGAReadAuthorizationModelResponse is the ReadAuthorizationModel response.
type OpenFGAReadAuthorizationModelResponse struct {
	AuthorizationModel OpenFGAAuthorizationModel `json:"authorization_model"`
}

// OpenFGACheckParams is the body of POST /v1/openfga/stores/:store/check.
// AuthorizationModelID defaults to the store's latest model.
type OpenFGACheckParams struct {
	TupleKey             OpenFGATupleKey   `json:"tuple_key"`
	AuthorizationModelID string            `json:"authorization_model_id,omitempty"`
	ContextualTuples     *OpenFGATupleKeys `json:"contextual_tuples,omitempty"`
}

// OpenFGACheckResponse is the check verdict.
type OpenFGACheckResponse struct {
	Allowed bool `json:"allowed"`
}

// OpenFGABatchCheckItem is one check in a batch, keyed by CorrelationID (the
// index is used when it is empty).
type OpenFGABatchCheckItem struct {
	TupleKey         OpenFGATupleKey   `json:"tuple_key"`
	CorrelationID    string            `json:"correlation_id,omitempty"`
	ContextualTuples *OpenFGATupleKeys `json:"contextual_tuples,omitempty"`
}

// OpenFGABatchCheckParams is the body of
// POST /v1/openfga/stores/:store/batch-check (up to 100 checks).
type OpenFGABatchCheckParams struct {
	Checks               []OpenFGABatchCheckItem `json:"checks"`
	AuthorizationModelID string                  `json:"authorization_model_id,omitempty"`
}

// OpenFGABatchCheckResponse maps each correlation id to its verdict.
type OpenFGABatchCheckResponse struct {
	Result map[string]OpenFGACheckResponse `json:"result"`
}

// OpenFGAWriteParams is the body of POST /v1/openfga/stores/:store/write.
type OpenFGAWriteParams struct {
	Writes  *OpenFGATupleKeys `json:"writes,omitempty"`
	Deletes *OpenFGATupleKeys `json:"deletes,omitempty"`
}

// OpenFGAReadParams is the body of POST /v1/openfga/stores/:store/read. A nil
// TupleKey reads every tuple; fields of a tuple key may be left empty to filter
// on the rest.
type OpenFGAReadParams struct {
	TupleKey          *OpenFGAReadTupleKey `json:"tuple_key,omitempty"`
	PageSize          int                  `json:"page_size,omitempty"`
	ContinuationToken string               `json:"continuation_token,omitempty"`
}

// OpenFGAReadTupleKey is a partial tuple-key filter for Read.
type OpenFGAReadTupleKey struct {
	User     string `json:"user,omitempty"`
	Relation string `json:"relation,omitempty"`
	Object   string `json:"object,omitempty"`
}

// OpenFGATuple is one tuple in a Read response.
type OpenFGATuple struct {
	Key       OpenFGATupleKey `json:"key"`
	Timestamp string          `json:"timestamp"`
}

// OpenFGAReadResponse is the Read response.
type OpenFGAReadResponse struct {
	Tuples            []OpenFGATuple `json:"tuples"`
	ContinuationToken string         `json:"continuation_token"`
}

// OpenFGAListObjectsParams is the body of
// POST /v1/openfga/stores/:store/list-objects.
type OpenFGAListObjectsParams struct {
	Type                 string            `json:"type"`
	Relation             string            `json:"relation"`
	User                 string            `json:"user"`
	AuthorizationModelID string            `json:"authorization_model_id,omitempty"`
	ContextualTuples     *OpenFGATupleKeys `json:"contextual_tuples,omitempty"`
}

// OpenFGAListObjectsResponse lists matching objects as type:id.
type OpenFGAListObjectsResponse struct {
	Objects []string `json:"objects"`
}

// OpenFGAExpandTupleKey names the (object, relation) to expand.
type OpenFGAExpandTupleKey struct {
	Object   string `json:"object"`
	Relation string `json:"relation"`
}

// OpenFGAExpandParams is the body of POST /v1/openfga/stores/:store/expand.
type OpenFGAExpandParams struct {
	TupleKey             OpenFGAExpandTupleKey `json:"tuple_key"`
	AuthorizationModelID string                `json:"authorization_model_id,omitempty"`
}

// OpenFGAExpandResponse carries the userset tree. Root is OpenFGA's Node: a
// name plus exactly one of leaf / union / intersection / difference.
type OpenFGAExpandResponse struct {
	Tree struct {
		Root map[string]interface{} `json:"root"`
	} `json:"tree"`
}

// ListStores lists the instance's stores. GET /v1/openfga/stores.
func (s *OpenFGAService) ListStores(ctx context.Context) (*OpenFGAStoreList, error) {
	out := &OpenFGAStoreList{}
	return out, s.client.get(ctx, "/v1/openfga/stores", nil, out)
}

// CreateStore creates a store. POST /v1/openfga/stores.
func (s *OpenFGAService) CreateStore(ctx context.Context, name string, opts ...RequestOption) (*OpenFGAStore, error) {
	out := &OpenFGAStore{}
	return out, s.client.post(ctx, "/v1/openfga/stores", map[string]string{"name": name}, out, opts...)
}

// GetStore fetches one store. GET /v1/openfga/stores/:store.
func (s *OpenFGAService) GetStore(ctx context.Context, store string) (*OpenFGAStore, error) {
	out := &OpenFGAStore{}
	return out, s.client.get(ctx, "/v1/openfga/stores/"+url.PathEscape(store), nil, out)
}

// WriteAuthorizationModel writes a new model to a store.
// POST /v1/openfga/stores/:store/authorization-models.
func (s *OpenFGAService) WriteAuthorizationModel(ctx context.Context, store string, params OpenFGAWriteAuthorizationModelParams, opts ...RequestOption) (*OpenFGAWriteAuthorizationModelResponse, error) {
	out := &OpenFGAWriteAuthorizationModelResponse{}
	return out, s.client.post(ctx, "/v1/openfga/stores/"+url.PathEscape(store)+"/authorization-models", params, out, opts...)
}

// ReadAuthorizationModels lists a store's models.
// GET /v1/openfga/stores/:store/authorization-models.
func (s *OpenFGAService) ReadAuthorizationModels(ctx context.Context, store string) (*OpenFGAAuthorizationModelList, error) {
	out := &OpenFGAAuthorizationModelList{}
	return out, s.client.get(ctx, "/v1/openfga/stores/"+url.PathEscape(store)+"/authorization-models", nil, out)
}

// ReadAuthorizationModel reads one model.
// GET /v1/openfga/stores/:store/authorization-models/:mid.
func (s *OpenFGAService) ReadAuthorizationModel(ctx context.Context, store, modelID string) (*OpenFGAReadAuthorizationModelResponse, error) {
	out := &OpenFGAReadAuthorizationModelResponse{}
	return out, s.client.get(ctx, "/v1/openfga/stores/"+url.PathEscape(store)+"/authorization-models/"+url.PathEscape(modelID), nil, out)
}

// Check answers whether a user has a relation on an object.
// POST /v1/openfga/stores/:store/check.
func (s *OpenFGAService) Check(ctx context.Context, store string, params OpenFGACheckParams, opts ...RequestOption) (*OpenFGACheckResponse, error) {
	out := &OpenFGACheckResponse{}
	return out, s.client.post(ctx, "/v1/openfga/stores/"+url.PathEscape(store)+"/check", params, out, opts...)
}

// BatchCheck runs up to 100 checks in one call.
// POST /v1/openfga/stores/:store/batch-check.
func (s *OpenFGAService) BatchCheck(ctx context.Context, store string, params OpenFGABatchCheckParams, opts ...RequestOption) (*OpenFGABatchCheckResponse, error) {
	out := &OpenFGABatchCheckResponse{}
	return out, s.client.post(ctx, "/v1/openfga/stores/"+url.PathEscape(store)+"/batch-check", params, out, opts...)
}

// Write writes and/or deletes tuples. POST /v1/openfga/stores/:store/write.
func (s *OpenFGAService) Write(ctx context.Context, store string, params OpenFGAWriteParams, opts ...RequestOption) error {
	return s.client.post(ctx, "/v1/openfga/stores/"+url.PathEscape(store)+"/write", params, nil, opts...)
}

// Read reads tuples, optionally filtered. POST /v1/openfga/stores/:store/read.
func (s *OpenFGAService) Read(ctx context.Context, store string, params OpenFGAReadParams, opts ...RequestOption) (*OpenFGAReadResponse, error) {
	out := &OpenFGAReadResponse{}
	return out, s.client.post(ctx, "/v1/openfga/stores/"+url.PathEscape(store)+"/read", params, out, opts...)
}

// ListObjects lists the objects of a type a user has a relation on.
// POST /v1/openfga/stores/:store/list-objects.
func (s *OpenFGAService) ListObjects(ctx context.Context, store string, params OpenFGAListObjectsParams, opts ...RequestOption) (*OpenFGAListObjectsResponse, error) {
	out := &OpenFGAListObjectsResponse{}
	return out, s.client.post(ctx, "/v1/openfga/stores/"+url.PathEscape(store)+"/list-objects", params, out, opts...)
}

// Expand expands the userset tree for an (object, relation).
// POST /v1/openfga/stores/:store/expand.
func (s *OpenFGAService) Expand(ctx context.Context, store string, params OpenFGAExpandParams, opts ...RequestOption) (*OpenFGAExpandResponse, error) {
	out := &OpenFGAExpandResponse{}
	return out, s.client.post(ctx, "/v1/openfga/stores/"+url.PathEscape(store)+"/expand", params, out, opts...)
}
