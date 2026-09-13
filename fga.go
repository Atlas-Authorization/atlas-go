package atlas

import (
	"context"
	"net/url"
)

// FGAService is the /v1/fga namespace — fine-grained relationship-based
// authorization (Zanzibar / OpenFGA). A tenant owns STORES; each store holds
// versioned authorization MODELS and the relationship TUPLES the engine resolves.
type FGAService struct {
	client *Client

	Stores *FGAStoresService
	Models *FGAModelsService
}

// FGAStore is an FGA store.
type FGAStore struct {
	Object    string `json:"object"`
	ID        string `json:"id"`
	Name      string `json:"name"`
	CreatedAt int64  `json:"created_at"`
	UpdatedAt int64  `json:"updated_at"`
}

// FGAAuthorizationModel is a versioned OpenFGA authorization model.
type FGAAuthorizationModel struct {
	Object        string                 `json:"object"`
	ID            string                 `json:"id"`
	StoreID       string                 `json:"store_id"`
	SchemaVersion string                 `json:"schema_version"`
	Model         map[string]interface{} `json:"model,omitempty"`
	CreatedAt     int64                  `json:"created_at"`
}

// FGATuple is a stored relationship tuple.
type FGATuple struct {
	Object    string `json:"object"`
	User      string `json:"user"`
	Relation  string `json:"relation"`
	Target    string `json:"target"`
	CreatedAt int64  `json:"created_at"`
}

// FGATupleKey is a tuple key. Object is the target as type:id.
type FGATupleKey struct {
	User     string `json:"user"`
	Relation string `json:"relation"`
	Object   string `json:"object"`
}

// FGAAuthorizationModelInput is an OpenFGA authorization model to persist.
type FGAAuthorizationModelInput struct {
	TypeDefinitions []interface{}          `json:"type_definitions"`
	SchemaVersion   string                 `json:"schema_version,omitempty"`
	Conditions      map[string]interface{} `json:"conditions,omitempty"`
}

// FGACheckParams resolves a single access question.
type FGACheckParams struct {
	User                 string        `json:"user"`
	Relation             string        `json:"relation"`
	Object               string        `json:"object"`
	AuthorizationModelID string        `json:"authorization_model_id,omitempty"`
	ContextualTuples     []FGATupleKey `json:"contextual_tuples,omitempty"`
}

// FGAListObjectsParams lists the objects of a type a user has a relation to.
type FGAListObjectsParams struct {
	User                 string        `json:"user"`
	Relation             string        `json:"relation"`
	Type                 string        `json:"type"`
	AuthorizationModelID string        `json:"authorization_model_id,omitempty"`
	ContextualTuples     []FGATupleKey `json:"contextual_tuples,omitempty"`
}

// FGABatchCheckItem is one item in a batch check.
type FGABatchCheckItem struct {
	User             string        `json:"user"`
	Relation         string        `json:"relation"`
	Object           string        `json:"object"`
	CorrelationID    string        `json:"correlation_id,omitempty"`
	ContextualTuples []FGATupleKey `json:"contextual_tuples,omitempty"`
}

// FGABatchCheckParams is the body of a batch check.
type FGABatchCheckParams struct {
	Checks               []FGABatchCheckItem `json:"checks"`
	AuthorizationModelID string              `json:"authorization_model_id,omitempty"`
}

// FGABatchCheckResult is the batch-check verdict set.
type FGABatchCheckResult struct {
	Object               string `json:"object"`
	AuthorizationModelID string `json:"authorization_model_id"`
	Result               []struct {
		CorrelationID string `json:"correlation_id"`
		Allowed       bool   `json:"allowed"`
	} `json:"result"`
}

// FGAWriteParams writes and/or deletes tuples in one atomic call.
type FGAWriteParams struct {
	Writes  []FGATupleKey `json:"writes,omitempty"`
	Deletes []FGATupleKey `json:"deletes,omitempty"`
}

// FGAWriteResult acknowledges a write.
type FGAWriteResult struct {
	Object  string `json:"object"`
	Writes  int    `json:"writes"`
	Deletes int    `json:"deletes"`
}

// FGAReadParams queries stored tuples by any of user / relation / object.
type FGAReadParams struct {
	User     string `json:"user,omitempty"`
	Relation string `json:"relation,omitempty"`
	Object   string `json:"object,omitempty"`
}

// FGACheckResult is a single check verdict.
type FGACheckResult struct {
	Object               string `json:"object"`
	Allowed              bool   `json:"allowed"`
	AuthorizationModelID string `json:"authorization_model_id"`
}

// FGAListObjectsResult is the list-objects verdict.
type FGAListObjectsResult struct {
	Object               string   `json:"object"`
	Objects              []string `json:"objects"`
	AuthorizationModelID string   `json:"authorization_model_id"`
}

// FGAExpandParams expands the full userset tree for an object#relation.
type FGAExpandParams struct {
	Object               string `json:"object"`
	Relation             string `json:"relation"`
	AuthorizationModelID string `json:"authorization_model_id,omitempty"`
}

// FGAExpandResult is the expand tree.
type FGAExpandResult struct {
	Object               string      `json:"object"`
	Tree                 interface{} `json:"tree"`
	AuthorizationModelID string      `json:"authorization_model_id"`
}

// --- Stores ----------------------------------------------------------------

// FGAStoresService is /v1/fga/stores.
type FGAStoresService struct{ client *Client }

// List returns the stores. GET /v1/fga/stores.
func (s *FGAStoresService) List(ctx context.Context) (*ListPage[FGAStore], error) {
	out := &ListPage[FGAStore]{}
	return out, s.client.get(ctx, "/v1/fga/stores", nil, out)
}

// Create creates a store. POST /v1/fga/stores.
func (s *FGAStoresService) Create(ctx context.Context, name string, opts ...RequestOption) (*FGAStore, error) {
	out := &FGAStore{}
	body := map[string]string{"name": name}
	return out, s.client.post(ctx, "/v1/fga/stores", body, out, opts...)
}

// Get returns one store. GET /v1/fga/stores/:id.
func (s *FGAStoresService) Get(ctx context.Context, id string) (*FGAStore, error) {
	out := &FGAStore{}
	return out, s.client.get(ctx, "/v1/fga/stores/"+url.PathEscape(id), nil, out)
}

// Delete removes a store. DELETE /v1/fga/stores/:id.
func (s *FGAStoresService) Delete(ctx context.Context, id string) (*DeletedObject, error) {
	out := &DeletedObject{}
	return out, s.client.del(ctx, "/v1/fga/stores/"+url.PathEscape(id), out)
}

// --- Models ----------------------------------------------------------------

// FGAModelsService is /v1/fga/stores/:storeId/authorization-models.
type FGAModelsService struct{ client *Client }

// List returns a store's models. GET .../authorization-models.
func (s *FGAModelsService) List(ctx context.Context, storeID string) (*ListPage[FGAAuthorizationModel], error) {
	out := &ListPage[FGAAuthorizationModel]{}
	return out, s.client.get(ctx, "/v1/fga/stores/"+url.PathEscape(storeID)+"/authorization-models", nil, out)
}

// Create persists a new model. POST .../authorization-models.
func (s *FGAModelsService) Create(ctx context.Context, storeID string, params FGAAuthorizationModelInput, opts ...RequestOption) (*FGAAuthorizationModel, error) {
	out := &FGAAuthorizationModel{}
	return out, s.client.post(ctx, "/v1/fga/stores/"+url.PathEscape(storeID)+"/authorization-models", params, out, opts...)
}

// Get returns one model. GET .../authorization-models/:modelId.
func (s *FGAModelsService) Get(ctx context.Context, storeID, modelID string) (*FGAAuthorizationModel, error) {
	out := &FGAAuthorizationModel{}
	return out, s.client.get(ctx, "/v1/fga/stores/"+url.PathEscape(storeID)+"/authorization-models/"+url.PathEscape(modelID), nil, out)
}

// --- Store operations ------------------------------------------------------

// Write writes and/or deletes tuples atomically. POST .../write.
func (s *FGAService) Write(ctx context.Context, storeID string, params FGAWriteParams, opts ...RequestOption) (*FGAWriteResult, error) {
	out := &FGAWriteResult{}
	return out, s.client.post(ctx, "/v1/fga/stores/"+url.PathEscape(storeID)+"/write", params, out, opts...)
}

// Read queries stored tuples. POST .../read.
func (s *FGAService) Read(ctx context.Context, storeID string, params FGAReadParams) (*ListPage[FGATuple], error) {
	out := &ListPage[FGATuple]{}
	return out, s.client.post(ctx, "/v1/fga/stores/"+url.PathEscape(storeID)+"/read", params, out)
}

// Check resolves a single access question. POST .../check.
func (s *FGAService) Check(ctx context.Context, storeID string, params FGACheckParams) (*FGACheckResult, error) {
	out := &FGACheckResult{}
	return out, s.client.post(ctx, "/v1/fga/stores/"+url.PathEscape(storeID)+"/check", params, out)
}

// BatchCheck resolves many access questions in one round trip. POST .../batch-check.
func (s *FGAService) BatchCheck(ctx context.Context, storeID string, params FGABatchCheckParams) (*FGABatchCheckResult, error) {
	out := &FGABatchCheckResult{}
	return out, s.client.post(ctx, "/v1/fga/stores/"+url.PathEscape(storeID)+"/batch-check", params, out)
}

// ListObjects lists the objects of a type a user has a relation to.
// POST .../list-objects.
func (s *FGAService) ListObjects(ctx context.Context, storeID string, params FGAListObjectsParams) (*FGAListObjectsResult, error) {
	out := &FGAListObjectsResult{}
	return out, s.client.post(ctx, "/v1/fga/stores/"+url.PathEscape(storeID)+"/list-objects", params, out)
}

// Expand expands the full userset tree for an object#relation. POST .../expand.
func (s *FGAService) Expand(ctx context.Context, storeID string, params FGAExpandParams) (*FGAExpandResult, error) {
	out := &FGAExpandResult{}
	return out, s.client.post(ctx, "/v1/fga/stores/"+url.PathEscape(storeID)+"/expand", params, out)
}

// BoundStore binds a default store id so an app that uses one store can call the
// operations without threading the store id through every call. Obtain one with
// FGAService.Store.
type BoundStore struct {
	svc     *FGAService
	storeID string
}

// Store returns operations with storeID pre-applied.
func (s *FGAService) Store(storeID string) *BoundStore {
	return &BoundStore{svc: s, storeID: storeID}
}

// Write writes/deletes tuples against the bound store.
func (b *BoundStore) Write(ctx context.Context, params FGAWriteParams, opts ...RequestOption) (*FGAWriteResult, error) {
	return b.svc.Write(ctx, b.storeID, params, opts...)
}

// Read queries tuples against the bound store.
func (b *BoundStore) Read(ctx context.Context, params FGAReadParams) (*ListPage[FGATuple], error) {
	return b.svc.Read(ctx, b.storeID, params)
}

// Check resolves one access question against the bound store.
func (b *BoundStore) Check(ctx context.Context, params FGACheckParams) (*FGACheckResult, error) {
	return b.svc.Check(ctx, b.storeID, params)
}

// BatchCheck resolves many questions against the bound store.
func (b *BoundStore) BatchCheck(ctx context.Context, params FGABatchCheckParams) (*FGABatchCheckResult, error) {
	return b.svc.BatchCheck(ctx, b.storeID, params)
}

// ListObjects lists objects against the bound store.
func (b *BoundStore) ListObjects(ctx context.Context, params FGAListObjectsParams) (*FGAListObjectsResult, error) {
	return b.svc.ListObjects(ctx, b.storeID, params)
}

// Expand expands a tree against the bound store.
func (b *BoundStore) Expand(ctx context.Context, params FGAExpandParams) (*FGAExpandResult, error) {
	return b.svc.Expand(ctx, b.storeID, params)
}

// ModelsList lists the bound store's models.
func (b *BoundStore) ModelsList(ctx context.Context) (*ListPage[FGAAuthorizationModel], error) {
	return b.svc.Models.List(ctx, b.storeID)
}

// ModelsCreate persists a model on the bound store.
func (b *BoundStore) ModelsCreate(ctx context.Context, params FGAAuthorizationModelInput, opts ...RequestOption) (*FGAAuthorizationModel, error) {
	return b.svc.Models.Create(ctx, b.storeID, params, opts...)
}

// ModelsGet returns one model on the bound store.
func (b *BoundStore) ModelsGet(ctx context.Context, modelID string) (*FGAAuthorizationModel, error) {
	return b.svc.Models.Get(ctx, b.storeID, modelID)
}
