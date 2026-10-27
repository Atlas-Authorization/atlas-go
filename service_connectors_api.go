package atlas

import (
	"context"
	"net/url"
)

// ServiceConnectorsService is the serviceConnectors resource.
type ServiceConnectorsService struct {
	client *Client
}

// Catalog: The services you can connect: for each kind the credential fields, the config fields
// and the operations with their inputs. Messaging (Twilio, SendGrid, Slack), CRM (HubSpot,
// Salesforce), analytics (Segment), fraud (Fingerprint, Arkose Labs, Forter, Sardine), identity
// verification (Persona, Onfido, Veriff, Stripe Identity) and a generic HTTPS connector.
// GET /v1/service_connector_catalog.
func (s *ServiceConnectorsService) Catalog(ctx context.Context, params ListParams) (*CursorPage[ServiceConnectorsCatalogItem], error) {
	out := &CursorPage[ServiceConnectorsCatalogItem]{}
	return out, s.client.do(ctx, "GET", "/v1/service_connector_catalog", params.values(), nil, out)
}

// List: List the instance's service connectors. Credentials are never returned.
// GET /v1/service_connectors.
func (s *ServiceConnectorsService) List(ctx context.Context, params ListParams) (*CursorPage[ServiceConnectorsListItem], error) {
	out := &CursorPage[ServiceConnectorsListItem]{}
	return out, s.client.do(ctx, "GET", "/v1/service_connectors", params.values(), nil, out)
}

// Create: Connect a service. `credentials` are checked against the kind's fields and stored in the
// vault (never returned again); `config` holds the non-secret settings. 409 when the name is
// taken.
// POST /v1/service_connectors.
func (s *ServiceConnectorsService) Create(ctx context.Context, params ServiceConnectorsCreateParams, opts ...RequestOption) (*ServiceConnectorsListItem, error) {
	out := &ServiceConnectorsListItem{}
	return out, s.client.do(ctx, "POST", "/v1/service_connectors", nil, params, out, opts...)
}

// Get: Read one service connector.
// GET /v1/service_connectors/{id}.
func (s *ServiceConnectorsService) Get(ctx context.Context, id string) (*ServiceConnectorsListItem, error) {
	out := &ServiceConnectorsListItem{}
	return out, s.client.do(ctx, "GET", "/v1/service_connectors/"+url.PathEscape(id), nil, nil, out)
}

// Update: Rename, enable or disable a connector, merge new `config` values, or replace individual
// `credentials` (written as a new vault version; the others are kept).
// PATCH /v1/service_connectors/{id}.
func (s *ServiceConnectorsService) Update(ctx context.Context, id string, params ServiceConnectorsUpdateParams, opts ...RequestOption) (*ServiceConnectorsListItem, error) {
	out := &ServiceConnectorsListItem{}
	return out, s.client.do(ctx, "PATCH", "/v1/service_connectors/"+url.PathEscape(id), nil, params, out, opts...)
}

// Delete: Delete a connector and its stored credentials.
// DELETE /v1/service_connectors/{id}.
func (s *ServiceConnectorsService) Delete(ctx context.Context, id string, opts ...RequestOption) (*UsersDeleteDeviceKeyResult, error) {
	out := &UsersDeleteDeviceKeyResult{}
	return out, s.client.do(ctx, "DELETE", "/v1/service_connectors/"+url.PathEscape(id), nil, nil, out, opts...)
}

// Invoke: Run one operation of the connector (send a message, read a fraud signal, start an
// identity check). `input` is checked against the operation's fields. A refusal or failure from
// the service is 502 CONNECTOR_UPSTREAM_ERROR with its own message. Each call is audited without
// its input or output.
// POST /v1/service_connectors/{id}/invoke.
func (s *ServiceConnectorsService) Invoke(ctx context.Context, id string, params ServiceConnectorsInvokeParams, opts ...RequestOption) (*ServiceConnectorsInvokeResult, error) {
	out := &ServiceConnectorsInvokeResult{}
	return out, s.client.do(ctx, "POST", "/v1/service_connectors/"+url.PathEscape(id)+"/invoke", nil, params, out, opts...)
}
