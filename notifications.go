package atlas

import (
	"context"
	"net/url"
)

// NotificationsService sends templated security notifications to end-users
// (POST /v1/notifications) and manages tenant-defined categories and templates.
type NotificationsService struct {
	client *Client

	Categories *NotificationCategoriesService
	Templates  *NotificationTemplatesService
}

// SendNotificationParams is the body of POST /v1/notifications.
type SendNotificationParams struct {
	UserID string `json:"user_id"`
	// Template is a tenant-defined template name or a built-in (new_device,
	// unattended_access, password_changed, …).
	Template string `json:"template"`
	// Data holds the variables interpolated into the template.
	Data map[string]string `json:"data,omitempty"`
}

// NotificationSend is the outcome of a send: "sent", or "suppressed" when the
// user's preferences opt out of the category.
type NotificationSend struct {
	Object string `json:"object"`
	ID     string `json:"id"`
	Status string `json:"status"`
}

// Send sends a notification email to an end-user. POST /v1/notifications.
func (s *NotificationsService) Send(ctx context.Context, params SendNotificationParams, opts ...RequestOption) (*NotificationSend, error) {
	out := &NotificationSend{}
	return out, s.client.post(ctx, "/v1/notifications", params, out, opts...)
}

// NotificationCategoriesService is /v1/notification_categories.
type NotificationCategoriesService struct{ client *Client }

// NotificationCategory is a tenant-defined notification category.
type NotificationCategory struct {
	Object    string `json:"object"`
	ID        string `json:"id"`
	Key       string `json:"key"`
	Label     string `json:"label"`
	Optional  bool   `json:"optional"`
	CreatedAt int64  `json:"created_at"`
}

// NotificationCategoryDeleted acknowledges a category delete.
type NotificationCategoryDeleted struct {
	Object  string `json:"object"`
	Key     string `json:"key"`
	Deleted bool   `json:"deleted"`
}

// List lists tenant-defined categories. GET /v1/notification_categories.
func (s *NotificationCategoriesService) List(ctx context.Context) (*ListPage[NotificationCategory], error) {
	out := &ListPage[NotificationCategory]{}
	return out, s.client.get(ctx, "/v1/notification_categories", nil, out)
}

// Create creates a category (a duplicate or built-in key is a 409).
// POST /v1/notification_categories.
func (s *NotificationCategoriesService) Create(ctx context.Context, key, label string, opts ...RequestOption) (*NotificationCategory, error) {
	out := &NotificationCategory{}
	body := map[string]string{"key": key, "label": label}
	return out, s.client.post(ctx, "/v1/notification_categories", body, out, opts...)
}

// Update changes a category's label. PUT /v1/notification_categories/:key.
func (s *NotificationCategoriesService) Update(ctx context.Context, key, label string, opts ...RequestOption) (*NotificationCategory, error) {
	out := &NotificationCategory{}
	body := map[string]string{"label": label}
	return out, s.client.put(ctx, "/v1/notification_categories/"+url.PathEscape(key), body, out, opts...)
}

// Delete deletes a category (409 while a template still uses it).
// DELETE /v1/notification_categories/:key.
func (s *NotificationCategoriesService) Delete(ctx context.Context, key string, opts ...RequestOption) (*NotificationCategoryDeleted, error) {
	out := &NotificationCategoryDeleted{}
	return out, s.client.del(ctx, "/v1/notification_categories/"+url.PathEscape(key), out, opts...)
}

// NotificationTemplatesService is /v1/notification_templates.
type NotificationTemplatesService struct{ client *Client }

// NotificationTemplate is a tenant-defined notification template.
type NotificationTemplate struct {
	Object    string `json:"object"`
	ID        string `json:"id"`
	Name      string `json:"name"`
	Subject   string `json:"subject"`
	Body      string `json:"body"`
	Category  string `json:"category"`
	CreatedAt int64  `json:"created_at"`
	UpdatedAt int64  `json:"updated_at"`
}

// CreateNotificationTemplateParams is the body of POST /v1/notification_templates.
type CreateNotificationTemplateParams struct {
	Name    string `json:"name"`
	Subject string `json:"subject"`
	// Body uses {{variables}}.
	Body string `json:"body"`
	// Category is a built-in or tenant-defined category key.
	Category string `json:"category"`
}

// UpdateNotificationTemplateParams is the body of PUT /v1/notification_templates/:name.
type UpdateNotificationTemplateParams struct {
	Subject  string `json:"subject"`
	Body     string `json:"body"`
	Category string `json:"category"`
}

// NotificationTemplateDeleted acknowledges a template delete.
type NotificationTemplateDeleted struct {
	Object  string `json:"object"`
	Name    string `json:"name"`
	Deleted bool   `json:"deleted"`
}

// List lists tenant-defined templates. GET /v1/notification_templates.
func (s *NotificationTemplatesService) List(ctx context.Context) (*ListPage[NotificationTemplate], error) {
	out := &ListPage[NotificationTemplate]{}
	return out, s.client.get(ctx, "/v1/notification_templates", nil, out)
}

// Create creates a template (a duplicate name is a 409).
// POST /v1/notification_templates.
func (s *NotificationTemplatesService) Create(ctx context.Context, params CreateNotificationTemplateParams, opts ...RequestOption) (*NotificationTemplate, error) {
	out := &NotificationTemplate{}
	return out, s.client.post(ctx, "/v1/notification_templates", params, out, opts...)
}

// Get fetches a template by name. GET /v1/notification_templates/:name.
func (s *NotificationTemplatesService) Get(ctx context.Context, name string) (*NotificationTemplate, error) {
	out := &NotificationTemplate{}
	return out, s.client.get(ctx, "/v1/notification_templates/"+url.PathEscape(name), nil, out)
}

// Update replaces a template's subject, body and category.
// PUT /v1/notification_templates/:name.
func (s *NotificationTemplatesService) Update(ctx context.Context, name string, params UpdateNotificationTemplateParams, opts ...RequestOption) (*NotificationTemplate, error) {
	out := &NotificationTemplate{}
	return out, s.client.put(ctx, "/v1/notification_templates/"+url.PathEscape(name), params, out, opts...)
}

// Delete deletes a template. DELETE /v1/notification_templates/:name.
func (s *NotificationTemplatesService) Delete(ctx context.Context, name string, opts ...RequestOption) (*NotificationTemplateDeleted, error) {
	out := &NotificationTemplateDeleted{}
	return out, s.client.del(ctx, "/v1/notification_templates/"+url.PathEscape(name), out, opts...)
}
