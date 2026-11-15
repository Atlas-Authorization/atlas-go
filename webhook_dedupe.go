package atlas

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// Webhook de-duplication: Atlas retries a delivery until your endpoint answers
// 2xx, and every retry carries the same atlas-id. VerifyAndDedupe verifies the
// signature (exactly as VerifyWebhook) and tells you whether that id was already
// seen, so a retried event is acknowledged without being processed twice.

// WebhookDedupeStore remembers seen delivery ids. SetIfAbsent must be atomic: it
// stores key for ttl and reports true when the key was NOT there, false when it
// already was (Redis: SET key 1 EX ttl NX). Delete lets a failed handler release
// the id so Atlas's retry is processed; a store that cannot delete may no-op.
type WebhookDedupeStore interface {
	SetIfAbsent(ctx context.Context, key string, ttl time.Duration) (bool, error)
	Delete(ctx context.Context, key string) error
}

// MemoryWebhookStore is a single-process WebhookDedupeStore, safe for concurrent
// use. Use a shared store (Redis, a database) when you run more than one instance.
type MemoryWebhookStore struct {
	mu   sync.Mutex
	seen map[string]time.Time
	// Now overrides the clock (tests); nil means time.Now.
	Now func() time.Time
}

// NewMemoryWebhookStore returns an empty in-memory store.
func NewMemoryWebhookStore() *MemoryWebhookStore {
	return &MemoryWebhookStore{seen: map[string]time.Time{}}
}

func (s *MemoryWebhookStore) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// SetIfAbsent implements WebhookDedupeStore.
func (s *MemoryWebhookStore) SetIfAbsent(_ context.Context, key string, ttl time.Duration) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.seen == nil {
		s.seen = map[string]time.Time{}
	}
	t := s.now()
	for k, exp := range s.seen {
		if !exp.After(t) {
			delete(s.seen, k)
		}
	}
	if _, ok := s.seen[key]; ok {
		return false, nil
	}
	s.seen[key] = t.Add(ttl)
	return true, nil
}

// Delete implements WebhookDedupeStore.
func (s *MemoryWebhookStore) Delete(_ context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.seen, key)
	return nil
}

// WebhookDedupeDialect selects the SQL flavour of SQLWebhookDedupeStore.
type WebhookDedupeDialect string

// SQL dialects of SQLWebhookDedupeStore.
const (
	WebhookDedupePostgres WebhookDedupeDialect = "postgres"
	WebhookDedupeSQLite   WebhookDedupeDialect = "sqlite"
	WebhookDedupeMySQL    WebhookDedupeDialect = "mysql"
)

// SQLWebhookDedupeStore is a WebhookDedupeStore on database/sql. Create the table
// once (key is the primary key; use varchar(255) on MySQL):
//
//	postgres: create table atlas_webhook_seen (key text primary key, expires_at timestamptz not null);
//	sqlite:   create table atlas_webhook_seen (key text primary key, expires_at integer not null);  -- epoch ms
//	mysql:    create table atlas_webhook_seen (`key` varchar(255) primary key, expires_at datetime not null);
//
// A key whose row has expired counts as unseen and is claimed again.
type SQLWebhookDedupeStore struct {
	DB      *sql.DB
	Dialect WebhookDedupeDialect
}

// SetIfAbsent implements WebhookDedupeStore.
func (s *SQLWebhookDedupeStore) SetIfAbsent(ctx context.Context, key string, ttl time.Duration) (bool, error) {
	secs := int64(ttl / time.Second)
	var res sql.Result
	var err error
	switch s.Dialect {
	case WebhookDedupeSQLite:
		now := time.Now().UnixMilli()
		res, err = s.DB.ExecContext(ctx,
			"insert into atlas_webhook_seen (key, expires_at) values (?, ?) "+
				"on conflict (key) do update set expires_at = excluded.expires_at where atlas_webhook_seen.expires_at <= ?",
			key, now+secs*1000, now)
	case WebhookDedupeMySQL:
		if _, err = s.DB.ExecContext(ctx, "delete from atlas_webhook_seen where `key` = ? and expires_at <= now()", key); err != nil {
			return false, err
		}
		res, err = s.DB.ExecContext(ctx,
			"insert ignore into atlas_webhook_seen (`key`, expires_at) values (?, now() + interval ? second)", key, secs)
	default:
		res, err = s.DB.ExecContext(ctx,
			"insert into atlas_webhook_seen (key, expires_at) values ($1, now() + ($2 || ' seconds')::interval) "+
				"on conflict (key) do update set expires_at = excluded.expires_at where atlas_webhook_seen.expires_at <= now()",
			key, strconv.FormatInt(secs, 10))
	}
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// Delete implements WebhookDedupeStore.
func (s *SQLWebhookDedupeStore) Delete(ctx context.Context, key string) error {
	q := "delete from atlas_webhook_seen where key = ?"
	switch s.Dialect {
	case WebhookDedupePostgres, "":
		q = "delete from atlas_webhook_seen where key = $1"
	case WebhookDedupeMySQL:
		q = "delete from atlas_webhook_seen where `key` = ?"
	}
	_, err := s.DB.ExecContext(ctx, q, key)
	return err
}

// WebhookVerificationError is returned when a delivery does not verify (answer
// 400). Reason is one of missing_headers, malformed_signature, stale_timestamp,
// signature_mismatch or invalid_body. An unverified delivery never touches the store.
type WebhookVerificationError struct {
	Reason string
	// Err is the underlying VerifyWebhook error, when there is one.
	Err error
}

func (e *WebhookVerificationError) Error() string {
	return "atlas: webhook verification failed: " + e.Reason
}

// Unwrap returns the underlying error so errors.Is(err, ErrWebhookSignatureMismatch) works.
func (e *WebhookVerificationError) Unwrap() error { return e.Err }

// VerifyAndDedupeOptions configures VerifyAndDedupe.
type VerifyAndDedupeOptions struct {
	// Secret is the endpoint's signing secret (whsec_...).
	Secret string
	// Store remembers seen delivery ids. Required.
	Store WebhookDedupeStore
	// TTL is how long a delivery id is remembered. Default 24 hours; keep it
	// longer than your endpoint's retry window.
	TTL time.Duration
	// KeyPrefix prefixes the id in the store. Default "atlas-webhook:".
	KeyPrefix string
	// Verify tunes signature and timestamp checks (nil = defaults).
	Verify *WebhookVerifyOptions
}

// DedupedWebhook is a verified delivery plus whether it was already seen.
type DedupedWebhook struct {
	// Event is the parsed envelope.
	Event *WebhookEvent
	// Duplicate is true when this atlas-id was already seen: acknowledge with
	// 2xx and do nothing.
	Duplicate bool
	// DeliveryID is the signed atlas-id, identical on every retry of one event.
	DeliveryID string

	store WebhookDedupeStore
	key   string
}

// Release forgets this delivery so a retry is processed, e.g. after your handler failed.
func (d *DedupedWebhook) Release(ctx context.Context) error {
	if d == nil || d.store == nil {
		return nil
	}
	return d.store.Delete(ctx, d.key)
}

// VerifyAndDedupe verifies an Atlas webhook (signature and timestamp, exactly as
// VerifyWebhook) and drops an event whose atlas-id was already seen. body must be
// the RAW request body.
func VerifyAndDedupe(ctx context.Context, body []byte, header http.Header, opts VerifyAndDedupeOptions) (*DedupedWebhook, error) {
	if opts.Store == nil {
		return nil, errors.New("atlas: VerifyAndDedupe needs a Store")
	}
	ttl := opts.TTL
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	prefix := opts.KeyPrefix
	if prefix == "" {
		prefix = "atlas-webhook:"
	}
	hook, err := VerifyWebhook(body, header, opts.Secret, opts.Verify)
	if err != nil {
		reason := "signature_mismatch"
		switch {
		case errors.Is(err, ErrWebhookMissingHeaders):
			reason = "missing_headers"
		case errors.Is(err, ErrWebhookMalformedSignature):
			reason = "malformed_signature"
		case errors.Is(err, ErrWebhookStaleTimestamp):
			reason = "stale_timestamp"
		}
		return nil, &WebhookVerificationError{Reason: reason, Err: err}
	}
	if hook.Event == nil {
		return nil, &WebhookVerificationError{Reason: "invalid_body"}
	}
	key := prefix + hook.DeliveryID
	fresh, err := opts.Store.SetIfAbsent(ctx, key, ttl)
	if err != nil {
		return nil, fmt.Errorf("atlas: webhook dedupe store: %w", err)
	}
	return &DedupedWebhook{Event: hook.Event, Duplicate: !fresh, DeliveryID: hook.DeliveryID, store: opts.Store, key: key}, nil
}

// WebhookDedupeHandler returns an http.Handler (works with net/http, chi, gin and
// echo via their http.Handler adapters) that verifies the delivery, skips
// duplicates, and calls onEvent once per distinct event. A delivery that does not
// verify answers 400; a failing onEvent releases the id and answers 500 so Atlas
// retries; everything else answers 200.
func WebhookDedupeHandler(opts VerifyAndDedupeOptions, onEvent func(ctx context.Context, event *WebhookEvent) error) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
		if err != nil {
			http.Error(w, "unreadable body", http.StatusBadRequest)
			return
		}
		res, err := VerifyAndDedupe(r.Context(), body, r.Header, opts)
		if err != nil {
			var verr *WebhookVerificationError
			if errors.As(err, &verr) {
				http.Error(w, "invalid webhook", http.StatusBadRequest)
				return
			}
			http.Error(w, "webhook store unavailable", http.StatusInternalServerError)
			return
		}
		if !res.Duplicate {
			if herr := onEvent(r.Context(), res.Event); herr != nil {
				_ = res.Release(r.Context())
				http.Error(w, "handler failed", http.StatusInternalServerError)
				return
			}
		}
		w.WriteHeader(http.StatusOK)
	})
}
