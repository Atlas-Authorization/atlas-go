package atlas

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
)

// A ready-made receiver for OIDC Back-Channel Logout: Atlas POSTs a signed
// logout_token (form-encoded) to your client's backchannel_logout_uri when a
// session ends (signed out elsewhere, revoked, the user banned or deleted).
// The handler verifies the token, calls OnLogout with whose session to end,
// and answers the way the spec and Atlas's retries expect:
//
//	200  verified and handled (also for a replayed token you already handled)
//	400  the token is bad: Atlas does not retry
//	503  your side could not check it right now (keys unreachable, or
//	     OnLogout failed): Retry-After is set and Atlas retries
//
// Every response carries Cache-Control: no-store. It is a plain http.Handler,
// so it mounts on net/http, chi, gin (gin.WrapH) and echo (echo.WrapHandler).

// BackchannelLogoutHandlerOptions configure BackchannelLogoutHandler.
type BackchannelLogoutHandlerOptions struct {
	// Verifier is a LogoutTokenVerifier you already have (keeps its key
	// cache). Built from Verify when nil.
	Verifier *LogoutTokenVerifier
	// Verify builds the verifier when Verifier is nil (JWKSURL, Issuer and
	// ClientID are required).
	Verify LogoutTokenVerifierOptions
	// OnLogout ends the matching session(s) in your app. Sid names one
	// session (the sid of the id_token you got at sign-in), Sub the user (end
	// all of them when there is no Sid). Returning an error answers 503, so
	// Atlas retries.
	OnLogout func(ctx context.Context, claims *LogoutTokenClaims) error
	// RetryAfterSeconds is the Retry-After of a 503 (default 30).
	RetryAfterSeconds int
}

// BackchannelLogoutHandler returns the receiver for a backchannel_logout_uri.
func BackchannelLogoutHandler(opts BackchannelLogoutHandlerOptions) (http.Handler, error) {
	if opts.OnLogout == nil {
		return nil, errors.New("atlas: BackchannelLogoutHandler requires OnLogout")
	}
	verifier := opts.Verifier
	if verifier == nil {
		v, err := NewLogoutTokenVerifier(opts.Verify)
		if err != nil {
			return nil, err
		}
		verifier = v
	}
	retry := opts.RetryAfterSeconds
	if retry <= 0 {
		retry = 30
	}
	write := func(w http.ResponseWriter, status int, payload map[string]interface{}, extra map[string]string) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		for k, v := range extra {
			w.Header().Set(k, v)
		}
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(payload)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			write(w, http.StatusMethodNotAllowed, map[string]interface{}{"error": "invalid_request", "error_description": "POST only."}, map[string]string{"Allow": "POST"})
			return
		}
		if err := r.ParseForm(); err != nil || r.PostForm.Get("logout_token") == "" {
			write(w, http.StatusBadRequest, map[string]interface{}{"error": "invalid_request", "error_description": "logout_token is missing."}, nil)
			return
		}
		claims, err := verifier.Verify(r.Context(), r.PostForm.Get("logout_token"))
		if err != nil {
			switch {
			case errors.Is(err, ErrLogoutTokenReplayed):
				write(w, http.StatusOK, map[string]interface{}{"ok": true, "replayed": true}, nil)
			case IsRetryable(err) || !isVerificationError(err):
				write(w, http.StatusServiceUnavailable, map[string]interface{}{"error": "temporarily_unavailable", "error_description": err.Error()}, map[string]string{"Retry-After": strconv.Itoa(retry)})
			default:
				write(w, http.StatusBadRequest, map[string]interface{}{"error": "invalid_request", "error_description": err.Error()}, nil)
			}
			return
		}
		if err := opts.OnLogout(r.Context(), claims); err != nil {
			write(w, http.StatusServiceUnavailable, map[string]interface{}{"error": "temporarily_unavailable", "error_description": "could not end the session"}, map[string]string{"Retry-After": strconv.Itoa(retry)})
			return
		}
		write(w, http.StatusOK, map[string]interface{}{"ok": true}, nil)
	}), nil
}

// isVerificationError reports whether err is a token verification failure (as
// opposed to, say, the replay guard's store being down).
func isVerificationError(err error) bool {
	var ve *VerificationError
	return errors.As(err, &ve)
}
