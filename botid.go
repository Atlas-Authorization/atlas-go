package atlas

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"time"
)

// Vercel BotID for Atlas: the signing half that runs next to your BotID check.
//
// BotID's verdict (checkBotId() from botid/server) only exists inside a
// Vercel-hosted request, so that route turns the verdict into a short signed
// attestation; the browser sends it to Atlas as captcha_token, and Atlas checks
// the signature, freshness and is_bot == false, and spends it (each
// attestation passes once). The same secret is stored in Atlas for the
// vercel_botid captcha provider.
//
// Format (version 1): "atlas_botid.v1.<payload>.<sig>" — payload is base64url
// JSON {v: 1, is_bot, verified_bot, iat, exp, jti}; sig is base64url
// HMAC-SHA256 over "atlas_botid.v1.<payload>" keyed by the shared secret.

const (
	// BotIDAttestationPrefix is the prefix every attestation carries.
	BotIDAttestationPrefix = "atlas_botid.v1."
	// BotIDAttestationMaxTTL is the longest lifetime Atlas accepts.
	BotIDAttestationMaxTTL = 300 * time.Second
	// BotIDSecretMinLength is the shortest secret Atlas accepts.
	BotIDSecretMinLength = 32
)

// BotIDVerdict is the part of BotID's checkBotId() result the attestation
// carries. A verified bot (a search engine crawler) is recorded and still
// refused.
type BotIDVerdict struct {
	IsBot         bool
	IsVerifiedBot bool
}

// BotIDAttestationOptions: TTL defaults to 60s and is capped at 300s; Now
// overrides the clock (tests).
type BotIDAttestationOptions struct {
	TTL time.Duration
	Now func() time.Time
}

// CreateBotIDAttestation signs a BotID verdict for Atlas. It fails when the
// secret is shorter than 32 characters (Atlas would refuse every attestation
// it signs). A bot verdict is still signed — Atlas refuses it.
func CreateBotIDAttestation(secret string, verdict BotIDVerdict, opts *BotIDAttestationOptions) (string, error) {
	if len(secret) < BotIDSecretMinLength {
		return "", errors.New("atlas: the BotID attestation secret must be at least 32 characters")
	}
	ttl := 60 * time.Second
	now := time.Now
	if opts != nil {
		if opts.TTL != 0 {
			ttl = opts.TTL
		}
		if opts.Now != nil {
			now = opts.Now
		}
	}
	secs := int64(ttl / time.Second)
	if secs < 1 {
		secs = 1
	}
	if max := int64(BotIDAttestationMaxTTL / time.Second); secs > max {
		secs = max
	}
	jti := make([]byte, 18)
	if _, err := rand.Read(jti); err != nil {
		return "", err
	}
	iat := now().Unix()
	payload, err := json.Marshal(map[string]interface{}{
		"v": 1, "is_bot": verdict.IsBot, "verified_bot": verdict.IsVerifiedBot,
		"iat": iat, "exp": iat + secs, "jti": base64.RawURLEncoding.EncodeToString(jti),
	})
	if err != nil {
		return "", err
	}
	p := base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(BotIDAttestationPrefix + p))
	return BotIDAttestationPrefix + p + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

// BotIDAttestationHandler answers {"token": "<attestation>"} (no-store) with
// the verdict check returns for the request. When check fails it answers 503
// {"error": "botid_unavailable"}, so the client never sends a token that was
// never checked.
func BotIDAttestationHandler(secret string, check func(*http.Request) (BotIDVerdict, error), opts *BotIDAttestationOptions) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		verdict, err := check(r)
		if err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"error":"botid_unavailable"}`))
			return
		}
		token, err := CreateBotIDAttestation(secret, verdict, opts)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"error":"botid_misconfigured"}`))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"token": token})
	}
}
