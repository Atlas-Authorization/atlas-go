package atlas

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Doctor check outcomes.
const (
	DoctorPass = "pass"
	DoctorWarn = "warn"
	DoctorFail = "fail"
	DoctorSkip = "skip"
)

// DoctorCheck is the outcome of one Doctor check.
type DoctorCheck struct {
	// Name is key, instance, clock, jwks, status or config.
	Name string `json:"name"`
	// Status is DoctorPass, DoctorWarn, DoctorFail or DoctorSkip.
	Status  string `json:"status"`
	Message string `json:"message"`
}

// DoctorReport is the result of Client.Doctor.
type DoctorReport struct {
	// OK is true when no check failed (warnings do not fail the report).
	OK     bool          `json:"ok"`
	Checks []DoctorCheck `json:"checks"`
}

// String renders the report as one line per check.
func (r *DoctorReport) String() string {
	var b strings.Builder
	for _, c := range r.Checks {
		fmt.Fprintf(&b, "[%s] %s: %s\n", c.Status, c.Name, c.Message)
	}
	return b.String()
}

// Check returns the named check (nil when it did not run).
func (r *DoctorReport) Check(name string) *DoctorCheck {
	for i := range r.Checks {
		if r.Checks[i].Name == name {
			return &r.Checks[i]
		}
	}
	return nil
}

// Clock skew thresholds: tokens are checked with a small leeway, so a drift
// beyond a minute starts to reject valid sessions.
const (
	doctorSkewWarn = 30 * time.Second
	doctorSkewFail = 2 * time.Minute
)

// Doctor checks this client's setup and reports what is wrong, without
// changing anything:
//
//   - key: the secret key is set, has the sk_ form and is not a publishable key
//   - instance: the key is accepted and the instance can be read
//   - clock: the local clock against the API's Date header
//   - jwks: the instance's signing keys can be fetched
//   - status: the service status and open incidents
//   - config: allowed origins and issuer are set
//
// The returned error is only for a cancelled context; every problem is a failed
// check in the report.
func (c *Client) Doctor(ctx context.Context) (*DoctorReport, error) {
	rep := &DoctorReport{}
	add := func(name, status, msg string) {
		rep.Checks = append(rep.Checks, DoctorCheck{Name: name, Status: status, Message: msg})
	}

	// key
	key := c.secretKey
	switch {
	case key == "" && c.platformKey != "":
		add("key", DoctorWarn, "no instance secret key set; only the platform surface can be reached")
	case key == "":
		add("key", DoctorFail, "no secret key set (use sk_...)")
	case strings.HasPrefix(key, "pk_"):
		add("key", DoctorFail, "this is a publishable key (pk_); the Backend API needs the secret key (sk_)")
	case !strings.HasPrefix(key, "sk_"):
		add("key", DoctorWarn, "the key does not start with sk_; check it is an instance secret key")
	default:
		add("key", DoctorPass, "secret key present")
	}

	// instance + clock
	status, header, raw, err := c.doctorGet(ctx, c.baseURL+"/v1/instance", true)
	var inst Instance
	instOK := false
	switch {
	case ctx.Err() != nil:
		return rep, ctx.Err()
	case err != nil:
		add("instance", DoctorFail, "cannot reach "+c.baseURL+": "+err.Error())
		add("clock", DoctorSkip, "no response to compare against")
	case status == http.StatusUnauthorized:
		add("instance", DoctorFail, "the API rejected the key (401); it is wrong, revoked or from another environment")
		doctorClock(add, header)
	case status == http.StatusForbidden:
		add("instance", DoctorWarn, "the key is valid but may not read the instance (403: missing scope)")
		doctorClock(add, header)
	case status < 200 || status >= 300:
		add("instance", DoctorFail, fmt.Sprintf("unexpected status %d from GET /v1/instance", status))
		doctorClock(add, header)
	default:
		if json.Unmarshal(raw, &inst) != nil {
			add("instance", DoctorFail, "the instance response was not valid JSON")
		} else {
			instOK = true
			add("instance", DoctorPass, fmt.Sprintf("instance %s (%s)", inst.ID, inst.Environment))
		}
		doctorClock(add, header)
	}

	// jwks
	switch {
	case !instOK:
		add("jwks", DoctorSkip, "instance not readable")
	case inst.JWKSURI == "":
		add("jwks", DoctorWarn, "the instance reports no jwks_uri")
	default:
		st, _, body, err := c.doctorGet(ctx, inst.JWKSURI, false)
		var set struct {
			Keys []json.RawMessage `json:"keys"`
		}
		switch {
		case ctx.Err() != nil:
			return rep, ctx.Err()
		case err != nil:
			add("jwks", DoctorFail, "cannot fetch "+inst.JWKSURI+": "+err.Error())
		case st != http.StatusOK:
			add("jwks", DoctorFail, fmt.Sprintf("%s answered %d", inst.JWKSURI, st))
		case json.Unmarshal(body, &set) != nil || len(set.Keys) == 0:
			add("jwks", DoctorFail, "the JWKS has no keys")
		default:
			add("jwks", DoctorPass, fmt.Sprintf("%d signing key(s) at %s", len(set.Keys), inst.JWKSURI))
		}
	}

	// status
	st, _, body, err := c.doctorGet(ctx, c.baseURL+"/v1/status", false)
	var svc ServiceStatus
	switch {
	case ctx.Err() != nil:
		return rep, ctx.Err()
	case err != nil || st != http.StatusOK || json.Unmarshal(body, &svc) != nil:
		add("status", DoctorWarn, "the status endpoint could not be read")
	case svc.Status == "operational":
		add("status", DoctorPass, "all systems operational")
	default:
		add("status", DoctorWarn, fmt.Sprintf("service is %s with %d open incident(s)", svc.Status, len(svc.Incidents)))
	}

	// config
	switch {
	case !instOK:
		add("config", DoctorSkip, "instance not readable")
	case len(inst.AllowedOrigins) == 0:
		add("config", DoctorWarn, "no allowed origins are set; browser sign-in from your app will be refused")
	case inst.Issuer == "":
		add("config", DoctorWarn, "the instance reports no issuer")
	default:
		add("config", DoctorPass, fmt.Sprintf("%d allowed origin(s), issuer %s", len(inst.AllowedOrigins), inst.Issuer))
	}

	rep.OK = true
	for _, ch := range rep.Checks {
		if ch.Status == DoctorFail {
			rep.OK = false
		}
	}
	return rep, nil
}

// doctorClock compares the response Date header with the local clock.
func doctorClock(add func(name, status, msg string), header http.Header) {
	d, err := http.ParseTime(header.Get("Date"))
	if err != nil {
		add("clock", DoctorSkip, "the response carried no Date header")
		return
	}
	skew := time.Since(d)
	if skew < 0 {
		skew = -skew
	}
	switch {
	case skew >= doctorSkewFail:
		add("clock", DoctorFail, fmt.Sprintf("the local clock is off by %s; token checks will fail", skew.Round(time.Second)))
	case skew >= doctorSkewWarn:
		add("clock", DoctorWarn, fmt.Sprintf("the local clock is off by %s", skew.Round(time.Second)))
	default:
		add("clock", DoctorPass, fmt.Sprintf("clock within %s of the API", skew.Round(time.Second)))
	}
}

// doctorGet is a single GET with no retries; auth adds the secret key.
func (c *Client) doctorGet(ctx context.Context, target string, auth bool) (int, http.Header, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return 0, nil, nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", userAgent)
	if auth {
		req.Header.Set("Authorization", "Bearer "+c.secretKey)
	}
	hc := c.httpClient
	if hc == nil {
		hc = http.DefaultClient
	}
	resp, err := hc.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return 0, nil, nil, err
	}
	return resp.StatusCode, resp.Header, raw, nil
}
