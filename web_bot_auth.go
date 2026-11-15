package atlas

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Web Bot Auth: verify who is behind an automated request.
//
// A bot signs its requests with an Ed25519 key (RFC 9421 HTTP Message Signatures,
// tag "web-bot-auth") and names the place its public keys live in the
// Signature-Agent header. The key is found in the directory served at
// <Signature-Agent>/.well-known/http-message-signatures-directory, and the
// signature's keyid is the RFC 7638 JWK thumbprint of that key.
//
// WebBotAuthVerifier runs inside your own server: no call to Atlas, directories
// cached in memory, fetched through an SSRF-safe client.

// Constants of the Web Bot Auth profile.
const (
	WebBotAuthTag                = "web-bot-auth"
	WebBotAuthDirectoryPath      = "/.well-known/http-message-signatures-directory"
	WebBotAuthDirectoryMediaType = "application/http-message-signatures-directory+json"
	// WebBotAuthDefaultSkew is the clock skew tolerated on created and expires.
	WebBotAuthDefaultSkew = 30 * time.Second
	// WebBotAuthDefaultMaxLifetime is the longest expires-created accepted.
	WebBotAuthDefaultMaxLifetime = time.Hour
)

// WebBotAuthJWK is an Ed25519 public key as a JWK.
type WebBotAuthJWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
}

// Ed25519JWKThumbprint is the RFC 7638 thumbprint (base64url SHA-256) of an Ed25519
// public JWK's x value: the web-bot-auth keyid.
func Ed25519JWKThumbprint(x string) string {
	sum := sha256.Sum256([]byte(`{"crv":"Ed25519","kty":"OKP","x":"` + x + `"}`))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// webBotAuthKeyBytes returns the raw 32-byte public key, or nil when the JWK is not a well-formed Ed25519 key.
func webBotAuthKeyBytes(k WebBotAuthJWK) []byte {
	if k.Kty != "OKP" || k.Crv != "Ed25519" || k.X == "" || !webBotB64URL.MatchString(k.X) {
		return nil
	}
	b, err := base64.RawURLEncoding.DecodeString(k.X)
	if err != nil || len(b) != 32 {
		return nil
	}
	return b
}

var (
	webBotB64URL   = regexp.MustCompile(`^[A-Za-z0-9_-]*$`)
	webBotB64Std   = regexp.MustCompile(`^[A-Za-z0-9+/]*={0,2}$`)
	webBotKeyRE    = regexp.MustCompile(`^[a-z*][a-z0-9_.*-]*$`)
	webBotKeyPre   = regexp.MustCompile(`^[a-z*][a-z0-9_.*-]*`)
	webBotNumRE    = regexp.MustCompile(`^-?\d{1,15}(\.\d{1,3})?$`)
	webBotNumPre   = regexp.MustCompile(`^-?\d{1,15}(\.\d{1,3})?`)
	webBotSigRE    = regexp.MustCompile(`^([a-z*][a-z0-9_.*-]*)=:([A-Za-z0-9+/=]*):$`)
	webBotDictRE   = regexp.MustCompile(`^[a-z*][a-z0-9_.*-]*(=|;|$)`)
	webBotDictEq   = regexp.MustCompile(`^[a-z*][a-z0-9_.*-]*=`)
	webBotSchemeRE = regexp.MustCompile(`(?i)^[a-z][a-z0-9+.-]*://`)
)

// ParseWebBotAuthDirectory picks the usable Ed25519 keys out of a directory document
// (a JWK Set). At most 20 are kept. Malformed input yields none.
func ParseWebBotAuthDirectory(doc []byte) []WebBotAuthJWK {
	var set struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if json.Unmarshal(doc, &set) != nil {
		return nil
	}
	var out []WebBotAuthJWK
	for _, raw := range set.Keys {
		var k WebBotAuthJWK
		if json.Unmarshal(raw, &k) == nil && webBotAuthKeyBytes(k) != nil {
			out = append(out, k)
			if len(out) == 20 {
				break
			}
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Structured fields (the subset RFC 9421 headers use)
// ---------------------------------------------------------------------------

// WebBotAuthParam is one parameter of a structured-field item; Value is a string,
// int64, float64, bool or []byte. Order is kept: the signature base echoes it.
type WebBotAuthParam struct {
	Key   string
	Value interface{}
}

func sfGet(params []WebBotAuthParam, key string) (interface{}, bool) {
	for _, p := range params {
		if p.Key == key {
			return p.Value, true
		}
	}
	return nil, false
}

func at(s string, i int) byte {
	if i < 0 || i >= len(s) {
		return 0
	}
	return s[i]
}

func isTokenChar(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || strings.IndexByte(":/!#$%&'*+-.^_`|~", c) >= 0
}

func isKeyChar(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '.' || c == '*' || c == '-'
}

// splitTop splits on sep outside of strings and parentheses, trimming members and dropping empty ones.
func splitTop(s string, sep byte) []string {
	var out []string
	depth, start := 0, 0
	quoted := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case quoted:
			if c == '\\' {
				i++
			} else if c == '"' {
				quoted = false
			}
		case c == '"':
			quoted = true
		case c == '(':
			depth++
		case c == ')':
			depth--
		case c == sep && depth == 0:
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	out = append(out, s[start:])
	res := out[:0]
	for _, m := range out {
		if m = strings.TrimSpace(m); m != "" {
			res = append(res, m)
		}
	}
	return res
}

// readString reads a quoted sf-string starting at i (which must be the opening quote).
func readString(s string, i int) (string, int, bool) {
	if at(s, i) != '"' {
		return "", 0, false
	}
	var b strings.Builder
	for j := i + 1; j < len(s); j++ {
		c := s[j]
		switch {
		case c == '\\':
			n := at(s, j+1)
			if n != '"' && n != '\\' {
				return "", 0, false
			}
			b.WriteByte(n)
			j++
		case c == '"':
			return b.String(), j + 1, true
		case c < 0x20 || c > 0x7e:
			return "", 0, false
		default:
			b.WriteByte(c)
		}
	}
	return "", 0, false
}

func base64ToBytes(in string) ([]byte, bool) {
	if !webBotB64Std.MatchString(in) {
		return nil, false
	}
	if pad := (4 - len(in)%4) % 4; pad > 0 {
		in += strings.Repeat("=", pad)
	}
	b, err := base64.StdEncoding.DecodeString(in)
	if err != nil {
		return nil, false
	}
	return b, true
}

// parseParams parses ";k=v;k2" (possibly empty). ok is false when malformed.
func parseParams(text string) ([]WebBotAuthParam, bool) {
	var out []WebBotAuthParam
	i := 0
	for i < len(text) {
		if text[i] != ';' {
			return nil, false
		}
		i++
		start := i
		for i < len(text) && isKeyChar(text[i]) {
			i++
		}
		key := text[start:i]
		if !webBotKeyRE.MatchString(key) {
			return nil, false
		}
		if at(text, i) != '=' {
			out = append(out, WebBotAuthParam{key, true})
			continue
		}
		i++
		c := at(text, i)
		switch {
		case c == '"':
			v, end, ok := readString(text, i)
			if !ok {
				return nil, false
			}
			out = append(out, WebBotAuthParam{key, v})
			i = end
		case c == ':':
			closeAt := strings.IndexByte(text[i+1:], ':')
			if closeAt < 0 {
				return nil, false
			}
			b, ok := base64ToBytes(text[i+1 : i+1+closeAt])
			if !ok {
				return nil, false
			}
			out = append(out, WebBotAuthParam{key, b})
			i = i + 1 + closeAt + 1
		case c == '?':
			b := text[i:min(i+2, len(text))]
			if b != "?0" && b != "?1" {
				return nil, false
			}
			out = append(out, WebBotAuthParam{key, b == "?1"})
			i += 2
		case c == '-' || (c >= '0' && c <= '9'):
			start := i
			for i < len(text) && (text[i] == '-' || text[i] == '.' || (text[i] >= '0' && text[i] <= '9')) {
				i++
			}
			n := text[start:i]
			if !webBotNumRE.MatchString(n) {
				return nil, false
			}
			if strings.Contains(n, ".") {
				f, _ := strconv.ParseFloat(n, 64)
				out = append(out, WebBotAuthParam{key, f})
			} else {
				v, _ := strconv.ParseInt(n, 10, 64)
				out = append(out, WebBotAuthParam{key, v})
			}
		case c == '*' || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'):
			start := i
			for i < len(text) && isTokenChar(text[i]) {
				i++
			}
			out = append(out, WebBotAuthParam{key, text[start:i]})
		default:
			return nil, false
		}
	}
	return out, true
}

// WebBotAuthComponent is a covered component: a header name or derived component,
// with its RFC 9421 parameters (sf, key, bs, name).
type WebBotAuthComponent struct {
	Name string
	// Params keep their order; values are string, int64, float64, bool or []byte.
	Params []WebBotAuthParam
}

type parsedSignatureInput struct {
	Label      string
	Components []WebBotAuthComponent
	Params     []WebBotAuthParam
	// Raw is the inner list and its parameters exactly as sent: the @signature-params value.
	Raw string
}

// parseSignatureInput parses a Signature-Input field. nil when any member is malformed.
func parseSignatureInput(header string) []parsedSignatureInput {
	var out []parsedSignatureInput
	for _, member := range splitTop(header, ',') {
		eq := strings.IndexByte(member, '=')
		if eq <= 0 {
			return nil
		}
		label := strings.TrimSpace(member[:eq])
		raw := strings.TrimSpace(member[eq+1:])
		if !webBotKeyRE.MatchString(label) || at(raw, 0) != '(' {
			return nil
		}
		closeAt := -1
		quoted := false
		for i := 1; i < len(raw); i++ {
			c := raw[i]
			if quoted {
				if c == '\\' {
					i++
				} else if c == '"' {
					quoted = false
				}
			} else if c == '"' {
				quoted = true
			} else if c == ')' {
				closeAt = i
				break
			}
		}
		if closeAt < 0 {
			return nil
		}
		inner := raw[1:closeAt]
		var comps []WebBotAuthComponent
		i := 0
		for i < len(inner) {
			if inner[i] == ' ' {
				i++
				continue
			}
			name, end, ok := readString(inner, i)
			if !ok {
				return nil
			}
			i = end
			var ptext strings.Builder
			for i < len(inner) && inner[i] != ' ' {
				if inner[i] == '"' {
					_, qend, qok := readString(inner, i)
					if !qok {
						return nil
					}
					ptext.WriteString(inner[i:qend])
					i = qend
				} else {
					ptext.WriteByte(inner[i])
					i++
				}
			}
			params, pok := parseParams(ptext.String())
			if !pok {
				return nil
			}
			comps = append(comps, WebBotAuthComponent{Name: name, Params: params})
		}
		params, ok := parseParams(raw[closeAt+1:])
		if !ok {
			return nil
		}
		out = append(out, parsedSignatureInput{Label: label, Components: comps, Params: params, Raw: raw})
	}
	return out
}

// parseSignatureHeader parses a Signature field into label -> signature bytes. nil when malformed.
func parseSignatureHeader(header string) map[string][]byte {
	out := map[string][]byte{}
	for _, member := range splitTop(header, ',') {
		m := webBotSigRE.FindStringSubmatch(member)
		if m == nil {
			return nil
		}
		b, ok := base64ToBytes(m[2])
		if !ok {
			return nil
		}
		out[m[1]] = b
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// ParseSignatureAgent returns the directory a Signature-Agent value names, normalised:
// https, no credentials, query or fragment, no trailing slash. It accepts a quoted
// string, a bare URL, or the dictionary form (sig1="https://bot.example"; the member
// for label wins, else the first). "" when it names nothing usable.
func ParseSignatureAgent(value, label string) string {
	v := strings.TrimSpace(value)
	if v == "" {
		return ""
	}
	if webBotDictEq.MatchString(v) {
		members := splitTop(v, ',')
		if len(members) == 0 {
			return ""
		}
		pick := members[0]
		for _, m := range members {
			if label != "" && strings.HasPrefix(m, label+"=") {
				pick = m
				break
			}
		}
		v = strings.TrimSpace(pick[strings.IndexByte(pick, '=')+1:])
	}
	if strings.HasPrefix(v, `"`) {
		s, end, ok := readString(v, 0)
		if !ok || end != len(v) {
			return ""
		}
		v = s
	}
	return NormalizeWebBotAuthDirectory(v)
}

// webBotOrigin returns scheme://host[:port] with the host lower-cased and the default port dropped.
func webBotHost(u *url.URL) string {
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	scheme := strings.ToLower(u.Scheme)
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		port = ""
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if port != "" {
		host += ":" + port
	}
	return host
}

// NormalizeWebBotAuthDirectory returns the canonical form of a directory reference,
// https://host[:port][/path]. A bare host gets https://. "" for anything that is not
// an https URL without credentials, query or fragment.
func NormalizeWebBotAuthDirectory(input string) string {
	s := strings.TrimSpace(input)
	if s == "" {
		return ""
	}
	if !webBotSchemeRE.MatchString(s) {
		s = "https://" + s
	}
	u, err := url.Parse(s)
	if err != nil || strings.ToLower(u.Scheme) != "https" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Hostname() == "" {
		return ""
	}
	return "https://" + webBotHost(u) + strings.TrimRight(u.EscapedPath(), "/")
}

// WebBotAuthDirectoryURL is the URL a directory's keys are fetched from.
func WebBotAuthDirectoryURL(directory string) string { return directory + WebBotAuthDirectoryPath }

// ---------------------------------------------------------------------------
// Signature base (RFC 9421 section 2.5)
// ---------------------------------------------------------------------------

// WebBotAuthRequest is the request a signature covers.
type WebBotAuthRequest struct {
	// Method is the HTTP method.
	Method string
	// URL is the absolute request URL as the origin server saw it (scheme, host, path, query).
	URL    string
	Header http.Header
}

// webBotHeaderValue is a header's value as RFC 9421 reads it: fields of one name
// joined with ", ", whitespace trimmed. ok is false when absent.
func webBotHeaderValue(h http.Header, name string) (string, bool) {
	vals := h.Values(name)
	if len(vals) == 0 {
		return "", false
	}
	parts := make([]string, len(vals))
	for i, v := range vals {
		parts[i] = strings.TrimSpace(v)
	}
	return strings.Join(parts, ", "), true
}

var webBotDerived = map[string]bool{"@method": true, "@authority": true, "@path": true, "@target-uri": true, "@scheme": true, "@query": true, "@request-target": true}

func escapeSfString(v string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(v) + `"`
}

func formatSfNumber(f float64) string {
	if f == float64(int64(f)) {
		return strconv.FormatInt(int64(f), 10)
	}
	return strconv.FormatFloat(f, 'f', -1, 64)
}

// serializeComponentID is the component identifier as written in Signature-Input and in the signature base: "name";param=value.
func serializeComponentID(c WebBotAuthComponent) string {
	out := escapeSfString(c.Name)
	for _, p := range c.Params {
		switch v := p.Value.(type) {
		case bool:
			if v {
				out += ";" + p.Key
			} else {
				out += ";" + p.Key + "=?0"
			}
		case string:
			out += ";" + p.Key + "=" + escapeSfString(v)
		case int64:
			out += ";" + p.Key + "=" + strconv.FormatInt(v, 10)
		case float64:
			out += ";" + p.Key + "=" + formatSfNumber(v)
		case []byte:
			out += ";" + p.Key + "=:" + base64.StdEncoding.EncodeToString(v) + ":"
		}
	}
	return out
}

type sfOut struct {
	out string
	end int
}

func sfBareItem(text string, i int) (sfOut, bool) {
	c := at(text, i)
	switch {
	case c == '"':
		_, end, ok := readString(text, i)
		if !ok {
			return sfOut{}, false
		}
		return sfOut{text[i:end], end}, true
	case c == ':':
		closeAt := strings.IndexByte(text[i+1:], ':')
		if closeAt < 0 {
			return sfOut{}, false
		}
		if _, ok := base64ToBytes(text[i+1 : i+1+closeAt]); !ok {
			return sfOut{}, false
		}
		end := i + 1 + closeAt + 1
		return sfOut{text[i:end], end}, true
	case c == '?':
		b := text[i:min(i+2, len(text))]
		if b != "?0" && b != "?1" {
			return sfOut{}, false
		}
		return sfOut{b, i + 2}, true
	case c == '-' || (c >= '0' && c <= '9'):
		m := webBotNumPre.FindStringSubmatch(text[i:])
		if m == nil {
			return sfOut{}, false
		}
		if m[1] == "" {
			return sfOut{m[0], i + len(m[0])}, true
		}
		f, _ := strconv.ParseFloat(m[0], 64)
		fixed := strings.TrimRight(strconv.FormatFloat(f, 'f', 3, 64), "0")
		if strings.HasSuffix(fixed, ".") {
			fixed += "0"
		}
		return sfOut{fixed, i + len(m[0])}, true
	case c == '*' || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'):
		j := i
		for j < len(text) && isTokenChar(text[j]) {
			j++
		}
		return sfOut{text[i:j], j}, true
	}
	return sfOut{}, false
}

func WebBotAuthParamsOut(text string, i int) (sfOut, bool) {
	out := ""
	for {
		j := i
		for at(text, j) == ' ' || at(text, j) == '\t' {
			j++
		}
		if at(text, j) != ';' {
			return sfOut{out, i}, true
		}
		j++
		for at(text, j) == ' ' {
			j++
		}
		key := ""
		if j <= len(text) {
			key = webBotKeyPre.FindString(text[j:])
		}
		if key == "" {
			return sfOut{}, false
		}
		j += len(key)
		out += ";" + key
		if at(text, j) == '=' {
			v, ok := sfBareItem(text, j+1)
			if !ok {
				return sfOut{}, false
			}
			out += "=" + v.out
			j = v.end
		}
		i = j
	}
}

func sfItem(text string) (string, bool) {
	t := strings.TrimSpace(text)
	var body sfOut
	if at(t, 0) == '(' {
		depth, closeAt := 0, -1
		quoted := false
		for k := 0; k < len(t); k++ {
			ch := t[k]
			if quoted {
				if ch == '\\' {
					k++
				} else if ch == '"' {
					quoted = false
				}
			} else if ch == '"' {
				quoted = true
			} else if ch == '(' {
				depth++
			} else if ch == ')' {
				depth--
				if depth == 0 {
					closeAt = k
					break
				}
			}
		}
		if closeAt < 0 {
			return "", false
		}
		collapsed := strings.Join(strings.Fields(t[1:closeAt]), " ")
		var members []string
		for _, m := range splitTop(collapsed, ' ') {
			canon, ok := sfItem(m)
			if !ok {
				return "", false
			}
			members = append(members, canon)
		}
		body = sfOut{"(" + strings.Join(members, " ") + ")", closeAt + 1}
	} else {
		b, ok := sfBareItem(t, 0)
		if !ok {
			return "", false
		}
		body = b
	}
	params, ok := WebBotAuthParamsOut(t, body.end)
	if !ok || strings.TrimSpace(t[min(params.end, len(t)):]) != "" {
		return "", false
	}
	return body.out + params.out, true
}

type sfMember struct{ key, value string }

// sfDictionary returns the key=value members of a Dictionary, canonicalised, in order. nil when malformed.
func sfDictionary(text string) []sfMember {
	var out []sfMember
	for _, member := range splitTop(text, ',') {
		key := webBotKeyPre.FindString(member)
		if key == "" {
			return nil
		}
		rest := member[len(key):]
		var value string
		var ok bool
		if strings.HasPrefix(rest, "=") {
			value, ok = sfItem(rest[1:])
		} else {
			value, ok = sfItem("?1" + rest)
		}
		if !ok {
			return nil
		}
		out = append(out, sfMember{key, value})
	}
	return out
}

// sfSerialize is the canonical Structured Field form of a header value (Dictionary when it reads as one, else List or Item).
func sfSerialize(text string) (string, bool) {
	members := splitTop(text, ',')
	all, anyEq := len(members) > 0, false
	for _, m := range members {
		if !webBotDictRE.MatchString(m) {
			all = false
		}
		if webBotDictEq.MatchString(m) {
			anyEq = true
		}
	}
	if all && anyEq {
		dict := sfDictionary(text)
		if dict == nil {
			return "", false
		}
		parts := make([]string, len(dict))
		for i, d := range dict {
			switch {
			case d.value == "?1":
				parts[i] = d.key
			case strings.HasPrefix(d.value, "?1;"):
				parts[i] = d.key + d.value[2:]
			default:
				parts[i] = d.key + "=" + d.value
			}
		}
		return strings.Join(parts, ", "), true
	}
	items := make([]string, 0, len(members))
	for _, m := range members {
		it, ok := sfItem(m)
		if !ok {
			return "", false
		}
		items = append(items, it)
	}
	if len(items) == 0 {
		return "", false
	}
	return strings.Join(items, ", "), true
}

// webBotPercentEncode is encodeURIComponent plus the characters it leaves bare (!'()*).
func webBotPercentEncode(v string) string {
	var b strings.Builder
	for i := 0; i < len(v); i++ {
		c := v[i]
		if c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.' || c == '~' {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

func webBotPath(u *url.URL) string {
	if p := u.EscapedPath(); p != "" {
		return p
	}
	return "/"
}

func webBotSearch(u *url.URL) string {
	if u.RawQuery == "" {
		return ""
	}
	return "?" + u.RawQuery
}

func webBotComponentValue(c WebBotAuthComponent, req WebBotAuthRequest, u *url.URL) (string, bool) {
	name := c.Name
	if name == "@query-param" {
		v, ok := sfGet(c.Params, "name")
		qn, isStr := v.(string)
		if len(c.Params) != 1 || !ok || !isStr {
			return "", false
		}
		vals, _ := url.ParseQuery(u.RawQuery)
		found := vals[qn]
		if len(found) != 1 {
			return "", false
		}
		return webBotPercentEncode(found[0]), true
	}
	if strings.HasPrefix(name, "@") {
		if len(c.Params) > 0 {
			return "", false
		}
		switch name {
		case "@method":
			return strings.ToUpper(req.Method), true
		case "@authority":
			return webBotHost(u), true
		case "@path":
			return webBotPath(u), true
		case "@target-uri":
			return strings.ToLower(u.Scheme) + "://" + webBotHost(u) + webBotPath(u) + webBotSearch(u), true
		case "@scheme":
			return strings.ToLower(u.Scheme), true
		case "@query":
			if u.RawQuery == "" {
				return "?", true
			}
			return "?" + u.RawQuery, true
		case "@request-target":
			return webBotPath(u) + webBotSearch(u), true
		}
		return "", false
	}
	raw, ok := webBotHeaderValue(req.Header, name)
	if !ok {
		return "", false
	}
	if len(c.Params) == 0 {
		return raw, true
	}
	// Header-field parameters: at most one of sf, key (with a string value) or bs. req and tr belong to responses and trailers.
	if len(c.Params) != 1 {
		return "", false
	}
	p := c.Params[0]
	switch {
	case p.Key == "sf" && p.Value == true:
		return sfSerialize(raw)
	case p.Key == "key":
		ks, isStr := p.Value.(string)
		if !isStr {
			return "", false
		}
		for _, d := range sfDictionary(raw) {
			if d.key == ks {
				return d.value, true
			}
		}
		return "", false
	case p.Key == "bs" && p.Value == true:
		return ":" + base64.StdEncoding.EncodeToString([]byte(raw)) + ":", true
	}
	return "", false
}

// BuildWebBotAuthSignatureBase builds the RFC 9421 signature base: one `"id": value`
// line per covered component, then the @signature-params line. signatureParams is the
// inner list with its parameters, serialised exactly as it appears in Signature-Input.
// A component is a name, or a name with parameters: a header with sf, key="member" or
// bs, and @query-param with name. The failure reason is one of unsupported_component,
// component_missing or bad_request.
func BuildWebBotAuthSignatureBase(req WebBotAuthRequest, components []WebBotAuthComponent, signatureParams string) (string, WebBotAuthFailure) {
	u, err := url.Parse(req.URL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", WebBotAuthBadRequest
	}
	seen := map[string]bool{}
	lines := make([]string, 0, len(components)+1)
	for _, c := range components {
		if c.Name != strings.ToLower(c.Name) {
			return "", WebBotAuthUnsupportedComponent
		}
		if strings.HasPrefix(c.Name, "@") && !webBotDerived[c.Name] && c.Name != "@query-param" {
			return "", WebBotAuthUnsupportedComponent
		}
		id := serializeComponentID(c)
		if seen[id] {
			return "", WebBotAuthUnsupportedComponent
		}
		seen[id] = true
		for _, p := range c.Params {
			if p.Key != "sf" && p.Key != "key" && p.Key != "bs" && p.Key != "name" {
				return "", WebBotAuthUnsupportedComponent
			}
		}
		// A derived component takes no header parameters (only @query-param takes name).
		if strings.HasPrefix(c.Name, "@") && c.Name != "@query-param" && len(c.Params) > 0 {
			return "", WebBotAuthUnsupportedComponent
		}
		v, ok := webBotComponentValue(c, req, u)
		if !ok || strings.ContainsAny(v, "\r\n") {
			return "", WebBotAuthComponentMissing
		}
		lines = append(lines, id+": "+v)
	}
	lines = append(lines, `"@signature-params": `+signatureParams)
	return strings.Join(lines, "\n"), ""
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

// WebBotAuthFailure says why a verification failed.
type WebBotAuthFailure string

// Reasons a request does not verify.
const (
	WebBotAuthNoSignature           WebBotAuthFailure = "no_signature"
	WebBotAuthNoWebBotSignature     WebBotAuthFailure = "no_web_bot_auth_signature"
	WebBotAuthMalformed             WebBotAuthFailure = "malformed"
	WebBotAuthMissingSignatureAgent WebBotAuthFailure = "missing_signature_agent"
	WebBotAuthBadSignatureAgent     WebBotAuthFailure = "bad_signature_agent"
	WebBotAuthBadParams             WebBotAuthFailure = "bad_params"
	WebBotAuthUnsupportedAlgorithm  WebBotAuthFailure = "unsupported_algorithm"
	WebBotAuthUnsupportedComponent  WebBotAuthFailure = "unsupported_component"
	WebBotAuthComponentMissing      WebBotAuthFailure = "component_missing"
	WebBotAuthComponentsNotCovered  WebBotAuthFailure = "components_not_covered"
	WebBotAuthBadRequest            WebBotAuthFailure = "bad_request"
	WebBotAuthNotYetValid           WebBotAuthFailure = "not_yet_valid"
	WebBotAuthExpired               WebBotAuthFailure = "expired"
	WebBotAuthLifetimeTooLong       WebBotAuthFailure = "lifetime_too_long"
	WebBotAuthDirectoryUnavailable  WebBotAuthFailure = "directory_unavailable"
	WebBotAuthKeyNotFound           WebBotAuthFailure = "key_not_found"
	WebBotAuthBadSignature          WebBotAuthFailure = "bad_signature"
	WebBotAuthReplayed              WebBotAuthFailure = "replayed"
)

// WebBotAuthResult is the outcome of VerifyWebBotAuth.
type WebBotAuthResult struct {
	// Signed is true when the request carried a signature header at all.
	Signed   bool
	Verified bool
	Reason   WebBotAuthFailure
	// Directory is the normalised directory the signer claims (set once Signature-Agent
	// parsed; trust it only when Verified).
	Directory string
	KeyID     string
	Label     string
	Created   int64
	Expires   int64
	Nonce     string
}

// WebBotAuthVerifyOptions configures VerifyWebBotAuth.
type WebBotAuthVerifyOptions struct {
	// GetKeys returns the directory keys for a directory URL. refresh asks for a fresh
	// copy (the key was not in the cached one). Return nil when the directory is
	// unavailable and a non-nil empty slice when it holds no usable key.
	GetKeys func(ctx context.Context, directoryURL string, refresh bool) []WebBotAuthJWK
	// Now overrides the clock; zero means time.Now.
	Now time.Time
	// Skew is the tolerated clock skew (default 30s).
	Skew time.Duration
	// MaxLifetime is the longest accepted expires-created (default 1h).
	MaxLifetime time.Duration
	// ClaimNonce is the replay guard: called after the signature verified, with a key
	// unique to the signature's nonce, it returns true the first time the key is seen.
	// Without it nonces are not tracked.
	ClaimNonce func(ctx context.Context, key string, expiresAtMS int64) bool
}

func webBotFail(reason WebBotAuthFailure, r WebBotAuthResult) WebBotAuthResult {
	r.Signed, r.Verified, r.Reason = true, false, reason
	return r
}

// VerifyWebBotAuth verifies the web-bot-auth signature on a request. It never panics on bad input.
func VerifyWebBotAuth(ctx context.Context, req WebBotAuthRequest, opts WebBotAuthVerifyOptions) WebBotAuthResult {
	inputHeader, okIn := webBotHeaderValue(req.Header, "signature-input")
	sigHeader, okSig := webBotHeaderValue(req.Header, "signature")
	if !okIn || !okSig {
		return WebBotAuthResult{Reason: WebBotAuthNoSignature}
	}
	inputs := parseSignatureInput(inputHeader)
	sigs := parseSignatureHeader(sigHeader)
	if inputs == nil || sigs == nil {
		return webBotFail(WebBotAuthMalformed, WebBotAuthResult{})
	}
	var input *parsedSignatureInput
	for i := range inputs {
		if tag, _ := sfGet(inputs[i].Params, "tag"); tag == WebBotAuthTag {
			if _, has := sigs[inputs[i].Label]; has {
				input = &inputs[i]
				break
			}
		}
	}
	if input == nil {
		return webBotFail(WebBotAuthNoWebBotSignature, WebBotAuthResult{})
	}
	signature := sigs[input.Label]
	createdV, _ := sfGet(input.Params, "created")
	expiresV, _ := sfGet(input.Params, "expires")
	keyIDV, _ := sfGet(input.Params, "keyid")
	nonceV, hasNonce := sfGet(input.Params, "nonce")
	created, okC := createdV.(int64)
	expires, okE := expiresV.(int64)
	keyID, okK := keyIDV.(string)
	nonce, okN := nonceV.(string)
	if !okC || !okE || !okK || keyID == "" || len(keyID) > 128 || (hasNonce && (!okN || len(nonce) > 512)) {
		return webBotFail(WebBotAuthBadParams, WebBotAuthResult{Label: input.Label})
	}
	base := WebBotAuthResult{Label: input.Label, KeyID: keyID, Created: created, Expires: expires}
	if alg, has := sfGet(input.Params, "alg"); has && alg != "ed25519" {
		return webBotFail(WebBotAuthUnsupportedAlgorithm, base)
	}

	// Time window: created not in the future, expires not in the past, both within a small skew.
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	nowSec := now.Unix()
	skew := opts.Skew
	if skew <= 0 {
		skew = WebBotAuthDefaultSkew
	}
	skewSec := int64(skew / time.Second)
	maxLife := opts.MaxLifetime
	if maxLife <= 0 {
		maxLife = WebBotAuthDefaultMaxLifetime
	}
	if expires <= created {
		return webBotFail(WebBotAuthBadParams, base)
	}
	if expires-created > int64(maxLife/time.Second) {
		return webBotFail(WebBotAuthLifetimeTooLong, base)
	}
	if created > nowSec+skewSec {
		return webBotFail(WebBotAuthNotYetValid, base)
	}
	if expires < nowSec-skewSec {
		return webBotFail(WebBotAuthExpired, base)
	}

	// Coverage: the signature must bind the host, and the directory claim it relies on.
	agentHeader, hasAgent := webBotHeaderValue(req.Header, "signature-agent")
	if !hasAgent {
		return webBotFail(WebBotAuthMissingSignatureAgent, base)
	}
	hasAuthority := false
	var agentComponent *WebBotAuthComponent
	for i := range input.Components {
		switch input.Components[i].Name {
		case "@authority":
			hasAuthority = true
		case "signature-agent":
			if agentComponent == nil {
				agentComponent = &input.Components[i]
			}
		}
	}
	if !hasAuthority || agentComponent == nil {
		return webBotFail(WebBotAuthComponentsNotCovered, base)
	}
	// Covered as a dictionary member (;key="m"): the directory must come from that member, or an uncovered one could be swapped in.
	agentKey := ""
	if kv, has := sfGet(agentComponent.Params, "key"); has {
		if ks, isStr := kv.(string); isStr {
			agentKey = ks
			found := false
			for _, m := range splitTop(agentHeader, ',') {
				if strings.HasPrefix(m, agentKey+"=") {
					found = true
					break
				}
			}
			if !found {
				return webBotFail(WebBotAuthBadSignatureAgent, base)
			}
		}
	}
	label := input.Label
	if agentKey != "" {
		label = agentKey
	}
	directory := ParseSignatureAgent(agentHeader, label)
	if directory == "" {
		return webBotFail(WebBotAuthBadSignatureAgent, base)
	}
	withDir := base
	withDir.Directory = directory

	sigBase, failure := BuildWebBotAuthSignatureBase(req, input.Components, input.Raw)
	if failure != "" {
		return webBotFail(failure, withDir)
	}

	dirURL := WebBotAuthDirectoryURL(directory)
	find := func(keys []WebBotAuthJWK) *WebBotAuthJWK {
		for i := range keys {
			if Ed25519JWKThumbprint(keys[i].X) == keyID {
				return &keys[i]
			}
		}
		return nil
	}
	if opts.GetKeys == nil {
		return webBotFail(WebBotAuthDirectoryUnavailable, withDir)
	}
	keys := opts.GetKeys(ctx, dirURL, false)
	jwk := find(keys)
	if jwk == nil {
		keys = opts.GetKeys(ctx, dirURL, true)
		jwk = find(keys)
	}
	if jwk == nil {
		if keys == nil {
			return webBotFail(WebBotAuthDirectoryUnavailable, withDir)
		}
		return webBotFail(WebBotAuthKeyNotFound, withDir)
	}
	pub := webBotAuthKeyBytes(*jwk)
	if pub == nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(ed25519.PublicKey(pub), []byte(sigBase), signature) {
		return webBotFail(WebBotAuthBadSignature, withDir)
	}
	if opts.ClaimNonce != nil && okN {
		if !opts.ClaimNonce(ctx, directory+"|"+keyID+"|"+nonce, expires*1000+skewSec*1000) {
			return webBotFail(WebBotAuthReplayed, withDir)
		}
	}
	res := withDir
	res.Signed, res.Verified = true, true
	if okN {
		res.Nonce = nonce
	}
	return res
}

// ---------------------------------------------------------------------------
// Signing (for bots and tests)
// ---------------------------------------------------------------------------

// SignWebBotAuthInput is what SignWebBotAuthRequest signs.
type SignWebBotAuthInput struct {
	Method string
	URL    string
	Header http.Header
	// SignatureAgent is the directory URL the bot publishes its keys under.
	SignatureAgent string
	// PrivateKey is the Ed25519 key: the 32-byte seed or the 64-byte private key.
	PrivateKey []byte
	Created    int64
	Expires    int64
	Nonce      string
	// Label defaults to sig1.
	Label string
	// Components must include @authority and signature-agent; default those two.
	Components []WebBotAuthComponent
}

// SignWebBotAuthRequest produces the three headers (signature-agent, signature-input,
// signature) for a request.
func SignWebBotAuthRequest(in SignWebBotAuthInput) (map[string]string, error) {
	label := in.Label
	if label == "" {
		label = "sig1"
	}
	components := in.Components
	if len(components) == 0 {
		components = []WebBotAuthComponent{{Name: "@authority"}, {Name: "signature-agent"}}
	}
	var priv ed25519.PrivateKey
	switch len(in.PrivateKey) {
	case ed25519.SeedSize:
		priv = ed25519.NewKeyFromSeed(in.PrivateKey)
	case ed25519.PrivateKeySize:
		priv = ed25519.PrivateKey(in.PrivateKey)
	default:
		return nil, errors.New("atlas: web bot auth private key must be a 32-byte seed or a 64-byte Ed25519 key")
	}
	pub, _ := priv.Public().(ed25519.PublicKey)
	keyID := Ed25519JWKThumbprint(base64.RawURLEncoding.EncodeToString(pub))
	agentHeader := `"` + in.SignatureAgent + `"`
	ids := make([]string, len(components))
	for i, c := range components {
		ids[i] = serializeComponentID(c)
	}
	params := "(" + strings.Join(ids, " ") + ");created=" + strconv.FormatInt(in.Created, 10) + `;keyid="` + keyID + `";alg="ed25519";expires=` + strconv.FormatInt(in.Expires, 10)
	if in.Nonce != "" {
		params += `;nonce="` + in.Nonce + `"`
	}
	params += `;tag="` + WebBotAuthTag + `"`
	header := http.Header{}
	for k, vs := range in.Header {
		header[k] = append([]string(nil), vs...)
	}
	header.Set("Signature-Agent", agentHeader)
	sigBase, failure := BuildWebBotAuthSignatureBase(WebBotAuthRequest{Method: in.Method, URL: in.URL, Header: header}, components, params)
	if failure != "" {
		return nil, fmt.Errorf("atlas: cannot sign: %s", failure)
	}
	sig := ed25519.Sign(priv, []byte(sigBase))
	return map[string]string{
		"signature-agent": agentHeader,
		"signature-input": label + "=" + params,
		"signature":       label + "=:" + base64.StdEncoding.EncodeToString(sig) + ":",
	}, nil
}

// ---------------------------------------------------------------------------
// Directory cache
// ---------------------------------------------------------------------------

// WebBotAuthDirectoryCacheOptions configures a WebBotAuthDirectoryCache.
type WebBotAuthDirectoryCacheOptions struct {
	// FetchJSON fetches a directory document; an error means unavailable.
	FetchJSON func(ctx context.Context, url string) ([]byte, error)
	// TTL is how long a fetched directory is trusted. Default 10 minutes.
	TTL time.Duration
	// FailureTTL is how long a failed fetch is remembered. Default 1 minute.
	FailureTTL time.Duration
	// RefreshCooldown is the least time between refreshes of one directory, so a bot
	// cannot force a fetch per request. Default 1 minute.
	RefreshCooldown time.Duration
	// MaxEntries is the most directories held. Default 1000.
	MaxEntries int
	// Now overrides the clock (tests).
	Now func() time.Time
}

type webBotCacheEntry struct {
	keys      []WebBotAuthJWK // nil = unavailable
	at        int64
	fetchedAt int64
}

// WebBotAuthDirectoryCache is a small in-memory directory cache, safe for concurrent use.
type WebBotAuthDirectoryCache struct {
	opts    WebBotAuthDirectoryCacheOptions
	mu      sync.Mutex
	entries map[string]*webBotCacheEntry
	order   []string
}

// NewWebBotAuthDirectoryCache builds a cache. FetchJSON is required.
func NewWebBotAuthDirectoryCache(opts WebBotAuthDirectoryCacheOptions) *WebBotAuthDirectoryCache {
	if opts.TTL <= 0 {
		opts.TTL = 10 * time.Minute
	}
	if opts.FailureTTL <= 0 {
		opts.FailureTTL = time.Minute
	}
	if opts.RefreshCooldown <= 0 {
		opts.RefreshCooldown = time.Minute
	}
	if opts.MaxEntries <= 0 {
		opts.MaxEntries = 1000
	}
	return &WebBotAuthDirectoryCache{opts: opts, entries: map[string]*webBotCacheEntry{}}
}

func (c *WebBotAuthDirectoryCache) nowMS() int64 {
	if c.opts.Now != nil {
		return c.opts.Now().UnixMilli()
	}
	return time.Now().UnixMilli()
}

// GetKeys is the GetKeys to hand to VerifyWebBotAuth.
func (c *WebBotAuthDirectoryCache) GetKeys(ctx context.Context, directoryURL string, refresh bool) []WebBotAuthJWK {
	t := c.nowMS()
	c.mu.Lock()
	hit := c.entries[directoryURL]
	if hit != nil {
		ttl := c.opts.FailureTTL
		if hit.keys != nil {
			ttl = c.opts.TTL
		}
		if t-hit.at < ttl.Milliseconds() && !(refresh && t-hit.fetchedAt >= c.opts.RefreshCooldown.Milliseconds()) {
			keys := hit.keys
			c.mu.Unlock()
			return keys
		}
	}
	c.mu.Unlock()

	var keys []WebBotAuthJWK
	if c.opts.FetchJSON != nil {
		if doc, err := c.opts.FetchJSON(ctx, directoryURL); err == nil {
			keys = ParseWebBotAuthDirectory(doc)
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	// A failed refresh keeps serving the last good copy rather than dropping a working directory.
	kept := keys
	if len(kept) == 0 {
		kept = nil
		if prev := c.entries[directoryURL]; prev != nil {
			kept = prev.keys
		}
	}
	if _, exists := c.entries[directoryURL]; !exists {
		if len(c.entries) >= c.opts.MaxEntries && len(c.order) > 0 {
			delete(c.entries, c.order[0])
			c.order = c.order[1:]
		}
		c.order = append(c.order, directoryURL)
	}
	c.entries[directoryURL] = &webBotCacheEntry{keys: kept, at: t, fetchedAt: t}
	return kept
}

// Clear drops every cached directory.
func (c *WebBotAuthDirectoryCache) Clear() {
	c.mu.Lock()
	c.entries = map[string]*webBotCacheEntry{}
	c.order = nil
	c.mu.Unlock()
}

// ---------------------------------------------------------------------------
// Decision (allow and block lists)
// ---------------------------------------------------------------------------

// WebBotAuthListEntry is one allow or block entry.
type WebBotAuthListEntry struct {
	// Directory is a directory URL or bare host. Normalised before comparing.
	Directory string
	// Name labels the agent in decisions and logs. Defaults to the directory host.
	Name string
}

// WebBotAuthPolicy lists the agents to allow or block. A block entry beats an allow entry.
type WebBotAuthPolicy struct {
	Allow []WebBotAuthListEntry
	Block []WebBotAuthListEntry
}

// WebBotAuthAgent is who signed a verified request.
type WebBotAuthAgent struct {
	Directory string
	KeyID     string
	Name      string
}

// WebBotAuthDecision is a verification result turned into a decision.
type WebBotAuthDecision struct {
	Verified bool
	// Agent is set only when Verified, because an unverified claim proves nothing.
	Agent *WebBotAuthAgent
	// Tier is allowed, blocked, verified or unverified.
	Tier string
	// Decision is allow, block or unknown.
	Decision string
	// Reason says why verification failed (empty when verified).
	Reason WebBotAuthFailure
}

// DecideWebBotAuth turns a verification result into a decision. Only a VERIFIED
// directory can be allowed or blocked: an unsigned or failed request is "unknown",
// never trusted and never attributed to the directory it claimed.
func DecideWebBotAuth(result WebBotAuthResult, policy WebBotAuthPolicy) WebBotAuthDecision {
	if !result.Verified || result.Directory == "" || result.KeyID == "" {
		return WebBotAuthDecision{Tier: "unverified", Decision: "unknown", Reason: result.Reason}
	}
	match := func(list []WebBotAuthListEntry) *WebBotAuthListEntry {
		for i := range list {
			if NormalizeWebBotAuthDirectory(list[i].Directory) == result.Directory {
				return &list[i]
			}
		}
		return nil
	}
	blocked := match(policy.Block)
	var allowed *WebBotAuthListEntry
	if blocked == nil {
		allowed = match(policy.Allow)
	}
	entry := blocked
	if entry == nil {
		entry = allowed
	}
	name := ""
	if entry != nil {
		name = strings.TrimSpace(entry.Name)
	}
	if name == "" {
		if u, err := url.Parse(result.Directory); err == nil {
			name = u.Host
		}
	}
	d := WebBotAuthDecision{Verified: true, Agent: &WebBotAuthAgent{Directory: result.Directory, KeyID: result.KeyID, Name: name}, Tier: "verified", Decision: "unknown"}
	switch {
	case blocked != nil:
		d.Tier, d.Decision = "blocked", "block"
	case allowed != nil:
		d.Tier, d.Decision = "allowed", "allow"
	}
	return d
}
