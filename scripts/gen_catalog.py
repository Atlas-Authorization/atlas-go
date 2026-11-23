#!/usr/bin/env python3
"""Generate the long-tail Backend / Platform API surface of the Go SDK from the
OpenAPI snapshot.

Usage (from sdks/go):

    python3 scripts/gen_catalog.py                 # from scripts/openapi.snapshot.json
    python3 scripts/gen_catalog.py --spec FILE     # or another copy of the spec
    python3 scripts/gen_catalog.py --update-pins   # record names of newly generated items

Reproducible: CI regenerates from the checked-in snapshot and fails on any diff.

Writes (all `*_gen.go`):
  catalog_gen.go        one method per operation the hand-written code does not
                        already implement (context.Context first, typed params /
                        query / result structs, cursor lists return CursorPage and
                        get a `...Iter` helper, writes take RequestOption so
                        WithIdempotencyKey / StrictBody / WithDryRun work)
  catalog_types_gen.go  the request / response structs (json tags; pointers for
                        optional scalars and structs; open schemas are
                        interface{} / map[string]interface{})
  catalog_wire_gen.go   the new resource groups hung on Client
  catalog_gen_test.go   every generated operation hits its method + path

Pins (scripts/catalog_pins.json) keep published names stable when the spec or the
hand-written code moves: `ops` maps "METHOD /path" to "Service.Method", `types`
maps a component to its Go name. New items need no hand edit: run with
--update-pins and commit. A pin whose operation left the spec fails the run.

Which operations: every spec operation whose path the hand-written files (the
non-generated .go files of this package) never mention. Hand-written code and
signatures are never touched.
"""
import json, re, os, sys, glob, subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
GEN_FILES = {'catalog_gen.go', 'catalog_types_gen.go', 'catalog_wire_gen.go', 'catalog_gen_test.go', 'catalog_full_gen.go', 'catalog_full_types_gen.go'}
PINS_PATH = os.path.join(HERE, 'catalog_pins.json')

def load_spec():
    src = os.path.join(HERE, 'openapi.snapshot.json')
    if '--spec' in sys.argv:
        src = sys.argv[sys.argv.index('--spec') + 1]
    with open(src) as f:
        return json.load(f)

d = load_spec()
comps = d['components']['schemas']
PINS = {'ops': {}, 'types': {}}
if os.path.exists(PINS_PATH):
    PINS.update(json.load(open(PINS_PATH)))
UPDATE_PINS = '--update-pins' in sys.argv

# ── naming ──────────────────────────────────────────────────────────────────
ACR = {'api': 'API', 'id': 'ID', 'ids': 'IDs', 'mcp': 'MCP', 'iga': 'IGA', 'fga': 'FGA', 'sso': 'SSO', 'scim': 'SCIM',
       'ldap': 'LDAP', 'oauth': 'OAuth', 'mfa': 'MFA', 'waf': 'WAF', 'lti': 'LTI', 'jwt': 'JWT', 'saml': 'SAML',
       'wsfed': 'WSFed', 'pdp': 'PDP', 'pdps': 'PDPs', 'opa': 'OPA', 'url': 'URL', 'urls': 'URLs', 'uri': 'URI',
       'uris': 'URIs', 'sms': 'SMS', 'ssf': 'SSF', 'vc': 'VC', 'abac': 'ABAC', 'dsr': 'DSR', 'ip': 'IP', 'ips': 'IPs',
       'ai': 'AI', 'ui': 'UI', 'oidc': 'OIDC', 'tls': 'TLS', 'kms': 'KMS', 'http': 'HTTP', 'https': 'HTTPS',
       'sdk': 'SDK', 'json': 'JSON', 'csv': 'CSV', 'pca': 'PCA', 'rp': 'RP', 'otp': 'OTP', 'totp': 'TOTP',
       'jwks': 'JWKS', 'jwk': 'JWK', 'sid': 'SID', 'rbac': 'RBAC', 'idp': 'IDP', 'sp': 'SP', 'csr': 'CSR',
       'html': 'HTML', 'css': 'CSS', 'sql': 'SQL', 'uuid': 'UUID', 'dns': 'DNS', 'cname': 'CNAME', 'tcp': 'TCP',
       'ttl': 'TTL', 'pii': 'PII', 'mtls': 'MTLS', 'spiffe': 'SPIFFE', 'svid': 'SVID', 'ca': 'CA', 'db': 'DB',
       'sla': 'SLA', 'ssh': 'SSH', 'xml': 'XML', 'ad': 'AD', 'cidr': 'CIDR', 'dpop': 'DPoP', 'fapi': 'FAPI',
       'ciba': 'CIBA', 'pkce': 'PKCE', 'tos': 'TOS', 'gdpr': 'GDPR', 'sca': 'SCA', 'otel': 'OTel', 'cdn': 'CDN',
       'aws': 'AWS', 'gcp': 'GCP', 'ssl': 'SSL', 'smtp': 'SMTP', 'mx': 'MX', 'tz': 'TZ', 'ux': 'UX', 'os': 'OS'}

def words(s):
    s = re.sub(r'([a-z0-9])([A-Z])', r'\1_\2', s)
    return [w for w in re.split(r'[^A-Za-z0-9]+', s) if w]

def pascal(s):
    out = ''.join(ACR.get(w.lower(), w[:1].upper() + w[1:]) for w in words(s))
    if not out or out[0].isdigit():
        out = 'X' + out
    return out

def sing(w):
    """Singularise the last word of a PascalCase name."""
    if w.endswith('ies') and len(w) > 4: return w[:-3] + 'y'
    if w.endswith('uses'): return w[:-2]
    for suf in ('sses', 'xes', 'zes', 'ches', 'shes'):
        if w.endswith(suf): return w[:-2]
    if w.endswith('IDs') or w.endswith('URLs') or w.endswith('PDPs') or w.endswith('IPs') or w.endswith('URIs'): return w[:-1]
    if w.endswith('ss') or w.endswith('us') or w.endswith('is'): return w
    if w.endswith('s') and len(w) > 3: return w[:-1]
    return w

GO_KW = {'break', 'case', 'chan', 'const', 'continue', 'default', 'defer', 'else', 'fallthrough', 'for', 'func', 'go',
         'goto', 'if', 'import', 'interface', 'map', 'package', 'range', 'return', 'select', 'struct', 'switch', 'type',
         'var', 'ctx', 'params', 'query', 'opts', 'out', 'err', 's', 'url', 'strconv', 'json', 'context', 'zero'}

def lower_camel(s):
    ws = words(s)
    if not ws: return 'v'
    out = ws[0].lower() + ''.join(ACR.get(w.lower(), w[:1].upper() + w[1:]) if w.lower() not in ('id',) else 'ID' for w in ws[1:])
    if out[0].isdigit(): out = 'v' + out
    return out + '_' if out in GO_KW else out

# ── existing (hand-written) code ─────────────────────────────────────────────
def scan_existing():
    idents, methods, types = set(), {}, set()
    client_fields = {}
    for f in sorted(glob.glob(os.path.join(ROOT, '*.go'))):
        if os.path.basename(f) in GEN_FILES:
            continue
        src = open(f).read()
        for m in re.finditer(r'^type (\w+)', src, re.M):
            idents.add(m.group(1)); types.add(m.group(1))
        for m in re.finditer(r'^func (\w+)', src, re.M):
            idents.add(m.group(1))
        for m in re.finditer(r'^(?:const|var) (\w+)', src, re.M):
            idents.add(m.group(1))
        for blk in re.finditer(r'^(?:const|var) \(\n(.*?)^\)', src, re.M | re.S):
            for m in re.finditer(r'^\t(\w+)', blk.group(1), re.M):
                idents.add(m.group(1))
        for m in re.finditer(r'^func \(\w+ \*?(\w+)(?:\[[^\]]*\])?\) (\w+)', src, re.M):
            methods.setdefault(m.group(1), set()).add(m.group(2))
        cm = re.search(r'^type Client struct \{\n(.*?)^\}', src, re.M | re.S)
        if cm:
            for m in re.finditer(r'^\t(\w+)\s+\*(\w+)\s*$|^\t(\w+)\s+\*(\w+)\s*//', cm.group(1), re.M):
                name, ty = (m.group(1), m.group(2)) if m.group(1) else (m.group(3), m.group(4))
                client_fields[name] = ty
            for m in re.finditer(r'^\t(\w+)\s', cm.group(1), re.M):
                client_fields.setdefault(m.group(1), None)
    return idents, methods, types, client_fields

# (verb, path) pairs the hand-written code implements (same path collapsing as scripts/sdk-field-drift.mjs)
def canon(p):
    p = re.sub(r'\{[^}]*\}|\*', '{}', p)
    p = re.sub(r':[A-Za-z_]\w*', '{}', p)
    return re.sub(r'/+$', '', p)

def collapse(text):
    t = re.sub(r'(["\'`])\s*(?:\+|\.|<>)\s*[^"\'`\n]{1,120}?\s*(?:\+|\.|<>)\s*\1', '{}', text)
    t = re.sub(r'(/v1/[\w\-./]*/)(["\'`])\s*(?:\+|\.|<>)\s*[\w$.()\[\]]+', r'\1{}\2', t)
    return re.sub(r'(?:#|\$)?\{\{?[^{}"\'`\n]{0,120}\}?\}', '{}', t)

def paths_in(text):
    out = set()
    for m in re.finditer(r'/v1/[A-Za-z0-9_\-./{}:~]*', collapse(text)):
        p = re.sub(r'[.]+$', '', m.group(0))
        if p.endswith('/'): p += '{}'
        out.add(canon(p))
    return out

HELPER_VERB = {'get': 'GET', 'post': 'POST', 'patch': 'PATCH', 'put': 'PUT', 'del': 'DELETE', 'delQ': 'DELETE',
               'postQ': 'POST', 'platGet': 'GET', 'platPost': 'POST', 'platPatch': 'PATCH', 'platPut': 'PUT',
               'platDel': 'DELETE', 'doBytes': None, 'do': None, 'doAuth': None, 'doRaw': None}
VERBS = ('GET', 'POST', 'PUT', 'PATCH', 'DELETE')

def call_args(src, start):
    """Text of the call whose '(' is at src[start]."""
    depth, i, in_str = 0, start, None
    while i < len(src):
        ch = src[i]
        if in_str:
            if ch == '\\' and in_str != '`': i += 1
            elif ch == in_str: in_str = None
        elif ch in '"`\'': in_str = ch
        elif ch == '(': depth += 1
        elif ch == ')':
            depth -= 1
            if depth == 0: return src[start:i + 1]
        i += 1
    return src[start:start + 400]

def sdk_ops():
    """-> (set of (VERB, canon path), set of canon paths)"""
    pairs, allpaths = set(), set()
    for f in sorted(glob.glob(os.path.join(ROOT, '**/*.go'), recursive=True)):
        rel = os.path.relpath(f, ROOT)
        if os.path.basename(f) in GEN_FILES or f.endswith('_test.go'):
            continue
        if rel.split(os.sep)[0] in ('scripts', 'test', 'tests', 'testing', 'examples', 'example', 'fixtures'):
            continue
        src = open(f).read()
        allpaths |= paths_in(src)
        for fn in re.split(r'\n(?=func )', src):
            fn_paths = paths_in(fn)
            for m in re.finditer(r'\.(get|post|patch|put|delQ|del|postQ|platGet|platPost|platPatch|platPut|platDel|doBytes|doAuth|doRaw|do)\(', fn):
                args = call_args(fn, m.end() - 1)
                verb = HELPER_VERB[m.group(1)]
                if verb is None:
                    vm = re.search(r'"(GET|POST|PUT|PATCH|DELETE)"|http\.Method(Get|Post|Put|Patch|Delete)', args)
                    if vm: verb = (vm.group(1) or vm.group(2)).upper()
                    else:
                        # a verb held in a variable: assume every verb the function names
                        vs = [v for v in VERBS if re.search(r'"%s"|http\.Method%s\b' % (v, v.capitalize()), fn)]
                        for v in vs:
                            for p in (paths_in(args) or fn_paths): pairs.add((v, p))
                        continue
                for p in (paths_in(args) or fn_paths): pairs.add((verb, p))
    return pairs, allpaths

IDENTS, METHODS, TYPES, CLIENT_FIELDS = scan_existing()
HAND_OPS, HAND_PATHS = sdk_ops()
TAKEN_TYPES = set(IDENTS)
SVC_FIELD_BY_TYPE = {t: n for n, t in CLIENT_FIELDS.items() if t}

# ── schema helpers ───────────────────────────────────────────────────────────
def deref(s):
    while isinstance(s, dict) and '$ref' in s:
        s = comps[s['$ref'].split('/')[-1]]
    return s

def merged_object(s):
    s = deref(s)
    props, req, addl = {}, set(), s.get('additionalProperties')
    for part in s.get('allOf', []):
        p2, r2, a2 = merged_object(part)
        props.update(p2); req |= r2
        if a2 is not None: addl = a2
    props.update(s.get('properties', {}) or {})
    req |= set(s.get('required', []) or [])
    return props, req, addl

def is_struct(s):
    s = deref(s)
    if not isinstance(s, dict): return False
    if s.get('properties'): return True
    return bool(s.get('allOf')) and any(is_struct(p) for p in s['allOf'])

def merge_schema(a, b):
    """Union of two property schemas: object properties merge, anything else keeps the first."""
    if a is None: return b
    if is_struct(a) and is_struct(b):
        pa, pb = merged_object(a)[0], merged_object(b)[0]
        props = dict(pa)
        for k, v in pb.items(): props[k] = merge_schema(props.get(k), v)
        return {'type': 'object', 'properties': props, 'description': deref(a).get('description', '')}
    return a

def clean_doc(text, width=96):
    text = re.sub(r'\s+', ' ', (text or '').replace('\r', ' ')).strip()
    if not text: return []
    lines, cur = [], ''
    for w in text.split():
        if cur and len(cur) + len(w) + 1 > width:
            lines.append(cur); cur = w
        else:
            cur = (cur + ' ' + w).strip()
    if cur: lines.append(cur)
    return lines

def comment(text, indent='', first=None):
    ls = clean_doc(text)
    if first and ls: ls[0] = first + ls[0]
    return ''.join(f'{indent}// {l}\n' for l in ls)

class Types:
    def __init__(self):
        self.out = []          # emitted source blocks
        self.comp_names = {}   # component -> go type
        self.in_progress = set()
        self.names = set()

    def unique(self, name):
        base, n = name, 2
        while name in TAKEN_TYPES or name in self.names:
            name = f'{base}{n}'; n += 1
        self.names.add(name)
        return name

    def gotype(self, s, ctx, direct=True):
        """-> (go type, kind, nullable); kind in scalar|struct|slice|map|any"""
        if s is None or s is True or s == {} or not isinstance(s, dict):
            return 'interface{}', 'any', False
        if '$ref' in s:
            cname = s['$ref'].split('/')[-1]
            t, k = self.component(cname)
            return t, k, False
        for key in ('anyOf', 'oneOf'):
            if key in s:
                vs = [v for v in s[key] if not (isinstance(v, dict) and v.get('type') == 'null')]
                nullable = len(vs) != len(s[key])
                if len(vs) == 1:
                    t, k, n2 = self.gotype(vs[0], ctx, direct)
                    return t, k, nullable or n2
                if any(is_struct(v) for v in vs) and all(is_struct(v) or deref(v).get('type') == 'object' for v in vs):
                    vs = [v for v in vs if is_struct(v)]
                    # shortcut: a union of objects is one struct with every variant's properties, all optional
                    merged = {}
                    for v in vs:
                        for pk, pv in merged_object(v)[0].items(): merged[pk] = merge_schema(merged.get(pk), pv)
                    return self.make_struct(self.unique(ctx), {'type': 'object', 'properties': merged,
                                            'description': s.get('description', '')}), 'struct', nullable
                return 'interface{}', 'any', False
        if s.get('allOf') and not s.get('properties') and len(s['allOf']) == 1:
            return self.gotype(s['allOf'][0], ctx, direct)
        t = s.get('type'); nullable = False
        if isinstance(t, list):
            nn = [x for x in t if x != 'null']
            nullable = len(nn) != len(t)
            if len(nn) != 1: return 'interface{}', 'any', False
            t = nn[0]
        if t is None and 'const' in s:
            t = {str: 'string', bool: 'boolean', int: 'integer', float: 'number'}.get(type(s['const']))
        if t is None and 'enum' in s and s['enum']:
            t = {str: 'string', bool: 'boolean', int: 'integer', float: 'number'}.get(type(s['enum'][0]))
        if t == 'string': return 'string', 'scalar', nullable
        if t == 'integer': return 'int64', 'scalar', nullable
        if t == 'number': return 'float64', 'scalar', nullable
        if t == 'boolean': return 'bool', 'scalar', nullable
        if t == 'array':
            it, ik, _ = self.gotype(s.get('items'), ctx + 'Item', False)
            if ik in ('struct',) and False: pass
            if ik == 'struct': it = '*' + it if it in self.in_progress else it
            return '[]' + it, 'slice', nullable
        if t == 'object' or s.get('properties') or s.get('allOf'):
            if is_struct(s):
                return self.make_struct(self.unique(ctx), s), 'struct', nullable
            ap = s.get('additionalProperties')
            if isinstance(ap, dict) and ap:
                vt, vk, _ = self.gotype(ap, ctx + 'Value', False)
                return f'map[string]{vt}', 'map', nullable
            return 'map[string]interface{}', 'map', nullable
        return 'interface{}', 'any', False

    def component(self, cname):
        if cname in self.comp_names:
            return self.comp_names[cname]
        s = comps[cname]
        if is_struct(s):
            pin = PINS['types'].get(cname)
            if pin:
                self.names.add(pin); name = pin
            else:
                name = self.unique(pascal(cname))
            if UPDATE_PINS: PINS['types'][cname] = name
            self.comp_names[cname] = (name, 'struct')
            self.make_struct(name, s, comp=cname)
            return name, 'struct'
        self.comp_names[cname] = ('interface{}', 'any')  # cycle guard for non-struct components
        t, k, _ = self.gotype(s, pascal(cname))
        self.comp_names[cname] = (t, k)
        return t, k

    def make_struct(self, name, s, comp=None):
        props, required, _ = merged_object(s)
        doc = deref(s).get('description') or (f'The `{comp}` object.' if comp else None)
        head = comment(doc, '', f'{name}: ') if doc else f'// {name} is a typed object of the Backend API.\n'
        self.in_progress.add(name)
        used, lines = set(), []
        for pn, ps in props.items():
            fname = pascal(pn)
            base, k = fname, 2
            while fname in used:
                fname = f'{base}{k}'; k += 1
            used.add(fname)
            ty, kind, nullable = self.gotype(ps, name + pascal(pn))
            psd = deref(ps) if isinstance(ps, dict) else {}
            req = pn in required
            if kind == 'struct':
                if (not req) or nullable or ty in self.in_progress: ty = '*' + ty
                omit = ',omitempty' if (not req or nullable) else ''
            elif kind == 'scalar':
                if not req or nullable: ty = '*' + ty
                omit = ',omitempty' if (not req or nullable) else ''
            elif kind == 'any':
                omit = ',omitempty' if not req else ''
            else:  # slice / map
                omit = ',omitempty' if (not req or nullable) else ''
            d = psd.get('description', '') if isinstance(psd, dict) else ''
            enum = None
            if isinstance(psd, dict) and isinstance(psd.get('enum'), list):
                enum = [str(v) for v in psd['enum']]
            if enum: d = (d + ' ' if d else '') + 'One of: ' + ', '.join(enum) + '.'
            lines.append(comment(d, '\t') + f'\t{fname} {ty} `json:"{pn}{omit}"`\n')
        self.in_progress.discard(name)
        body = f'type {name} struct {{\n' + ''.join(lines) + '}\n' if lines else f'type {name} struct{{}}\n'
        self.out.append((name, head + body))
        return name

T = Types()

# ── operations ───────────────────────────────────────────────────────────────
HOST_METHODS = ('get', 'post', 'put', 'patch', 'delete')
ops = []
HIDDEN = []  # missing by verb, but the path is hand-written (invisible to the path-only drift gate)
for p, item in d['paths'].items():
    for m in HOST_METHODS:
        if m in item and (m.upper(), canon(p)) not in HAND_OPS:
            ops.append((m.upper(), p, item[m]))
            if canon(p) in HAND_PATHS: HIDDEN.append(f'{m.upper()} {p}')
ops.sort(key=lambda o: (o[1], ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'].index(o[0])))

def service_of(path):
    segs = path.split('/')[2:]
    if segs[0] == 'platform' and len(segs) > 1:
        return 'platform', segs[1:]
    return segs[0], segs[1:]

def default_method_name(m, rel, op):
    segs = [s for s in rel if s]
    lits = [s for s in segs if not s.startswith('{')]
    ends_param = bool(segs) and segs[-1].startswith('{')
    L = [pascal(x) for x in lits]
    noun_pl = ''.join(L)
    noun_sg = ''.join(L[:-1] + [sing(L[-1])]) if L else ''
    is_list = False
    for c, r in op.get('responses', {}).items():
        if c.startswith('2'):
            sch = deref(((r.get('content') or {}).get('application/json') or {}).get('schema') or {})
            pr = merged_object(sch)[0] if isinstance(sch, dict) else {}
            if 'data' in pr and deref(pr['data']).get('type') == 'array': is_list = True
    if m == 'GET':
        if ends_param: return 'Get' + noun_sg
        return ('List' if is_list else 'Get') + noun_pl
    if m == 'DELETE': return 'Delete' + (noun_sg if True else noun_pl)
    if m == 'PATCH': return 'Update' + noun_sg
    if m == 'PUT': return 'Set' + (noun_sg if ends_param else noun_pl)
    # POST
    if not lits: return 'Create' if not ends_param else 'Post'
    if ends_param: return 'Create' + noun_sg if len(lits) == 1 else 'Post' + noun_sg
    last = L[-1]
    if last.endswith('s') and not last.endswith('ss') and len(lits) >= 1 and last not in ('Status', 'Access', 'Process'):
        return 'Create' + noun_sg
    return last + ''.join(sing(x) for x in L[:-1])

TAKEN_METHODS = {}  # service -> set
services = {}       # service go name -> dict(field, existing, ops=[])
CLIENT_USED = set(CLIENT_FIELDS) | set(METHODS.get('Client', ()))  # a Client method name is taken too

_SVC_MEMO = {}  # one name resolution per segment: wire + tests must agree on the field

def svc_for(seg):
    if seg not in _SVC_MEMO: _SVC_MEMO[seg] = _svc_for(seg)
    return _SVC_MEMO[seg]

def _svc_for(seg):
    base = pascal(seg) + 'Service'
    if base in TYPES and base in SVC_FIELD_BY_TYPE:
        return base, SVC_FIELD_BY_TYPE[base], True
    name = base if base not in TYPES else pascal(seg) + 'OpsService'
    field = name[:-len('Service')]
    if field in CLIENT_USED: field += 'API'
    return name, field, False

def go_params(path, op):
    names = re.findall(r'\{([^}]+)\}', path)
    out, used = [], set()
    for n in names:
        idn = lower_camel(n); base, k = idn, 2
        while idn in used:
            idn = f'{base}{k}'; k += 1
        used.add(idn); out.append((n, idn))
    return out

def body_schema(op):
    rb = op.get('requestBody')
    if not rb: return None
    c = (rb.get('content') or {}).get('application/json')
    return None if c is None else (c.get('schema') or {})

def resp_schema(op):
    for c, r in sorted(op.get('responses', {}).items()):
        if not c.startswith('2'): continue
        content = r.get('content') or {}
        j = content.get('application/json')
        if j and j.get('schema') is not None: return 'json', j['schema']
        return 'empty', None
    return 'empty', None

def query_params(op):
    out = []
    for x in op.get('parameters', []):
        if isinstance(x, dict) and x.get('in') == 'query':
            out.append(x)
    return out

# reserve every pinned name first, so a new op visited earlier cannot take a published method name
for _pv in PINS['ops'].values():
    _sn, _mn = _pv.split('.')
    TAKEN_METHODS.setdefault(_sn, set(METHODS.get(_sn, set()))).add(_mn)

specs = []  # emitted per-op records
for m, p, op in ops:
    prefix_seg, rel = service_of(p)
    key = f'{m} {p}'
    pinned = PINS['ops'].get(key)
    sname, sfield, existing = svc_for(prefix_seg)
    if prefix_seg == 'platform' and 'PlatformService' in TYPES:
        sname, sfield, existing = 'PlatformService', SVC_FIELD_BY_TYPE.get('PlatformService', 'Platform'), True
    mname = default_method_name(m, rel, op)
    if pinned:
        sname2, mname = pinned.split('.')
        assert sname2 == sname or True
        sname = sname2
        if sname in TYPES and sname in SVC_FIELD_BY_TYPE: sfield, existing = SVC_FIELD_BY_TYPE[sname], True
    else:
        taken = TAKEN_METHODS.setdefault(sname, set(METHODS.get(sname, set())))
        if mname in taken:
            first = re.search(r'\{([^}]+)\}', p)
            cand = default_method_name(m, rel, op) + ('By' + pascal(first.group(1)) if first else 'Alt')
            base, n = cand, 2
            while cand in taken:
                cand = f'{base}{n}'; n += 1
            mname = cand
    taken = TAKEN_METHODS.setdefault(sname, set(METHODS.get(sname, set())))
    taken.add(mname)
    if UPDATE_PINS: PINS['ops'][key] = f'{sname}.{mname}'
    specs.append(dict(m=m, p=p, op=op, svc=sname, field=sfield, existing=existing, name=mname, rel=rel))
    if not existing:
        CLIENT_USED.add(sfield)
        services.setdefault(sname, dict(field=sfield, seg=prefix_seg))

# stale pins
spec_keys = {f'{m.upper()} {p}' for p, it in d['paths'].items() for m in it if m in HOST_METHODS}
for k in PINS['ops']:
    if k not in spec_keys:
        sys.exit(f'stale pin: {k} no longer in the spec')

# ── emit ─────────────────────────────────────────────────────────────────────
def render_value_query(q, fname):
    ty, kind, _ = T.gotype(q.get('schema') or {'type': 'string'}, 'Q')
    nm = q['name']
    if ty == 'string':
        return 'string', f'\tif q.{fname} != "" {{\n\t\tv.Set("{nm}", q.{fname})\n\t}}\n'
    if ty == 'int64':
        return '*int64', f'\tif q.{fname} != nil {{\n\t\tv.Set("{nm}", strconv.FormatInt(*q.{fname}, 10))\n\t}}\n'
    if ty == 'float64':
        return '*float64', f'\tif q.{fname} != nil {{\n\t\tv.Set("{nm}", strconv.FormatFloat(*q.{fname}, \'f\', -1, 64))\n\t}}\n'
    if ty == 'bool':
        return '*bool', f'\tif q.{fname} != nil {{\n\t\tv.Set("{nm}", strconv.FormatBool(*q.{fname}))\n\t}}\n'
    if ty in ('[]string',):
        return '[]string', f'\tfor _, x := range q.{fname} {{\n\t\tv.Add("{nm}", x)\n\t}}\n'
    if ty in ('[]int64',):
        return '[]int64', f'\tfor _, x := range q.{fname} {{\n\t\tv.Add("{nm}", strconv.FormatInt(x, 10))\n\t}}\n'
    return 'string', f'\tif q.{fname} != "" {{\n\t\tv.Set("{nm}", q.{fname})\n\t}}\n'

CLEAR_ROOTS = set()
method_blocks = {}   # svc -> [text]
tests = []

def emit(s, method_blocks, tests):
    m, p, op, svc, name, rel = s['m'], s['p'], s['op'], s['svc'], s['name'], s['rel']
    ctxn = svc[:-len('Service')] + name if svc.endswith('Service') else svc + name
    ctxn = pascal(ctxn) if False else ctxn
    pparams = go_params(p, op)
    sig = ['ctx context.Context'] + [f'{i} string' for _, i in pparams]
    call_args = ['ctx'] + [i for _, i in pparams]
    test_args = ['ctx'] + ['"p%d"' % (k + 1) for k in range(len(pparams))]
    # query
    qps = query_params(op)
    # a query the spec added after release: the shipped method keeps its signature, `<Name>WithQuery` takes the query
    legacy_name = name if qps and f'{m} {p}' in PINS.get('no_query', []) else None
    if legacy_name: name = name + 'WithQuery'
    qtype = None
    qblock = ''
    if qps:
        qtype = T.unique(ctxn + 'Query')
        used, fields, body = set(), [], ''
        for q in qps:
            fname = pascal(q['name']); base, k = fname, 2
            while fname in used:
                fname = f'{base}{k}'; k += 1
            used.add(fname)
            gty, code = render_value_query(q, fname)
            fields.append(comment(q.get('description', ''), '\t') + f'\t{fname} {gty}\n')
            body += code
        qblock = (f'// {qtype} holds the query parameters of {svc}.{name}.\ntype {qtype} struct {{\n' + ''.join(fields) + '}\n\n'
                  f'func (q {qtype}) values() url.Values {{\n\tv := url.Values{{}}\n{body}\treturn v\n}}\n\n')
        sig.append(f'query {qtype}'); call_args.append('query'); test_args.append(f'{qtype}{{}}')
    # body
    bs = body_schema(op)
    body_expr = 'nil'
    if bs is not None:
        if '$ref' in bs and is_struct(bs):
            bt, _ = T.component(bs['$ref'].split('/')[-1])
        elif is_struct(bs):
            bt = T.unique(ctxn + 'Params'); T.make_struct(bt, bs)
        else:
            bt, bk, _ = T.gotype(bs, ctxn + 'Params')
        sig.append(f'params {bt}'); call_args.append('params'); body_expr = 'params'
        if m in ('PATCH', 'PUT'): CLEAR_ROOTS.add(bt)
        if bt.startswith('[]') or bt.startswith('map[') or bt == 'interface{}':
            test_args.append('nil')
        elif bt == 'string': test_args.append('""')
        elif bt in ('int64', 'float64'): test_args.append('0')
        elif bt == 'bool': test_args.append('false')
        else:
            test_args.append(f'{bt}{{}}')
    # response
    kind, rs = resp_schema(op)
    ret = None; rkind = 'empty'; item = None; cursor = False
    if kind == 'json':
        rd = deref(rs)
        props = merged_object(rd)[0] if is_struct(rd) else {}
        if 'data' in props and deref(props['data']).get('type') == 'array' and set(props) <= {'object', 'data', 'has_more', 'next_cursor'}:
            it = deref(props['data']).get('items')
            if it is not None and (is_struct(it) or True):
                if isinstance(it, dict) and '$ref' in it:
                    itt, ik, _ = T.gotype(it, ctxn + 'Item')
                elif is_struct(it):
                    itt = T.unique(ctxn + 'Item'); T.make_struct(itt, it); ik = 'struct'
                else:
                    itt, ik, _ = T.gotype(it, ctxn + 'Item')
                has_cursor = 'has_more' in props or 'next_cursor' in props
                ret = f'*CursorPage[{itt}]' if has_cursor else f'*ListPage[{itt}]'
                rkind = 'ptr'; item = itt; cursor = has_cursor
        if ret is None:
            if '$ref' in rs and is_struct(rs):
                rt, _ = T.component(rs['$ref'].split('/')[-1]); ret = '*' + rt; rkind = 'ptr'
            elif is_struct(rs):
                rt = T.unique(ctxn + 'Result'); T.make_struct(rt, rs); ret = '*' + rt; rkind = 'ptr'
            else:
                rt, rk, _ = T.gotype(rs, ctxn + 'Result')
                if rk in ('struct', 'scalar'):
                    ret = rt if rk == 'scalar' else '*' + rt
                    rkind = 'val' if rk == 'scalar' else 'ptr'
                else:
                    ret = rt; rkind = 'val'
    sig.append('opts ...RequestOption')
    path_expr = '"' + p + '"'
    if pparams:
        parts, last = [], 0
        for mm in re.finditer(r'\{([^}]+)\}', p):
            lit = p[last:mm.start()]
            if lit: parts.append('"' + lit + '"')
            parts.append('url.PathEscape(' + dict(pparams)[mm.group(1)] + ')')
            last = mm.end()
        if p[last:]: parts.append('"' + p[last:] + '"')
        path_expr = '+'.join(parts)
    qexpr = 'query.values()' if qps else 'nil'
    plat = op.get('tags', [''])[0] == 'PLATFORM'
    doc = comment(op.get('summary') or op.get('description') or '', '', f'{name}: ') or f'// {name} calls {m} {p}.\n'
    doc += f'// {m} {p}.\n'
    callexpr = (f's.client.doAuth(ctx, authPlatform, "{m}", {path_expr}, {qexpr}, {body_expr}, %s, opts...)' if plat
               else f's.client.do(ctx, "{m}", {path_expr}, {qexpr}, {body_expr}, %s, opts...)')
    if ret is None:
        fn = f'func (s *{svc}) {name}({", ".join(sig)}) error {{\n\treturn {callexpr % "nil"}\n}}\n'
        test_call = f'return c.{s["field"]}.{name}({", ".join(test_args)}, opts...)'
    elif rkind == 'ptr':
        base = ret[1:]
        fn = (f'func (s *{svc}) {name}({", ".join(sig)}) ({ret}, error) {{\n\tout := &{base}{{}}\n'
              f'\tif err := {callexpr % "out"}; err != nil {{\n\t\treturn nil, err\n\t}}\n\treturn out, nil\n}}\n')
        test_call = f'_, err := c.{s["field"]}.{name}({", ".join(test_args)}, opts...)\n\t\treturn err'
    else:
        nilable = ret.startswith('[]') or ret.startswith('map[') or ret == 'interface{}'
        zero = 'nil' if nilable else ('""' if ret == 'string' else 'false' if ret == 'bool' else '0')
        fn = (f'func (s *{svc}) {name}({", ".join(sig)}) ({ret}, error) {{\n\tvar out {ret}\n'
              f'\tif err := {callexpr % "&out"}; err != nil {{\n\t\treturn {zero}, err\n\t}}\n\treturn out, nil\n}}\n')
        test_call = f'_, err := c.{s["field"]}.{name}({", ".join(test_args)}, opts...)\n\t\treturn err'
    blk = qblock + doc + fn
    if legacy_name:
        wsig = [x for x in sig if not x.startswith('query ')]
        wcall = [f'{qtype}{{}}' if x == 'query' else x for x in call_args]
        blk += (f'\n// {legacy_name} calls {name} without the query (the signature it shipped with).\n'
                f'func (s *{svc}) {legacy_name}({", ".join(wsig)}) {"error" if ret is None else "(" + ret + ", error)"} {{\n'
                f'\treturn s.{name}({", ".join(wcall)}, opts...)\n}}\n')
    # cursor iterator helper
    if cursor and any(q['name'] == 'starting_after' for q in qps):
        iname = name + 'Iter'
        while iname in TAKEN_METHODS[svc]: iname += '2'
        TAKEN_METHODS[svc].add(iname)
        isig = [x for x in sig if not x.startswith('opts')] + ['opts ...RequestOption']
        blk += (f'\n// {iname} walks every page of {name}, fetching the next one on demand.\n'
                f'func (s *{svc}) {iname}({", ".join(isig)}) *Iterator[{item}] {{\n'
                f'\treturn Paginate(func(cursor string) (*CursorPage[{item}], error) {{\n'
                f'\t\tq := query\n\t\tif cursor != "" {{\n\t\t\tq.StartingAfter = cursor\n\t\t}}\n'
                f'\t\treturn s.{name}({", ".join(a if a != "query" else "q" for a in call_args)}, opts...)\n\t}})\n}}\n')
    method_blocks.setdefault(svc, []).append(blk)
    exp_path = p
    for k, (n, i) in enumerate(pparams): exp_path = exp_path.replace('{' + n + '}', f'p{k + 1}')
    resp_body = '[]' if (rkind == 'val' and ret and ret.startswith('[]')) else '{}'
    tests.append((m, exp_path, test_call, resp_body, plat))

for s in specs:
    emit(s, method_blocks, tests)
PASS1_TYPES = len(T.out)

# ── pass 2: typed models for operations the hand-written code already covers ─
# The drift gate also wants every request / response / query field of the spec
# modelled. Where a hand-written method returns an older or untyped shape, emit
# a typed `...Full` variant (never changing the published one).
def spec_fields():
    fields = {}
    def props(schema, out, seen, depth=0):
        if not isinstance(schema, dict) or depth > 4: return
        if '$ref' in schema:
            if schema['$ref'] in seen: return
            seen.add(schema['$ref'])
            return props(comps.get(schema['$ref'].split('/')[-1]), out, seen, depth)
        for k in ('allOf', 'oneOf', 'anyOf'):
            for x in schema.get(k, []): props(x, out, seen, depth + 1)
        if schema.get('items'): props(schema['items'], out, seen, depth + 1)
        for k, v in (schema.get('properties') or {}).items():
            out.add(k); props(v, out, seen, depth + 1)
    for p, item in d['paths'].items():
        for m, op in item.items():
            if m not in HOST_METHODS: continue
            key = f'{m.upper()} {p}'
            names = {x['name'] for x in op.get('parameters', []) if isinstance(x, dict) and x.get('in') == 'query'}
            props((((op.get('requestBody') or {}).get('content') or {}).get('application/json') or {}).get('schema'), names, set())
            for code in ('200', '201', '202'):
                props((((op.get('responses') or {}).get(code) or {}).get('content') or {}).get('application/json', {}).get('schema'), names, set())
            for n in sorted(names):
                if re.match(r'^[A-Za-z_]\w*$', n) and n not in fields: fields[n] = (key, m.upper(), p)
    return fields

def idents_of(text):
    return {w.lower().replace('_', '') for w in re.findall(r'[A-Za-z][A-Za-z0-9_]*', text)}

def hand_text():
    text = ''
    for f in sorted(glob.glob(os.path.join(ROOT, '**/*.go'), recursive=True)):
        rel = os.path.relpath(f, ROOT)
        if os.path.basename(f) in GEN_FILES | {'catalog_full_gen.go'} or f.endswith('_test.go'): continue
        if rel.split(os.sep)[0] in ('scripts', 'test', 'tests', 'testing', 'examples', 'example', 'fixtures'): continue
        text += open(f).read() + '\n'
    return text

# the pass-1 output counts as source: render it first (in memory) for the ident set
_pass1 = ''.join(b for _, b in T.out) + ''.join(''.join(v) for v in method_blocks.values())
_have = idents_of(hand_text() + _pass1)
_missing = {n: v for n, v in spec_fields().items() if n.lower().replace('_', '') not in _have}
# a pinned `...Full` operation stays generated even once pass 1 models its fields (published names never vanish)
_pinned_full = {k for k, v in PINS['ops'].items() if v.endswith('Full') and ' ' in k and k.split(' ', 1)[1] in d['paths']
                and k.split(' ', 1)[0].lower() in d['paths'][k.split(' ', 1)[1]]}
_pass1_keys = {f"{x['m'].upper()} {x['p']}" for x in specs}
_full_keys = sorted({v[0] for v in _missing.values()} | (_pinned_full - _pass1_keys))
full_blocks, full_tests = {}, {}
full_specs = []
for key in _full_keys:
    m, p = key.split(' ', 1)
    op = d['paths'][p][m.lower()]
    prefix_seg, rel = service_of(p)
    sname, sfield, existing = svc_for(prefix_seg)
    if prefix_seg == 'platform' and 'PlatformService' in TYPES:
        sname, sfield, existing = 'PlatformService', SVC_FIELD_BY_TYPE.get('PlatformService', 'Platform'), True
    pinned = PINS['ops'].get(key)
    taken = TAKEN_METHODS.setdefault(sname, set(METHODS.get(sname, set())))
    if pinned:
        sname, mname = pinned.split('.')
        if sname in TYPES and sname in SVC_FIELD_BY_TYPE: sfield, existing = SVC_FIELD_BY_TYPE[sname], True
    else:
        base = default_method_name(m, rel, op) + 'Full'
        mname, n = base, 2
        while mname in taken:
            mname = f'{base}{n}'; n += 1
    taken.add(mname)
    if UPDATE_PINS: PINS['ops'][key] = f'{sname}.{mname}'
    if not existing:
        CLIENT_USED.add(sfield)
        services.setdefault(sname, dict(field=sfield, seg=prefix_seg))
    full_specs.append(dict(m=m, p=p, op=op, svc=sname, field=sfield, existing=existing, name=mname, rel=rel))
tests_pass1_len = len(tests)
for s in full_specs:
    emit(s, full_blocks, tests)

# ── null-clearing for PATCH / PUT bodies ─────────────────────────────────────
# The API clears a stored value when a field is sent as null. Unset fields stay
# omitted; to clear one, list its JSON name in ClearFields.
def add_clear_fields():
    blocks = dict(T.out)
    known = set(blocks)
    refs = {n: (set(re.findall(r'\w+', t)) & known) - {n} for n, t in blocks.items()}
    todo, clear = [r for r in CLEAR_ROOTS if r in known], set()
    while todo:
        n = todo.pop()
        if n in clear: continue
        clear.add(n)
        todo.extend(refs[n])
    out = []
    for n, t in T.out:
        if n in clear:
            field = ('\t// ClearFields lists JSON field names to send as null, which clears them on the server.\n'
                     '\t// Fields left unset are omitted.\n\tClearFields []string `json:"-"`\n')
            if f'type {n} struct{{}}' in t:
                t = t.replace(f'type {n} struct{{}}', f'type {n} struct {{\n{field}}}')
            else:
                head, _ = t.rstrip().rsplit('}', 1)
                t = head + field + '}\n'
            t += (f'\n// MarshalJSON sends the set fields and a null for each name in ClearFields.\n'
                  f'func (p {n}) MarshalJSON() ([]byte, error) {{\n\ttype plain {n}\n'
                  f'\textra := map[string]interface{{}}{{}}\n\tfor _, f := range p.ClearFields {{\n\t\textra[f] = nil\n\t}}\n'
                  f'\treturn marshalWithExtra(plain(p), extra)\n}}\n')
        out.append((n, t))
    T.out[:] = out
    return clear

CLEARABLE = add_clear_fields()

# ── write files ──────────────────────────────────────────────────────────────
HDR = '// Code generated by scripts/gen_catalog.py from the Atlas OpenAPI document. DO NOT EDIT.\n\npackage atlas\n\n'
def write(name, text):
    path = os.path.join(ROOT, name)
    with open(path, 'w') as f: f.write(text)
    subprocess.run(['gofmt', '-w', path], check=True)

svc_src = HDR + 'import (\n\t"context"\n\t"encoding/json"\n\t"net/url"\n\t"strconv"\n)\n\n' \
    '// The generated surface may not use every import; keep them referenced.\nvar (\n\t_ = json.Marshal\n\t_ = strconv.Itoa\n\t_ = url.PathEscape\n)\n\n'
for sname in sorted(method_blocks):
    if sname in services:
        seg = services[sname]['seg']
        svc_src += f'// {sname} is the generated surface of /v1/{seg}.\ntype {sname} struct {{\n\tclient *Client\n}}\n\n'
    svc_src += '\n'.join(method_blocks[sname]) + '\n'
for sname in sorted(set(services) - set(method_blocks)):
    svc_src += f'// {sname} is the generated surface of /v1/{services[sname]["seg"]}.\ntype {sname} struct {{\n\tclient *Client\n}}\n\n'
write('catalog_gen.go', svc_src)
full_src = HDR + 'import (\n\t"context"\n\t"encoding/json"\n\t"net/url"\n\t"strconv"\n)\n\nvar (\n\t_ = json.Marshal\n\t_ = strconv.Itoa\n\t_ = url.PathEscape\n)\n\n'
for sname in sorted(full_blocks):
    full_src += '\n'.join(full_blocks[sname]) + '\n'
write('catalog_full_gen.go', full_src)

# types: stable order = emission order
write('catalog_types_gen.go', HDR + '\n'.join(b for _, b in T.out[:PASS1_TYPES]))
write('catalog_full_types_gen.go', HDR + '\n'.join(b for _, b in T.out[PASS1_TYPES:]))

wire = HDR + '// catalogServices holds the resource groups generated from the API description.\ntype catalogServices struct {\n'
for sname in sorted(services):
    wire += f'\t{services[sname]["field"]} *{sname}\n'
wire += '}\n\nfunc (c *Client) wireCatalog() {\n'
for sname in sorted(services):
    wire += f'\tc.{services[sname]["field"]} = &{sname}{{client: c}}\n'
wire += '}\n'
write('catalog_wire_gen.go', wire)

tsrc = HDR.replace('package atlas', 'package atlas') + '''import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

type genCase struct {
	method, path, body string
	call               func(c *Client, ctx context.Context, opts ...RequestOption) error
}

func TestGeneratedCatalogOperations(t *testing.T) {
	cases := []genCase{
'''
for m, ep, call, body, plat in tests:
    tsrc += f'\t\t{{"{m}", "{ep}", `{body}`, func(c *Client, ctx context.Context, opts ...RequestOption) error {{\n\t\t\t{call}\n\t\t}}}},\n'
tsrc += '''	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			var gotMethod, gotPath, gotAuth, gotIdem string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotMethod, gotPath, gotAuth, gotIdem = r.Method, r.URL.Path, r.Header.Get("Authorization"), r.Header.Get("Idempotency-Key")
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()
			c := New("sk_test", WithBaseURL(srv.URL), WithPlatformKey("psk_test"))
			if err := tc.call(c, context.Background(), WithIdempotencyKey("idem-1")); err != nil {
				t.Fatalf("call failed: %v", err)
			}
			if gotMethod != tc.method || gotPath != tc.path {
				t.Fatalf("got %s %s, want %s %s", gotMethod, gotPath, tc.method, tc.path)
			}
			if gotAuth == "" {
				t.Fatalf("no Authorization header")
			}
			if tc.method == "POST" && gotIdem != "idem-1" {
				t.Fatalf("Idempotency-Key not sent")
			}
		})
	}
}
'''
write('catalog_gen_test.go', tsrc)

if UPDATE_PINS:
    json.dump({'ops': dict(sorted(PINS['ops'].items())), 'types': dict(sorted(PINS['types'].items()))},
              open(PINS_PATH, 'w'), indent=1, sort_keys=True)
    open(PINS_PATH, 'a').write('\n')
print(f'{len(full_specs)} typed `Full` variants for {len(_missing)} otherwise-unmodelled fields')
print(f'{len(HIDDEN)} operations were hidden from the path-only drift gate (verb missing, path hand-written)')
print(f'{len(CLEARABLE)} request types can send explicit nulls')
print(f'generated {len(specs)} operations, {len(T.out)} types, {len(services)} new services')
