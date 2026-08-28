#!/usr/bin/env python3
"""
unifi — command-line control of a UniFi network.

Two transports, deliberately:

  mongo  (via ssh)  — reads. No credentials, always available, sees the
                      entire controller database including settings the
                      web UI never exposes.
  api    (HTTPS)    — writes. Needs a LOCAL admin account; SSO admins
                      cannot authenticate an API call.

Reads default to mongo because it works with nothing configured.
Writes always go through the API — never write to mongo directly, the
controller caches config in memory and will happily overwrite you.
"""

import argparse
import json
import os
import re
import ssl
import subprocess
import sys
import urllib.error
import urllib.request
from http.cookiejar import CookieJar

def _env_file():
    """First .env we find: $UNIFI_ENV, beside the script, then XDG config."""
    for cand in (
        os.environ.get("UNIFI_ENV"),
        os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"),
        os.path.expanduser("~/.config/unifi-cli/.env"),
    ):
        if cand and os.path.exists(cand):
            return cand
    return None


ENV_FILE = _env_file()


def load_env():
    """Pull UNIFI_* out of the .env file without exporting the whole file.

    Real environment variables always win over the file.
    """
    if not ENV_FILE:
        return
    with open(ENV_FILE) as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            k = k.strip()
            if k.startswith("UNIFI_") and k not in os.environ:
                os.environ[k] = v.strip().strip("'\"")


# Must run before the constants below, or a .env would be read too late to matter.
load_env()

HOST = os.environ.get("UNIFI_HOST", "192.168.1.1")
SSH_ALIAS = os.environ.get("UNIFI_SSH", "udm")
SITE = os.environ.get("UNIFI_SITE", "default")

SECRET_RE = re.compile(
    r"passphrase|password|secret|_psk\b|^psk$|priv(ate)?_key|x_shadow|"
    r"sha512passwd|token|x_mgmt_key|dh_key|certificate_key",
    re.I,
)


# ---------------------------------------------------------------- helpers


def die(msg, code=1):
    print(f"error: {msg}", file=sys.stderr)
    sys.exit(code)


def redact(obj):
    """Recursively blank anything that looks like a credential."""
    if isinstance(obj, dict):
        return {
            k: ("<redacted>" if SECRET_RE.search(k) and v else redact(v))
            for k, v in obj.items()
        }
    if isinstance(obj, list):
        return [redact(x) for x in obj]
    return obj


def emit(data, raw=False):
    if not raw:
        data = redact(data)
    print(json.dumps(data, indent=2, sort_keys=True))


# ---------------------------------------------------------------- mongo


def mongo(js):
    """Run a JS snippet against the controller DB over SSH. Read-only by convention."""
    cmd = ["ssh", "-o", "BatchMode=yes", SSH_ALIAS,
           f"mongo --quiet --port 27117 ace --eval {json_shell_quote(js)}"]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
    except subprocess.TimeoutExpired:
        die(f"ssh {SSH_ALIAS} timed out")
    if out.returncode != 0:
        die(f"ssh {SSH_ALIAS} failed: {out.stderr.strip()[:300]}")
    docs = []
    for line in out.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            docs.append(json.loads(line))
        except json.JSONDecodeError:
            pass
    return docs


def json_shell_quote(s):
    return "'" + s.replace("'", "'\\''") + "'"


COLLECTION_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

# Operators that make the server evaluate JavaScript. Binding the filter as
# data is not much use if the data itself asks mongod to run code.
JS_EVAL_OPS = ("$where", "$function", "$accumulator")


def shell_query_to_json(q):
    """Rewrite mongo shell object syntax into strict JSON.

    The shell accepts bare keys ({name:"guest"}) and single-quoted strings;
    neither is JSON. Rewriting has to respect string literals, so this walks
    the input rather than reaching for a regex: a bare key inside a string
    value is not a key.
    """
    out, i, n = [], 0, len(q)
    while i < n:
        c = q[i]
        if c in "\"'":
            quote, buf, i = c, ['"'], i + 1
            while i < n and q[i] != quote:
                if q[i] == "\\" and i + 1 < n:
                    nxt = q[i + 1]
                    # \' is only an escape inside single quotes; in JSON it is not
                    buf.append("'" if (quote == "'" and nxt == "'") else q[i] + nxt)
                    i += 2
                    continue
                buf.append('\\"' if q[i] == '"' else q[i])
                i += 1
            if i >= n:
                raise ValueError("unterminated string")
            out.append("".join(buf) + '"')
            i += 1
            continue
        if c.isalpha() or c in "_$":
            j = i
            while j < n and (q[j].isalnum() or q[j] in "_$."):
                j += 1
            word, k = q[i:j], j
            while k < n and q[k].isspace():
                k += 1
            if k < n and q[k] == ":":
                out.append(json.dumps(word))      # bare key -> quoted key
            elif word in ("true", "false", "null"):
                out.append(word)
            else:
                raise ValueError(f"unsupported token {word!r}")
            i = j
            continue
        out.append(c)
        i += 1
    return "".join(out)


def reject_js_operators(node):
    """Refuse server-side JavaScript anywhere in the filter, at any depth."""
    if isinstance(node, dict):
        for k, v in node.items():
            if k in JS_EVAL_OPS:
                die(f"{k} is not allowed in --query: it runs JavaScript on the controller")
            reject_js_operators(v)
    elif isinstance(node, list):
        for item in node:
            reject_js_operators(item)


def parse_query(q):
    """Parse a mongo filter into Python data. Never returns a string to splice."""
    for candidate in (lambda: json.loads(q), lambda: json.loads(shell_query_to_json(q))):
        try:
            parsed = candidate()
        except (ValueError, json.JSONDecodeError):
            continue
        if not isinstance(parsed, dict):
            die(f"--query must be an object, got {type(parsed).__name__}")
        reject_js_operators(parsed)
        return parsed
    die(
        f"cannot parse --query as a mongo filter: {q}\n"
        "  Queries are parsed into data and bound to a variable rather than\n"
        "  spliced into JavaScript, so they must be expressible as JSON.\n"
        "  supported:    '{name:\"guest\"}'  '{vlan:{$gt:10}}'  '{enabled:true}'\n"
        "  unsupported:  /regex/, ObjectId(...), new Date(...), function bodies"
    )


def read_collection(name, query="{}"):
    if not COLLECTION_RE.match(name):
        die(f"invalid collection name: {name}\n"
            "  expected a plain identifier, e.g. wlanconf, device, networkconf")
    # The filter is bound to a variable as a JSON literal and the collection is
    # indexed by string, so neither argument is ever evaluated as JavaScript.
    js = (f"var q = {json.dumps(parse_query(query))};"
          f"db[{json.dumps(name)}].find(q)"
          ".forEach(function(d){print(JSON.stringify(d))})")
    return mongo(js)


def list_collections():
    js = ("db.getCollectionNames().forEach(function(c){"
          "var n=db[c].count(); if(n>0) print(JSON.stringify({collection:c,count:n}));})")
    return mongo(js)


# ---------------------------------------------------------------- api


class Api:
    def __init__(self):
        self.user = os.environ.get("UNIFI_USER")
        self.password = os.environ.get("UNIFI_PASS")
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # self-signed CN=unifi.local
        self.jar = CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=ctx),
            urllib.request.HTTPCookieProcessor(self.jar),
        )
        self.csrf = None

    def _raw(self, method, url, body=None, headers=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("Content-Type", "application/json")
        for k, v in (headers or {}).items():
            req.add_header(k, v)
        if self.csrf and method != "GET":
            req.add_header("X-CSRF-Token", self.csrf)
        try:
            resp = self.opener.open(req, timeout=25)
        except urllib.error.HTTPError as e:
            detail = e.read().decode(errors="replace")[:400]
            raise SystemExit(f"error: HTTP {e.code} on {method} {url}\n{detail}")
        except urllib.error.URLError as e:
            raise SystemExit(f"error: cannot reach {HOST}: {e.reason}")
        tok = resp.headers.get("X-CSRF-Token") or resp.headers.get("x-csrf-token")
        if tok:
            self.csrf = tok
        payload = resp.read().decode(errors="replace")
        return json.loads(payload) if payload.strip() else {}

    def login(self):
        if not self.user or not self.password:
            target = ENV_FILE or os.path.join(
                os.path.dirname(os.path.abspath(__file__)), ".env"
            )
            die(
                "no API credentials.\n"
                "  An SSO admin cannot authenticate an API call, however correct the password.\n"
                "  Create a LOCAL admin:  UniFi → Settings → Admins & Users → Add Admin\n"
                "                         → tick 'Restrict to Local Access Only'\n"
                f"  Then add to {target}:\n"
                "      UNIFI_USER=<that username>\n"
                "      UNIFI_PASS=<that password>\n"
                "  Reads still work without this — try:  unifi wlans"
            )
        self._raw("POST", f"https://{HOST}/api/auth/login",
                  {"username": self.user, "password": self.password})
        return self

    def call(self, method, path, body=None):
        if not path.startswith("/"):
            path = "/" + path
        if not path.startswith("/proxy/") and not path.startswith("/api/"):
            path = f"/proxy/network/api/s/{SITE}{path}"
        return self._raw(method, f"https://{HOST}{path}", body)


# ---------------------------------------------------------------- views


def view_radios():
    devs = read_collection("device")
    rows = []
    for d in devs:
        name = d.get("name", "?")
        for r in d.get("radio_table", []) or []:
            over = next(
                (o for o in (d.get("radio_table_stats") or []) if o.get("radio") == r.get("radio")),
                {},
            )
            rows.append({
                "ap": name,
                "band": {"ng": "2.4", "na": "5", "6e": "6"}.get(r.get("radio"), r.get("radio")),
                "channel": r.get("channel"),
                "width": r.get("ht"),
                "tx_power_mode": r.get("tx_power_mode"),
                "min_rssi_enabled": r.get("min_rssi_enabled", False),
                "clients": over.get("user-num_sta"),
            })
    rows.sort(key=lambda x: (str(x["ap"]), str(x["band"])))
    return rows


def view_wlans():
    out = []
    for w in read_collection("wlanconf"):
        out.append({
            "name": w.get("name"),
            "enabled": w.get("enabled"),
            "security": w.get("security"),
            "wpa_mode": w.get("wpa_mode"),
            "wpa3": w.get("wpa3_support", False),
            "pmf": w.get("pmf_mode", "not set"),
            "fast_roaming": w.get("fast_roaming_enabled", False),
            "network_id": w.get("networkconf_id"),
            "bands": w.get("wlan_bands"),
            "hidden": w.get("hide_ssid", False),
            "_id": (w.get("_id") or {}).get("$oid") if isinstance(w.get("_id"), dict) else w.get("_id"),
        })
    return out


def view_forwards():
    return [{
        "name": p.get("name"),
        "enabled": p.get("enabled"),
        "ext_port": p.get("dst_port"),
        "to": f"{p.get('fwd')}:{p.get('fwd_port')}",
        "proto": p.get("proto"),
        "log": p.get("log"),
        "src": p.get("src"),
        "_id": (p.get("_id") or {}).get("$oid") if isinstance(p.get("_id"), dict) else p.get("_id"),
    } for p in read_collection("portforward")]


def view_networks():
    return [{
        "name": n.get("name"),
        "purpose": n.get("purpose"),
        "enabled": n.get("enabled", True),
        "subnet": n.get("ip_subnet"),
        "vlan": n.get("vlan"),
        "vlan_enabled": n.get("vlan_enabled", False),
        "dhcp": f"{n.get('dhcpd_start','-')}–{n.get('dhcpd_stop','-')}" if n.get("dhcpd_enabled") else None,
        "dns": [d for d in (n.get("dhcpd_dns_1"), n.get("dhcpd_dns_2")) if d],
        "isolation": n.get("network_isolation_enabled", False),
    } for n in read_collection("networkconf")]


def view_devices():
    return [{
        "name": d.get("name"),
        "model": d.get("model"),
        "version": d.get("version"),
        "ip": d.get("ip"),
        "adopted": d.get("adopted"),
        "uplink": (d.get("uplink") or {}).get("type") if isinstance(d.get("uplink"), dict) else None,
    } for d in read_collection("device")]


def view_settings(key=None):
    out = {}
    for s in read_collection("setting"):
        k = s.get("key")
        if key and k != key:
            continue
        out[k] = {kk: vv for kk, vv in s.items() if kk not in ("_id", "site_id", "key")}
    return out


# ---------------------------------------------------------------- main


def main():
    p = argparse.ArgumentParser(prog="unifi", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--raw", action="store_true", help="do not redact secrets (be careful)")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("collections", help="list non-empty controller collections")
    sub.add_parser("radios", help="every radio: channel, width, power, clients")
    sub.add_parser("wlans", help="SSIDs with security posture")
    sub.add_parser("networks", help="networks / VLANs / DHCP")
    sub.add_parser("forwards", help="port forwards")
    sub.add_parser("devices", help="devices and firmware")

    s = sub.add_parser("settings", help="site settings")
    s.add_argument("key", nargs="?", help="only this settings key, e.g. ips")

    r = sub.add_parser("read", help="raw read of any collection")
    r.add_argument("collection")
    r.add_argument("--query", default="{}", help="mongo query, e.g. '{name:\"guest\"}'")

    a = sub.add_parser("api", help="authenticated API call (writes)")
    a.add_argument("method", choices=["GET", "POST", "PUT", "DELETE"])
    a.add_argument("path", help="/rest/wlanconf/<id>  (site prefix added automatically)")
    a.add_argument("body", nargs="?", help="JSON body")

    sub.add_parser("whoami", help="check credentials and connectivity")

    args = p.parse_args()

    if args.cmd == "collections":
        emit(list_collections(), args.raw)
    elif args.cmd == "radios":
        emit(view_radios(), args.raw)
    elif args.cmd == "wlans":
        emit(view_wlans(), args.raw)
    elif args.cmd == "networks":
        emit(view_networks(), args.raw)
    elif args.cmd == "forwards":
        emit(view_forwards(), args.raw)
    elif args.cmd == "devices":
        emit(view_devices(), args.raw)
    elif args.cmd == "settings":
        emit(view_settings(args.key), args.raw)
    elif args.cmd == "read":
        emit(read_collection(args.collection, args.query), args.raw)
    elif args.cmd == "api":
        body = json.loads(args.body) if args.body else None
        emit(Api().login().call(args.method, args.path, body), args.raw)
    elif args.cmd == "whoami":
        ok_ssh = bool(read_collection("site"))
        creds = bool(os.environ.get("UNIFI_USER") and os.environ.get("UNIFI_PASS"))
        print(f"host          {HOST}  (site: {SITE})")
        print(f"ssh {SSH_ALIAS:<10}{'ok — reads available' if ok_ssh else 'FAILED'}")
        print(f"api creds     {'present — writes available' if creds else 'missing — reads only'}")
        if creds:
            me = Api().login().call("GET", "/self")
            print(f"api login     ok as {me.get('data',[{}])[0].get('name','?')}")


if __name__ == "__main__":
    main()
