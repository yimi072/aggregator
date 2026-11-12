#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Rebuild a full v2ray subscription from the clash.yaml in the same Gist.

Why: aggregator's bundled subconverter only emits vmess links for the
v2ray target and silently drops ss / hysteria2 / trojan / vless nodes.
This script reads clash.yaml (which contains every collected proxy),
converts each proxy to its share link, base64-encodes the list and
writes it back to the Gist as v2ray.txt.

Workflow mode (default): needs env GIST_PAT and GIST_LINK (user/gist_id).
Offline mode: --input clash.yaml --output v2ray.txt
Only the Python standard library plus PyYAML are used.
"""

import base64
import json
import os
import sys
import urllib.parse
import urllib.request

import yaml

API = "https://api.github.com"


def b64url_nopad(text: str) -> str:
    return base64.urlsafe_b64encode(text.encode()).decode().rstrip("=")


def q(text) -> str:
    return urllib.parse.quote(str(text), safe="")


def conv_ss(p):
    userinfo = b64url_nopad(f"{p.get('cipher')}:{p.get('password')}")
    link = f"ss://{userinfo}@{p.get('server')}:{p.get('port')}"
    plugin = p.get("plugin")
    if plugin:
        opts = p.get("plugin-opts") or {}
        parts = [str(plugin)]
        for k, v in opts.items():
            parts.append(f"{k}={v}")
        link += "?plugin=" + q(";".join(parts))
    return link + "#" + q(p.get("name", ""))


def conv_hysteria2(p):
    params = {}
    sni = p.get("sni") or p.get("servername")
    if sni:
        params["sni"] = sni
    if p.get("skip-cert-verify"):
        params["insecure"] = "1"
    if p.get("obfs"):
        params["obfs"] = p["obfs"]
        if p.get("obfs-password"):
            params["obfs-password"] = p["obfs-password"]
    if p.get("alpn"):
        alpn = p["alpn"]
        params["alpn"] = ",".join(alpn) if isinstance(alpn, list) else str(alpn)
    if p.get("ports"):
        params["mport"] = str(p["ports"]).replace(",", "-")
    query = urllib.parse.urlencode(params)
    auth = q(p.get("password", ""))
    link = f"hysteria2://{auth}@{p.get('server')}:{p.get('port')}"
    if query:
        link += "?" + query
    return link + "#" + q(p.get("name", ""))


def conv_hysteria(p):
    params = {}
    auth = p.get("auth-str") or p.get("auth_str") or p.get("password", "")
    if auth:
        params["auth"] = auth
    sni = p.get("sni") or p.get("peer") or p.get("servername")
    if sni:
        params["peer"] = sni
    if p.get("skip-cert-verify"):
        params["insecure"] = "1"
    if p.get("alpn"):
        alpn = p["alpn"]
        params["alpn"] = ",".join(alpn) if isinstance(alpn, list) else str(alpn)
    if p.get("up"):
        params["upmbps"] = p["up"]
    if p.get("down"):
        params["downmbps"] = p["down"]
    query = urllib.parse.urlencode(params)
    link = f"hysteria://{p.get('server')}:{p.get('port')}"
    if query:
        link += "?" + query
    return link + "#" + q(p.get("name", ""))


def conv_vmess(p):
    data = {
        "v": "2",
        "ps": str(p.get("name", "")),
        "add": str(p.get("server", "")),
        "port": str(p.get("port", "")),
        "id": str(p.get("uuid", "")),
        "aid": str(p.get("alterId", 0)),
        "scy": str(p.get("cipher", "auto")),
        "net": str(p.get("network", "tcp")),
        "type": "none",
        "host": "",
        "path": "",
        "tls": "tls" if p.get("tls") else "",
        "sni": str(p.get("servername") or p.get("sni") or ""),
    }
    ws = p.get("ws-opts") or {}
    if ws:
        headers = ws.get("headers") or {}
        if headers.get("Host"):
            data["host"] = str(headers["Host"])
        if ws.get("path"):
            data["path"] = str(ws["path"])
    grpc = p.get("grpc-opts") or {}
    if grpc.get("grpc-service-name"):
        data["path"] = str(grpc["grpc-service-name"])
    raw = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
    return "vmess://" + base64.b64encode(raw.encode()).decode()


def conv_trojan(p):
    params = {}
    sni = p.get("sni") or p.get("servername")
    if sni:
        params["sni"] = sni
    if p.get("skip-cert-verify"):
        params["allowInsecure"] = "1"
    if p.get("network"):
        params["type"] = p["network"]
    ws = p.get("ws-opts") or {}
    if ws.get("path"):
        params["path"] = ws["path"]
    headers = ws.get("headers") or {}
    if headers.get("Host"):
        params["host"] = headers["Host"]
    query = urllib.parse.urlencode(params)
    link = f"trojan://{q(p.get('password', ''))}@{p.get('server')}:{p.get('port')}"
    if query:
        link += "?" + query
    return link + "#" + q(p.get("name", ""))


def conv_vless(p):
    params = {"encryption": "none"}
    if p.get("tls"):
        params["security"] = "reality" if p.get("reality-opts") else "tls"
    else:
        params["security"] = "none"
    sni = p.get("servername") or p.get("sni")
    if sni:
        params["sni"] = sni
    if p.get("flow"):
        params["flow"] = p["flow"]
    params["type"] = p.get("network", "tcp")
    ro = p.get("reality-opts") or {}
    if ro.get("public-key"):
        params["pbk"] = ro["public-key"]
    if ro.get("short-id"):
        params["sid"] = ro["short-id"]
    ws = p.get("ws-opts") or {}
    if ws.get("path"):
        params["path"] = ws["path"]
    headers = ws.get("headers") or {}
    if headers.get("Host"):
        params["host"] = headers["Host"]
    grpc = p.get("grpc-opts") or {}
    if grpc.get("grpc-service-name"):
        params["serviceName"] = grpc["grpc-service-name"]
    query = urllib.parse.urlencode(params)
    return (
        f"vless://{p.get('uuid')}@{p.get('server')}:{p.get('port')}?{query}"
        f"#{q(p.get('name', ''))}"
    )


def conv_tuic(p):
    params = {}
    sni = p.get("sni") or p.get("servername")
    if sni:
        params["sni"] = sni
    if p.get("alpn"):
        alpn = p["alpn"]
        params["alpn"] = ",".join(alpn) if isinstance(alpn, list) else str(alpn)
    if p.get("congestion-controller"):
        params["congestion_control"] = p["congestion-controller"]
    if p.get("skip-cert-verify"):
        params["allow_insecure"] = "1"
    query = urllib.parse.urlencode(params)
    link = f"tuic://{q(p.get('uuid', ''))}:{q(p.get('password', ''))}@{p.get('server')}:{p.get('port')}"
    if query:
        link += "?" + query
    return link + "#" + q(p.get("name", ""))


CONVERTERS = {
    "ss": conv_ss,
    "hysteria2": conv_hysteria2,
    "hy2": conv_hysteria2,
    "hysteria": conv_hysteria,
    "vmess": conv_vmess,
    "trojan": conv_trojan,
    "vless": conv_vless,
    "tuic": conv_tuic,
}


def convert_proxies(proxies):
    links, skipped = [], {}
    for p in proxies or []:
        if not isinstance(p, dict):
            continue
        ptype = str(p.get("type", "")).lower()
        fn = CONVERTERS.get(ptype)
        if fn is None:
            skipped[ptype] = skipped.get(ptype, 0) + 1
            continue
        try:
            links.append(fn(p))
        except Exception:
            skipped[ptype] = skipped.get(ptype, 0) + 1
    return links, skipped


def build_v2ray_content(clash_text: str) -> str:
    data = yaml.safe_load(clash_text) or {}
    proxies = data.get("proxies") or []
    links, skipped = convert_proxies(proxies)
    counts = {}
    for link in links:
        scheme = link.split("://", 1)[0]
        counts[scheme] = counts.get(scheme, 0) + 1
    print(
        f"proxies={len(proxies)} links={len(links)} by_scheme={counts} skipped={skipped}",
        flush=True,
    )
    if not links:
        raise SystemExit("no convertible proxies found, refusing to overwrite v2ray.txt")
    body = "\n".join(links)
    return base64.b64encode(body.encode()).decode()


def http(method, url, token, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Accept", "application/vnd.github+json")
    if data is not None:
        req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=60) as resp:
        raw = resp.read()
        return json.loads(raw.decode()) if raw.strip() else {}


def main(argv):
    if "--input" in argv:
        i = argv.index("--input")
        o = argv.index("--output")
        with open(argv[i + 1], encoding="utf8") as f:
            content = build_v2ray_content(f.read())
        with open(argv[o + 1], "w", encoding="utf8") as f:
            f.write(content)
        print(f"wrote {argv[o + 1]}")
        return 0

    token = os.environ.get("GIST_PAT", "").strip()
    link = os.environ.get("GIST_LINK", "").strip()
    if not token or "/" not in link:
        raise SystemExit("GIST_PAT and GIST_LINK (user/gist_id) are required")
    gist_id = link.split("/", 1)[1].strip()

    gist = http("GET", f"{API}/gists/{gist_id}", token)
    files = gist.get("files") or {}
    clash_file = files.get("clash.yaml")
    if not clash_file:
        raise SystemExit("clash.yaml not found in gist, collect may have failed")

    clash_text = clash_file.get("content") or ""
    if clash_file.get("truncated") or not clash_text:
        raw_url = clash_file.get("raw_url")
        req = urllib.request.Request(raw_url, method="GET")
        req.add_header("Authorization", f"Bearer {token}")
        with urllib.request.urlopen(req, timeout=60) as resp:
            clash_text = resp.read().decode()

    content = build_v2ray_content(clash_text)
    http(
        "PATCH",
        f"{API}/gists/{gist_id}",
        token,
        body={"files": {"v2ray.txt": {"content": content, "filename": "v2ray.txt"}}},
    )
    print("v2ray.txt updated in gist")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
