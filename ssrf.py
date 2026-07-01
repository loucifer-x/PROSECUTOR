"""
scanners/ssrf.py

Addon entrypoint, loaded dynamically by main.py via:

    asset = parse_spa(url)   # or parser.py's parse() -- identical schema
    result = addons[addon_name](asset)

Exposed as ssrf(asset) -- main.py's loader does getattr(module, addon_name),
and addon_name is derived from this file's name ("ssrf.py" -> "ssrf"), so
the entrypoint function must be named exactly `ssrf`. Also aliased as
scan/run/analyze/main for convenience if you ever import this module
directly instead of through the addon loader.

asset is consumed per the schema parse_spa()/parse() actually return:
forms[].fields, parameters, target.final_url -- see
_extract_injection_points() below for the exact mapping.

Still TODO on your end:
  - InteractshOOBClient: wire in a real interactsh-client (or your own
    DNS/HTTP callback logger). Currently stubbed to report zero
    interactions, so scan() runs end-to-end but won't find anything yet.
  - SSRF_OOB_DOMAIN env var: point it at your OOB listener's base domain.
"""

import os
import re
import sys
from typing import Any
import threading

# sys.path target: adjust to wherever you place ssrf_prober.py.
# If it lives at the project root (next to main.py), alongside scanners/:
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
# If instead you put it in a lib/ or helpers/ folder, point there instead, e.g.:
#   sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "lib"))

from ssrf_prober import SSRFProber, InjectionPoint, build_report

import requests


# ---------------------------------------------------------------------------
# OOB client -- talks to oob_listener.py running on your own server/IP.
# See oob_listener.py for the companion script you run there.
# ---------------------------------------------------------------------------

from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

import json
from datetime import datetime


_oob_events = {}
_oob_server = None

class OOBHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        parsed = urlparse(self.path)

        # Callback endpoint:
        # /cb/<token>
        if parsed.path.startswith("/cb/"):
            token = parsed.path.split("/cb/", 1)[1]

            print(
                f"[OOB] CALLBACK RECEIVED token={token} "
                f"source={self.client_address[0]}",
                file=sys.stderr
            )

            _oob_events.setdefault(token, []).append({
                "time": datetime.utcnow().isoformat(),
                "method": "GET",
                "source": self.client_address[0],
                "headers": dict(self.headers),
                "path": parsed.path,
            })

            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")
            return


        # Poll endpoint:
        # /_check?token=<token>
        if parsed.path == "/_check":
            params = parse_qs(parsed.query)
            token = params.get("token", [""])[0]

            body = json.dumps({
                "interactions": _oob_events.get(token, [])
            }).encode()

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        self.send_response(404)
        self.end_headers()

import socket



def start_oob_listener():
    global _oob_server

    if _oob_server:
        return _oob_server

    server = HTTPServer(
        ("0.0.0.0", 9000),
        OOBHandler
    )

 
    thread = threading.Thread(
        target=server.serve_forever,
        daemon=True
    )

    thread.start()

    _oob_server = server

    return server



class SelfHostedOOBClient:
    def __init__(self, host: str, check_url: str):
        self._host = host.replace("https://", "").replace("http://", "").rstrip("/")
        self._check_url = check_url.rstrip("/")

    def new_payload_host(self, token: str) -> str:
        return f"https://{self._host}/cb/{token}"

    def poll_interactions(self, token: str) -> list[dict]:
        try:
            resp = requests.get(self._check_url, params={"token": token}, timeout=5)
            resp.raise_for_status()
            interactions = resp.json().get("interactions", [])

            if interactions:
                print(
                    f"[OOB] FOUND {len(interactions)} interaction(s) for token={token}",
                    file=sys.stderr
                )

            return interactions
        except requests.RequestException:
            return []


_OOB_HOST = "monetary-granular-splashy.ngrok-free.dev"

_OOB_CHECK_URL = "https://monetary-granular-splashy.ngrok-free.dev/_check"



_oob_client = SelfHostedOOBClient(_OOB_HOST, _OOB_CHECK_URL)


# ---------------------------------------------------------------------------
# HTTP send -- swap in your project's own request layer if it has one
# (session reuse, proxy config, auth, rate limiting, etc.)
# ---------------------------------------------------------------------------

def _send_request(point: InjectionPoint, injected_value: str):
    try:
        if point.param_type == "query":

            response = requests.request(
                point.method,
                point.location,
                params={
                    point.field: injected_value
                },
                timeout=10,
                allow_redirects=False
            )
            print(response.url, file=sys.stderr)
            print(response.text[:200], file=sys.stderr)
            print(
                f"[SSRF TEST] final_url={response.url}",
                file=sys.stderr
            )

            print(
                f"[SSRF TEST] response={response.status_code}",
                file=sys.stderr
            )
        elif point.param_type == "form":

            if point.method.upper() == "GET":

                response = requests.get(
                    point.location,
                    params={
                        point.field: injected_value
                    },
                    timeout=10,
                    allow_redirects=False
                )

            else:

                response = requests.request(
                    point.method,
                    point.location,
                    data={
                        point.field: injected_value
                    },
                    timeout=10,
                    allow_redirects=False
                )

            print(
                f"[SSRF TEST] sent URL={response.url}",
                file=sys.stderr
            )

            print(
                f"[SSRF TEST] response={response.status_code}",
                file=sys.stderr
            )
        elif point.param_type == "json":
            body = {**point.base_params, point.field: injected_value}
            requests.request(point.method, point.location, json=body, timeout=5)
        elif point.param_type == "header":
            headers = {point.field: injected_value}
            requests.request(point.method, point.location, headers=headers, timeout=5)
    except requests.RequestException:
        pass


# ---------------------------------------------------------------------------
# asset -> InjectionPoint[] adapter
#
# Matches the schema returned by parse_spa() / parse():
#   {
#     "target":       {"url", "final_url", "domain", "path"},
#     "response":     {...},
#     "page":         {...},
#     "links":        [{"url", "text", "internal", "parameters"}],
#     "forms":        [{"action", "method", "enctype",
#                        "fields": [{"name","type","id","value","required"}]}],
#     "inputs":       [{"name","type","id","value","required"}],  # loose, no form
#     "scripts":      [...],
#     "resources":    [...],
#     "parameters":   [{"name", "value"}],   # query params on the page URL itself
#     "technologies": [...],
#   }
# ---------------------------------------------------------------------------

# Field name/id/type fragments that suggest the value is fetched server-side
# as a URL (image fetch, webhook registration, redirect target, etc). This is
# a heuristic filter to avoid spraying every text field on every form; widen
# or narrow as you see fit for your targets.
_URL_LIKE_PATTERN = re.compile(
    r"(url|uri|link|callback|webhook|redirect|return|next|"
    r"image|avatar|photo|picture|src|endpoint|target|host|"
    r"domain|fetch|proxy|feed|file|path|resource|"
    r"remote|source|import|template|attachment|document|"
    r"xml|server|api)",
    re.I,
)


_PROBE_ALL_FIELDS = os.environ.get("SSRF_PROBE_ALL_FIELDS", "1").lower() in ("1", "true", "yes")


def _looks_url_relevant(field: dict[str, Any]) -> bool:
    if _PROBE_ALL_FIELDS:
        return True
    if str(field.get("type", "")).lower() == "url":
        return True
    name = str(field.get("name", ""))
    fid = str(field.get("id", ""))
    return bool(_URL_LIKE_PATTERN.search(name) or _URL_LIKE_PATTERN.search(fid))


def _extract_injection_points(asset: dict[str, Any], debug: bool = False) -> list[InjectionPoint]:
    points: list[InjectionPoint] = []

    page_url = (
        asset.get("target", {}).get("final_url")
        or asset.get("target", {}).get("url", "")
    )

    seen = set()

    def add_query_params_from_url(url: str, source="url"):
        if not url:
            return

        try:
            parsed = urlparse(url)

            if debug:
                print(
                    f"[ssrf] inspecting {source}: {url}",
                    file=sys.stderr
                )

            for name in parse_qs(parsed.query):

                key = (
                    name,
                    url,
                    "GET",
                    "query"
                )

                if key in seen:
                    continue

                seen.add(key)

                points.append(
                    InjectionPoint(
                        field=name,
                        location=url,
                        method="GET",
                        param_type="query"
                    )
                )

                if debug:
                    print(
                        f"[ssrf] query parameter: {name} -> {url}",
                        file=sys.stderr
                    )

        except Exception:
            pass


    # -------------------------
    # Main target URL
    # -------------------------

    add_query_params_from_url(
        page_url,
        "target"
    )


    # -------------------------
    # Existing parameters
    # -------------------------

    for param in asset.get("parameters", []) or []:

        name = param.get("name")

        if not name:
            continue

        key = (
            name,
            page_url,
            "GET",
            "query"
        )

        if key in seen:
            continue

        seen.add(key)

        points.append(
            InjectionPoint(
                field=name,
                location=page_url,
                method="GET",
                param_type="query"
            )
        )

        if debug:
            print(
                f"[ssrf] parameter: {name}",
                file=sys.stderr
            )


    # -------------------------
    # Links
    # -------------------------

    for link in asset.get("links", []) or []:

        if isinstance(link, dict):
            url = link.get("url")
        else:
            url = link

        add_query_params_from_url(
            url,
            "link"
        )


    # -------------------------
    # Resources
    # -------------------------

    for resource in asset.get("resources", []) or []:

        if isinstance(resource, dict):
            url = resource.get("url")
        else:
            url = resource

        add_query_params_from_url(
            url,
            "resource"
        )


    # -------------------------
    # Scripts
    # -------------------------

    url_regex = re.compile(
        r"https?://[^\s\"'<>]+",
        re.I
    )

    for script in asset.get("scripts", []) or []:

        content = ""

        if isinstance(script, dict):

            content = (
                script.get("content")
                or script.get("text")
                or script.get("body")
                or ""
            )

            script_url = script.get("url")

            if script_url:
                add_query_params_from_url(
                    script_url,
                    "script"
                )

        elif isinstance(script, str):
            content = script


        for match in url_regex.findall(content):

            add_query_params_from_url(
                match,
                "javascript"
            )


    # -------------------------
    # Forms
    # -------------------------

    for form in asset.get("forms", []) or []:

        action = (
            form.get("action")
            or page_url
        )


        # Fix relative actions:
        # /fetch -> http://host/fetch

        if action.startswith("/"):

            parsed_page = urlparse(page_url)

            action = (
                f"{parsed_page.scheme}://"
                f"{parsed_page.netloc}"
                f"{action}"
            )


        method = str(
            form.get("method")
            or "GET"
        ).upper()


        enctype = str(
            form.get("enctype")
            or ""
        )


        param_type = (
            "json"
            if "json" in enctype.lower()
            else "form"
        )


        for fld in form.get("fields", []) or []:

            name = (
                fld.get("name")
                or fld.get("id")
            )


            if not name:
                continue


            if not _looks_url_relevant(fld):
                continue


            key = (
                name,
                action,
                method,
                param_type
            )


            if key in seen:
                continue


            seen.add(key)


            points.append(
                InjectionPoint(
                    field=name,
                    location=action,
                    method=method,
                    param_type=param_type
                )
            )


            if debug:
                print(
                    f"[ssrf] form field: {name} -> {action}",
                    file=sys.stderr
                )


    if debug:
        print(
            f"[ssrf] total injection points: {len(points)}",
            file=sys.stderr
        )


    return points

# ---------------------------------------------------------------------------
# Entrypoint -- main.py's loader does getattr(module, addon_name), where
# addon_name is derived from this file's name ("ssrf.py" -> "ssrf"). So the
# function MUST be named exactly `ssrf` for addons["ssrf"](asset) to resolve.
# ---------------------------------------------------------------------------

_DEBUG = os.environ.get("SSRF_DEBUG", "1").lower() in ("1", "true", "yes")


def ssrf(asset: dict) -> dict:
    start_oob_listener()
    points = _extract_injection_points(asset, debug=_DEBUG)

    if not points:
        print("[ssrf] found 0 injection point(s) -- nothing to probe", file=sys.stderr)
        return build_report([])

    prober = SSRFProber(
        oob_client=_oob_client,
        http_send=_send_request,
        poll_wait_seconds=10.0,
        poll_interval_seconds=2.0,
    )

    findings = prober.run(points)

    # Print failed payloads
    tested_payloads = getattr(prober, "tested_payloads", [])

    successful_payloads = set()
    for finding in findings:
        if isinstance(finding, dict):
            payload = finding.get("payload")
            if payload:
                successful_payloads.add(payload)
        else:
            payload = getattr(finding, "payload", None)
            if payload:
                successful_payloads.add(payload)

    for payload in tested_payloads:
        if payload not in successful_payloads:
            print(f"FAILED PAYLOAD [{payload}]", file=sys.stderr)

    return build_report(findings)

# Aliases kept around for convenience if you call into this module directly
# (e.g. from a test script) -- main.py's loader only needs ssrf() above.
scan = ssrf
run = ssrf
analyze = ssrf
main = ssrf