"""
csrf_probe.py
-------------
Active CSRF probe built on top of parser.py.

Confirms CSRF vulnerabilities by actually submitting requests with missing,
blank, forged, and mismatched tokens, then inspecting server responses.
Only reports findings on *confirmed* or *strongly indicated* weaknesses.

Only use against systems you own or have explicit written permission to test.

Usage:
    from parser import parse
    from csrf_probe import probe, report

    asset    = parse("https://example.com")
    findings = probe(asset)
    report(findings)
"""

from __future__ import annotations

import textwrap
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from enum import Enum
from typing import Any
from urllib.parse import urlparse

import httpx


# ── Config ─────────────────────────────────────────────────────────────────────

TIMEOUT     = 15
MAX_WORKERS = 6
DELAY       = 0.0

# Forged origin used to test Origin/Referer validation
FORGED_ORIGIN  = "https://evil.example.com"
FORGED_REFERER = "https://evil.example.com/csrf"

# Status codes that suggest the server accepted the request
_SUCCESS_CODES: frozenset[int] = frozenset({200, 201, 202, 204, 301, 302, 303})

# Status codes that suggest the server rejected the request (good)
_REJECT_CODES: frozenset[int] = frozenset({400, 401, 403, 405, 419, 422})

# Substrings in response body that suggest a CSRF rejection
_REJECT_BODY_SIGNALS: tuple[str, ...] = (
    "csrf",
    "token",
    "invalid",
    "forbidden",
    "mismatch",
    "expired",
    "security",
    "verification failed",
    "bad request",
    "csrf token invalid",
    "invalid csrf token",
    "csrf verification failed",
    "token mismatch",
    "request forbidden",
    "403 forbidden",
)

# Substrings that suggest the request was *accepted* (bad — means no protection)
_ACCEPT_BODY_SIGNALS: tuple[str, ...] = (
    "success",
    "saved",
    "updated",
    "welcome",
    "logged in",
    "thank you",
    "submitted",
)

# CSRF token field name substrings
_TOKEN_NAMES: tuple[str, ...] = (
    "csrf", "xsrf", "_token", "authenticity_token",
    "csrf_token", "xsrf_token", "__requestverificationtoken",
    "csrfmiddlewaretoken", "nonce", "antiforgery",
)

# ── Verbose logging ───────────────────────────────────────────────────────────

VERBOSE = True

def log(message: str):
    if VERBOSE:
        print(f"[CSRF] {message}")
# ── Severity ───────────────────────────────────────────────────────────────────

class Severity(str, Enum):
    HIGH   = "HIGH"
    MEDIUM = "MEDIUM"
    LOW    = "LOW"
    INFO   = "INFO"


# ── Finding ────────────────────────────────────────────────────────────────────

@dataclass
class ProbeFinding:
    severity:   Severity
    check:      str      # what was tested
    location:   str      # form action URL
    method:     str
    detail:     str
    evidence:   str = "" # status code + body snippet


# ── Helpers ────────────────────────────────────────────────────────────────────

def _is_token_field(name: str) -> bool:
    n = name.lower()
    return any(t in n for t in _TOKEN_NAMES)

def _accepted(status: int, body: str) -> bool:
    if status in _REJECT_CODES:
        return False

    body_lower = body.lower()

    failure_words = (
        "invalid username",
        "invalid password",
        "login failed",
        "incorrect password",
    )

    if any(x in body_lower for x in failure_words):
        return False

    return status in _SUCCESS_CODES


def _evidence(resp: httpx.Response) -> str:
    body_snippet = resp.text[:200].replace("\n", " ").strip()
    return f"HTTP {resp.status_code} — {body_snippet}"


def _make_client(extra_headers: dict[str, str] | None = None) -> httpx.Client:
    headers = {
        "User-Agent": "Mozilla/5.0 (compatible; CSRFProbe/1.0)",
        "Accept":     "text/html,application/xhtml+xml,*/*;q=0.8",
    }
    if extra_headers:
        headers.update(extra_headers)
    return httpx.Client(
        follow_redirects=True,
        timeout=httpx.Timeout(connect=10.0, read=TIMEOUT, write=10.0, pool=5.0),
        headers=headers,
    )


def _build_baseline(fields: list[dict[str, Any]]) -> dict[str, str]:
    """Build a normal form submission payload from field defaults."""
    return {
        f["name"]: f.get("value", "test")
        for f in fields
        if f.get("name") and f.get("type", "").lower() not in {
            "submit", "button", "reset", "image", "file"
        }
    }


# ── Checks ─────────────────────────────────────────────────────────────────────

def _check_missing_token(
    action: str,
    method: str,
    fields: list[dict[str, Any]],
) -> list[ProbeFinding]:
    """Submit the form with the CSRF token field removed entirely."""
    findings: list[ProbeFinding] = []
    log(f"Checking missing CSRF token: {action}")
    token_fields = [f for f in fields if _is_token_field(f.get("name", ""))]
    if not token_fields:
        return findings  # no token to remove — passive scanner already flagged this

    data = _build_baseline(fields)
    for tf in token_fields:
        data.pop(tf["name"], None)

    try:
        with _make_client() as client:
            if DELAY:
                time.sleep(DELAY)
            resp = client.request(method, action, data=data)

        if _accepted(resp.status_code, resp.text):
            log(f"Possible CSRF bypass confirmed: token removed accepted")
            findings.append(ProbeFinding(
                severity=Severity.HIGH,
                check="Token Removed",
                location=action,
                method=method,
                detail=(
                    f"Form submitted without the CSRF token field(s) "
                    f"({', '.join(f['name'] for f in token_fields)}) and the "
                    "server returned an apparent success response. The token "
                    "is not being validated server-side."
                ),
                evidence=_evidence(resp),
            ))
    except httpx.RequestError:
        pass

    return findings


def _check_blank_token(
    action: str,
    method: str,
    fields: list[dict[str, Any]],
) -> list[ProbeFinding]:
    """Submit the form with the CSRF token set to an empty string."""
    findings: list[ProbeFinding] = []
    token_fields = [f for f in fields if _is_token_field(f.get("name", ""))]
    if not token_fields:
        return findings

    data = _build_baseline(fields)
    for tf in token_fields:
        data[tf["name"]] = ""

    try:
        with _make_client() as client:
            if DELAY:
                time.sleep(DELAY)
            resp = client.request(method, action, data=data)

        if _accepted(resp.status_code, resp.text):
            findings.append(ProbeFinding(
                severity=Severity.HIGH,
                check="Blank Token",
                location=action,
                method=method,
                detail=(
                    "Form submitted with the CSRF token set to an empty string "
                    "and the server returned an apparent success response. "
                    "The server accepts blank tokens."
                ),
                evidence=_evidence(resp),
            ))
    except httpx.RequestError:
        pass

    return findings


def _check_forged_token(
    action: str,
    method: str,
    fields: list[dict[str, Any]],
) -> list[ProbeFinding]:
    """Submit the form with a random forged token value."""
    findings: list[ProbeFinding] = []
    token_fields = [f for f in fields if _is_token_field(f.get("name", ""))]
    if not token_fields:
        return findings

    data = _build_baseline(fields)
    forged = "aaaaaaaabbbbbbbbccccccccdddddddd"   # fixed fake token
    for tf in token_fields:
        data[tf["name"]] = forged

    try:
        with _make_client() as client:
            if DELAY:
                time.sleep(DELAY)
            resp = client.request(method, action, data=data)

        if _accepted(resp.status_code, resp.text):
            findings.append(ProbeFinding(
                severity=Severity.HIGH,
                check="Forged Token",
                location=action,
                method=method,
                detail=(
                    f"Form submitted with a forged CSRF token ('{forged}') and "
                    "the server returned an apparent success response. "
                    "The server is not validating the token value."
                ),
                evidence=_evidence(resp),
            ))
    except httpx.RequestError:
        pass

    return findings


def _check_origin_header(
    action: str,
    method: str,
    fields: list[dict[str, Any]],
) -> list[ProbeFinding]:
    """Submit with a forged Origin header to test cross-origin validation."""
    findings: list[ProbeFinding] = []
    data = _build_baseline(fields)

    try:
        with _make_client({"Origin": FORGED_ORIGIN, "Referer": FORGED_REFERER}) as client:
            if DELAY:
                time.sleep(DELAY)
            resp = client.request(method, action, data=data)

        if _accepted(resp.status_code, resp.text):
            findings.append(ProbeFinding(
                severity=Severity.HIGH,
                check="Forged Origin/Referer",
                location=action,
                method=method,
                detail=(
                    f"Form submitted with Origin: {FORGED_ORIGIN} and "
                    f"Referer: {FORGED_REFERER} — the server accepted the "
                    "request without validating that it originated from the "
                    "expected domain."
                ),
                evidence=_evidence(resp),
            ))
    except httpx.RequestError:
        pass

    return findings


def _check_method_override(
    action: str,
    fields: list[dict[str, Any]],
) -> list[ProbeFinding]:
    """
    Some frameworks honour _method=GET or X-HTTP-Method-Override to bypass
    CSRF checks that only apply to POST.
    """
    findings: list[ProbeFinding] = []
    data = {**_build_baseline(fields), "_method": "POST"}

    try:
        with _make_client({"X-HTTP-Method-Override": "POST"}) as client:
            if DELAY:
                time.sleep(DELAY)
            # Send as GET with _method override
            resp = client.get(action, params=data)

        if _accepted(resp.status_code, resp.text):
            findings.append(ProbeFinding(
                severity=Severity.MEDIUM,
                check="Method Override",
                location=action,
                method="GET+_method=POST",
                detail=(
                    "A GET request with '_method=POST' and "
                    "'X-HTTP-Method-Override: POST' was accepted by the server. "
                    "If the CSRF check only applies to POST requests, this "
                    "override bypasses it entirely."
                ),
                evidence=_evidence(resp),
            ))
    except httpx.RequestError:
        pass

    return findings


def _check_content_type_bypass(
    action: str,
    method: str,
    fields: list[dict[str, Any]],
) -> list[ProbeFinding]:
    """
    Some CSRF defences only trigger on application/x-www-form-urlencoded.
    Sending as text/plain or application/json may bypass them.
    """
    findings: list[ProbeFinding] = []
    if method != "POST":
        return findings

    data = _build_baseline(fields)
    # Remove token fields — if ct bypass works, token is irrelevant
    for name in list(data.keys()):
        if _is_token_field(name):
            del data[name]

    body = "&".join(f"{k}={v}" for k, v in data.items())

    try:
        with _make_client({"Content-Type": "text/plain"}) as client:
            if DELAY:
                time.sleep(DELAY)
            resp = client.post(action, content=body)

        if _accepted(resp.status_code, resp.text):
            findings.append(ProbeFinding(
                severity=Severity.MEDIUM,
                check="Content-Type Bypass",
                location=action,
                method=method,
                detail=(
                    "Form submitted as 'Content-Type: text/plain' without a "
                    "CSRF token and the server accepted it. The CSRF defence "
                    "may only trigger on standard form content types."
                ),
                evidence=_evidence(resp),
            ))
    except httpx.RequestError:
        pass

    return findings


def _check_no_token_form(
    action: str,
    method: str,
    fields: list[dict[str, Any]],
) -> list[ProbeFinding]:
    """
    For forms that have NO token field at all, submit a plain request and
    confirm the server accepts it (confirming the passive finding).
    """
    log(f"Testing form without CSRF token: {action}")
    findings: list[ProbeFinding] = []
    token_fields = [f for f in fields if _is_token_field(f.get("name", ""))]
    if token_fields:
        return findings  # has a token — handled by other checks

    data = _build_baseline(fields)

    try:
        with _make_client() as client:
            if DELAY:
                time.sleep(DELAY)
            resp = client.request(method, action, data=data)

        if _accepted(resp.status_code, resp.text):
            findings.append(ProbeFinding(
                severity=Severity.HIGH,
                check="No Token — Request Accepted",
                location=action,
                method=method,
                detail=(
                    "This form has no CSRF token field and the server accepted "
                    "a plain cross-origin-style submission. Any attacker page "
                    "can trigger this action on behalf of a logged-in user."
                ),
                evidence=_evidence(resp),
            ))
    except httpx.RequestError:
        pass

    return findings


# ── Per-form orchestration ─────────────────────────────────────────────────────

def _probe_form(form: dict[str, Any]) -> list[ProbeFinding]:
    action = form.get("action", "")
    method = form.get("method", "GET").upper()
    fields = form.get("fields", [])

    log(f"Testing form: {action}")
    log(f"Method: {method}")
    log(f"Fields: {[f.get('name') for f in fields]}")

    if method not in {"POST", "GET"} or not action:
        return []

    # Only probe POST forms for CSRF (GET forms are lower risk)
    if method == "GET":
        return []

    findings: list[ProbeFinding] = []
    findings += _check_no_token_form(action, method, fields)
    findings += _check_missing_token(action, method, fields)
    findings += _check_blank_token(action, method, fields)
    findings += _check_forged_token(action, method, fields)
    findings += _check_origin_header(action, method, fields)
    findings += _check_method_override(action, fields)
    findings += _check_content_type_bypass(action, method, fields)
    return findings


# ── Public API ─────────────────────────────────────────────────────────────────

def probe(asset: dict[str, Any]) -> list[ProbeFinding]:
    """
    Actively probe all POST forms in *asset* for CSRF vulnerabilities.

    Parameters
    ----------
    asset:
        The dict returned by ``parser.parse()``.

    Returns
    -------
    list[ProbeFinding]
        Confirmed or strongly indicated CSRF findings.
    """
    forms = asset.get("forms", [])

    log(f"CSRF scan started")
    log(f"Forms discovered: {len(forms)}")
    findings: list[ProbeFinding] = []

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = {pool.submit(_probe_form, form): form for form in forms}
        for future in as_completed(futures):
            try:
                findings.extend(future.result())
                log(f"Findings collected: {len(findings)}")
            except Exception:
                pass

    _order = {Severity.HIGH: 0, Severity.MEDIUM: 1, Severity.LOW: 2, Severity.INFO: 3}
    findings.sort(key=lambda f: _order[f.severity])
    return findings


# ── Reporting ──────────────────────────────────────────────────────────────────

_SEP = "─" * 72

_SEVERITY_LABEL = {
    Severity.HIGH:   "[HIGH]  ",
    Severity.MEDIUM: "[MEDIUM]",
    Severity.LOW:    "[LOW]   ",
    Severity.INFO:   "[INFO]  ",
}


def report(findings: list[ProbeFinding], target: str = "") -> None:
    header = f"CSRF Probe Report — {target}" if target else "CSRF Probe Report"
    print(f"\n{_SEP}")
    print(f"  {header}")
    print(_SEP)

    if not findings:
        print("\n  ✓  No CSRF vulnerabilities confirmed.\n")
        print(_SEP + "\n")
        return

    print(f"\n  {len(findings)} confirmed finding(s)\n")

    for i, f in enumerate(findings, 1):
        label = _SEVERITY_LABEL[f.severity]
        print(f"  {label}  [{i}/{len(findings)}] {f.check}")
        print(f"  Location    : {f.location}")
        print(f"  Method      : {f.method}")
        print("  Detail      :")
        for line in textwrap.wrap(f.detail, width=66):
            print(f"                {line}")
        if f.evidence:
            print(f"  Evidence    : {f.evidence[:120]}")
        print()

    print(_SEP + "\n")


# ── Convenience entry point ────────────────────────────────────────────────────
def _extract_status(evidence: str) -> int | None:
    try:
        return int(evidence.split()[1])
    except Exception:
        return None
def csrf(asset: dict) -> dict[str, Any]:
    findings = probe(asset)

    return {
        "findings": [
            {
                "source": {
                    "field_name": f.check,
                    "url": f.location,
                    "method": f.method,
                },
                "payload": f.detail,
                "triggered_by": [
                    f.check
                ],
                "status_code": _extract_status(f.evidence),
            }
            for f in findings
        ]
    }
