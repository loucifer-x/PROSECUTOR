"""
headers.py
----------
HTTP Security Header scanner — matches the finding schema used by sqli.py.

Each finding looks like:
    {
        "payload": None,
        "triggered_by": ["missing_header", ...],
        "status_code": <int>,
        "elapsed": 0.0,
        "source": {
            "type": "header",
            "field_name": "Content-Security-Policy",
        },
    }

Usage:
    findings = headers(asset)
"""

import requests
import urllib3
from typing import Any

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}


# ---------------------------------------------------------------------------
# Finding builder — matches sqli.py's schema
# ---------------------------------------------------------------------------

def _finding(field_name: str, severity: str, reason: str, status_code: int) -> dict[str, Any]:
    return {
        "payload": None,
        "triggered_by": [f"{severity.lower()}: {reason}"],
        "status_code": status_code,
        "elapsed": 0.0,
        "source": {
            "type": "header",
            "field_name": field_name,
        },
        # kept for convenience / readability in reports, not used by main.py
        "severity": severity,
        "message": reason,
    }


# ---------------------------------------------------------------------------
# Individual header checks
# Each returns a list of finding dicts (possibly empty)
# ---------------------------------------------------------------------------

def check_strict_transport_security(value, status_code):
    findings = []
    field = "Strict-Transport-Security"

    if value is None:
        return [_finding(field, "HIGH", "Missing Strict-Transport-Security header", status_code)]

    if "max-age" not in value.lower():
        return [_finding(field, "HIGH", "HSTS has no max-age", status_code)]

    try:
        max_age = int(value.lower().split("max-age=")[1].split(";")[0].strip())
    except (IndexError, ValueError):
        return [_finding(field, "HIGH", "HSTS max-age value is malformed", status_code)]

    if max_age < 31536000:
        findings.append(_finding(field, "MEDIUM", f"HSTS max-age too short: {max_age} (minimum 31536000)", status_code))

    if "includesubdomains" not in value.lower():
        findings.append(_finding(field, "LOW", "HSTS missing includeSubDomains", status_code))

    if "preload" not in value.lower():
        findings.append(_finding(field, "INFO", "HSTS missing preload", status_code))

    return findings


def check_content_security_policy(value, status_code):
    findings = []
    field = "Content-Security-Policy"

    if value is None:
        return [_finding(field, "HIGH", "Missing Content-Security-Policy header", status_code)]

    if "default-src" not in value:
        findings.append(_finding(field, "HIGH", "CSP has no default-src directive", status_code))

    if "* " in value or value.strip().endswith("*"):
        findings.append(_finding(field, "HIGH", "CSP uses wildcard * — too permissive", status_code))

    if "unsafe-inline" in value:
        findings.append(_finding(field, "HIGH", "CSP allows unsafe-inline — XSS risk", status_code))

    if "unsafe-eval" in value:
        findings.append(_finding(field, "MEDIUM", "CSP allows unsafe-eval — code injection risk", status_code))

    if "http:" in value:
        findings.append(_finding(field, "MEDIUM", "CSP allows http: — insecure resources permitted", status_code))

    return findings


def check_x_frame_options(value, status_code):
    field = "X-Frame-Options"
    if value is None:
        return [_finding(field, "HIGH", "Missing X-Frame-Options header", status_code)]
    if value.upper() not in ("DENY", "SAMEORIGIN"):
        return [_finding(field, "HIGH", f"X-Frame-Options has invalid value: {value}", status_code)]
    return []


def check_x_content_type_options(value, status_code):
    field = "X-Content-Type-Options"
    if value is None:
        return [_finding(field, "MEDIUM", "Missing X-Content-Type-Options header", status_code)]
    if value.lower() != "nosniff":
        return [_finding(field, "MEDIUM", f"X-Content-Type-Options has invalid value: {value}", status_code)]
    return []


def check_referrer_policy(value, status_code):
    field = "Referrer-Policy"
    if value is None:
        return [_finding(field, "LOW", "Missing Referrer-Policy header", status_code)]

    weak_values = ("unsafe-url", "no-referrer-when-downgrade")
    if value.lower() in weak_values:
        return [_finding(field, "MEDIUM", f"Referrer-Policy is too permissive: {value}", status_code)]
    return []


def check_permissions_policy(value, status_code):
    findings = []
    field = "Permissions-Policy"

    if value is None:
        return [_finding(field, "LOW", "Missing Permissions-Policy header", status_code)]

    sensitive = ("camera", "microphone", "geolocation")
    for api in sensitive:
        if api not in value.lower():
            findings.append(_finding(field, "LOW", f"Permissions-Policy does not restrict: {api}", status_code))
    return findings


def check_x_xss_protection(value, status_code):
    field = "X-XSS-Protection"
    if value is None:
        return [_finding(field, "LOW", "Missing X-XSS-Protection header", status_code)]

    if value.strip() == "0":
        return [_finding(field, "MEDIUM", "X-XSS-Protection is disabled (value: 0)", status_code)]

    if "mode=block" not in value.lower():
        return [_finding(field, "LOW", "X-XSS-Protection should include mode=block", status_code)]
    return []


def check_cache_control(value, status_code):
    findings = []
    field = "Cache-Control"

    if value is None:
        return [_finding(field, "LOW", "Missing Cache-Control header", status_code)]

    if "no-store" not in value.lower():
        findings.append(_finding(field, "MEDIUM", "Cache-Control missing no-store — page may be cached", status_code))

    if "no-cache" not in value.lower():
        findings.append(_finding(field, "LOW", "Cache-Control missing no-cache", status_code))
    return findings


def check_server(value, status_code):
    field = "Server"
    if value is None:
        return []
    if any(char.isdigit() for char in value):
        return [_finding(field, "LOW", f"Server header reveals version info: {value}", status_code)]
    return [_finding(field, "INFO", f"Server header present (no version): {value}", status_code)]


def check_x_powered_by(value, status_code):
    field = "X-Powered-By"
    if value is None:
        return []
    return [_finding(field, "LOW", f"X-Powered-By header present — remove it: {value}", status_code)]


def check_access_control_allow_origin(value, status_code):
    field = "Access-Control-Allow-Origin"
    if value is None:
        return []
    if value.strip() == "*":
        return [_finding(field, "MEDIUM", "CORS allows any origin (*) — verify this is intentional", status_code)]
    return []


def check_cross_origin_opener_policy(value, status_code):
    field = "Cross-Origin-Opener-Policy"
    if value is None:
        return [_finding(field, "LOW", "Missing Cross-Origin-Opener-Policy header", status_code)]
    if value.lower() not in ("same-origin", "same-origin-allow-popups"):
        return [_finding(field, "LOW", f"Cross-Origin-Opener-Policy has weak value: {value}", status_code)]
    return []


def check_cross_origin_resource_policy(value, status_code):
    field = "Cross-Origin-Resource-Policy"
    if value is None:
        return [_finding(field, "LOW", "Missing Cross-Origin-Resource-Policy header", status_code)]
    return []


def check_set_cookie(value, status_code):
    """value can be a single string or a list of cookie strings."""
    findings = []
    field = "Set-Cookie"
    if value is None:
        return findings

    cookies = value if isinstance(value, list) else [value]
    for cookie in cookies:
        name = cookie.split("=")[0].strip()
        lc = cookie.lower()
        if "secure" not in lc:
            findings.append(_finding(field, "MEDIUM", f"Cookie '{name}' missing Secure flag", status_code))
        if "httponly" not in lc:
            findings.append(_finding(field, "MEDIUM", f"Cookie '{name}' missing HttpOnly flag", status_code))
        if "samesite" not in lc:
            findings.append(_finding(field, "LOW", f"Cookie '{name}' missing SameSite attribute", status_code))
    return findings


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def headers(asset: dict) -> dict[str, Any]:
    response = asset["response"]
    raw_headers = response["headers"]
    status_code = response.get("status_code", 0)
    url = asset["target"]["final_url"]

    # Normalize header keys to lowercase for case-insensitive lookups,
    # since servers/proxies don't always preserve canonical casing.
    #
    # IMPORTANT: this must work for plain dicts AND mapping-like objects
    # such as requests.structures.CaseInsensitiveDict (which is what
    # response.headers actually is when using the `requests` library).
    # CaseInsensitiveDict is NOT a subclass of dict, so a previous
    # `isinstance(raw_headers, dict)` check would always be False for it,
    # fall into an `else` branch that iterated the object directly
    # (yielding keys only, not (key, value) pairs), and silently produce
    # an empty/garbage `normalized` dict — causing every header to be
    # reported as "missing" even when it was present. Checking for an
    # `.items()` method instead handles dict, CaseInsensitiveDict, and
    # any other standard mapping correctly.
    if hasattr(raw_headers, "items"):
        normalized = {k.lower(): v for k, v in raw_headers.items()}
    else:
        normalized = {k.lower(): v for k, v in raw_headers}

    print(f"\n========== HEADERS SCAN START ==========")
    print(f"Target  : {url}")
    print(f"Status  : {status_code}")
    print(f"==========================================\n")

    findings: list[dict] = []
    findings += check_strict_transport_security(normalized.get("strict-transport-security"), status_code)
    findings += check_content_security_policy(normalized.get("content-security-policy"), status_code)
    findings += check_x_frame_options(normalized.get("x-frame-options"), status_code)
    findings += check_x_content_type_options(normalized.get("x-content-type-options"), status_code)
    findings += check_referrer_policy(normalized.get("referrer-policy"), status_code)
    findings += check_permissions_policy(normalized.get("permissions-policy"), status_code)
    findings += check_x_xss_protection(normalized.get("x-xss-protection"), status_code)
    findings += check_cache_control(normalized.get("cache-control"), status_code)
    findings += check_server(normalized.get("server"), status_code)
    findings += check_x_powered_by(normalized.get("x-powered-by"), status_code)
    findings += check_access_control_allow_origin(normalized.get("access-control-allow-origin"), status_code)
    findings += check_cross_origin_opener_policy(normalized.get("cross-origin-opener-policy"), status_code)
    findings += check_cross_origin_resource_policy(normalized.get("cross-origin-resource-policy"), status_code)
    findings += check_set_cookie(normalized.get("set-cookie"), status_code)

    # Sort by severity so the worst issues are listed first
    findings.sort(key=lambda f: SEVERITY_ORDER.get(f.get("severity", "INFO"), 99))

    for f in findings:
        field = f["source"]["field_name"]
        print(f"[{f['severity']}] {field}: {f['message']}")

    print(f"\n========== HEADERS SCAN COMPLETE ==========")
    print(f"Hits    : {len(findings)}")
    print(f"=============================================\n")
    print(f"DEBUG raw_headers type: {type(raw_headers)!r}, sample: {raw_headers!r}")
    return {
        "name": "headers",
        "target": url,
        "findings": findings,
        "probed": len(findings),
    }


# ---------------------------------------------------------------------------
# Optional standalone runner — scan a live URL directly
# ---------------------------------------------------------------------------

def scan_url(url: str, timeout: int = 10) -> dict[str, Any]:
    """Convenience helper: fetch a URL and run the header scan on it."""
    resp = requests.get(url, timeout=timeout, verify=False, allow_redirects=True)
    asset = {
        "response": {
            "headers": dict(resp.headers),
            "status_code": resp.status_code,
        },
        "target": {"final_url": resp.url},
    }
    return headers(asset)


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python headers.py <url>")
        sys.exit(1)
    scan_url(sys.argv[1])
