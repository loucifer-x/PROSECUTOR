"""
parser_spa.py
-------------
SPA (Single Page Application) parser for the web audit toolkit.

Drops in alongside parser.py and returns the IDENTICAL asset schema,
so every extension (sqli, xss, headers, etc.) works unchanged.

The difference: instead of fetching raw HTML with httpx, this module
launches a real Chromium browser via Playwright, waits for JavaScript
to finish rendering, then extracts from the fully-built DOM.

Use this for:
    React, Angular, Vue, Svelte, Ember apps
    Any URL with a # hash route  (e.g. /#/login)
    Pages that show blank forms until JS runs

Use parser.py for:
    Server-rendered HTML  (PHP, JSP, Django, Rails)
    Pages that work without JavaScript

Install:
    pip install playwright
    playwright install chromium

Usage:
    from parser_spa import parse_spa

    asset = parse_spa("https://juice-shop.herokuapp.com/#/login")
    # identical schema to parse() — plug straight into sqli.scan(asset)
"""

from __future__ import annotations

import time
from typing import Any
from urllib.parse import (
    ParseResult,
    parse_qs,
    urljoin,
    urlparse,
    urlunparse,
)

from bs4 import BeautifulSoup, Tag
from playwright.sync_api import sync_playwright, Page, Response as PlaywrightResponse


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def parse_spa(
    url: str,
    wait_for: str = "networkidle",
    timeout: int = 30_000,
    wait_for_selector: str | None = None,
) -> dict[str, Any]:
    """
    Launch a headless browser, render *url*, and return a normalized asset dict.

    Parameters
    ----------
    url:
        Target URL — hash routes like ``/#/login`` are fully supported.
    wait_for:
        Playwright load state to wait for before extracting.
        ``"networkidle"`` — no network requests for 500ms (default, safest).
        ``"domcontentloaded"`` — faster but JS may not have rendered yet.
        ``"load"`` — page load event fired.
    timeout:
        Max milliseconds to wait for the page to load (default 30s).
    wait_for_selector:
        Optional CSS selector to wait for before extracting
        e.g. ``"form"`` or ``"input[type='email']"``.
        Useful when networkidle fires before a specific component mounts.

    Returns
    -------
    dict
        Identical schema to ``parser.parse()`` — compatible with all extensions.
    """
    normalized_url = _normalize_url(url)

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(
            user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            ),
            viewport={"width": 1280, "height": 800},
        )

        page = context.new_page()
        discovered_urls = []

        def _capture_request(request):
            url = request.url

            if request.resource_type in (
                "xhr",
                "fetch",
                "document",
                "script"
            ):
                discovered_urls.append({
                    "url": url,
                    "type": request.resource_type,
                    "method": request.method
                })


        page.on("request", _capture_request)

        # collect HTTP response metadata from the initial navigation
        captured: dict[str, Any] = {
            "status_code":      0,
            "headers":          {},
            "content_type":     "",
            "redirect_history": [],
        }

        def _on_response(response: PlaywrightResponse) -> None:
            # capture only the primary document response
            if response.request.resource_type == "document":
                if captured["status_code"] == 0:
                    captured["status_code"] = response.status
                    captured["headers"]     = dict(response.headers)
                    captured["content_type"] = response.headers.get("content-type", "")
                else:
                    # track redirects
                    captured["redirect_history"].append({
                        "url":         response.url,
                        "status_code": response.status,
                    })

        page.on("response", _on_response)

        # navigate and wait for JS to finish
        start = time.perf_counter()
        page.goto(normalized_url, wait_until=wait_for, timeout=timeout)

        if wait_for_selector:
            try:
                page.wait_for_selector(
                    wait_for_selector,
                    timeout=timeout,
                    state="attached",
                )
            except Exception:
                pass  # selector never appeared — extract whatever rendered

        elapsed  = time.perf_counter() - start
        final_url = page.url
        html      = page.content()       # fully rendered DOM
        url_candidates = page.evaluate("""
        () => {
            let urls = [];

            document.querySelectorAll("*").forEach(e => {
                for (let attr of e.attributes) {
                    if (
                        attr.name.includes("url") ||
                        attr.name.includes("src") ||
                        attr.name.includes("href") ||
                        attr.name.includes("action")
                    ) {
                        urls.push({
                            attribute: attr.name,
                            value: attr.value
                        });
                    }
                }
            });

            return urls;
        }
        """)
        script_urls = []
        for script in page.locator("script").all():
            src = script.get_attribute("src")
            if src:
                script_urls.append(
                    _resolve_url(src, final_url)
                )
        cookies   = context.cookies()    # browser cookie jar

        browser.close()
        print(discovered_urls)

    soup = BeautifulSoup(html, "html.parser")

    return {
        "target":       _build_target(normalized_url, final_url),
        "response":     _build_response(captured, elapsed, cookies, html),
        "page":         _build_page(soup),
        "links":        _extract_links(soup, final_url),
        "forms":        _extract_forms(soup, final_url),
        "inputs":       _extract_loose_inputs(soup),
        "scripts":      _extract_scripts(soup, final_url),
        "resources":    _extract_resources(soup, final_url),
        "parameters":   _extract_url_parameters(final_url),
        "technologies": _collect_technology_indicators(soup, captured, cookies),
        "discovered_urls": discovered_urls,
        "javascript_files": script_urls,
        "url_candidates": url_candidates,
    }


# ---------------------------------------------------------------------------
# Section builders
# ---------------------------------------------------------------------------

def _build_target(original_url: str, final_url: str) -> dict[str, str]:
    parsed: ParseResult = urlparse(final_url)
    return {
        "url":       original_url,
        "final_url": final_url,
        "domain":    parsed.netloc,
        "path":      parsed.path or "/",
    }


def _build_response(
    captured: dict[str, Any],
    elapsed: float,
    cookies: list[dict],
    html: str,
) -> dict[str, Any]:
    normalised_cookies: list[dict[str, Any]] = [
        {
            "name":      c.get("name", ""),
            "value":     c.get("value", ""),
            "domain":    c.get("domain", ""),
            "path":      c.get("path", "/"),
            "secure":    c.get("secure", False),
            "http_only": c.get("httpOnly", False),
            "same_site": c.get("sameSite", None),
            "expires":   c.get("expires", None),
        }
        for c in cookies
    ]

    return {
        "status_code":      captured["status_code"],
        "content_type":     captured["content_type"],
        "content_length":   len(html.encode("utf-8")),
        "response_time":    round(elapsed, 4),
        "headers":          captured["headers"],
        "cookies":          normalised_cookies,
        "redirect_history": captured["redirect_history"],
    }


def _build_page(soup: BeautifulSoup) -> dict[str, Any]:
    return {
        "title":    _extract_title(soup),
        "meta":     _extract_meta(soup),
        "language": _extract_language(soup),
    }


# ---------------------------------------------------------------------------
# HTML extraction  (mirrors parser.py exactly)
# ---------------------------------------------------------------------------

def _extract_title(soup: BeautifulSoup) -> str:
    tag = soup.find("title")
    return tag.get_text(strip=True) if tag else ""


def _extract_language(soup: BeautifulSoup) -> str:
    html_tag = soup.find("html")
    if isinstance(html_tag, Tag):
        return html_tag.get("lang", "") or ""  # type: ignore[return-value]
    return ""


def _extract_meta(soup: BeautifulSoup) -> dict[str, str]:
    meta: dict[str, str] = {}
    for tag in soup.find_all("meta"):
        if not isinstance(tag, Tag):
            continue
        key   = tag.get("name") or tag.get("property") or tag.get("http-equiv") or ""
        value = tag.get("content") or tag.get("charset") or ""
        if key and value:
            meta[str(key).lower()] = str(value)
    return meta


def _extract_links(soup: BeautifulSoup, base_url: str) -> list[dict[str, Any]]:
    base_domain = urlparse(base_url).netloc
    links: list[dict[str, Any]] = []

    for tag in soup.find_all("a", href=True):
        if not isinstance(tag, Tag):
            continue
        raw_href: str = str(tag["href"]).strip()
        if not raw_href or raw_href.startswith(("#", "mailto:", "javascript:", "tel:")):
            continue

        abs_url  = _resolve_url(raw_href, base_url)
        parsed   = urlparse(abs_url)
        internal = parsed.netloc == base_domain
        params   = _parse_query_parameters(parsed.query)

        links.append({
            "url":        abs_url,
            "text":       tag.get_text(strip=True),
            "internal":   internal,
            "parameters": params,
        })

    return links


def _extract_forms(soup: BeautifulSoup, base_url: str) -> list[dict[str, Any]]:
    forms: list[dict[str, Any]] = []

    for form in soup.find_all("form"):
        if not isinstance(form, Tag):
            continue

        raw_action: str = str(form.get("action") or "").strip()
        action_url = _resolve_url(raw_action, base_url) if raw_action else base_url
        method     = str(form.get("method") or "get").upper()
        enctype    = str(form.get("enctype") or "application/x-www-form-urlencoded")

        fields: list[dict[str, Any]] = []
        for el in form.find_all(["input", "select", "textarea", "button"]):
            if not isinstance(el, Tag):
                continue
            fields.append(_normalise_field(el))

        forms.append({
            "action":  action_url,
            "method":  method,
            "enctype": enctype,
            "fields":  fields,
        })

    return forms


def _normalise_field(el: Tag) -> dict[str, Any]:
    return {
        "name":     str(el.get("name") or ""),
        "type":     str(el.get("type") or el.name or ""),
        "id":       str(el.get("id") or ""),
        "value":    str(el.get("value") or ""),
        "required": el.has_attr("required"),
    }


def _extract_loose_inputs(soup: BeautifulSoup) -> list[dict[str, Any]]:
    loose: list[dict[str, Any]] = []
    for el in soup.find_all(["input", "select", "textarea"]):
        if not isinstance(el, Tag):
            continue
        if not el.find_parent("form"):
            loose.append(_normalise_field(el))
    return loose


def _extract_scripts(soup: BeautifulSoup, base_url: str) -> list[dict[str, Any]]:
    scripts: list[dict[str, Any]] = []

    for tag in soup.find_all("script"):
        if not isinstance(tag, Tag):
            continue
        src: str = str(tag.get("src") or "").strip()

        if src:
            abs_src  = _resolve_url(src, base_url)
            filename = abs_src.rstrip("/").split("/")[-1].split("?")[0]
            scripts.append({
                "type":     "external",
                "src":      src,
                "url":      abs_src,
                "filename": filename,
            })
        else:
            content = tag.get_text()
            scripts.append({
                "type":    "inline",
                "length":  len(content),
                "content": content,
            })

    return scripts


def _extract_resources(soup: BeautifulSoup, base_url: str) -> list[dict[str, Any]]:
    resources: list[dict[str, Any]] = []

    for tag in soup.find_all("img", src=True):
        if not isinstance(tag, Tag):
            continue
        resources.append({
            "type": "image",
            "url":  _resolve_url(str(tag["src"]), base_url),
            "alt":  str(tag.get("alt") or ""),
        })

    for tag in soup.find_all("iframe", src=True):
        if not isinstance(tag, Tag):
            continue
        resources.append({
            "type": "iframe",
            "url":  _resolve_url(str(tag["src"]), base_url),
        })

    for tag in soup.find_all("link", href=True):
        if not isinstance(tag, Tag):
            continue
        resources.append({
            "type": str(tag.get("rel", ["link"])[0]),
            "url":  _resolve_url(str(tag["href"]), base_url),
        })

    return resources


# ---------------------------------------------------------------------------
# Parameter extraction
# ---------------------------------------------------------------------------

def _extract_url_parameters(url: str) -> list[dict[str, str]]:
    return _parse_query_parameters(urlparse(url).query)


def _parse_query_parameters(query: str) -> list[dict[str, str]]:
    params: list[dict[str, str]] = []
    for name, values in parse_qs(query, keep_blank_values=True).items():
        for value in values:
            params.append({"name": name, "value": value})
    return params


# ---------------------------------------------------------------------------
# Technology indicator collection
# ---------------------------------------------------------------------------

def _collect_technology_indicators(
    soup: BeautifulSoup,
    captured: dict[str, Any],
    cookies: list[dict],
) -> list[dict[str, str]]:
    indicators: list[dict[str, str]] = []

    # meta generator
    generator = soup.find("meta", attrs={"name": "generator"})
    if isinstance(generator, Tag):
        content = str(generator.get("content") or "").strip()
        if content:
            indicators.append({"indicator": content, "source": "html"})

    # script filenames
    for tag in soup.find_all("script", src=True):
        if not isinstance(tag, Tag):
            continue
        src      = str(tag["src"])
        filename = src.rstrip("/").split("/")[-1].split("?")[0]
        if filename:
            indicators.append({"indicator": filename, "source": "script"})

    # cookie names
    for cookie in cookies:
        name = cookie.get("name", "")
        if name:
            indicators.append({"indicator": name, "source": "cookie"})

    # response headers that hint at technology
    server = captured["headers"].get("server", "")
    if server:
        indicators.append({"indicator": server, "source": "html"})

    x_powered = captured["headers"].get("x-powered-by", "")
    if x_powered:
        indicators.append({"indicator": x_powered, "source": "html"})

    return indicators


# ---------------------------------------------------------------------------
# URL utilities
# ---------------------------------------------------------------------------

def _normalize_url(url: str) -> str:
    url = url.strip()

    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    return url


def _resolve_url(href: str, base_url: str) -> str:
    return urljoin(base_url, href)