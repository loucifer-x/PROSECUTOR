import urllib.parse
from collections import deque
import requests
import urllib3

try:
    from bs4 import BeautifulSoup
except ImportError:
    print("[!] Missing dependency: pip install beautifulsoup4")
    exit(1)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico",
    ".pdf", ".zip", ".gz", ".tar", ".rar", ".7z",
    ".mp4", ".mp3", ".avi", ".mov", ".woff", ".woff2", ".ttf",
    ".css", ".js", ".map",
}


def get_base_domain(url):
    host = urllib.parse.urlparse(url).netloc.split(":")[0]
    parts = host.split(".")
    return ".".join(parts[-2:])


def is_allowed(url, base_domain):
    host = urllib.parse.urlparse(url).netloc.split(":")[0]
    return host == base_domain or host.endswith("." + base_domain)


def normalise(url):
    """
    Canonical form for deduplication:
    - strip fragment
    - sort query parameters
    - strip trailing slash from path (unless it's the root)
    """
    p = urllib.parse.urlparse(url)
    sorted_qs = urllib.parse.urlencode(
        sorted(urllib.parse.parse_qsl(p.query))
    )
    path = p.path.rstrip("/") or "/"
    return urllib.parse.urlunparse((
        p.scheme, p.netloc, path, p.params, sorted_qs, ""
    ))


def is_asset(url):
    path = urllib.parse.urlparse(url).path.lower()
    return any(path.endswith(ext) for ext in SKIP_EXTENSIONS)


def extract_urls(base_url, soup):
    """Pull links from <a href> and form action attributes."""
    urls = set()

    for tag in soup.find_all("a", href=True):
        # Respect nofollow
        rel = tag.get("rel", [])
        if "nofollow" in rel:
            continue
        href = tag["href"].strip()
        if href.startswith(("#", "mailto:", "javascript:", "tel:")):
            continue
        absolute = urllib.parse.urljoin(base_url, href).split("#")[0]
        if absolute:
            urls.add(absolute)

    for form in soup.find_all("form", action=True):
        action = form["action"].strip()
        if action.startswith(("#", "javascript:")):
            continue
        absolute = urllib.parse.urljoin(base_url, action).split("#")[0]
        if absolute:
            urls.add(absolute)

    return urls


def crawl(start_url, max_pages=3):
    session = requests.Session()
    session.headers.update({"User-Agent": "Perscrutator/1.0 (crawler)"})

    base_domain = get_base_domain(start_url)
    queue       = deque([start_url])
    visited     = set()   # normalised URLs
    discovered  = []      # raw URLs in crawl order

    print(f"\n[*] Crawling: {start_url}")
    print(f"    Domain   : {base_domain} (+ subdomains)")
    print(f"    Max pages: {max_pages}\n")

    while queue and len(visited) < max_pages:
        url  = queue.popleft()
        norm = normalise(url)

        if norm in visited:
            continue
        if is_asset(url):
            continue

        visited.add(norm)

        try:
            resp = session.get(url, timeout=10, verify=False, allow_redirects=True)
        except requests.RequestException as e:
            print(f"  [ERROR] {url} — {e}")
            continue

        if "text/html" not in resp.headers.get("Content-Type", ""):
            continue

        # Respect meta robots noindex (skip adding children, but still report page)
        soup = BeautifulSoup(resp.text, "html.parser")
        meta_robots = soup.find("meta", attrs={"name": "robots"})
        nofollow    = False
        if meta_robots:
            content = meta_robots.get("content", "").lower()
            nofollow = "nofollow" in content

        print(f"  [+] {url} ({resp.status_code})")
        discovered.append(url)

        if not nofollow:
            for link in extract_urls(url, soup):
                if normalise(link) not in visited and is_allowed(link, base_domain):
                    queue.append(link)

    print(f"\n[*] Crawl complete — {len(discovered)} pages found\n")
    return discovered