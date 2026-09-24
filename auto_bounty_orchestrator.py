#!/usr/bin/env python3
"""
auto_bounty_orchestrator.py

Passive recon building blocks used by watchlist_scheduler.py.
Real implementations based on `requests` (passive HTTP fetches only —
no active scanning, no payloads):
  - PassiveRecon: robots.txt, sitemap.xml, TLS certificate info, and a
    polite same-domain crawl that records passive findings.
  - triage_findings: severity mapping for the collected findings.
  - build_markdown_report: renders findings as a Markdown report.

Added during the wave-1 fix campaign (2026-09-24): this module was imported
by watchlist_scheduler.py but did not exist anywhere in the repo.
"""
import logging
import re
import socket
import ssl
import time
from datetime import datetime
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

log = logging.getLogger(__name__)

USER_AGENT = "WatchlistRecon/1.0 (passive security monitoring)"
DEFAULT_TIMEOUT = 15


class PassiveRecon:
    """Passive recon for a single target URL."""

    def __init__(self, url, max_pages=30, rate_limit=1.0):
        self.base_url = url.rstrip("/")
        parsed = urlparse(self.base_url)
        self.host = parsed.netloc
        self.scheme = parsed.scheme or "https"
        self.max_pages = max_pages
        self.rate_limit = rate_limit
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": USER_AGENT})
        self.visited = []
        self.findings = []

    # -- helpers ---------------------------------------------------------
    def _get(self, url):
        time.sleep(self.rate_limit)
        r = self.session.get(url, timeout=DEFAULT_TIMEOUT, allow_redirects=True)
        return r

    def _add_finding(self, kind, severity, title, detail, evidence=""):
        self.findings.append({
            "kind": kind,
            "severity": severity,
            "title": title,
            "detail": detail,
            "evidence": evidence,
            "timestamp": datetime.utcnow().isoformat(),
        })

    # -- passive collection ----------------------------------------------
    def fetch_robots(self):
        """Fetch /robots.txt and note interesting disallowed paths."""
        url = f"{self.scheme}://{self.host}/robots.txt"
        try:
            r = self._get(url)
            if r.status_code == 200 and r.text.strip():
                interesting = [ln for ln in r.text.splitlines()
                               if re.match(r"(?i)^disallow:", ln.strip())
                               and any(k in ln.lower() for k in
                                        ("admin", "backup", "config", "db", "internal",
                                         "private", "secret", "staging", ".git", ".env"))]
                self._add_finding("robots", "info",
                                  "robots.txt retrieved",
                                  f"{len(interesting)} interesting disallowed path(s)",
                                  "\n".join(interesting)[:1000])
                return r.text
        except requests.RequestException as e:
            log.warning("robots.txt fetch failed for %s: %s", self.host, e)
        return ""

    def fetch_sitemap(self):
        """Fetch /sitemap.xml and count listed URLs."""
        url = f"{self.scheme}://{self.host}/sitemap.xml"
        try:
            r = self._get(url)
            if r.status_code == 200 and "<url" in r.text:
                urls = re.findall(r"<loc>(.*?)</loc>", r.text)
                self._add_finding("sitemap", "info",
                                  "sitemap.xml retrieved",
                                  f"{len(urls)} URL(s) enumerated passively")
                return urls
        except requests.RequestException as e:
            log.warning("sitemap fetch failed for %s: %s", self.host, e)
        return []

    def get_tls_info(self):
        """Read the TLS certificate (handshake only, no requests sent)."""
        info = {}
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((self.host, 443), timeout=DEFAULT_TIMEOUT) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.host) as ssock:
                    cert = ssock.getpeercert()
                    info = {
                        "subject": dict(x[0] for x in cert.get("subject", ())),
                        "issuer": dict(x[0] for x in cert.get("issuer", ())),
                        "notAfter": cert.get("notAfter"),
                        "version": ssock.version(),
                    }
            self._add_finding("tls", "info", "TLS certificate read",
                              f"issuer={info['issuer'].get('organizationName', '?')} "
                              f"expires={info['notAfter']}")
        except (socket.error, ssl.SSLError, OSError) as e:
            self._add_finding("tls", "low", "TLS check failed", str(e))
            log.warning("TLS info failed for %s: %s", self.host, e)
        return info

    def crawl(self):
        """Polite same-domain crawl; records passive findings per page."""
        queue = [self.base_url]
        seen = set()
        while queue and len(self.visited) < self.max_pages:
            url = queue.pop(0)
            if url in seen:
                continue
            seen.add(url)
            try:
                r = self._get(url)
            except requests.RequestException as e:
                log.warning("crawl fetch failed %s: %s", url, e)
                continue
            self.visited.append(url)
            ctype = r.headers.get("Content-Type", "")
            if "text/html" not in ctype:
                continue
            soup = BeautifulSoup(r.text, "html.parser")

            # Exposed server/version headers (passive observation)
            server = r.headers.get("Server", "")
            if server:
                self._add_finding("headers", "low", "Server header exposed",
                                  f"{url} advertises Server: {server}", server)

            # HTML comments that look like leftovers
            comments = re.findall(r"<!--(.*?)-->", r.text, re.S)
            juicy = [c.strip()[:200] for c in comments
                     if re.search(r"(todo|fixme|debug|password|secret|key|admin)", c, re.I)]
            if juicy:
                self._add_finding("comments", "low", "Interesting HTML comments",
                                  f"{len(juicy)} match(es) on {url}", "\n".join(juicy)[:1000])

            # Same-domain links to keep crawling
            for a in soup.find_all("a", href=True):
                nxt = urljoin(url, a["href"]).split("#")[0]
                p = urlparse(nxt)
                if p.netloc == self.host and p.scheme in ("http", "https") \
                        and nxt not in seen and nxt not in queue:
                    queue.append(nxt)
        return self.visited


def triage_findings(findings):
    """Map raw findings to triaged severities (info/low/medium/high)."""
    triaged = []
    for f in findings:
        sev = f.get("severity", "info")
        title = f.get("title", "")
        # Escalate a couple of well-known weak signals
        if f.get("kind") == "headers" and re.search(r"(apache/2\.[0-2]|nginx/1\.[0-9]\.|iis/6|php/5)", f.get("evidence", ""), re.I):
            sev = "medium"
        if f.get("kind") == "tls" and "expired" in f.get("detail", "").lower():
            sev = "high"
        triaged.append({**f, "severity": sev,
                        "triaged_title": f"[{sev.upper()}] {title}"})
    return triaged


def build_markdown_report(program_name, scan_result):
    """Render a scan result dict as a Markdown report string."""
    lines = [f"# Recon Report — {program_name}",
             f"_Generated {datetime.utcnow().isoformat()}Z_\n",
             f"- Pages visited: {scan_result.get('pages_visited', 0)}",
             f"- Findings: {scan_result.get('findings_count', 0)}\n",
             "## Findings"]
    for f in scan_result.get("findings", []):
        lines.append(f"\n### {f.get('triaged_title', f.get('title', ''))}")
        lines.append(f.get("detail", ""))
        if f.get("evidence"):
            lines.append(f"\n```\n{f['evidence'][:1500]}\n```")
    if not scan_result.get("findings"):
        lines.append("\n_No findings._")
    return "\n".join(lines)
