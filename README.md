# Aether

**Wireless penetration testing orchestrator** — five-phase automated assessment of WPA/WPA2/WPA3 networks with real-time Spectre protocol token emission.

Aether automates the full wireless attack surface: monitor mode management, AP discovery, handshake capture and cracking, WPA-Enterprise credential harvesting, WPA3 SAE cryptographic vulnerability testing, resource exhaustion, and KRACK key reinstallation testing — sequenced into a single configurable pipeline. When launched by [Spectre](../spectre/) with `SPECTRE_MANAGED=1`, structured protocol tokens stream to the frontend in real time. Run standalone or under orchestration.

---

## Features

- **5-phase attack pipeline** — WPA/WPA2/WPA3 handshake capture + offline cracking, WPA-Enterprise rogue AP credential harvesting, WPA3 SAE Dragonblood cryptographic testing, SAE resource exhaustion flooding, and KRACK key reinstallation testing; each phase independently toggleable
- **Monitor mode management** — airmon-ng primary with `iw` + `ip` fallback; enabled before assessment, disabled in `finally` block on any exit path
- **AP discovery** — airodump-ng primary with iwlist fallback; SSID and BSSID filtering applied post-scan; channel and encryption type extracted per AP
- **Per-phase timeout control** — configurable `timeout_per_phase` (default 300 s); each phase tracks elapsed time and terminates subprocesses on expiry
- **Spectre protocol integration** — emits `__SPECTRE_LOG__`, `__SPECTRE_ERR__`, `__SPECTRE_STATUS__`, and `__SPECTRE_FINDING__` tokens to stdout with `flush=True` for real-time parsing
- **Configurable tool paths** — all external tool binaries set in `config.json`; missing tools skip their phase gracefully rather than aborting
- **CLI overrides** — interface, wordlist, and target SSIDs overridable at runtime without editing config

---

## Requirements

- Python 3.6+
- Linux (monitor mode, wireless tooling)
- Root privileges (`sudo`) — required for monitor mode and all attack phases

**Core wireless utilities** (at least one of each pair required):

| Role | Primary | Fallback |
|------|---------|---------|
| Monitor mode | `airmon-ng` (aircrack-ng) | `iw` + `ip` |
| AP scanning | `airodump-ng` (aircrack-ng) | `iwlist` |
| Network restart | `systemctl` | `service` |

**Phase tools** (each required only if its phase is enabled):

| Phase | Tool | Source |
|-------|------|--------|
| WPA Handshake | `wifite` / `wifite2` | `pip install wifite2` |
| WPA-Enterprise | `eaphammer` | [s0md3v/eaphammer](https://github.com/s0md3v/eaphammer) |
| WPA3 SAE | `dragonslayer-client.sh` | [vanhoefm/dragonslayer](https://github.com/vanhoefm/dragonslayer) |
| WPA3 Exhaustion | `dragondrain` | [vanhoefm/dragondrain-and-time](https://github.com/vanhoefm/dragondrain-and-time) |
| KRACK | `krack-test-client.py` | [vanhoefm/krackattacks-scripts](https://github.com/vanhoefm/krackattacks-scripts) |

```bash
# Kali / apt-based
sudo apt install aircrack-ng wireless-tools

# Tool installations
pip install wifite2
git clone https://github.com/s0md3v/eaphammer /opt/eaphammer
git clone https://github.com/vanhoefm/dragonslayer /opt/dragonslayer
git clone https://github.com/vanhoefm/dragondrain-and-time /opt/dragondrain-and-time
git clone https://github.com/vanhoefm/krackattacks-scripts /opt/krackattacks-scripts
```

---

## Installation

```bash
git clone https://github.com/yourorg/aether
cd aether
# No pip installs — stdlib only (argparse, json, os, re, shutil, subprocess, sys, time)
```

---

## Usage

```bash
# Full assessment — all enabled phases
sudo python3 aether.py --config config.json --project my_assessment

# Single-phase run
sudo python3 aether.py --config config.json --project test --phase wpa

# Multiple target SSIDs with custom wordlist
sudo python3 aether.py --config config.json --project office \
  --ssid "Corp-5G" --ssid "Corp-Guest" \
  --wordlist /path/to/wordlist.txt

# Override interface
sudo python3 aether.py --config config.json --project pentest --interface wlan1

# List available phases
python3 aether.py --list-phases

# Spectre-managed (launched automatically by Spectre)
SPECTRE_MANAGED=1 python3 aether.py --config config.json --project assessment
```

---

## CLI Reference

| Argument | Short | Default | Description |
|----------|-------|---------|-------------|
| `--project` | `-p` | **required** | Project name / output directory path |
| `--config` | `-c` | `config.json` | Path to JSON configuration file |
| `--interface` | `-i` | from config | Wireless interface override |
| `--wordlist` | `-w` | from config | Wordlist path override for WPA cracking |
| `--ssid` | | from config | Target SSID (repeatable); overrides `target_ssids` |
| `--phase` | | all enabled | Run a single phase: `wpa` \| `enterprise` \| `wpa3` \| `drain` \| `krack` |
| `--list-phases` | | | Print available phases and exit |

**Override priority:** CLI arguments → `config.json` → code defaults

---

## Assessment Phases

| # | Phase | Config Key | Tool | CVEs |
|---|-------|-----------|------|------|
| 1 | **WPA Handshake** | `wpa_handshake` | wifite2 | — |
| 2 | **WPA-Enterprise** | `wpa_enterprise` | EAPHammer | — |
| 3 | **WPA3 SAE** | `dragonblood_sae` | dragonslayer | CVE-2019-9494, CVE-2019-9495, CVE-2019-9497 – 9502 |
| 4 | **WPA3 Exhaustion** | `dragonblood_drain` | dragondrain | CVE-2019-9496 |
| 5 | **KRACK** | `krack` | krackattacks-scripts | CVE-2017-13077, CVE-2017-13078, CVE-2017-13080 |

### Phase 1 — WPA/WPA2/WPA3 Handshake Capture (`wpa_handshake`)

Launches wifite2 in automated mode on the monitor interface. Captures WPA/WPA2/WPA3 handshakes via PMKID attack (no deauth required) or standard 4-way handshake deauth, then attempts offline cracking with the configured wordlist. Iterates per SSID if targets are specified, or auto-selects all visible networks.

- **Findings:** CRITICAL — "WPA Pre-Shared Key Cracked"; HIGH — "WPA Handshake Captured"
- **Output:** `aether_output/wifite/wifite_<SSID>.txt`
- **Hardware:** Any monitor-mode capable adapter

### Phase 2 — WPA-Enterprise Credential Harvesting (`wpa_enterprise`)

Launches EAPHammer to create a rogue AP impersonating the target. Downgrades 802.1X authentication to a capturable method and harvests NTLM challenge/response or MSCHAPv2 hashes. Targets up to 3 enterprise APs; falls back to first 3 discovered APs if no enterprise encryption detected.

- **Findings:** CRITICAL — "WPA-Enterprise Credentials Captured"
- **Output:** `aether_output/eaphammer/eaphammer_<SSID>.txt`, `aether_output/eaphammer/<SSID>/`
- **Hardware:** AP-mode capable adapter

### Phase 3 — WPA3 SAE Cryptographic Testing (`dragonblood_sae`)

Runs dragonslayer against WPA3 SAE implementations. Generates a per-SSID `client_<SSID>.conf` and tests configurable attack modes: reflection (0), invalid curve (1, default), secondary invalid curve (2), zero-scalar (3). Targets up to 3 WPA3 APs; falls back to first discovered APs.

- **Attack modes:** 0 = reflection, 1 = invalid curve (default), 2 = secondary invalid curve, 3 = zero-scalar
- **Findings:** HIGH — "WPA3 SAE Dragonblood Vulnerability Detected"
- **Output:** `aether_output/dragonslayer/dragonslayer_<SSID>_attack<N>.txt`
- **Hardware:** Atheros card with `ath_masker` kernel module required

### Phase 4 — WPA3 SAE Resource Exhaustion (`dragonblood_drain`)

Floods the target AP with forged SAE Commit messages at 20 handshakes/second using 10 spoofed source MACs, targeting curve group 21 (521-bit elliptic). Fixed 60 s run per target. Tests whether the AP is susceptible to commit flooding causing service degradation.

- **Findings:** MEDIUM — "WPA3 SAE Resource Exhaustion (Dragondrain) Tested"
- **Output:** `aether_output/dragondrain/dragondrain_<SSID>.txt`
- **Hardware:** Atheros card with curve group 21 support; disruptive — authorized environments only

### Phase 5 — KRACK Key Reinstallation Testing (`krack`)

Runs three KRACK test variants against up to 2 target APs. Disables hardware crypto via `disable-hwcrypto.sh` before testing. Tests: standard 4-way handshake (CVE-2017-13077), group key reinstallation (CVE-2017-13080), and TPTK variant (CVE-2017-13078).

- **Findings:** HIGH — "WPA2 KRACK Vulnerability: \<Variant\> (\<SSID\>)"
- **Output:** `aether_output/krack/krack_<SSID>_<variant>.txt`
- **Hardware:** Intel AC 7260 or TP-Link TL-WN722N v1 recommended; hardware crypto must be disabled

---

## Configuration

```json
{
  "interface":           "wlan0",
  "monitor_interface":   "wlan0mon",
  "wordlist":            "/usr/share/wordlists/rockyou.txt",
  "target_ssids":        [],
  "target_bssids":       [],
  "channel":             null,
  "timeout_per_phase":   300,

  "phases": {
    "wpa_handshake":     true,
    "wpa_enterprise":    false,
    "krack":             true,
    "dragonblood_sae":   true,
    "dragonblood_drain": false
  },

  "tools": {
    "wifite2":              "wifite",
    "eaphammer":            "/opt/eaphammer/eaphammer",
    "dragonslayer_client":  "/opt/dragonslayer/dragonslayer-client.sh",
    "dragonslayer_server":  "/opt/dragonslayer/dragonslayer-server.sh",
    "dragondrain":          "/opt/dragondrain-and-time/dragondrain",
    "krackattacks":         "/opt/krackattacks-scripts/krackattack/krack-test-client.py"
  },

  "eaphammer": {
    "auth":         "wpa-eap",
    "creds_output": "creds/",
    "identity":     ""
  },

  "dragonslayer": {
    "attack":       1,
    "client_conf":  "/opt/dragonslayer/client.conf",
    "hostapd_conf": "/opt/dragonslayer/hostapd.conf"
  },

  "output_dir": "aether_output"
}
```

| Key | Description |
|-----|-------------|
| `interface` | Physical wireless interface for monitor mode |
| `monitor_interface` | Expected monitor-mode interface name (e.g. `wlan0mon`) |
| `wordlist` | Path to wordlist for offline WPA cracking; skipped if missing |
| `target_ssids` | SSIDs to target; empty = scan all visible networks |
| `target_bssids` | BSSIDs to target; empty = no BSSID filtering |
| `channel` | Fixed channel; `null` = auto-scan |
| `timeout_per_phase` | Maximum seconds per phase (default: 300) |
| `phases.*` | Boolean flags enabling/disabling each phase |
| `tools.*` | Paths to each tool binary or script; missing tools skip their phase |
| `eaphammer.auth` | EAP auth method passed to `--auth` (default: `wpa-eap`) |
| `dragonslayer.attack` | Attack mode 0–3 (default: 1, invalid curve) |
| `output_dir` | Base output directory relative to project directory |

---

## Spectre Protocol

When Aether runs under Spectre orchestration (`SPECTRE_MANAGED=1`), it emits structured tokens to stdout that Spectre parses line-by-line. All tokens are flushed immediately for real-time streaming.

| Token | Format | Action |
|-------|--------|--------|
| `__SPECTRE_LOG__` | `<token> <message>` | Informational log line |
| `__SPECTRE_ERR__` | `<token> <message>` | Error line (coloured red in Spectre) |
| `__SPECTRE_STATUS__` | `<token> <JSON>` | Phase status update |
| `__SPECTRE_FINDING__` | `<token> <JSON>` | Security finding |
| `__SPECTRE_PROMPT__` | `<token> <message>` | Defined; not currently emitted |

### `__SPECTRE_STATUS__` payload

```json
{
  "phase":  "p1_wifite",
  "label":  "Phase 1: WPA Handshake Capture",
  "status": "running",
  "step":   "Capturing handshake on ch6",
  "ts":     "2026-04-07T09:00:00.000000"
}
```

Phase IDs: `p1_wifite`, `p2_eaphammer`, `p3_dragonslayer`, `p4_dragondrain`, `p5_krack`

Status values: `running`, `complete`, `skipped`

### `__SPECTRE_FINDING__` payload

```json
{
  "title":       "WPA Pre-Shared Key Cracked: HomeNetwork",
  "severity":    "CRITICAL",
  "description": "wifite2 recovered PSK for SSID 'HomeNetwork': password123",
  "data": {
    "ssid":  "HomeNetwork",
    "psk":   "password123"
  },
  "output_file": "my_assessment/aether_output/wifite/wifite_HomeNetwork.txt",
  "ts":          "2026-04-07T09:00:00.000000"
}
```

Severity values: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`

---

## Output Structure

```
<project>/
└── aether_output/
    ├── wifite/
    │   ├── wifite_<SSID>.txt          Per-SSID wifite2 output
    │   └── wifite_all.txt             Auto-scan output (no target SSIDs)
    ├── eaphammer/
    │   ├── eaphammer_<SSID>.txt       EAPHammer raw output
    │   └── <SSID>/                    Captured credential files
    ├── dragonslayer/
    │   ├── dragonslayer_<SSID>_attack<N>.txt
    │   └── client_<SSID>.conf         Generated wpa_supplicant config
    ├── dragondrain/
    │   └── dragondrain_<SSID>.txt
    └── krack/
        ├── krack_<SSID>_standard_4-way.txt
        ├── krack_<SSID>_group_key.txt
        └── krack_<SSID>_tptk_variant.txt
```

---

## Execution Pipeline

```
1. Load & merge config + CLI overrides
2. Enable monitor mode
   ├─ airmon-ng check kill → airmon-ng start <iface>
   └─ Fallback: iw + ip (set monitor none)
3. Scan for APs
   ├─ airodump-ng (30 s capture → CSV parse)
   └─ Fallback: iwlist scan
4. Filter by target_ssids / target_bssids
5. Phase 1: wifite2          (if wpa_handshake: true)
6. Phase 2: EAPHammer        (if wpa_enterprise: true)
7. Phase 3: dragonslayer     (if dragonblood_sae: true)
8. Phase 4: dragondrain      (if dragonblood_drain: true)
9. Phase 5: krackattacks     (if krack: true)
10. Disable monitor mode     (always — in finally block)
```

Each phase function:
- Validates tool existence → skips with `status: skipped` if missing
- Emits `status: running` on start, `status: complete` on finish
- Pipes subprocess stdout line-by-line; keyword-matches trigger `__SPECTRE_FINDING__` tokens
- Terminates subprocess on timeout; logs error, continues to next phase

---

## Hardware Requirements

| Phase | Required Hardware |
|-------|------------------|
| 1 — WPA Handshake | Any monitor-mode capable adapter |
| 2 — WPA-Enterprise | Any adapter supporting AP mode |
| 3 — WPA3 SAE | Atheros card with `ath_masker` kernel module |
| 4 — WPA3 Exhaustion | Atheros card with curve group 21 support |
| 5 — KRACK | Intel AC 7260 or TP-Link TL-WN722N v1 (hardware crypto disabled) |

---

## Project Structure

```
aether/
├── aether.py      Wireless assessment orchestrator
└── config.json    Configuration template
```

Aether is intentionally self-contained — one file, no external Python dependencies beyond the standard library. Place `aether.py` in the same directory as Spectre's `app.py` for Spectre orchestration.

---

## Contributors

The following external tools are orchestrated by Aether. Full credit goes to their respective authors and maintainers.

- **wifite2**
  - Originally created by **derv82**; actively maintained by **kimocoder** (Ronnie Nilsson)
  - GitHub: [https://github.com/kimocoder/wifite2](https://github.com/kimocoder/wifite2)

- **EAPHammer**
  - Created by **s0md3v** (Dhiyaneshwaran)
  - GitHub: [https://github.com/s0md3v/eaphammer](https://github.com/s0md3v/eaphammer)

- **dragonslayer**
  - Created by **Mathy Vanhoef** (@vanhoefm)
  - Research on Dragonblood WPA3 SAE vulnerabilities (CVE-2019-9494 through CVE-2019-9502)
  - GitHub: [https://github.com/vanhoefm/dragonslayer](https://github.com/vanhoefm/dragonslayer)

- **dragondrain-and-time**
  - Created by **Mathy Vanhoef** (@vanhoefm)
  - WPA3 SAE resource exhaustion / Dragondrain tool (CVE-2019-9496)
  - GitHub: [https://github.com/vanhoefm/dragondrain-and-time](https://github.com/vanhoefm/dragondrain-and-time)

- **krackattacks-scripts**
  - Created by **Mathy Vanhoef** (@vanhoefm)
  - Key reinstallation attack (KRACK) proof-of-concept test scripts (CVE-2017-13077, CVE-2017-13078, CVE-2017-13080)
  - GitHub: [https://github.com/vanhoefm/krackattacks-scripts](https://github.com/vanhoefm/krackattacks-scripts)

- **aircrack-ng suite** (airmon-ng, airodump-ng)
  - Created and maintained by the **aircrack-ng team**
  - GitHub: [https://github.com/aircrack-ng/aircrack-ng](https://github.com/aircrack-ng/aircrack-ng)
