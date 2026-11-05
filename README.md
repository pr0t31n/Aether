<details>
<summary><strong>FULL DISCLOSURE</strong> — AI Development & Legal Notice</summary>

---

### AI Development Disclosure

This tool is part of the **pr0t31n toolkit**, a collection of security testing and penetration testing automation tools. The toolkit was created through AI-assisted development, guided by the professional experience and domain expertise of a cybersecurity consultant and penetration tester. Ya, I named it after myself - but to be fair, AI is horrible at naming things.

**The pr0t31n toolkit exists to serve two purposes:**

1. **Automate repetitive penetration testing workflow steps.** Security assessments involve significant amounts of repetitive, procedural work — running sequential tool chains, parsing outputs, correlating findings across tools, and managing engagement data. Automating these steps frees testers to focus on the work that requires human judgment: manual testing, creative attack paths, analysis, and reporting.

2. **Demonstrate the benefits and failures of AI-assisted development.** This toolkit is a real-world case study in building production security tooling with AI assistance. It demonstrates both what AI-assisted development can accomplish and where it falls short. The quality of AI-generated code varies significantly — between context refreshes, the output can range from senior/principal-level software engineering to the work of a still-in-school intern. This inconsistency is itself part of the demonstration.

In the interest of transparency, every tool in the pr0t31n toolkit carries this disclosure. The creator believes that AI-assisted development should be acknowledged openly, not concealed. Users, reviewers, and anyone examining this code should know how it was built so they can evaluate it accordingly.

---

### Legal & Authorization Notice

> **⚠ WARNING: AUTHORIZED USE ONLY**

This tool is designed and intended **exclusively** for use in **authorized security testing engagements**. "Authorized" means **all** of the following conditions are met:

- **Explicit Written Permission.** You possess explicit, documented, written authorization from the owner or authorized representative of the target system(s), network(s), or application(s) to conduct security testing. Verbal agreements are not sufficient.
- **Defined Scope.** The authorization clearly defines the scope of testing, including which systems, networks, IP ranges, applications, and/or endpoints are included. You must not exceed the boundaries of this defined scope under any circumstances.
- **Defined Timeframe.** The authorization specifies the dates and times during which testing is permitted. Testing outside the authorized window is unauthorized testing.
- **Rules of Engagement.** You are operating under a set of rules of engagement (RoE) or equivalent governing document that establishes acceptable testing methods, escalation procedures, emergency contacts, and any restrictions or exclusions.
- **Legal Compliance.** Your testing complies with all applicable local, state, national, and international laws and regulations, including but not limited to the Computer Fraud and Abuse Act (CFAA), the General Data Protection Regulation (GDPR), and equivalent legislation in your jurisdiction.

**Prohibited uses** include but are not limited to: unauthorized access to or testing of any system; testing against systems without explicit written authorization; any activity that violates applicable laws; use for malicious purposes including data theft, extortion, sabotage, or disruption of services; distribution intended to facilitate unauthorized access; and use without a clear legal basis.

**THIS TOOL IS PROVIDED "AS IS," WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND NONINFRINGEMENT.**

The creator(s) and contributor(s) accept no responsibility or liability for any damage, loss, legal consequence, or other harm resulting from the use or misuse of this tool — including damage to systems or data, legal penalties or prosecution, loss of data or revenue, and any direct, indirect, incidental, special, consequential, or punitive damages.

**By using this tool, you acknowledge that you are solely responsible for ensuring that your use is authorized, lawful, and within the defined scope of your engagement. You assume all risk associated with the use of this tool.**

Security testing is a professional discipline with significant ethical and legal obligations. Users operating in a professional capacity are expected to adhere to the standards and codes of conduct established by recognized industry bodies, including PTES, OWASP, NIST, and any certifying body under which they hold credentials.

---

</details>

# Aether

**Wireless penetration testing orchestrator** — 25-phase automated assessment of WEP/WPA/WPA2/WPA3 networks with real-time Crucible protocol token emission.

Aether automates the full wireless attack surface: monitor mode management, AP discovery and intelligence scoring, WEP IV capture, PMKID clientless capture, handshake capture and cracking, deauth-triggered handshake capture, WPA-Enterprise credential harvesting, rogue AP / Evil Twin / KARMA / MANA deployment, client-side management frame attacks (PMF/BTM/probe harvest), EAP downgrade and EAP-FAST anonymous provisioning testing, WPA3 SAE cryptographic vulnerability testing, SAE transition-mode downgrade, resource exhaustion, KRACK key reinstallation testing, post-connection attacks (ARP/LLMNR/nmap), legacy/niche attacks (TKIP/Wi-Fi Direct/captive portal bypass), server certificate analysis, Meraki iPSK detection, captive portal splash bypass, and EAP-TLS identity disclosure analysis — sequenced into a single configurable pipeline. When launched by Crucible with `CRUCIBLE_MANAGED=1`, structured protocol tokens stream to the frontend in real time. Run standalone or under orchestration.

---


> **[View full documentation on the Codex Wiki](https://wiki.pr0t31n.com/tools/aether)** — detailed features, CLI reference, findings catalogue, and integration guides.

## Features

- **25-phase attack pipeline** — WEP cracking, PMKID clientless capture, WPA/WPA2/WPA3 handshake capture + offline cracking, deauth-triggered handshake capture, WPA-Enterprise rogue AP credential harvesting, WPA3 SAE Dragonblood cryptographic testing, SAE resource exhaustion flooding, KRACK key reinstallation testing, Evil Twin / KARMA / MANA loud mode, client-side PMF/BTM/probe attacks, EAP downgrade, EAP-FAST anonymous PAC provisioning, SAE transition-mode downgrade, post-connection ARP/LLMNR/nmap, legacy TKIP/WPS/captive bypass, server certificate analysis, Meraki iPSK detection, captive portal splash bypass, and EAP-TLS identity disclosure analysis; each phase independently toggleable
- **Wireless intelligence** — AP enumeration with client counting, signal scoring, vendor OUI lookup, and automatic best-target selection; contextual findings for every observed AP/client/channel/auth type
- **Meraki infrastructure recon** — classifies APs, identifies shared-physical-AP multi-SSID deployments, fingerprints firmware
- **Scope enforcement** — per-SSID active/passive mode scoping; passive SSIDs get monitoring only, no client attacks
- **Monitor mode management** — airmon-ng primary with `iw` + `ip` fallback; enabled before assessment, disabled in `finally` block on any exit path
- **AP discovery** — airodump-ng primary with iwlist fallback; SSID and BSSID filtering applied post-scan; channel and encryption type extracted per AP
- **Per-phase timeout control** — configurable `timeout_per_phase` (default 300 s); each phase tracks elapsed time and terminates subprocesses on expiry
- **Crucible protocol integration** — emits `__CRUCIBLE_LOG__`, `__CRUCIBLE_ERR__`, `__CRUCIBLE_STATUS__`, and `__CRUCIBLE_FINDING__` tokens to stdout with `flush=True` for real-time parsing
- **Domain-derived wordlists** — deep-parses domains into password mutations; merges with base wordlist and website scrape output
- **Multi-wordlist support** — multiple `--wordlist` paths are merged and deduplicated into a single base wordlist
- **Hashcat rule stacking** — staged PMKID cracking with configurable rule files via `--rules`
- **Configurable tool paths** — all external tool binaries set in `config.json`; missing tools skip their phase gracefully rather than aborting

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
| WEP Cracking | `aircrack-ng` / `aireplay-ng` | aircrack-ng suite |
| PMKID Capture | `hcxdumptool` / `hcxpcapngtool` / `hashcat` | system packages |
| WPA Handshake | `wifite` / `wifite2` | `pip install wifite2` |
| Deauth+Handshake | `aireplay-ng` / `aircrack-ng` | aircrack-ng suite |
| WPA-Enterprise | `eaphammer` | [s0md3v/eaphammer](https://github.com/s0md3v/eaphammer) |
| Rogue AP / Evil Twin | `hostapd` / `dnsmasq` / `bettercap` | system packages |
| KARMA / MANA | `hostapd-mana` / `bettercap` | system packages |
| Client Attacks (PMF) | `mdk4` | system packages |
| EAP Downgrade | `eaphammer` | [s0md3v/eaphammer](https://github.com/s0md3v/eaphammer) |
| WPA3 SAE | `dragonslayer-client.sh` | [vanhoefm/dragonslayer](https://github.com/vanhoefm/dragonslayer) |
| WPA3 Exhaustion | `dragondrain` | [vanhoefm/dragondrain-and-time](https://github.com/vanhoefm/dragondrain-and-time) |
| SAE Downgrade | `hostapd` / `bettercap` | system packages |
| KRACK | `krack-test-client.py` | [vanhoefm/krackattacks-scripts](https://github.com/vanhoefm/krackattacks-scripts) |
| Post-Connection | `nmap` / `responder` | system packages |
| Legacy (TKIP) | `tkiptun-ng` / `aireplay-ng` | aircrack-ng suite |
| Legacy (Wi-Fi Direct) | `wash` / `wpa_cli` | system packages |
| Server Cert Analysis | `tshark` | Wireshark suite |
| Captive Portal Bypass | `curl` / `iptables` | system packages |

```bash
# Kali / apt-based
sudo apt install aircrack-ng wireless-tools hashcat hcxdumptool hcxpcapngtool \
  hostapd dnsmasq mdk4 nmap responder tshark wash

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
cd /opt/pr0t31n/Aether
sudo python3 install.py
```

---

## Usage

```bash
# Full assessment — all enabled phases
sudo python3 aether.py --config config.json --project my_assessment

# Single-phase run
sudo python3 aether.py --config config.json --project test --phase pmkid

# Multiple target SSIDs with custom wordlist
sudo python3 aether.py --config config.json --project office \
  --ssid "Corp-5G" --ssid "Corp-Guest" \
  --wordlist /path/to/wordlist.txt

# Override interface
sudo python3 aether.py --config config.json --project pentest --interface wlan1

# Scoped assessment — active + passive SSIDs
sudo python3 aether.py --config config.json --project scoped \
  --scope-active "Corp-Internal" --scope-passive "Corp-Guest" \
  --scope-default-mode active

# Domain-derived wordlist generation
sudo python3 aether.py --config config.json --project corp \
  --domain example.com --domain corp.local

# Staged PMKID cracking with hashcat rules
sudo python3 aether.py --config config.json --project crack \
  --phase pmkid --rules /usr/share/hashcat/rules/best64.rule

# List available phases
python3 aether.py --list-phases

# Crucible-managed (launched automatically by Crucible)
CRUCIBLE_MANAGED=1 python3 aether.py --config config.json --project assessment
```

---

## CLI Reference

| Argument | Short | Default | Description |
|----------|-------|---------|-------------|
| `--config` | `-c` | `config.json` (next to aether.py) | Path to JSON configuration file |
| `--project` | `-p` | `aether_<timestamp>` | Project name / output root directory |
| `--interface` | `-i` | from config | Wireless interface override |
| `--phase` | | all enabled | Run a single phase only (see values below) |
| `--ssid` | | from config | Target SSID (repeatable); overrides `target_ssids` in config |
| `--bssid` | | from config | Target BSSID (repeatable); overrides `target_bssids` in config |
| `--channel` | `-C` | from config | Lock AP scan to this channel number |
| `--timeout` | `-t` | from config (300) | Per-phase timeout in seconds |
| `--wordlist` | `-w` | from config | Wordlist path for WPA cracking (repeatable; multiple lists are merged and deduplicated) |
| `--scope-bssid` | | none | Scope whitelist BSSID (repeatable); attacks blocked outside scope |
| `--scope-ssid` | | none | Scope whitelist SSID (repeatable) |
| `--scope-active` | | none | SSID in active scope — full testing (repeatable) |
| `--scope-passive` | | none | SSID in passive scope — monitoring only (repeatable) |
| `--scope-default-mode` | | `active` | Default scope mode for unlisted SSIDs: `active` or `passive` |
| `--domain` | | none | Domain to deep-parse into wordlist entries (repeatable); merged with base wordlist |
| `--rules` | | none | Hashcat rule file for staged PMKID cracking (repeatable) |
| `--list-phases` | | | Print available phases and exit |

### `--phase` values

| Value | Config key | Phase |
|-------|-----------|-------|
| `wep` | `wep` | Phase 0: WEP Testing |
| `pmkid` | `pmkid` | Phase 1a: PMKID Capture |
| `wpa` | `wpa_handshake` | Phase 1b: WPA Handshake + WPS |
| `enterprise` | `wpa_enterprise` | Phase 2: WPA-Enterprise Attack |
| `wpa3` | `dragonblood_sae` | Phase 3: WPA3 SAE Testing |
| `drain` | `dragonblood_drain` | Phase 4: WPA3 Resource Exhaustion |
| `krack` | `krack` | Phase 5: KRACK Testing |
| `rogue` | `rogue_ap` | Phase 6a: Rogue AP / Evil Twin |
| `karma` | `karma` | Phase 6b: KARMA / MANA Attack |
| `client` | `client_attacks` | Phase 7: Client-Side / Management Frame Attacks |
| `eap-downgrade` | `eap_downgrade` | Phase 8: EAP Downgrade Attack |
| `sae-downgrade` | `sae_downgrade` | Phase 9: SAE Transition Mode Downgrade |
| `post` | `post_connection` | Phase 10: Post-Connection Attacks |
| `legacy` | `legacy_attacks` | Phase 11: Legacy / Niche Attacks |

**Override priority:** CLI arguments > `config.json` > code defaults

---

## Assessment Phases

Aether executes up to 25 phases in the order shown below. Each phase is independently toggleable via the `phases` object in `config.json`. Phases marked "default: off" must be explicitly enabled.

### Intelligence & Reconnaissance (always-on)

| # | Phase ID | Label | Config Key | Default | Tool(s) |
|---|----------|-------|-----------|---------|---------|
| 0-I | `p0_intel` | Wireless Intelligence | (always runs) | on | airodump-ng / iwlist |
| 0-II | `p_ctx` | Contextual Intelligence | `contextual_intel` | on | (analysis) |
| 0-III | `p_meraki` | Meraki Infrastructure Recon | `meraki_recon` | on | (analysis) |

**Phase 0-I: Wireless Intelligence** — Enumerates all APs broadcasting the target SSID(s), identifies connected clients, scores and selects the best target AP based on signal strength and client count. Vendor OUI lookup provides manufacturer context.

**Phase 0-II: Contextual Intelligence** — Emits informational findings for every observed AP, client, vendor, channel, and authentication type so the engagement report has full attribution regardless of which risk-graded findings subsequent phases produce.

**Phase 0-III: Meraki Infrastructure Recon** — Classifies APs, identifies shared-physical-AP multi-SSID deployments, and fingerprints firmware for Meraki/Cisco environments.

### WEP & WPA Cracking

| # | Phase ID | Label | Config Key | Default | Tool(s) | CVEs |
|---|----------|-------|-----------|---------|---------|------|
| 0 | `p0_wep` | WEP Testing | `wep` | on | aircrack-ng / aireplay-ng | -- |
| 1a | `p1a_pmkid` | PMKID Capture | `pmkid` | on | hcxdumptool / hashcat | -- |
| 1b | `p1b_wifite` | WPA Handshake + WPS | `wpa_handshake` | on | wifite2 | -- |
| 1c | `p1c_deauth` | Deauth + Handshake | `deauth_handshake` | on | aireplay-ng / aircrack-ng | -- |
| 1c | `p1c_pmkid_roam` | PMKID Roam Capture | `pmkid_roam` | off | hcxdumptool / hashcat | -- |

**Phase 0 -- WEP Testing** — Captures WEP IVs via ARP replay injection (aireplay-ng) and cracks the WEP key with aircrack-ng. Targets WEP-encrypted networks only. Findings: CRITICAL -- "WEP Key Cracked".

**Phase 1a -- PMKID Capture** — Clientless PMKID capture via hcxdumptool; does not require a connected client or deauthentication. Captured PMKIDs are cracked with hashcat using the configured wordlist and optional rule files. Findings: CRITICAL -- "WPA PSK Cracked via PMKID".

**Phase 1b -- WPA Handshake + WPS** — Launches wifite2 in automated mode. Captures WPA/WPA2/WPA3 handshakes via PMKID attack or standard 4-way handshake deauth, then attempts offline cracking. Also tests WPS PIN attacks. Findings: CRITICAL -- "WPA Pre-Shared Key Cracked"; HIGH -- "WPA Handshake Captured".

**Phase 1c -- Deauth + Handshake** — Targeted deauthentication of APs with known connected clients, followed by handshake capture and cracking. Uses client count from Phase 0-I intelligence to prioritize targets.

**Phase 1c -- PMKID Roam Capture** (default off) — Captures PMKID frames from FT (Fast Transition / 802.11r) roaming events between APs. Requires multiple BSSIDs broadcasting the same SSID.

### WPA-Enterprise & EAP Attacks

| # | Phase ID | Label | Config Key | Default | Tool(s) |
|---|----------|-------|-----------|---------|---------|
| 2 | `p2_eaphammer` | WPA-Enterprise Attack | `wpa_enterprise` | off | EAPHammer / asleap |
| 8 | `p8_eap_downgrade` | EAP Downgrade Attack | `eap_downgrade` | off | EAPHammer |
| 8b | `p8b_eap_fast` | EAP-FAST Anonymous PAC | `eap_fast_anon` | off | EAPHammer |

**Phase 2 -- WPA-Enterprise** — Creates a rogue AP impersonating the target, downgrades 802.1X authentication, and harvests NTLM challenge/response or MSCHAPv2 hashes via EAPHammer. Cracks captured hashes with asleap. Findings: CRITICAL -- "WPA-Enterprise Credentials Captured".

**Phase 8 -- EAP Downgrade** — Tests for weak EAP methods by presenting a rogue RADIUS server that negotiates downgraded authentication. Identifies networks accepting EAP-MD5, LEAP, or other deprecated methods.

**Phase 8b -- EAP-FAST Anonymous PAC** — Tests for EAP-FAST anonymous PAC provisioning vulnerability, which allows an attacker to provision a PAC to a client without mutual authentication.

### WPA3 / Dragonblood

| # | Phase ID | Label | Config Key | Default | Tool(s) | CVEs |
|---|----------|-------|-----------|---------|---------|------|
| 3 | `p3_dragonslayer` | WPA3 SAE Testing | `dragonblood_sae` | on | dragonslayer | CVE-2019-9494, CVE-2019-9495, CVE-2019-9497 -- 9502 |
| 4 | `p4_dragondrain` | WPA3 Resource Exhaustion | `dragonblood_drain` | off | dragondrain | CVE-2019-9496 |
| 9 | `p9_sae_downgrade` | SAE Transition Mode Downgrade | `sae_downgrade` | off | hostapd / bettercap |

**Phase 3 -- WPA3 SAE** — Runs dragonslayer against WPA3 SAE implementations. Tests configurable attack modes: reflection (0), invalid curve (1, default), secondary invalid curve (2), zero-scalar (3). Findings: HIGH -- "WPA3 SAE Dragonblood Vulnerability Detected".

**Phase 4 -- WPA3 Exhaustion** — Floods the target AP with forged SAE Commit messages at 20 handshakes/second using 10 spoofed source MACs, targeting curve group 21 (521-bit elliptic). Tests whether the AP is susceptible to commit flooding causing service degradation. Findings: MEDIUM -- "WPA3 SAE Resource Exhaustion (Dragondrain) Tested".

**Phase 9 -- SAE Transition Mode Downgrade** — Tests WPA3 transition mode deployments for downgrade attacks. Deploys a rogue AP advertising only WPA2 to force clients into the weaker protocol, capturing handshakes for offline cracking.

### KRACK

| # | Phase ID | Label | Config Key | Default | Tool(s) | CVEs |
|---|----------|-------|-----------|---------|---------|------|
| 5 | `p5_krack` | KRACK Testing | `krack` | on | krackattacks-scripts | CVE-2017-13077, CVE-2017-13078, CVE-2017-13080 |

**Phase 5 -- KRACK** — Runs three KRACK test variants: standard 4-way handshake (CVE-2017-13077), group key reinstallation (CVE-2017-13080), and TPTK variant (CVE-2017-13078). Disables hardware crypto before testing. Runs after monitor mode is disabled (requires managed mode). Findings: HIGH -- "WPA2 KRACK Vulnerability".

### Rogue AP / KARMA / MANA

| # | Phase ID | Label | Config Key | Default | Tool(s) |
|---|----------|-------|-----------|---------|---------|
| 6a | `p6_rogue_ap` | Rogue AP / Evil Twin | `rogue_ap` | off | hostapd / dnsmasq / bettercap |
| 6b | `p6b_karma` | KARMA / MANA Attack | `karma` | off | hostapd-mana / bettercap |
| 6c | `p6c_mana_loud` | MANA Loud Mode | `mana_loud` | off | bettercap |

**Phase 6a -- Rogue AP / Evil Twin** — Deploys a rogue AP impersonating a target SSID. Captures credentials from clients that associate. Uses cracked PSKs from earlier phases when available.

**Phase 6b -- KARMA / MANA Attack** — Responds to all client probe requests with matching SSIDs (KARMA), harvesting credentials from opportunistic associations.

**Phase 6c -- MANA Loud Mode** — Beacon-spam variant that broadcasts hundreds of SSIDs from observed probe requests, maximizing client associations.

### Client-Side & Management Frame

| # | Phase ID | Label | Config Key | Default | Tool(s) |
|---|----------|-------|-----------|---------|---------|
| 7 | `p7_client` | Client-Side / Management Frame Attacks | `client_attacks` | on | mdk4 / scapy |

Phase 7 contains three sub-phases:

- **7a (`p7_pmf`)** -- PMF Enforcement Testing -- Tests whether APs enforce 802.11w Protected Management Frames
- **7b (`p7_btm`)** -- BSS Transition Hijacking -- Tests BSS Transition Management frame acceptance for AP steering attacks
- **7c (`p7_probes`)** -- Client Probe Harvest Analysis -- Captures and analyzes client probe requests to identify previously connected SSIDs

### Post-Connection & Legacy

| # | Phase ID | Label | Config Key | Default | Tool(s) |
|---|----------|-------|-----------|---------|---------|
| 10 | `p10_post` | Post-Connection Attacks | `post_connection` | off | nmap / responder |
| 11 | `p11_legacy` | Legacy / Niche Attacks | `legacy_attacks` | on | tkiptun-ng / wash / wpa_cli / curl |

**Phase 10 -- Post-Connection** — Runs after associating to a target network. Performs ARP/LLMNR poisoning (responder), network scanning (nmap), and gateway analysis.

**Phase 11 -- Legacy / Niche Attacks** — Contains three sub-phases:
- **11a (`p11_tkip`)** -- TKIP ChopChop / Fragmentation attacks against TKIP-encrypted networks
- **11b (`p11_wifidirect`)** -- Wi-Fi Direct / P2P WPS Scanning for misconfigured direct connections
- **11c (`p11_captive`)** -- Captive Portal Bypass Testing using MAC spoofing and DNS manipulation

### Post-Capture Analysis (always-on)

| # | Phase ID | Label | Config Key | Default | Tool(s) |
|---|----------|-------|-----------|---------|---------|
| 0-IV | `p_cert` | EAP-TLS Server Certificate Analysis | `server_cert_analysis` | on | tshark / openssl |
| 0-V | `p_ipsk` | Meraki iPSK Test | `ipsk_test` | on | (analysis) |
| 0-VI | `p_splash` | Captive Portal / Splash Bypass | `captive_portal_test` | on | curl / iptables |
| 0-VII | `p_eaptls_id` | EAP-TLS Identity Disclosure | `eaptls_identity_analysis` | on | tshark |

**Phase 0-IV -- Server Certificate Analysis** — Parses captured EAP-TLS exchanges to extract server certificates, validates trust chains, checks for weak algorithms and expiry.

**Phase 0-V -- Meraki iPSK Test** — Detects Meraki per-client PSK (iPSK) configurations by testing multiple credential sets against the same SSID.

**Phase 0-VI -- Captive Portal / Splash Bypass** — Tests captive portal implementations for common bypasses (DNS tunneling, MAC cloning, direct IP access).

**Phase 0-VII -- EAP-TLS Identity Disclosure** — Parses EAPOL frames from captured traffic for leaked user identities in EAP-TLS exchange Identity Response packets.

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
    "wep":               true,
    "pmkid":             true,
    "pmkid_roam":        false,
    "wpa_handshake":     true,
    "deauth_handshake":  true,
    "wpa_enterprise":    false,
    "dragonblood_sae":   true,
    "dragonblood_drain": false,
    "krack":             true,
    "rogue_ap":          false,
    "karma":             false,
    "mana_loud":         false,
    "client_attacks":    true,
    "eap_downgrade":     false,
    "eap_fast_anon":     false,
    "sae_downgrade":     false,
    "post_connection":   false,
    "legacy_attacks":    true,
    "contextual_intel":  true,
    "meraki_recon":      true,
    "server_cert_analysis":     true,
    "ipsk_test":                true,
    "captive_portal_test":      true,
    "eaptls_identity_analysis": true
  },

  "scope": {
    "bssids": [],
    "ssids":  [],
    "modes":  {},
    "default_mode": "active"
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

  "rogue_ap": {
    "ap_interface": ""
  },

  "post_connection": {},

  "domains":       [],
  "hashcat_rules": [],
  "scrape_url":    "",
  "scrape_depth":  4,
  "intel_scan_seconds": 45,
  "deauth_packets":     5,
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
| `scope.bssids` | BSSID whitelist; attacks blocked outside scope |
| `scope.ssids` | SSID whitelist; attacks blocked outside scope |
| `scope.modes` | Per-SSID mode map (`{"Corp-Guest": "passive", ...}`) |
| `scope.default_mode` | Default mode for SSIDs not in `modes` map (default: `active`) |
| `tools.*` | Paths to each tool binary or script; missing tools skip their phase |
| `eaphammer.auth` | EAP auth method passed to `--auth` (default: `wpa-eap`) |
| `dragonslayer.attack` | Attack mode 0-3 (default: 1, invalid curve) |
| `rogue_ap.ap_interface` | Dedicated AP-mode interface for rogue AP phases |
| `domains` | Domains to deep-parse into wordlist entries |
| `hashcat_rules` | Hashcat rule files for staged PMKID cracking |
| `scrape_url` | Website URL to scrape for wordlist generation |
| `scrape_depth` | Website scrape crawl depth (default: 4) |
| `intel_scan_seconds` | Duration of intelligence scan in seconds (default: 45) |
| `deauth_packets` | Number of deauth packets per target (default: 5) |
| `output_dir` | Base output directory relative to project directory |

---

## Crucible Protocol

When Aether runs under Crucible orchestration (`CRUCIBLE_MANAGED=1`), it emits structured tokens to stdout that Crucible parses line-by-line. All tokens are flushed immediately for real-time streaming.

| Token | Format | Action |
|-------|--------|--------|
| `__CRUCIBLE_LOG__` | `<token> <message>` | Informational log line |
| `__CRUCIBLE_ERR__` | `<token> <message>` | Error line (coloured red in Crucible) |
| `__CRUCIBLE_STATUS__` | `<token> <JSON>` | Phase status update |
| `__CRUCIBLE_FINDING__` | `<token> <JSON>` | Security finding |
| `__CRUCIBLE_PROMPT__` | `<token> <message>` | Defined; not currently emitted |

### `__CRUCIBLE_STATUS__` payload

```json
{
  "phase":  "p1a_pmkid",
  "label":  "Phase 1a: PMKID Capture",
  "status": "running",
  "step":   "Capturing PMKID on ch6",
  "ts":     "2026-04-07T09:00:00.000000"
}
```

Phase IDs: `p0_intel`, `p_ctx`, `p_meraki`, `p0_wep`, `p1a_pmkid`, `p1b_wifite`, `p1c_deauth`, `p1c_pmkid_roam`, `p2_eaphammer`, `p3_dragonslayer`, `p4_dragondrain`, `p5_krack`, `p6_rogue_ap`, `p6b_karma`, `p6c_mana_loud`, `p7_client`, `p7_pmf`, `p7_btm`, `p7_probes`, `p8_eap_downgrade`, `p8b_eap_fast`, `p9_sae_downgrade`, `p10_post`, `p11_legacy`, `p11_tkip`, `p11_wifidirect`, `p11_captive`, `p_cert`, `p_ipsk`, `p_splash`, `p_eaptls_id`

Status values: `running`, `complete`, `skipped`, `error`

### `__CRUCIBLE_FINDING__` payload

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

Severity values: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`

---

## Output Structure

```
<project>/
├── wordlists/
│   ├── merged_base.txt               Merged + deduped multi-wordlist output
│   ├── website_scraped.txt            Website-derived wordlist
│   └── domain_derived.txt             Domain mutation wordlist
└── aether_output/
    ├── intel/
    │   └── wireless_intel.json        AP enumeration + scoring data
    ├── wep/
    │   └── wep_<SSID>.txt             Per-SSID WEP cracking output
    ├── pmkid/
    │   ├── <SSID>.pcapng              Raw PMKID capture
    │   └── hashcat_<SSID>.txt         Hashcat cracking output
    ├── wifite/
    │   ├── wifite_<SSID>.txt          Per-SSID wifite2 output
    │   └── wifite_all.txt             Auto-scan output (no target SSIDs)
    ├── deauth/
    │   └── deauth_<SSID>.cap          Deauth-triggered handshake captures
    ├── eaphammer/
    │   ├── eaphammer_<SSID>.txt       EAPHammer raw output
    │   └── <SSID>/                    Captured credential files
    ├── dragonslayer/
    │   ├── dragonslayer_<SSID>_attack<N>.txt
    │   └── client_<SSID>.conf         Generated wpa_supplicant config
    ├── dragondrain/
    │   └── dragondrain_<SSID>.txt
    ├── krack/
    │   ├── krack_<SSID>_standard_4-way.txt
    │   ├── krack_<SSID>_group_key.txt
    │   └── krack_<SSID>_tptk_variant.txt
    ├── rogue_ap/
    │   └── rogue_<SSID>.txt           Evil Twin attack output
    ├── karma/
    │   └── karma_capture.txt          KARMA/MANA credential harvest
    ├── mana_loud/
    │   └── mana_loud.txt              MANA loud mode output
    ├── client_attacks/
    │   ├── pmf_<SSID>.txt             PMF enforcement test results
    │   ├── btm_<SSID>.txt             BSS Transition hijacking results
    │   └── probes.txt                 Client probe harvest analysis
    ├── eap_downgrade/
    │   └── eap_downgrade_<SSID>.txt   EAP method downgrade results
    ├── sae_downgrade/
    │   └── sae_downgrade_<SSID>.txt   SAE transition mode results
    ├── post_connection/
    │   └── post_<target>.txt          Post-connection scan results
    └── legacy/
        ├── tkip_<SSID>.txt            TKIP attack output
        ├── wifidirect_scan.txt        Wi-Fi Direct / P2P results
        └── captive_bypass.txt         Captive portal bypass results
```

---

## Execution Pipeline

```
 1. Load & merge config + CLI overrides
 2. Build effective wordlist (merge base + website scrape + domain derivation)
 3. Enable monitor mode
    +-- airmon-ng check kill -> airmon-ng start <iface>
    +-- Fallback: iw + ip (set monitor none)
 4. Check packet injection capability
 5. Phase 0-I:   Wireless Intelligence (AP enum, client count, best-target scoring)
 6. Phase 0-II:  Contextual Intelligence (informational findings for all APs/clients)
 7. Phase 0-III: Meraki Infrastructure Recon
 8. Scan & filter targets by SSID/BSSID/scope
 9. Phase 0:     WEP Testing                        (if wep: true)
10. Phase 1a:    PMKID Capture                       (if pmkid: true)
11. Phase 1c:    PMKID Roam Capture                  (if pmkid_roam: true)
12. Phase 1b:    WPA Handshake + WPS (wifite2)       (if wpa_handshake: true)
13. Phase 1c:    Deauth + Handshake                  (if deauth_handshake: true)
14. Phase 2:     WPA-Enterprise (EAPHammer)           (if wpa_enterprise: true)
15. Phase 3:     WPA3 SAE (dragonslayer)             (if dragonblood_sae: true)
16. Phase 4:     WPA3 Exhaustion (dragondrain)       (if dragonblood_drain: true)
17. Phase 6a:    Rogue AP / Evil Twin                (if rogue_ap: true)
18. Phase 6b:    KARMA / MANA Attack                 (if karma: true)
19. Phase 6c:    MANA Loud Mode                      (if mana_loud: true)
20. Phase 7:     Client Attacks (PMF/BTM/Probes)     (if client_attacks: true)
21. Phase 8:     EAP Downgrade                       (if eap_downgrade: true)
22. Phase 8b:    EAP-FAST Anonymous PAC              (if eap_fast_anon: true)
23. Phase 9:     SAE Transition Mode Downgrade       (if sae_downgrade: true)
24. Phase 11:    Legacy Attacks (TKIP/WPS/Captive)   (if legacy_attacks: true)
25. Phase 0-IV:  Server Certificate Analysis         (if server_cert_analysis: true)
26. Phase 0-V:   Meraki iPSK Test                    (if ipsk_test: true)
27. Phase 0-VI:  Captive Portal / Splash Bypass      (if captive_portal_test: true)
28. Phase 0-VII: EAP-TLS Identity Disclosure         (if eaptls_identity_analysis: true)
29. Disable monitor mode (always -- in finally block)
30. Phase 5:     KRACK Testing (managed mode)        (if krack: true)
31. Save findings & write meta.json
```

Each phase function:
- Validates tool existence -- skips with `status: skipped` if missing
- Emits `status: running` on start, `status: complete` on finish
- Pipes subprocess stdout line-by-line; keyword-matches trigger `__CRUCIBLE_FINDING__` tokens
- Terminates subprocess on timeout; logs error, continues to next phase
- Respects scope enforcement: passive-scope SSIDs are skipped for active attack phases

---

## Hardware Requirements

| Phase | Required Hardware |
|-------|------------------|
| 0-I -- Intelligence | Any monitor-mode capable adapter |
| 0 -- WEP | Any monitor-mode capable adapter |
| 1a -- PMKID | Any monitor-mode capable adapter |
| 1b -- WPA Handshake | Any monitor-mode capable adapter |
| 1c -- Deauth | Any monitor-mode capable adapter |
| 2 -- WPA-Enterprise | Any adapter supporting AP mode |
| 3 -- WPA3 SAE | Atheros card with `ath_masker` kernel module |
| 4 -- WPA3 Exhaustion | Atheros card with curve group 21 support |
| 5 -- KRACK | Intel AC 7260 or TP-Link TL-WN722N v1 (hardware crypto disabled) |
| 6a/6b/6c -- Rogue AP / KARMA / MANA | Any adapter supporting AP mode |
| 7 -- Client Attacks | Any monitor-mode capable adapter |
| 9 -- SAE Downgrade | Any adapter supporting AP mode |
| 10 -- Post-Connection | Network adapter (associated to target) |

---

## Project Structure

```
Aether/
├── aether.py               Wireless assessment orchestrator
├── config.json             Configuration template
├── findings_catalogue.json Findings catalogue (Arbiter-compatible)
├── install.py              Multi-platform installer
├── requirements.txt        Python dependencies
├── VERSION                 Version file
└── README.md               This file
```

Aether is intentionally self-contained — one file, no external Python dependencies beyond the standard library. Place `aether.py` in `/opt/pr0t31n/Aether/` for Crucible orchestration.

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
