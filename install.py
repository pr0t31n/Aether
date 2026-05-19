#!/usr/bin/env python3
# install.py — Aether Wireless Penetration Testing Orchestrator
# VERSION: 1.5.2 (referenced from /opt/pr0t31n/Aether/VERSION — do not bump here)
# Installs all dependencies for aether.py and configures the system.

import argparse
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# ANSI colour helpers
# ---------------------------------------------------------------------------
RESET  = "\033[0m"
BOLD   = "\033[1m"
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BLUE   = "\033[94m"
MAGENTA = "\033[95m"

def cprint(msg: str, colour: str = RESET, bold: bool = False) -> None:
    prefix = BOLD if bold else ""
    print(f"{prefix}{colour}{msg}{RESET}")

def phase_header(title: str) -> None:
    bar = "=" * 60
    print()
    cprint(bar, CYAN, bold=True)
    cprint(f"  {title}", CYAN, bold=True)
    cprint(bar, CYAN, bold=True)

def info(msg: str)    -> None: cprint(f"  [*] {msg}", BLUE)
def success(msg: str) -> None: cprint(f"  [+] {msg}", GREEN)
def warn(msg: str)    -> None: cprint(f"  [!] {msg}", YELLOW)
def error(msg: str)   -> None: cprint(f"  [-] {msg}", RED)

# ---------------------------------------------------------------------------
# OS detection
# ---------------------------------------------------------------------------

def detect_os() -> str:
    """Return one of: macos | kali | ubuntu | rhel | suse | windows | unknown"""
    system = platform.system()
    if system == "Windows":
        return "windows"
    if system == "Darwin":
        return "macos"
    if system == "Linux":
        release_files = ["/etc/os-release", "/usr/lib/os-release"]
        release_info = {}
        for rf in release_files:
            if os.path.exists(rf):
                with open(rf) as fh:
                    for line in fh:
                        line = line.strip()
                        if "=" in line:
                            k, _, v = line.partition("=")
                            release_info[k] = v.strip('"').lower()
                break
        name = release_info.get("ID", "")
        like = release_info.get("ID_LIKE", "")
        if "kali" in name:
            return "kali"
        if "ubuntu" in name or "ubuntu" in like:
            return "ubuntu"
        if name in ("rhel", "centos", "rocky", "almalinux", "fedora") or "rhel" in like or "fedora" in like:
            return "rhel"
        if name in ("opensuse", "sles", "suse") or "suse" in like:
            return "suse"
        # fallback debian-like
        if "debian" in name or "debian" in like:
            return "ubuntu"
    return "unknown"

# ---------------------------------------------------------------------------
# Command runner
# ---------------------------------------------------------------------------

def run(cmd: list, check: bool = False, dry_run: bool = False,
        env: dict = None, cwd: str = None) -> int:
    """Run a command; return exit code. If dry_run, just print and return 0."""
    display = " ".join(str(c) for c in cmd)
    if dry_run:
        cprint(f"    [DRY-RUN] {display}", MAGENTA)
        return 0
    info(f"Running: {display}")
    try:
        result = subprocess.run(
            cmd,
            env={**os.environ, **(env or {})},
            cwd=cwd,
        )
        if check and result.returncode != 0:
            error(f"Command failed (exit {result.returncode}): {display}")
        return result.returncode
    except FileNotFoundError:
        error(f"Executable not found for command: {display}")
        return 127
    except Exception as exc:
        error(f"Unexpected error running {display}: {exc}")
        return 1

# ---------------------------------------------------------------------------
# Privilege helpers
# ---------------------------------------------------------------------------

def is_root() -> bool:
    return hasattr(os, "getuid") and os.getuid() == 0

def require_root() -> None:
    if not is_root():
        error("This installer must be run as root (or with sudo) on Linux.")
        sys.exit(1)

# ---------------------------------------------------------------------------
# Package managers
# ---------------------------------------------------------------------------

APT_PACKAGES = [
    # aircrack-ng suite (airmon-ng, airodump-ng, aireplay-ng, aircrack-ng)
    "aircrack-ng",
    # WPS tools (wash ships with reaver)
    "reaver",
    # PMKID capture
    "hcxdumptool",
    # hcxpcapngtool and hcxpcaptool
    "hcxtools",
    # GPU/CPU hash cracking
    "hashcat",
    # LEAP/EAP-MD5 cracking
    "asleap",
    # wireless config / monitor mode helpers
    "iw", "wireless-tools", "iproute2", "net-tools",
    # build tools (needed for dragondrain-and-time C compilation)
    "build-essential",
    # Python Scapy for dragonslayer / krackattacks + client/BTM attacks
    "python3-scapy",
    # hostapd base (eaphammer builds hostapd-wpe on top of this)
    "hostapd",
    # hostapd-mana for KARMA/MANA attacks (Phase 6b)
    "hostapd-mana",
    # DHCP server for rogue AP / post-connection phases
    "dnsmasq",
    # Port scanning for post-connection discovery (Phase 10)
    "nmap",
    # ARP spoofing for post-connection MITM; dsniff provides arpspoof (Phase 10)
    "dsniff",
    # Deauth / beacon flooding / client confusion (Phase 7)
    "mdk4",
    # LLMNR/NBT-NS/MDNS poisoning for credential capture (Phase 10)
    "responder",
    # bettercap for KARMA fallback + ARP/MITM (Phase 6b / 10)
    "bettercap",
    # nl80211 libs for dragonslayer
    "libnl-3-dev", "libnl-genl-3-dev",
    # build deps for C tools
    "libssl-dev", "libpcap-dev",
    # Python / git build essentials
    "python3-pip", "python3-dev", "git",
]

DNF_PACKAGES = [
    "epel-release", "aircrack-ng", "hashcat", "reaver", "iw", "wireless-tools",
    "iproute", "net-tools", "python3-pip", "python3-devel", "git",
    "openssl-devel", "libpcap-devel", "gcc", "make",
    "libnl3-devel", "dnsmasq", "nmap", "dsniff", "mdk4",
]

ZYPPER_PACKAGES = [
    "aircrack-ng", "hashcat", "reaver", "iw", "wireless-tools", "iproute2",
    "net-tools", "python3-pip", "python3-devel", "git",
    "gcc", "make", "libnl3-devel", "dnsmasq", "nmap", "dsniff",
]

BREW_PACKAGES = ["aircrack-ng", "hashcat"]


def phase_apt(dry_run: bool) -> None:
    phase_header("PHASE 1 — System Packages (apt)")
    require_root()
    info("Updating package lists…")
    run(["apt-get", "update", "-y"], check=True, dry_run=dry_run)
    info("Upgrading installed packages…")
    run(["apt-get", "upgrade", "-y"], check=True, dry_run=dry_run)
    info(f"Installing: {' '.join(APT_PACKAGES)}")
    run(["apt-get", "install", "-y"] + APT_PACKAGES, check=True, dry_run=dry_run)


def phase_dnf(dry_run: bool) -> None:
    phase_header("PHASE 1 — System Packages (dnf)")
    require_root()
    # Install epel-release first so subsequent packages resolve
    run(["dnf", "install", "-y", "epel-release"], dry_run=dry_run)
    run(["dnf", "upgrade", "-y"], dry_run=dry_run)
    info(f"Installing: {' '.join(DNF_PACKAGES)}")
    run(["dnf", "install", "-y"] + DNF_PACKAGES, check=True, dry_run=dry_run)
    warn("hcxdumptool/hcxtools may not be available in EPEL; "
         "you may need to build from source: https://github.com/ZerBea/hcxdumptool")


def phase_zypper(dry_run: bool) -> None:
    phase_header("PHASE 1 — System Packages (zypper)")
    require_root()
    run(["zypper", "refresh"], dry_run=dry_run)
    run(["zypper", "update", "-y"], dry_run=dry_run)
    info(f"Installing: {' '.join(ZYPPER_PACKAGES)}")
    run(["zypper", "install", "-y"] + ZYPPER_PACKAGES, check=True, dry_run=dry_run)


def phase_brew(dry_run: bool) -> None:
    phase_header("PHASE 1 — System Packages (Homebrew / macOS)")
    warn("Note: Aether requires Linux for monitor mode and most wireless phases.")
    warn("macOS support is limited to passive scanning with compatible adapters.")

    brew_bin = shutil.which("brew")
    if not brew_bin:
        error("Homebrew not found. Install from https://brew.sh and re-run.")
        return

    if is_root():
        sudo_user = os.environ.get("SUDO_USER", "")
        if not sudo_user:
            warn("Running as root but SUDO_USER is not set — skipping brew install "
                 "to avoid corrupting Homebrew. Re-run as your normal user.")
            return
        base_cmd = ["sudo", "-u", sudo_user, brew_bin]
    else:
        base_cmd = [brew_bin]

    info(f"Installing brew packages: {' '.join(BREW_PACKAGES)}")
    run(base_cmd + ["install"] + BREW_PACKAGES, dry_run=dry_run)


# ---------------------------------------------------------------------------
# Pip phase (no pip packages for Aether — stdlib only)
# ---------------------------------------------------------------------------

def phase_pip(dry_run: bool) -> None:
    phase_header("PHASE 2 — Python Packages (pip)")
    info("Aether uses only Python standard-library modules — no pip packages required.")
    success("Pip phase complete (nothing to install).")


# ---------------------------------------------------------------------------
# Go phase (no Go tools for Aether)
# ---------------------------------------------------------------------------

def phase_go(dry_run: bool) -> None:
    phase_header("PHASE 3 — Go Tools")
    info("Aether does not use any Go tools — skipping.")
    success("Go phase complete (nothing to install).")


# ---------------------------------------------------------------------------
# Git phase
# ---------------------------------------------------------------------------

GIT_REPOS = [
    # krackattacks pins scapy==2.6.1 — must install BEFORE wifite2 so that
    # wifite2's scapy>=2.7.1rc1, installed last, becomes the active version.
    {
        "url":   "https://github.com/vanhoefm/krackattacks-scripts",
        "dest":  "/opt/krackattacks-scripts",
        "label": "krackattacks-scripts",
        "post_cmds": [
            ["pip3", "install", "--break-system-packages", "--ignore-installed", "-r",
             "/opt/krackattacks-scripts/krackattack/requirements.txt"],
        ],
    },
    {
        "url":   "https://github.com/vanhoefm/dragonslayer",
        "dest":  "/opt/dragonslayer",
        "label": "dragonslayer",
        "post_cmds": [
            ["pip3", "install", "--break-system-packages", "--ignore-installed", "-r",
             "/opt/dragonslayer/requirements.txt"],
        ],
    },
    {
        "url":   "https://github.com/vanhoefm/dragondrain-and-time",
        "dest":  "/opt/dragondrain-and-time",
        "label": "dragondrain-and-time",
        "post_cmds": [
            # Makefile may be in a subdirectory — resolved at runtime via _find_makefile().
            ["make", "-C", "/opt/dragondrain-and-time"],
        ],
    },
    {
        "url":   "https://github.com/s0lst1c3/eaphammer",
        "dest":  "/opt/eaphammer",
        "label": "eaphammer",
        "post_cmds": [
            # requirements.txt — resolved at runtime via _find_requirements().
            # If missing, the step is skipped and known deps are installed below.
            ["pip3", "install", "--break-system-packages", "--ignore-installed", "-r",
             "/opt/eaphammer/requirements.txt"],
            # Explicit known deps — covers the case where requirements.txt is absent.
            # flask-cors is the first thing eaphammer imports; omitting it aborts --setup.
            ["pip3", "install", "--break-system-packages", "--ignore-installed",
             "flask-cors", "flask", "twisted", "service_identity",
             "pyOpenSSL", "cryptography", "passlib", "netaddr", "pem"],
            # NOTE: eaphammer --setup (hostapd-wpe compilation) is intentionally
            # omitted here. On Python 3.13 + dnspython >= 2.4 (which ships with
            # current Kali), eventlet's monkey-patching of the socket module
            # conflicts with trio via dns.quic, causing an AttributeError before
            # --setup can do anything. This is an upstream eaphammer bug. To
            # compile hostapd-wpe manually once the conflict is resolved, run:
            #   python3 /opt/eaphammer/eaphammer --setup
        ],
    },
    # wifite2 goes LAST so its scapy>=2.7.1rc1 overwrites any older pin.
    {
        "url":   "https://github.com/kimocoder/wifite2",
        "dest":  "/opt/wifite2",
        "label": "wifite2",
        "post_cmds": [
            ["pip3", "install", "--break-system-packages", "--ignore-installed",
             "/opt/wifite2/"],
        ],
    },
]


def _find_requirements(dest: str, hinted_path: str) -> str | None:
    """Locate a requirements file.

    Returns hinted_path if it exists. Otherwise searches dest recursively for
    any requirements*.txt and returns the first match. Returns None if nothing found.
    """
    if Path(hinted_path).exists():
        return hinted_path
    dest_path = Path(dest)
    if dest_path.exists():
        for candidate in sorted(dest_path.rglob("requirements*.txt")):
            warn(f"  Hinted path not found; using {candidate} instead")
            return str(candidate)
    return None


_MAKEFILE_SKIP_DIRS = {
    "contrib", "test", "tests", "examples", "doc", "docs", ".git",
    # Skip bundled auxiliary tooling that ships inside some repos
    "scripts", "airgraph-ng",
}


def _find_makefile(dest: str, hinted_dir: str) -> str | None:
    """Locate a directory that contains a Makefile, excluding auxiliary directories.

    Checks hinted_dir first, then searches dest recursively skipping contrib/,
    test/, and similar paths that hold build-support files rather than the main tool.
    Returns the containing directory path, or None if nothing suitable is found.
    """
    if (Path(hinted_dir) / "Makefile").exists():
        return hinted_dir
    dest_path = Path(dest)
    if dest_path.exists():
        for mf in sorted(dest_path.rglob("Makefile")):
            if any(part in _MAKEFILE_SKIP_DIRS for part in mf.parts):
                continue
            warn(f"Makefile not at {hinted_dir}; building in {mf.parent} instead")
            return str(mf.parent)
    warn(f"No suitable Makefile found under {dest} — skipping build step")
    return None


def clone_or_update(repo: dict, dry_run: bool) -> None:
    url      = repo["url"]
    dest     = repo["dest"]
    label    = repo["label"]
    dest_path = Path(dest)

    if dest_path.exists():
        info(f"{label}: directory exists — pulling latest changes…")
        rc = run(["git", "-C", dest, "pull", "--ff-only"], dry_run=dry_run)
        if rc != 0:
            warn(f"{label}: git pull failed — continuing with existing clone.")
    else:
        info(f"{label}: cloning {url} → {dest}")
        rc = run(["git", "clone", "--depth=1", url, dest], check=True, dry_run=dry_run)
        if rc != 0:
            error(f"{label}: clone failed — skipping post-install steps.")
            return

    for cmd in repo.get("post_cmds") or []:
        resolved: list = list(cmd)
        skip = False

        # Resolve requirements.txt paths — hinted path may not match actual layout.
        for i, arg in enumerate(resolved):
            if isinstance(arg, str) and arg.endswith("requirements.txt"):
                actual = _find_requirements(dest, arg)
                if actual is None:
                    warn(f"{label}: no requirements file found (tried {arg}) — skipping step")
                    skip = True
                    break
                resolved[i] = actual
        if skip:
            continue

        # Resolve make -C <dir> — the Makefile may be in a subdirectory.
        if resolved and resolved[0] == "make" and "-C" in resolved:
            ci = resolved.index("-C")
            if ci + 1 < len(resolved):
                actual_dir = _find_makefile(dest, resolved[ci + 1])
                if actual_dir is None:
                    warn(f"{label}: no Makefile found under {dest} — skipping build")
                    skip = True
                else:
                    resolved[ci + 1] = actual_dir
        if skip:
            continue

        info(f"{label}: post-install: {' '.join(str(c) for c in resolved)}")
        run(resolved, dry_run=dry_run)


def phase_git(os_id: str, dry_run: bool) -> None:
    phase_header("PHASE 4 — Git Repositories")
    if os_id == "macos":
        warn("Skipping git tool clones on macOS — these tools require Linux.")
        return
    for repo in GIT_REPOS:
        clone_or_update(repo, dry_run)
    warn("eaphammer --setup (hostapd-wpe compilation) was skipped.")
    warn("Python 3.13 + system dnspython >= 2.4 conflict prevents it from running.")
    warn("To compile hostapd-wpe manually after resolving the conflict:")
    warn("  python3 /opt/eaphammer/eaphammer --setup")
    success("Git phase complete.")


# ---------------------------------------------------------------------------
# Symlinks
# ---------------------------------------------------------------------------

SYMLINKS = {
    "/usr/local/bin/aether":    "/opt/pr0t31n/Aether/aether.py",
    "/usr/local/bin/eaphammer": "/opt/eaphammer/eaphammer",
}


def phase_symlinks(dry_run: bool) -> None:
    phase_header("PHASE 5 — Symlinks")
    for link, target in SYMLINKS.items():
        target_path = Path(target)
        link_path   = Path(link)
        if not target_path.exists():
            warn(f"Target not found: {target} — symlink will be created anyway.")
        if link_path.is_symlink() or link_path.exists():
            info(f"Removing existing: {link}")
            if not dry_run:
                try:
                    link_path.unlink()
                except OSError as exc:
                    error(f"Could not remove {link}: {exc}")
                    continue
        info(f"Creating symlink: {link} → {target}")
        if not dry_run:
            try:
                link_path.symlink_to(target)
                if target_path.exists():
                    target_path.chmod(0o755)
                success(f"Symlink created: {link}")
            except OSError as exc:
                error(f"Could not create symlink {link}: {exc}")


# ---------------------------------------------------------------------------
# Service installation
# ---------------------------------------------------------------------------

SYSTEMD_SERVICE = """\
[Unit]
Description=Aether Wireless Penetration Testing Orchestrator
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/bin/python3 /opt/pr0t31n/Aether/aether.py
WorkingDirectory=/opt/pr0t31n/Aether
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
"""

LAUNCHD_PLIST = """\
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.pr0t31n.aether</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/bin/python3</string>
        <string>/opt/pr0t31n/Aether/aether.py</string>
    </array>
    <key>WorkingDirectory</key>
    <string>/opt/pr0t31n/Aether</string>
    <key>RunAtLoad</key>
    <false/>
    <key>KeepAlive</key>
    <false/>
    <key>StandardOutPath</key>
    <string>/var/log/aether.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/aether.err</string>
</dict>
</plist>
"""


def phase_service(os_id: str, dry_run: bool) -> None:
    phase_header("PHASE 6 — Service Installation")
    if os_id in ("kali", "ubuntu", "rhel", "suse"):
        service_path = Path("/etc/systemd/system/pr0t31n-aether.service")
        info(f"Writing systemd unit: {service_path}")
        if not dry_run:
            try:
                service_path.write_text(SYSTEMD_SERVICE)
                run(["systemctl", "daemon-reload"], dry_run=dry_run)
                run(["systemctl", "enable", "pr0t31n-aether"], dry_run=dry_run)
                success("Systemd service installed and enabled.")
            except OSError as exc:
                error(f"Failed to write service file: {exc}")
        else:
            cprint(f"    [DRY-RUN] Would write {service_path}", MAGENTA)

    elif os_id == "macos":
        plist_path = Path("/Library/LaunchDaemons/com.pr0t31n.aether.plist")
        info(f"Writing launchd plist: {plist_path}")
        if not dry_run:
            try:
                plist_path.write_text(LAUNCHD_PLIST)
                run(["launchctl", "load", str(plist_path)], dry_run=dry_run)
                success("Launchd plist installed and loaded.")
            except OSError as exc:
                error(f"Failed to write plist: {exc}")
        else:
            cprint(f"    [DRY-RUN] Would write {plist_path}", MAGENTA)
    else:
        warn("Service installation skipped for this OS.")


# ---------------------------------------------------------------------------
# Post-install verification
# ---------------------------------------------------------------------------

VERIFY_TOOLS = [
    # aircrack-ng suite
    "aircrack-ng", "airodump-ng", "aireplay-ng", "airmon-ng",
    # WPS
    "reaver", "wash",
    # PMKID capture / conversion
    "hcxdumptool", "hcxpcapngtool",
    # cracking
    "hashcat", "asleap",
    # automated wifi attacks
    "wifite",
    # EAP attacks
    "eaphammer",
    # rogue AP / post-connection phases
    "hostapd", "dnsmasq", "nmap", "arpspoof", "mdk4", "responder", "bettercap",
]


def phase_verify() -> None:
    phase_header("POST-INSTALL SUMMARY")
    all_ok = True
    for tool in VERIFY_TOOLS:
        found = shutil.which(tool)
        if found:
            success(f"{tool:25s} found at {found}")
        else:
            warn(f"{tool:25s} NOT FOUND")
            all_ok = False

    # Check git-cloned tools that don't land in PATH
    git_tool_paths = [
        ("/opt/dragonslayer",          "dragonslayer"),
        ("/opt/dragondrain-and-time",  "dragondrain-and-time"),
        ("/opt/krackattacks-scripts",  "krackattacks-scripts"),
    ]
    for path, label in git_tool_paths:
        if Path(path).exists():
            success(f"{label:25s} found at {path}")
        else:
            warn(f"{label:25s} NOT FOUND at {path}")
            all_ok = False

    print()
    if all_ok:
        success("All tools verified successfully.")
    else:
        warn("Some tools were not found. Check the output above and install manually if needed.")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Aether installer — wireless penetration testing orchestrator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--skip-apt",  action="store_true", help="Skip system package installation")
    p.add_argument("--skip-pip",  action="store_true", help="Skip pip package installation")
    p.add_argument("--skip-go",   action="store_true", help="Skip Go tool installation")
    p.add_argument("--skip-git",  action="store_true", help="Skip git repository cloning")
    p.add_argument("--check",     action="store_true", help="Dry-run — print commands without executing")
    return p.parse_args()


def main() -> None:
    # Line-buffer stdout so phase headers appear before subprocess output in logs
    sys.stdout.reconfigure(line_buffering=True)

    args = parse_args()
    dry_run = args.check

    cprint("\n" + "=" * 60, GREEN, bold=True)
    cprint("  Aether Installer  —  v1.6.0", GREEN, bold=True)
    cprint("  Wireless Penetration Testing Orchestrator", GREEN, bold=True)
    cprint("=" * 60 + "\n", GREEN, bold=True)

    if dry_run:
        warn("DRY-RUN MODE — no changes will be made to this system.\n")

    os_id = detect_os()
    info(f"Detected OS: {os_id}")

    # Windows gate
    if os_id == "windows":
        error("Aether is designed for Linux. Windows is not supported.")
        error("Wireless monitor mode and injection require Linux with a compatible adapter.")
        sys.exit(1)

    # macOS advisory
    if os_id == "macos":
        warn("macOS detected. Monitor mode and most Aether phases require Linux.")
        warn("Only a limited subset of tools will be installed via Homebrew.")

    # Phase 1 — system packages
    if not args.skip_apt:
        if os_id in ("kali", "ubuntu"):
            phase_apt(dry_run)
        elif os_id == "rhel":
            phase_dnf(dry_run)
        elif os_id == "suse":
            phase_zypper(dry_run)
        elif os_id == "macos":
            phase_brew(dry_run)
        else:
            warn(f"Unknown OS '{os_id}' — skipping system package phase.")
    else:
        info("Skipping system package phase (--skip-apt).")

    # Phase 2 — pip
    if not args.skip_pip:
        phase_pip(dry_run)
    else:
        info("Skipping pip phase (--skip-pip).")

    # Phase 3 — Go
    if not args.skip_go:
        phase_go(dry_run)
    else:
        info("Skipping Go phase (--skip-go).")

    # Phase 4 — Git
    if not args.skip_git:
        phase_git(os_id, dry_run)
    else:
        info("Skipping git phase (--skip-git).")

    # Phase 5 — Symlinks
    if not dry_run and os_id != "windows":
        if is_root():
            phase_symlinks(dry_run)
        else:
            warn("Not running as root — skipping symlink creation.")
    elif dry_run:
        phase_symlinks(dry_run)

    # Phase 6 — Service
    if is_root() or dry_run:
        phase_service(os_id, dry_run)
    else:
        warn("Not running as root — skipping service installation.")

    # Verify
    phase_verify()

    print()
    cprint("  Aether installation complete.", GREEN, bold=True)
    cprint("  Run:  aether --help  to get started.\n", CYAN)


if __name__ == "__main__":
    main()
