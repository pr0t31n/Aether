#!/usr/bin/env python3
"""
install.py — Aether Wireless Penetration Testing Orchestrator
=============================================================
Installs all Python packages from requirements.txt and all required system
tools and GitHub-based attack tools. Platform-aware: supports Linux (apt)
and macOS (brew). GitHub tools are cloned to /opt/<toolname>/.

Usage:
    sudo python3 install.py
"""

import os
import platform
import subprocess
import sys
from pathlib import Path

REQUIREMENTS_FILE = Path(__file__).parent / "requirements.txt"

# System packages required by platform
APT_PACKAGES = [
    "aircrack-ng",        # airmon-ng, airodump-ng — monitor mode and AP scanning
    "wireless-tools",     # iwlist fallback scanner
    "iw",                 # iw monitor mode fallback
    "iproute2",           # ip link management
]

BREW_PACKAGES = [
    # macOS does not support monitor mode for most wireless attacks;
    # packages listed here are best-effort for development/testing only.
    "aircrack-ng",
]

# GitHub-based tools: (repo_url, clone_target_dir, friendly_name)
GITHUB_TOOLS = [
    (
        "https://github.com/kimocoder/wifite2",
        "/opt/wifite2",
        "wifite2 (by kimocoder / originally derv82)",
    ),
    (
        "https://github.com/s0lst1c3/eaphammer",
        "/opt/eaphammer",
        "EAPHammer (by s0lst1c3)",
    ),
    (
        "https://github.com/vanhoefm/dragonslayer",
        "/opt/dragonslayer",
        "dragonslayer (by Mathy Vanhoef @vanhoefm)",
    ),
    (
        "https://github.com/vanhoefm/dragondrain-and-time",
        "/opt/dragondrain-and-time",
        "dragondrain (by Mathy Vanhoef @vanhoefm)",
    ),
    (
        "https://github.com/vanhoefm/krackattacks-scripts",
        "/opt/krackattacks-scripts",
        "krackattacks-scripts (by Mathy Vanhoef @vanhoefm)",
    ),
]


def _run(cmd: list, check: bool = True, **kwargs) -> subprocess.CompletedProcess:
    print(f"  $ {' '.join(str(c) for c in cmd)}")
    return subprocess.run(cmd, check=check, **kwargs)


def _detect_platform() -> str:
    """Return 'linux', 'macos', or 'unknown'."""
    system = platform.system().lower()
    if system == "linux":
        return "linux"
    if system == "darwin":
        return "macos"
    return "unknown"


def install_python_packages() -> None:
    print("\n[*] Installing Python packages from requirements.txt ...")
    if not REQUIREMENTS_FILE.exists():
        print(f"    [!] requirements.txt not found at {REQUIREMENTS_FILE}")
        return
    try:
        _run([sys.executable, "-m", "pip", "install", "--break-system-packages", "-r", str(REQUIREMENTS_FILE)])
        print("    [+] Python packages installed.")
    except subprocess.CalledProcessError as exc:
        print(f"    [!] pip install failed: {exc}")


def install_system_packages_linux() -> None:
    print("\n[*] Installing system packages via apt ...")
    try:
        _run(["apt-get", "update", "-qq"], check=False)
        _run(["apt-get", "install", "-y"] + APT_PACKAGES)
        print("    [+] System packages installed.")
    except subprocess.CalledProcessError as exc:
        print(f"    [!] apt install failed: {exc}")
    except FileNotFoundError:
        print("    [!] apt-get not found — are you on a Debian/Ubuntu system?")


def install_system_packages_macos() -> None:
    print("\n[*] Installing system packages via brew ...")
    try:
        _brew_user = os.environ.get("SUDO_USER", "")
        _brew_pfx  = ["sudo", "-u", _brew_user] if _brew_user and _brew_user != "root" else []
        _run(_brew_pfx + ["brew", "install"] + BREW_PACKAGES)
        print("    [+] Homebrew packages installed.")
    except subprocess.CalledProcessError as exc:
        print(f"    [!] brew install failed: {exc}")
    except FileNotFoundError:
        print("    [!] brew not found — install Homebrew from https://brew.sh first.")


def clone_github_tools() -> None:
    print("\n[*] Cloning GitHub-based attack tools to /opt/ ...")
    for repo_url, target_dir, friendly_name in GITHUB_TOOLS:
        target = Path(target_dir)
        print(f"\n  [{friendly_name}]")
        print(f"    Repo   : {repo_url}")
        print(f"    Target : {target_dir}")
        if target.exists():
            print(f"    [i] Already exists — pulling latest changes ...")
            try:
                _run(["git", "-C", str(target), "pull", "--ff-only"], check=False)
            except Exception as exc:
                print(f"    [!] git pull failed: {exc}")
        else:
            try:
                target.parent.mkdir(parents=True, exist_ok=True)
                _run(["git", "clone", "--depth=1", repo_url, str(target)])
                print(f"    [+] Cloned to {target_dir}")
            except subprocess.CalledProcessError as exc:
                print(f"    [!] git clone failed: {exc}")
            except FileNotFoundError:
                print("    [!] git not found — install git first.")
                return

    # Post-clone: install eaphammer Python dependencies if present
    eaphammer_req = Path("/opt/eaphammer/requirements.txt")
    if eaphammer_req.exists():
        print("\n  [*] Installing EAPHammer Python dependencies ...")
        try:
            _run([sys.executable, "-m", "pip", "install", "--break-system-packages", "-r", str(eaphammer_req)])
            print("    [+] EAPHammer dependencies installed.")
        except subprocess.CalledProcessError as exc:
            print(f"    [!] EAPHammer pip install failed: {exc}")


def _install_symlinks() -> None:
    """Create /usr/local/bin symlinks for all-user access (including root)."""
    from pathlib import Path as _Path
    import stat as _stat
    app_dir = _Path(__file__).parent.resolve()
    bin_dir = _Path("/usr/local/bin")

    # (script_relative_to_app_dir, symlink_name_in_bin_dir)
    LINKS = [
        ("aether.py", "aether"),
    ]

    try:
        bin_dir.mkdir(parents=True, exist_ok=True)
    except PermissionError:
        print("[!] Cannot access /usr/local/bin — run as root to install symlinks.")
        return

    for script_rel, link_name in LINKS:
        script = app_dir / script_rel
        link   = bin_dir / link_name
        if not script.exists():
            print(f"[~] Script not found, skipping symlink: {script}")
            continue
        # Make script executable
        current = script.stat().st_mode
        script.chmod(current | _stat.S_IXUSR | _stat.S_IXGRP | _stat.S_IXOTH)
        # Ensure shebang
        try:
            text = script.read_text(encoding="utf-8", errors="ignore")
            if not text.startswith("#!"):
                script.write_text("#!/usr/bin/env python3\n" + text, encoding="utf-8")
        except Exception:
            pass
        # Create/replace symlink
        if link.exists() or link.is_symlink():
            link.unlink()
        link.symlink_to(script)
        print(f"[+] Symlink installed: {link}  →  {script}")


def main() -> None:
    print("=" * 60)
    print("  Aether — Wireless Penetration Testing Orchestrator")
    print("  Installer")
    print("=" * 60)

    os_type = _detect_platform()
    print(f"\n[i] Detected platform: {platform.system()} ({os_type})")

    if os_type == "linux" and os.geteuid() != 0:
        print("[!] Warning: not running as root. System package installation may fail.")
        print("    Re-run with: sudo python3 install.py\n")

    # Step 1: Python packages
    install_python_packages()

    # Step 2: System packages
    if os_type == "linux":
        install_system_packages_linux()
    elif os_type == "macos":
        install_system_packages_macos()
    else:
        print(f"\n[!] Unsupported platform '{os_type}' — skipping system package install.")
        print("    Install aircrack-ng and wireless-tools manually.")

    # Step 3: GitHub tools
    clone_github_tools()

    # Step 4: Symlinks
    _install_symlinks()

    print("\n" + "=" * 60)
    print("  Installation complete.")
    print("  Review any [!] warnings above before running aether.py.")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    main()
