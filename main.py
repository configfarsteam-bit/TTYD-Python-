#!/usr/bin/env python3

"""
TTYD Python - blitz.cloud compatible

Features:
- No Python packages required
- Downloads official ttyd binary
- Verifies SHA-256
- Verifies ELF binary
- Works on amd64/x86_64
- Uses PORT from blitz.cloud
- Binds to 0.0.0.0 by default
- Works as root or non-root
- Generates a secure password when none is supplied
- Starts ttyd directly with os.execv()
"""

from __future__ import annotations

import hashlib
import os
import platform
import secrets
import shutil
import string
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path


# ============================================================
# CONFIGURATION
# ============================================================

TTYD_VERSION = os.environ.get(
    "TTYD_VERSION",
    "1.7.7",
).strip()

# blitz.cloud provides PORT.
# 8080 is the safe default for this platform.
PORT = os.environ.get(
    "PORT",
    os.environ.get(
        "TTYD_PORT",
        "8080",
    ),
).strip()

# Public container interface.
# Do NOT use 127.0.0.1 for a cloud web service.
BIND = os.environ.get(
    "TTYD_BIND",
    "0.0.0.0",
).strip()

USERNAME = os.environ.get(
    "TTYD_USER",
    "admin",
).strip()

PASSWORD = os.environ.get(
    "TTYD_PASSWORD",
)

NO_START = (
    os.environ.get(
        "TTYD_NO_START",
        "0",
    ).strip()
    == "1"
)

# Install inside the user's home directory.
# This works without root.
INSTALL_DIR = Path(
    os.environ.get(
        "TTYD_INSTALL_DIR",
        str(Path.home() / ".local" / "bin"),
    )
).expanduser()

TTYD_PATH = INSTALL_DIR / "ttyd"

BASE_URL = os.environ.get(
    "TTYD_BASE_URL",
    (
        "https://github.com/tsl0922/ttyd/releases/"
        f"download/{TTYD_VERSION}"
    ),
).rstrip("/")

try:
    MAX_DOWNLOAD_BYTES = int(
        os.environ.get(
            "TTYD_MAX_DOWNLOAD_BYTES",
            str(100 * 1024 * 1024),
        )
    )
except ValueError:
    MAX_DOWNLOAD_BYTES = 100 * 1024 * 1024


# ============================================================
# ARCHITECTURE
# ============================================================

ARCH_MAP = {
    "x86_64": "x86_64",
    "amd64": "x86_64",

    "aarch64": "aarch64",
    "arm64": "aarch64",

    "armv7l": "armhf",
    "armv7": "armhf",

    "armv6l": "arm",
    "armv6": "arm",

    "i686": "i686",
    "x86": "i686",

    "s390x": "s390x",

    "mips": "mips",
    "mips64": "mips64",
    "mipsel": "mipsel",
    "mips64el": "mips64el",
}


# ============================================================
# OUTPUT
# ============================================================

def info(message: str) -> None:
    print(f"[+] {message}", flush=True)


def warning(message: str) -> None:
    print(f"[!] {message}", flush=True)


def die(message: str, code: int = 1) -> None:
    print(
        f"[ERROR] {message}",
        file=sys.stderr,
        flush=True,
    )
    raise SystemExit(code)


# ============================================================
# VALIDATION
# ============================================================

def validate_config() -> None:
    """Validate all environment configuration."""

    if not TTYD_VERSION:
        die("TTYD_VERSION cannot be empty.")

    if any(char in TTYD_VERSION for char in "\r\n"):
        die("TTYD_VERSION contains invalid characters.")

    if not BASE_URL.startswith(
        (
            "https://",
            "http://",
        )
    ):
        die(
            "TTYD_BASE_URL must start with "
            "http:// or https://."
        )

    try:
        port_number = int(PORT)
    except ValueError:
        die("PORT must be a number.")

    if not 1 <= port_number <= 65535:
        die("PORT must be between 1 and 65535.")

    if not BIND:
        die("TTYD_BIND cannot be empty.")

    if any(char in BIND for char in "\r\n"):
        die("TTYD_BIND contains invalid characters.")

    if not USERNAME:
        die("TTYD_USER cannot be empty.")

    if any(
        char in USERNAME
        for char in ":\r\n"
    ):
        die(
            "TTYD_USER cannot contain ':', "
            "CR or LF."
        )

    if PASSWORD is not None:
        if not PASSWORD:
            die(
                "TTYD_PASSWORD cannot be empty."
            )

        if any(
            char in PASSWORD
            for char in "\r\n"
        ):
            die(
                "TTYD_PASSWORD cannot contain "
                "CR or LF."
            )

    if MAX_DOWNLOAD_BYTES < 4096:
        die(
            "TTYD_MAX_DOWNLOAD_BYTES must be "
            "at least 4096."
        )

    if INSTALL_DIR == Path("/"):
        die("TTYD_INSTALL_DIR cannot be '/'.")


# ============================================================
# ARCHITECTURE DETECTION
# ============================================================

def detect_architecture() -> tuple[str, str]:
    machine = (
        platform.machine()
        .strip()
        .lower()
    )

    asset_arch = ARCH_MAP.get(machine)

    if not asset_arch:
        supported = ", ".join(
            sorted(
                set(
                    ARCH_MAP.values()
                )
            )
        )

        die(
            f"Unsupported architecture: {machine}\n"
            f"Supported: {supported}"
        )

    asset_name = f"ttyd.{asset_arch}"

    return machine, asset_name


# ============================================================
# HTTP
# ============================================================

def create_request(
    url: str,
) -> urllib.request.Request:

    return urllib.request.Request(
        url,
        headers={
            "User-Agent": (
                "ConfigFars-ttyd-installer/4.0"
            ),
        },
    )


def download_bytes(
    url: str,
    timeout: int = 60,
) -> bytes:

    info(f"Downloading: {url}")

    try:
        with urllib.request.urlopen(
            create_request(url),
            timeout=timeout,
        ) as response:

            data = response.read(
                MAX_DOWNLOAD_BYTES + 1
            )

    except (
        urllib.error.URLError,
        TimeoutError,
        OSError,
    ) as exc:

        die(
            f"Download failed: {exc}"
        )

    if len(data) > MAX_DOWNLOAD_BYTES:
        die(
            "Downloaded data exceeded "
            "the maximum allowed size."
        )

    return data


# ============================================================
# CHECKSUM
# ============================================================

def get_official_sha256(
    asset_name: str,
) -> str:

    sums_url = (
        f"{BASE_URL}/SHA256SUMS"
    )

    data = download_bytes(
        sums_url
    ).decode(
        "utf-8",
        errors="strict",
    )

    for raw_line in data.splitlines():

        line = raw_line.strip()

        if not line:
            continue

        if line.startswith("#"):
            continue

        parts = line.split()

        if len(parts) < 2:
            continue

        digest = parts[0].strip()

        filename = (
            parts[-1]
            .strip()
            .lstrip("*")
        )

        if Path(filename).name != asset_name:
            continue

        if len(digest) != 64:
            die(
                "Invalid SHA-256 length "
                f"for {asset_name}."
            )

        if any(
            char not in string.hexdigits
            for char in digest
        ):
            die(
                f"Invalid SHA-256 for "
                f"{asset_name}."
            )

        return digest.lower()

    die(
        f"SHA-256 entry for "
        f"{asset_name} was not found."
    )

    return ""


# ============================================================
# INSTALL TTYD
# ============================================================

def download_and_install(
    asset_name: str,
    expected_sha256: str,
) -> None:

    try:
        INSTALL_DIR.mkdir(
            parents=True,
            exist_ok=True,
            mode=0o755,
        )

    except OSError as exc:
        die(
            f"Cannot create install directory: "
            f"{exc}"
        )

    if not INSTALL_DIR.is_dir():
        die(
            f"Install path is not a directory: "
            f"{INSTALL_DIR}"
        )

    if INSTALL_DIR.is_symlink():
        die(
            "Install directory must not be "
            "a symbolic link."
        )

    temp_path: Path | None = None

    try:

        temp_fd, temp_name = (
            tempfile.mkstemp(
                prefix=".ttyd-",
                dir=str(INSTALL_DIR),
            )
        )

        os.close(temp_fd)

        temp_path = Path(temp_name)

        url = (
            f"{BASE_URL}/{asset_name}"
        )

        info(
            f"Downloading ttyd binary: {url}"
        )

        sha256 = hashlib.sha256()

        total = 0

        try:

            with (
                urllib.request.urlopen(
                    create_request(url),
                    timeout=120,
                ) as response,
                temp_path.open(
                    "wb"
                ) as output,
            ):

                while True:

                    chunk = response.read(
                        1024 * 1024
                    )

                    if not chunk:
                        break

                    total += len(chunk)

                    if (
                        total
                        > MAX_DOWNLOAD_BYTES
                    ):
                        die(
                            "ttyd binary exceeded "
                            "the maximum download size."
                        )

                    output.write(chunk)

                    sha256.update(chunk)

                output.flush()

                os.fsync(
                    output.fileno()
                )

        except (
            urllib.error.URLError,
            TimeoutError,
            OSError,
        ) as exc:

            die(
                f"ttyd download failed: {exc}"
            )

        if total < 4096:
            die(
                "Downloaded ttyd binary is "
                "unexpectedly small."
            )

        actual_sha256 = (
            sha256.hexdigest()
        )

        info(
            "Verifying SHA-256..."
        )

        if not secrets.compare_digest(
            actual_sha256,
            expected_sha256,
        ):
            die(
                "SHA-256 verification failed.\n"
                f"Expected: {expected_sha256}\n"
                f"Actual:   {actual_sha256}"
            )

        info(
            "SHA-256 verification passed."
        )

        with temp_path.open(
            "rb"
        ) as binary_file:

            magic = binary_file.read(4)

        if magic != b"\x7fELF":
            die(
                "Downloaded file is not "
                "a valid ELF executable."
            )

        info(
            "ELF executable verified."
        )

        try:
            os.chmod(
                temp_path,
                0o755,
            )
        except OSError as exc:
            die(
                f"Cannot make ttyd executable: "
                f"{exc}"
            )

        # Atomic replacement.
        os.replace(
            temp_path,
            TTYD_PATH,
        )

        temp_path = None

        info(
            f"ttyd installed at {TTYD_PATH}"
        )

        info(
            f"Binary size: {total} bytes"
        )

    finally:

        if temp_path is not None:

            try:
                temp_path.unlink(
                    missing_ok=True
                )
            except OSError:
                pass


# ============================================================
# VERIFY TTYD
# ============================================================

def verify_ttyd() -> None:

    if not TTYD_PATH.exists():
        die(
            f"ttyd was not installed: "
            f"{TTYD_PATH}"
        )

    if not TTYD_PATH.is_file():
        die(
            f"ttyd path is not a file: "
            f"{TTYD_PATH}"
        )

    if not os.access(
        TTYD_PATH,
        os.X_OK,
    ):
        die(
            f"ttyd is not executable: "
            f"{TTYD_PATH}"
        )

    info(
        "Running ttyd --version..."
    )

    try:

        result = subprocess.run(
            [
                str(TTYD_PATH),
                "--version",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=15,
            check=False,
        )

    except (
        OSError,
        subprocess.SubprocessError,
    ) as exc:

        die(
            f"Could not execute ttyd: {exc}"
        )

    output = (
        result.stdout
        + result.stderr
    ).strip()

    if output:
        print(
            output,
            flush=True,
        )

    if result.returncode != 0:
        die(
            "ttyd --version returned "
            f"exit code {result.returncode}."
        )

    if "ttyd" not in output.lower():
        warning(
            "ttyd version output did not "
            "contain the word 'ttyd'."
        )

    info(
        "ttyd binary is working."
    )


# ============================================================
# SHELL
# ============================================================

def get_shell() -> str:

    configured_shell = (
        os.environ.get(
            "SHELL"
        )
    )

    if configured_shell:

        configured_path = Path(
            configured_shell
        )

        if (
            configured_path.is_file()
            and os.access(
                configured_path,
                os.X_OK,
            )
        ):
            return str(
                configured_path
            )

    shell_candidates = (
        "bash",
        "sh",
    )

    for shell_name in shell_candidates:

        shell_path = shutil.which(
            shell_name
        )

        if shell_path:
            return shell_path

    die(
        "Neither bash nor sh was found."
    )

    return ""


# ============================================================
# PASSWORD
# ============================================================

def create_password() -> str:

    if PASSWORD is not None:
        return PASSWORD

    alphabet = (
        string.ascii_letters
        + string.digits
    )

    return "".join(
        secrets.choice(
            alphabet
        )
        for _ in range(32)
    )


# ============================================================
# START TTYD
# ============================================================

def start_ttyd(
    password: str,
) -> None:

    shell = get_shell()

    home = Path.home()

    if not home.is_dir():
        die(
            f"Home directory does not exist: "
            f"{home}"
        )

    current_user = os.environ.get(
        "USER",
        "unknown",
    )

    print()
    print("=" * 60)
    print(" ConfigFars TTYD")
    print("=" * 60)
    print(
        f"Address : http://{BIND}:{PORT}"
    )
    print(
        f"Username: {USERNAME}"
    )
    print(
        f"Linux user: {current_user}"
    )
    print(
        f"Home    : {home}"
    )
    print(
        f"Shell   : {shell}"
    )
    print("=" * 60)
    print()
    print(
        "[+] Starting ttyd..."
    )
    print(
        "[+] ttyd will inherit the current "
        "container user."
    )
    print(
        "[+] Press Ctrl+C to stop."
    )
    print()

    command = [
        str(TTYD_PATH),

        "--port",
        PORT,

        "--interface",
        BIND,

        "--writable",

        "--credential",
        f"{USERNAME}:{password}",

        "--cwd",
        str(home),

        shell,
    ]

    # Replace Python with ttyd.
    # This makes ttyd PID 1 inside the container.
    try:

        os.execv(
            str(TTYD_PATH),
            command,
        )

    except OSError as exc:

        die(
            f"Failed to start ttyd: {exc}"
        )


# ============================================================
# MAIN
# ============================================================

def main() -> None:

    print()
    print("=" * 60)
    print(" TTYD Python - blitz.cloud")
    print(" No Python packages required")
    print("=" * 60)
    print()

    validate_config()

    machine, asset_name = (
        detect_architecture()
    )

    info(
        f"Architecture: {machine}"
    )

    info(
        f"TTYD version: {TTYD_VERSION}"
    )

    info(
        f"TTYD asset: {asset_name}"
    )

    info(
        f"Install directory: {INSTALL_DIR}"
    )

    info(
        f"Web port: {PORT}"
    )

    info(
        f"Bind address: {BIND}"
    )

    print()

    # --------------------------------------------------------
    # Download official checksum
    # --------------------------------------------------------

    expected_sha256 = (
        get_official_sha256(
            asset_name
        )
    )

    info(
        f"Official SHA-256: "
        f"{expected_sha256}"
    )

    print()

    # --------------------------------------------------------
    # Download + verify + install
    # --------------------------------------------------------

    download_and_install(
        asset_name,
        expected_sha256,
    )

    print()

    # --------------------------------------------------------
    # Verify executable
    # --------------------------------------------------------

    verify_ttyd()

    print()

    # --------------------------------------------------------
    # Installation-only mode
    # --------------------------------------------------------

    if NO_START:

        info(
            "TTYD_NO_START=1 is enabled."
        )

        info(
            "Installation and verification "
            "completed."
        )

        return

    # --------------------------------------------------------
    # Password
    # --------------------------------------------------------

    generated_password = (
        create_password()
    )

    if PASSWORD is None:

        warning(
            "TTYD_PASSWORD was not provided."
        )

        info(
            "A random password was generated:"
        )

        print(
            generated_password,
            flush=True,
        )

    else:

        info(
            "Using TTYD_PASSWORD from "
            "the environment."
        )

    print()

    # --------------------------------------------------------
    # Start
    # --------------------------------------------------------

    start_ttyd(
        generated_password
    )


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":

    try:

        main()

    except KeyboardInterrupt:

        print(
            "\n[+] Stopped by user.",
            flush=True,
        )

        sys.exit(130)

    except SystemExit:

        raise

    except Exception as exc:

        print(
            "\n[ERROR] Unexpected error:",
            file=sys.stderr,
            flush=True,
        )

        print(
            repr(exc),
            file=sys.stderr,
            flush=True,
        )

        sys.exit(1)
