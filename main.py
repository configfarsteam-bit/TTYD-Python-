#!/usr/bin/env python3

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


TTYD_VERSION = "1.7.7"

PORT = os.environ.get("PORT", "8080")
BIND = "0.0.0.0"

USERNAME = os.environ.get("TTYD_USER", "admin")
PASSWORD = os.environ.get("TTYD_PASSWORD")

INSTALL_DIR = (
    Path.home()
    / ".local"
    / "bin"
)

TTYD_PATH = INSTALL_DIR / "ttyd"

BASE_URL = (
    "https://github.com/tsl0922/ttyd/releases/download/"
    f"{TTYD_VERSION}"
)

MAX_DOWNLOAD_BYTES = 100 * 1024 * 1024


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


def die(message: str) -> None:
    print(f"[ERROR] {message}", file=sys.stderr, flush=True)
    sys.exit(1)


def request(url: str):
    return urllib.request.Request(
        url,
        headers={
            "User-Agent": "ConfigFars-TTYD/1.0"
        },
    )


def detect_architecture() -> str:
    machine = platform.machine().lower()

    if machine not in ARCH_MAP:
        die(
            f"Unsupported architecture: {machine}"
        )

    return ARCH_MAP[machine]


def download(url: str) -> bytes:
    try:
        with urllib.request.urlopen(
            request(url),
            timeout=120,
        ) as response:
            data = response.read(
                MAX_DOWNLOAD_BYTES + 1
            )

    except (
        urllib.error.URLError,
        TimeoutError,
        OSError,
    ) as exc:
        die(f"Download failed: {exc}")

    if len(data) > MAX_DOWNLOAD_BYTES:
        die("Downloaded file is too large.")

    return data


def get_sha256(asset_name: str) -> str:
    url = f"{BASE_URL}/SHA256SUMS"

    data = download(url).decode(
        "utf-8",
        errors="strict",
    )

    for line in data.splitlines():

        line = line.strip()

        if not line or line.startswith("#"):
            continue

        parts = line.split()

        if len(parts) < 2:
            continue

        digest = parts[0]
        filename = parts[-1].lstrip("*")

        if Path(filename).name != asset_name:
            continue

        if len(digest) != 64:
            die("Invalid SHA-256.")

        if any(
            c not in string.hexdigits
            for c in digest
        ):
            die("Invalid SHA-256.")

        return digest.lower()

    die(
        f"SHA-256 for {asset_name} was not found."
    )
    return ""


def install_ttyd(
    asset_name: str,
    expected_sha256: str,
) -> None:

    INSTALL_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    fd, temp_name = tempfile.mkstemp(
        prefix=".ttyd-",
        dir=str(INSTALL_DIR),
    )

    os.close(fd)

    temp_path = Path(temp_name)

    try:

        url = f"{BASE_URL}/{asset_name}"

        print(
            "[+] Downloading ttyd...",
            flush=True,
        )

        sha256 = hashlib.sha256()
        total = 0

        try:

            with (
                urllib.request.urlopen(
                    request(url),
                    timeout=120,
                ) as response,
                temp_path.open("wb") as output,
            ):

                while True:

                    chunk = response.read(
                        1024 * 1024
                    )

                    if not chunk:
                        break

                    total += len(chunk)

                    if total > MAX_DOWNLOAD_BYTES:
                        die("TTYD is too large.")

                    output.write(chunk)
                    sha256.update(chunk)

                output.flush()
                os.fsync(output.fileno())

        except (
            urllib.error.URLError,
            TimeoutError,
            OSError,
        ) as exc:
            die(
                f"TTYD download failed: {exc}"
            )

        if total < 4096:
            die("TTYD file is too small.")

        actual_sha256 = sha256.hexdigest()

        if not secrets.compare_digest(
            actual_sha256,
            expected_sha256,
        ):
            die(
                "SHA-256 verification failed."
            )

        with temp_path.open("rb") as f:
            if f.read(4) != b"\x7fELF":
                die(
                    "Downloaded file is not a valid ELF."
                )

        os.chmod(
            temp_path,
            0o755,
        )

        os.replace(
            temp_path,
            TTYD_PATH,
        )

        print(
            "[+] TTYD installed.",
            flush=True,
        )

    finally:

        try:
            temp_path.unlink(
                missing_ok=True
            )
        except OSError:
            pass


def verify_ttyd() -> None:

    if not TTYD_PATH.exists():
        die("TTYD was not installed.")

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

    except OSError as exc:
        die(
            f"Cannot execute TTYD: {exc}"
        )

    output = (
        result.stdout
        + result.stderr
    ).strip()

    if result.returncode != 0:
        die(
            "TTYD version check failed."
        )

    print(
        f"[+] {output}",
        flush=True,
    )


def get_shell() -> str:

    shell = shutil.which("bash")

    if shell:
        return shell

    shell = shutil.which("sh")

    if shell:
        return shell

    die("bash/sh not found.")
    return ""


def start_ttyd() -> None:

    if PASSWORD is None:
        die(
            "TTYD_PASSWORD is not set."
        )

    if not USERNAME:
        die(
            "TTYD_USER cannot be empty."
        )

    shell = get_shell()

    home = str(Path.home())

    command = [
        str(TTYD_PATH),
        "--port",
        PORT,
        "--interface",
        BIND,
        "--writable",
        "--credential",
        f"{USERNAME}:{PASSWORD}",
        "--cwd",
        home,
        shell,
    ]

    print(
        "[+] Starting TTYD...",
        flush=True,
    )

    os.execv(
        str(TTYD_PATH),
        command,
    )


def main() -> None:

    print(
        "========================================",
        flush=True,
    )
    print(
        " ConfigFars TTYD",
        flush=True,
    )
    print(
        "========================================",
        flush=True,
    )

    asset_arch = detect_architecture()

    asset_name = f"ttyd.{asset_arch}"

    print(
        f"[+] Architecture: {asset_arch}",
        flush=True,
    )

    print(
        f"[+] Port: {PORT}",
        flush=True,
    )

    print(
        f"[+] User: {USERNAME}",
        flush=True,
    )

    expected_sha256 = get_sha256(
        asset_name
    )

    install_ttyd(
        asset_name,
        expected_sha256,
    )

    verify_ttyd()

    start_ttyd()


if __name__ == "__main__":

    try:
        main()

    except KeyboardInterrupt:
        print(
            "\n[+] Stopped.",
            flush=True,
        )

        sys.exit(130)
