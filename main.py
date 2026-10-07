#!/usr/bin/env python3
"""
Download, verify, install, and optionally run ttyd safely.

این اسکریپت به root نیاز دارد، چون به‌صورت پیش‌فرض در
/usr/local/bin نصب می‌کند و در حالت اجرا یک shell با دسترسی root باز می‌کند.
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


# =========================================================
# CONFIG
# =========================================================

VERSION = os.environ.get("TTYD_VERSION", "1.7.7").strip()

INSTALL_DIR = Path(
    os.environ.get("TTYD_INSTALL_DIR", "/usr/local/bin")
).expanduser()

TTYD_PATH = INSTALL_DIR / "ttyd"

BASE_URL = os.environ.get(
    "TTYD_BASE_URL",
    f"https://github.com/tsl0922/ttyd/releases/download/{VERSION}",
).rstrip("/")

PORT = os.environ.get("TTYD_PORT", "7681").strip()

# پیش‌فرض فقط روی localhost گوش می‌دهد.
# برای دسترسی شبکه:
# TTYD_BIND=0.0.0.0
BIND = os.environ.get("TTYD_BIND", "127.0.0.1").strip()

USERNAME = os.environ.get("TTYD_USER", "admin")
PASSWORD = os.environ.get("TTYD_PASSWORD")

# در حالت تست، ttyd اجرا نمی‌شود.
NO_START = os.environ.get("TTYD_NO_START") == "1"

# جلوگیری از دانلود فایل غیرعادی بزرگ
MAX_DOWNLOAD_BYTES = int(
    os.environ.get(
        "TTYD_MAX_DOWNLOAD_BYTES",
        str(100 * 1024 * 1024),
    )
)


# =========================================================
# ARCHITECTURES
# =========================================================

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


# =========================================================
# HELPERS
# =========================================================

def die(message: str, code: int = 1) -> None:
    """چاپ خطا و خروج از برنامه."""
    print(f"[!] {message}", file=sys.stderr)
    raise SystemExit(code)


def require_root() -> None:
    """بررسی اجرای اسکریپت با دسترسی root."""
    if not hasattr(os, "geteuid"):
        die("این اسکریپت برای Linux/Unix طراحی شده است.")

    if os.geteuid() != 0:
        script_path = os.path.abspath(__file__)

        die(
            "این اسکریپت باید با root اجرا شود.
"
            f"مثال: sudo python3 {script_path}"
        )


def validate_config() -> None:
    """اعتبارسنجی تنظیمات محیطی."""

    if not VERSION or any(char in VERSION for char in "\r
"):
        die("TTYD_VERSION نامعتبر است.")

    if not BASE_URL.startswith(("https://", "http://")):
        die(
            "TTYD_BASE_URL باید با http:// یا https:// شروع شود."
        )

    try:
        port = int(PORT)
    except ValueError:
        die("TTYD_PORT باید یک عدد باشد.")

    if not 1 <= port <= 65535:
        die("TTYD_PORT باید بین 1 و 65535 باشد.")

    if not USERNAME:
        die("TTYD_USER نمی‌تواند خالی باشد.")

    if any(char in USERNAME for char in ":\r
"):
        die(
            "TTYD_USER نباید شامل ':' یا خط جدید باشد."
        )

    if PASSWORD is not None:
        if not PASSWORD:
            die("TTYD_PASSWORD نمی‌تواند خالی باشد.")

        if any(char in PASSWORD for char in "\r
"):
            die(
                "TTYD_PASSWORD نباید شامل خط جدید باشد."
            )

    if not BIND:
        die("TTYD_BIND نمی‌تواند خالی باشد.")

    if any(char in BIND for char in "\r
"):
        die("TTYD_BIND نامعتبر است.")

    if MAX_DOWNLOAD_BYTES < 4096:
        die(
            "TTYD_MAX_DOWNLOAD_BYTES باید حداقل 4096 باشد."
        )

    if INSTALL_DIR == Path("/") or TTYD_PATH == Path("/"):
        die("مسیر نصب نامعتبر است.")


def detect_architecture() -> tuple[str, str]:
    """تشخیص معماری CPU و نام فایل release."""
    machine = platform.machine().lower()
    asset_arch = ARCH_MAP.get(machine)

    if not asset_arch:
        supported = ", ".join(
            sorted(set(ARCH_MAP.values()))
        )

        die(
            f"معماری پشتیبانی نمی‌شود: {machine}
"
            f"Supported: {supported}"
        )

    return machine, f"ttyd.{asset_arch}"


def http_get(url: str, timeout: int = 30) -> bytes:
    """دانلود داده با کتابخانه استاندارد Python."""
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "ttyd-installer/2.0"
        },
    )

    try:
        with urllib.request.urlopen(
            request,
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
        die(f"دانلود ناموفق بود: {exc}")

    if len(data) > MAX_DOWNLOAD_BYTES:
        die(
            "فایل دریافتی از سقف اندازه مجاز بزرگ‌تر است."
        )

    return data


# =========================================================
# SHA256
# =========================================================

def get_official_sha256(asset_name: str) -> str:
    """دریافت SHA-256 فایل از SHA256SUMS رسمی."""
    sums_url = f"{BASE_URL}/SHA256SUMS"

    print(f"[+] دریافت checksum رسمی: {sums_url}")

    try:
        raw_data = http_get(sums_url)

        data = raw_data.decode(
            "utf-8",
            errors="strict",
        )

    except UnicodeDecodeError as exc:
        die(
            f"فایل SHA256SUMS متن UTF-8 معتبر نیست: {exc}"
        )

    for raw_line in data.splitlines():
        line = raw_line.strip()

        if not line or line.startswith("#"):
            continue

        parts = line.split()

        if len(parts) < 2:
            continue

        digest = parts[0]
        filename = parts[-1].lstrip("*")

        if Path(filename).name != asset_name:
            continue

        if (
            len(digest) != 64
            or any(
                char not in string.hexdigits
                for char in digest
            )
        ):
            die(
                f"SHA-256 نامعتبر برای {asset_name}"
            )

        return digest.lower()

    die(
        f"checksum مربوط به {asset_name} "
        "در SHA256SUMS پیدا نشد."
    )


# =========================================================
# DOWNLOAD + VERIFY + INSTALL
# =========================================================

def download_and_install(
    asset_name: str,
    expected_sha256: str,
) -> None:
    """دانلود، بررسی checksum، بررسی ELF و نصب اتمیک."""

    INSTALL_DIR.mkdir(
        parents=True,
        exist_ok=True,
        mode=0o755,
    )

    if not INSTALL_DIR.is_dir():
        die(
            f"مسیر نصب دایرکتوری نیست: {INSTALL_DIR}"
        )

    if INSTALL_DIR.is_symlink():
        die(
            f"مسیر نصب نباید symlink باشد: {INSTALL_DIR}"
        )

    temp_fd, temp_name = tempfile.mkstemp(
        prefix=".ttyd-",
        dir=str(INSTALL_DIR),
    )

    os.close(temp_fd)

    temp_path = Path(temp_name)

    try:
        url = f"{BASE_URL}/{asset_name}"

        print(f"[+] دانلود: {url}")

        request = urllib.request.Request(
            url,
            headers={
                "User-Agent": "ttyd-installer/2.0"
            },
        )

        sha256 = hashlib.sha256()
        total = 0

        try:
            with (
                urllib.request.urlopen(
                    request,
                    timeout=60,
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
                        die(
                            "فایل دانلودشده از سقف "
                            "اندازه مجاز بزرگ‌تر است."
                        )

                    output.write(chunk)
                    sha256.update(chunk)

                output.flush()
                os.fsync(output.fileno())

        except (
            urllib.error.URLError,
            TimeoutError,
            OSError,
        ) as exc:
            die(f"دانلود ttyd ناموفق بود: {exc}")

        if total < 4096:
            die(
                "فایل دانلودشده غیرعادی کوچک است: "
                f"{total} bytes"
            )

        actual_sha256 = sha256.hexdigest()

        print("[+] بررسی SHA-256...")

        if not secrets.compare_digest(
            actual_sha256,
            expected_sha256,
        ):
            die(
                "SHA-256 تطابق ندارد!
"
                f"Expected: {expected_sha256}
"
                f"Actual:   {actual_sha256}"
            )

        print("[+] SHA-256 صحیح است.")

        with temp_path.open("rb") as binary_file:
            magic = binary_file.read(4)

        if magic != b"\x7fELF":
            die(
                "فایل دانلودشده یک ELF معتبر نیست."
            )

        print("[+] فایل ELF تأیید شد.")

        os.chmod(temp_path, 0o755)

        # نصب اتمیک
        os.replace(temp_path, TTYD_PATH)

        print(
            "[+] نصب اتمیک انجام شد:
"
            f"    مسیر: {TTYD_PATH}
"
            f"    حجم: {total} bytes
"
            "    مجوز: 755"
        )

    finally:
        try:
            temp_path.unlink()
        except FileNotFoundError:
            pass


# =========================================================
# VERIFY BINARY
# =========================================================

def verify_ttyd() -> None:
    """اجرای ttyd --version برای بررسی binary."""

    print("[+] تست ttyd --version...")

    try:
        result = subprocess.run(
            [
                str(TTYD_PATH),
                "--version",
            ],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )

    except (
        OSError,
        subprocess.SubprocessError,
    ) as exc:
        die(f"اجرای ttyd ناموفق بود: {exc}")

    output = (
        result.stdout + result.stderr
    ).strip()

    print("[+] خروجی نسخه ttyd:")
    print(output or "(بدون خروجی)")

    if result.returncode != 0:
        die(
            "اجرای ttyd --version با خطا تمام شد."
        )

    if "ttyd" not in output.lower():
        die(
            "خروجی ttyd --version غیرمنتظره است."
        )


# =========================================================
# PASSWORD
# =========================================================

def create_password() -> str:
    """استفاده از رمز محیطی یا ساخت رمز تصادفی امن."""

    if PASSWORD is not None:
        return PASSWORD

    alphabet = (
        string.ascii_letters + string.digits
    )

    return "".join(
        secrets.choice(alphabet)
        for _ in range(24)
    )


# =========================================================
# START
# =========================================================

def start_ttyd(password: str) -> None:
    """اجرای ttyd با shell."""

    shell = (
        shutil.which("bash")
        or shutil.which("sh")
    )

    if not shell:
        die(
            "bash یا sh روی سیستم پیدا نشد."
        )

    if os.geteuid() != 0:
        die(
            "ttyd با root اجرا نمی‌شود."
        )

    print()
    print("=" * 40)
    print(" ttyd ROOT TERMINAL")
    print("=" * 40)
    print()
    print(f"Address : {BIND}:{PORT}")
    print(f"User    : {USERNAME}")
    print(f"UID     : {os.geteuid()}")
    print()

    # توجه:
    # ttyd در این نسخه رمز را از طریق argv دریافت می‌کند.
    # بنابراین ممکن است رمز در process list قابل مشاهده باشد.
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
        "/root",
        shell,
    ]

    print("[+] اجرای ttyd...")

    # جایگزینی پردازش Python با ttyd
    os.execv(
        str(TTYD_PATH),
        command,
    )


# =========================================================
# MAIN
# =========================================================

def main() -> None:
    print()
    print("=" * 40)
    print(" ttyd Python Installer")
    print(" No external Python packages")
    print("=" * 40)
    print()

    require_root()
    validate_config()

    machine, asset_name = detect_architecture()

    print(f"[+] CPU     : {machine}")
    print(f"[+] Asset   : {asset_name}")
    print(f"[+] Version : {VERSION}")
    print(f"[+] Install : {TTYD_PATH}")
    print()

    expected_sha256 = get_official_sha256(
        asset_name
    )

    print("[+] Official SHA-256:")
    print(f"    {expected_sha256}")
    print()

    download_and_install(
        asset_name,
        expected_sha256,
    )

    print()
    verify_ttyd()

    print()

    if NO_START:
        print("[+] حالت تست فعال است.")
        print("[+] ttyd اجرا نشد.")
        return

    password = create_password()
    start_ttyd(password)


if __name__ == "__main__":
    main()
