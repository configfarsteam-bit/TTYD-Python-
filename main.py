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


# =========================================================
# CONFIG
# =========================================================

VERSION = os.environ.get("TTYD_VERSION", "1.7.7").strip()

INSTALL_DIR = Path(
    os.environ.get(
        "TTYD_INSTALL_DIR",
        str(Path.home() / ".local" / "bin"),
    )
).expanduser()

TTYD_PATH = INSTALL_DIR / "ttyd"

BASE_URL = os.environ.get(
    "TTYD_BASE_URL",
    f"https://github.com/tsl0922/ttyd/releases/download/{VERSION}",
).rstrip("/")

PORT = os.environ.get("TTYD_PORT", "7681").strip()

# پیش‌فرض فقط روی همین سیستم قابل دسترسی است.
# برای دسترسی شبکه:
# TTYD_BIND=0.0.0.0
BIND = os.environ.get("TTYD_BIND", "127.0.0.1").strip()

USERNAME = os.environ.get("TTYD_USER", "admin")
PASSWORD = os.environ.get("TTYD_PASSWORD")

# مقدار 1 یعنی فقط نصب و تست، بدون اجرای ttyd
NO_START = os.environ.get("TTYD_NO_START", "0") == "1"

# حداکثر اندازه فایل دانلودی
try:
    MAX_DOWNLOAD_BYTES = int(
        os.environ.get(
            "TTYD_MAX_DOWNLOAD_BYTES",
            str(100 * 1024 * 1024),
        )
    )
except ValueError:
    MAX_DOWNLOAD_BYTES = 100 * 1024 * 1024


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
    """نمایش خطا و خروج."""
    print(f"[!] {message}", file=sys.stderr)
    raise SystemExit(code)


def validate_config() -> None:
    """بررسی تنظیمات ورودی."""

    if not VERSION:
        die("TTYD_VERSION نمی‌تواند خالی باشد.")

    if any(char in VERSION for char in "\r
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

    if not BIND:
        die("TTYD_BIND نمی‌تواند خالی باشد.")

    if any(char in BIND for char in "\r
"):
        die("TTYD_BIND نامعتبر است.")

    if not USERNAME:
        die("TTYD_USER نمی‌تواند خالی باشد.")

    if any(char in USERNAME for char in ":\r
"):
        die(
            "TTYD_USER نباید شامل ':' یا خط جدید باشد."
        )

    if PASSWORD is not None:
        if not PASSWORD:
            die(
                "TTYD_PASSWORD نمی‌تواند خالی باشد."
            )

        if any(char in PASSWORD for char in "\r
"):
            die(
                "TTYD_PASSWORD نباید شامل خط جدید باشد."
            )

    if MAX_DOWNLOAD_BYTES < 4096:
        die(
            "TTYD_MAX_DOWNLOAD_BYTES باید حداقل 4096 باشد."
        )

    if INSTALL_DIR == Path("/"):
        die("TTYD_INSTALL_DIR نامعتبر است.")


def detect_architecture() -> tuple[str, str]:
    """تشخیص معماری و نام فایل binary."""

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


def create_request(url: str) -> urllib.request.Request:
    """ساخت درخواست HTTP با User-Agent مشخص."""

    return urllib.request.Request(
        url,
        headers={
            "User-Agent": "ttyd-python-installer/3.0"
        },
    )


def download_bytes(
    url: str,
    timeout: int = 30,
) -> bytes:
    """دانلود فایل کوچک مثل SHA256SUMS."""

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
        die(f"دانلود ناموفق بود: {exc}")

    if len(data) > MAX_DOWNLOAD_BYTES:
        die(
            "فایل دریافتی از سقف اندازه مجاز "
            "بزرگ‌تر است."
        )

    return data


# =========================================================
# CHECKSUM
# =========================================================

def get_official_sha256(asset_name: str) -> str:
    """دریافت checksum رسمی فایل binary."""

    sums_url = f"{BASE_URL}/SHA256SUMS"

    print(f"[+] دریافت checksum رسمی: {sums_url}")

    data = download_bytes(sums_url).decode(
        "utf-8",
        errors="strict",
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

        if len(digest) != 64:
            die(
                f"طول SHA-256 برای {asset_name} "
                "معتبر نیست."
            )

        if any(
            char not in string.hexdigits
            for char in digest
        ):
            die(
                f"SHA-256 برای {asset_name} "
                "معتبر نیست."
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
    """دانلود، بررسی، و نصب اتمیک ttyd."""

    try:
        INSTALL_DIR.mkdir(
            parents=True,
            exist_ok=True,
            mode=0o755,
        )
    except OSError as exc:
        die(
            f"ساخت مسیر نصب ناموفق بود: {exc}"
        )

    if not INSTALL_DIR.is_dir():
        die(
            f"مسیر نصب دایرکتوری نیست: {INSTALL_DIR}"
        )

    if INSTALL_DIR.is_symlink():
        die(
            f"مسیر نصب نباید symlink باشد: {INSTALL_DIR}"
        )

    try:
        temp_fd, temp_name = tempfile.mkstemp(
            prefix=".ttyd-",
            dir=str(INSTALL_DIR),
        )
    except OSError as exc:
        die(
            f"ساخت فایل موقت ناموفق بود: {exc}"
        )

    os.close(temp_fd)
    temp_path = Path(temp_name)

    try:
        url = f"{BASE_URL}/{asset_name}"

        print(f"[+] دانلود binary: {url}")

        sha256 = hashlib.sha256()
        total = 0

        try:
            with (
                urllib.request.urlopen(
                    create_request(url),
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
            die(
                f"دانلود ttyd ناموفق بود: {exc}"
            )

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

        print("[+] نصب با موفقیت انجام شد.")
        print(f"[+] مسیر binary: {TTYD_PATH}")
        print(f"[+] اندازه فایل: {total} bytes")

    finally:
        try:
            temp_path.unlink()
        except FileNotFoundError:
            pass


# =========================================================
# VERIFY
# =========================================================

def verify_ttyd() -> None:
    """بررسی اجرای binary نصب‌شده."""

    print("[+] اجرای ttyd --version...")

    if not TTYD_PATH.exists():
        die(
            f"فایل ttyd پیدا نشد: {TTYD_PATH}"
        )

    if not os.access(TTYD_PATH, os.X_OK):
        die(
            f"فایل ttyd قابل اجرا نیست: {TTYD_PATH}"
        )

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
        die(
            f"اجرای ttyd ناموفق بود: {exc}"
        )

    output = (
        result.stdout + result.stderr
    ).strip()

    print("[+] خروجی نسخه:")

    if output:
        print(output)
    else:
        print("(بدون خروجی)")

    if result.returncode != 0:
        die(
            "ttyd --version با خطا تمام شد."
        )

    if "ttyd" not in output.lower():
        die(
            "خروجی ttyd --version غیرمنتظره است."
        )


# =========================================================
# PASSWORD
# =========================================================

def create_password() -> str:
    """دریافت رمز از محیط یا تولید رمز تصادفی."""

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

def get_shell() -> str:
    """پیدا کردن shell کاربر فعلی."""

    configured_shell = os.environ.get("SHELL")

    if configured_shell:
        configured_path = Path(configured_shell)

        if configured_path.is_file() and os.access(
            configured_path,
            os.X_OK,
        ):
            return str(configured_path)

    shell = (
        shutil.which("bash")
        or shutil.which("sh")
    )

    if not shell:
        die(
            "bash یا sh روی سیستم پیدا نشد."
        )

    return shell


def start_ttyd(password: str) -> None:
    """اجرای ttyd با کاربر فعلی."""

    shell = get_shell()

    current_user = os.environ.get(
        "USER",
        "current-user",
    )

    current_home = Path.home()

    if not current_home.is_dir():
        die(
            f"Home directory پیدا نشد: {current_home}"
        )

    print()
    print("=" * 40)
    print(" ttyd USER TERMINAL")
    print("=" * 40)
    print()
    print(f"Address : {BIND}:{PORT}")
    print(f"User    : {USERNAME}")
    print(f"OS user : {current_user}")
    print(f"Workdir : {current_home}")
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
        str(current_home),
        shell,
    ]

    print("[+] اجرای ttyd...")
    print(
        "[!] برای توقف، Ctrl+C یا ترمینال را ببند."
    )

    # توجه:
    # ttyd نسخه 1.7.7 رمز را از argv می‌گیرد.
    # بنابراین ممکن است رمز در process list دیده شود.
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
    print(" Non-root compatible")
    print("=" * 40)
    print()

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

    print(f"[+] Official SHA-256: {expected_sha256}")
    print()

    download_and_install(
        asset_name,
        expected_sha256,
    )

    print()
    verify_ttyd()

    print()

    if NO_START:
        print(
            "[+] TTYD_NO_START=1 فعال است."
        )
        print(
            "[+] ttyd نصب و تست شد، اما اجرا نشد."
        )
        return

    password = create_password()

    print(
        "[!] اگر رمز را با TTYD_PASSWORD تعیین نکرده‌ای، "
        "رمز تولیدشده را پایین ببین:"
    )
    print(f"[+] Password: {password}")

    start_ttyd(password)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("
[+] عملیات توسط کاربر متوقف شد.")
        sys.exit(130)
