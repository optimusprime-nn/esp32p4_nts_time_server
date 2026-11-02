"""Shared setup logic for the ESP32-P4 time server.

Everything that talks to the board, the serial port, esptool or Cloudflare
lives here. The guided CLI (cli.py) and the window (gui.py) only collect
answers and call these functions, so both always behave the same way.

Nothing here prints. Progress goes through the `log` callback each function
takes, so a front end can show it however it likes.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import http.client
import ipaddress
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable, Optional

Log = Callable[[str], None]


def _quiet(_message: str) -> None:
    pass


class SetupError(Exception):
    """A step failed in a way the user can act on. The message says how."""


# ---------------------------------------------------------------------------
# Serial console
# ---------------------------------------------------------------------------

ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
RE_CODE = re.compile(r"enrollment code:\s*([0-9A-F]{32})\b")
# The certificate the board is serving: its bootstrap certificate, or (on a
# claimed board that already has one) its production certificate.
RE_FINGERPRINT = re.compile(r"(?:Bootstrap|Server) certificate SHA-256:\s*([0-9A-Fa-f]{64})\b")
RE_IPV4 = re.compile(r"(?:DHCP|Static) IPv4 acquired:\s*(\d{1,3}(?:\.\d{1,3}){3})")
RE_PROVISIONED = re.compile(r"Management ownership is provisioned")
RE_VERSION = re.compile(r"App version:\s*(\S+)")


@dataclass
class BootInfo:
    """What the board reported on the serial console during one boot."""
    enrollment_code: Optional[str] = None
    fingerprint: Optional[str] = None
    ip: Optional[str] = None
    provisioned: bool = False
    version: Optional[str] = None

    def complete(self) -> bool:
        if self.provisioned:
            return bool(self.ip and self.fingerprint)
        return bool(self.enrollment_code and self.fingerprint and self.ip)


def parse_console_line(line: str, info: BootInfo) -> None:
    """Update `info` from one line of the board's serial output."""
    text = ANSI.sub("", line)
    if (m := RE_CODE.search(text)):
        info.enrollment_code = m.group(1)
    if (m := RE_FINGERPRINT.search(text)):
        info.fingerprint = m.group(1).upper()
    if (m := RE_IPV4.search(text)):
        info.ip = m.group(1)
    if RE_PROVISIONED.search(text):
        info.provisioned = True
    if (m := RE_VERSION.search(text)):
        info.version = m.group(1)


def list_serial_ports() -> list[tuple[str, str]]:
    """(device, description) for each serial port, most likely board first."""
    from serial.tools import list_ports
    ports = []
    for p in list_ports.comports():
        desc = p.description or ""
        if p.manufacturer and p.manufacturer not in desc:
            desc = f"{desc} ({p.manufacturer})"
        ports.append((p.device, desc))
    likely = ("usb", "uart", "cp210", "ch34", "ftdi", "jtag", "espressif")
    ports.sort(key=lambda d: (not any(k in d[1].lower() for k in likely), d[0]))
    return ports


def read_boot(port: str, *, reset: bool = True, timeout: float = 240.0,
              log: Log = _quiet, echo: Optional[Log] = None) -> BootInfo:
    """Reset the board (optional) and read its boot log until the enrollment
    details, or the provisioned marker and IP address, have all appeared.

    The first boot after flashing encrypts the flash and restarts at least
    once, which is why the default timeout is long.
    """
    import serial
    info = BootInfo()
    try:
        ser = serial.Serial(port, 115200, timeout=0.5)
    except serial.SerialException as exc:
        raise SetupError(f"Cannot open {port}: {exc}. Close any serial monitor using it and try again.") from exc
    with ser:
        if reset:
            log("Resetting the board...")
            ser.dtr = False
            ser.rts = True
            time.sleep(0.2)
            ser.rts = False
        deadline = time.monotonic() + timeout
        grace = None  # a claimed board prints a fingerprint only while on its bootstrap certificate
        buffer = b""
        while time.monotonic() < deadline:
            if info.provisioned and info.ip and grace is None:
                grace = time.monotonic() + 20.0
            if grace is not None and time.monotonic() > grace:
                return info
            chunk = ser.read(512)
            if not chunk:
                continue
            buffer += chunk
            *lines, buffer = buffer.split(b"\n")
            for raw in lines:
                line = raw.decode("utf-8", "replace").rstrip()
                if echo:
                    echo(line)
                parse_console_line(line, info)
            if info.complete():
                return info
    missing = []
    if not info.ip:
        missing.append("an IP address (is the Ethernet cable connected, with DHCP on the network?)")
    if not info.provisioned and not info.enrollment_code:
        missing.append("the enrollment code")
    if not info.provisioned and not info.fingerprint:
        missing.append("the bootstrap certificate fingerprint (firmware older than 3.1.11?)")
    raise SetupError("The board did not report " + " or ".join(missing) + f" within {int(timeout)} s.")


# ---------------------------------------------------------------------------
# Flashing (first flash of a new board only)
# ---------------------------------------------------------------------------

FIRMWARE_FILES = ("bootloader.bin", "partition-table.bin", "ota_data_initial.bin",
                  "esp32p4_nts_time_server.bin")
RE_CHIP_REVISION = re.compile(r"revision v(\d+)\.(\d+)")


@dataclass
class FirmwareVariant:
    """One firmware build. ESP32-P4 silicon below v3.0 and v3.x need different
    images; variant.json in each folder records the revisions it supports."""
    folder: Path
    name: str = "firmware"
    min_rev: int = 0
    max_rev: int = 9999
    cpu_mhz: int = 0
    preview: str = ""  # set when this variant has not yet been proven on its silicon

    def supports(self, rev: int) -> bool:
        return self.min_rev <= rev <= self.max_rev

    def describe(self) -> str:
        span = f"v{self.min_rev // 100}.{self.min_rev % 100} to v{self.max_rev // 100}.{self.max_rev % 100}"
        return f"{self.name} (silicon {span}" + (f", {self.cpu_mhz} MHz)" if self.cpu_mhz else ")")


def _is_image_folder(c: Path) -> bool:
    return (c / "flash_args").is_file() and all((c / f).is_file() for f in FIRMWARE_FILES)


def _variant(folder: Path) -> FirmwareVariant:
    meta = folder / "variant.json"
    if meta.is_file():
        d = json.loads(meta.read_text())
        return FirmwareVariant(folder, d.get("name", folder.name), int(d["min_rev"]),
                               int(d["max_rev"]), int(d.get("cpu_mhz", 0)), d.get("preview", ""))
    return FirmwareVariant(folder, folder.name)


def find_firmware(directory: Optional[str] = None) -> list[FirmwareVariant]:
    """Locate the release firmware: a folder of per-silicon variants (as
    released), or a single folder of images (a local build)."""
    candidates = []
    if directory:
        candidates.append(Path(directory))
    here = Path(__file__).resolve().parent
    candidates += [here.parent / "firmware", here.parent.parent / "firmware", Path.cwd() / "firmware"]
    for c in candidates:
        if _is_image_folder(c):
            return [_variant(c)]
        if c.is_dir():
            found = [_variant(s) for s in sorted(c.iterdir()) if s.is_dir() and _is_image_folder(s)]
            if found:
                return found
    raise SetupError("Firmware not found. Point the tool at the release's 'firmware' folder, "
                     "which holds a folder of images for each kind of ESP32-P4 silicon.")


def select_firmware(variants: list[FirmwareVariant], revision: int) -> FirmwareVariant:
    for v in variants:
        if v.supports(revision):
            return v
    have = ", ".join(v.describe() for v in variants)
    raise SetupError(f"No firmware in this release supports this chip (ESP32-P4 revision "
                     f"v{revision // 100}.{revision % 100}). Available: {have}.")


def _esptool(args: list[str], log: Log) -> str:
    cmd = [sys.executable, "-m", "esptool", "--chip", "esp32p4"] + args
    proc = subprocess.run(cmd, capture_output=True, text=True)
    out = (proc.stdout or "") + (proc.stderr or "")
    for line in out.splitlines():
        if line.strip():
            log("  " + line.strip())
    if proc.returncode != 0:
        raise SetupError("esptool failed. Check the cable and port, hold BOOT while pressing RESET if the "
                         "board will not connect, and close any serial monitor.")
    return out


def parse_security_info(out: str) -> tuple[int, bool]:
    """(chip revision as major*100+minor, flash encryption on) from esptool output."""
    m = RE_CHIP_REVISION.search(out)
    if not m:
        raise SetupError("Could not read the chip's silicon revision, so it was not flashed.")
    revision = int(m.group(1)) * 100 + int(m.group(2))
    if "Flash Encryption: Enabled" in out:
        return revision, True
    if "Flash Encryption: Disabled" in out:
        return revision, False
    raise SetupError("Could not read the board's flash-encryption state, so it was not flashed.")


def inspect_chip(port: str, log: Log = _quiet) -> tuple[int, bool]:
    return parse_security_info(_esptool(["-p", port, "get-security-info"], log))


def flash_new_board(port: str, variants: list[FirmwareVariant], log: Log = _quiet,
                    confirm: Optional[Callable[[str], bool]] = None) -> FirmwareVariant:
    """Write the right release images to a board that has never been encrypted.

    The chip's silicon revision picks the image (below v3.0 and v3.x need
    different builds). The bootloader burns the flash-encryption key on the
    first boot afterwards. That is permanent, which is why an already-encrypted
    board is refused: its firmware is updated over the network instead.

    A preview variant is only written after `confirm` (shown the reason)
    returns True; without a confirm callback it is refused.
    """
    revision, encrypted = inspect_chip(port, log)
    variant = select_firmware(variants, revision)
    log(f"Chip is ESP32-P4 revision v{revision // 100}.{revision % 100}; using {variant.describe()}.")
    if encrypted:
        raise SetupError("This board is already encrypted, so it must not be flashed this way. "
                         "Update its firmware over the network from its Firmware page instead.")
    if variant.preview:
        log("Preview firmware: " + variant.preview)
        if confirm is None or not confirm(variant.preview):
            raise SetupError("Stopped before flashing the preview firmware; nothing was written.")
    tokens = (variant.folder / "flash_args").read_text().split()
    mapped = []
    for t in tokens:
        name = os.path.basename(t)
        mapped.append(str(variant.folder / name) if name.endswith(".bin") else t)
    log("Writing firmware (about a minute)...")
    _esptool(["-p", port, "-b", "460800", "--before", "default-reset", "--after", "hard-reset",
              "write-flash"] + mapped, log)
    return variant


# ---------------------------------------------------------------------------
# Management credentials
# ---------------------------------------------------------------------------

CREDENTIAL_FILES = ("management-ca.key.pem", "management-ca.crt.pem",
                    "admin-client.key.pem", "admin-client.crt.pem", "admin-client.p12")


@dataclass
class Credentials:
    folder: Path
    password: str = field(repr=False)

    @property
    def ca_cert(self) -> Path: return self.folder / "management-ca.crt.pem"
    @property
    def ca_key(self) -> Path: return self.folder / "management-ca.key.pem"
    @property
    def client_cert(self) -> Path: return self.folder / "admin-client.crt.pem"
    @property
    def client_key(self) -> Path: return self.folder / "admin-client.key.pem"
    @property
    def p12(self) -> Path: return self.folder / "admin-client.p12"


def create_credentials(folder: str | Path, password: str, admin_name: str = "ntp-admin",
                       log: Log = _quiet) -> Credentials:
    """Create a management CA and an administrator certificate for one board.

    Only the CA certificate ever leaves this computer. Private keys are
    written encrypted with `password`. Existing credentials are never
    overwritten.
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import pkcs12
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    if len(password) < 8:
        raise SetupError("Use a password of at least 8 characters.")
    path = Path(folder).expanduser().resolve()
    if any((path / f).exists() for f in CREDENTIAL_FILES):
        raise SetupError(f"{path} already holds credentials. Choose a new folder for this board; "
                         "existing credentials are never overwritten.")
    path.mkdir(parents=True, exist_ok=True)
    now = _dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(minutes=5)
    enc = serialization.BestAvailableEncryption(password.encode())

    log("Creating the management certificate authority...")
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ESP32-P4 Management CA")])
    ca_cert = (x509.CertificateBuilder()
               .subject_name(ca_name).issuer_name(ca_name)
               .public_key(ca_key.public_key())
               .serial_number(x509.random_serial_number())
               .not_valid_before(now).not_valid_after(now + _dt.timedelta(days=3650))
               .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
               .add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False,
                                            key_encipherment=False, data_encipherment=False,
                                            key_agreement=False, key_cert_sign=True, crl_sign=True,
                                            encipher_only=False, decipher_only=False), critical=True)
               .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
               .sign(ca_key, hashes.SHA256()))

    log("Creating the administrator certificate...")
    admin_key = ec.generate_private_key(ec.SECP256R1())
    admin_cert = (x509.CertificateBuilder()
                  .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, admin_name)]))
                  .issuer_name(ca_name)
                  .public_key(admin_key.public_key())
                  .serial_number(x509.random_serial_number())
                  .not_valid_before(now).not_valid_after(now + _dt.timedelta(days=825))
                  .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                  .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                                               key_encipherment=False, data_encipherment=False,
                                               key_agreement=False, key_cert_sign=False, crl_sign=False,
                                               encipher_only=False, decipher_only=False), critical=True)
                  .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
                  .add_extension(x509.SubjectKeyIdentifier.from_public_key(admin_key.public_key()), critical=False)
                  .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
                  .sign(ca_key, hashes.SHA256()))

    pem = serialization.Encoding.PEM
    pkcs8 = serialization.PrivateFormat.PKCS8
    (path / "management-ca.key.pem").write_bytes(ca_key.private_bytes(pem, pkcs8, enc))
    (path / "management-ca.crt.pem").write_bytes(ca_cert.public_bytes(pem))
    (path / "admin-client.key.pem").write_bytes(admin_key.private_bytes(pem, pkcs8, enc))
    (path / "admin-client.crt.pem").write_bytes(admin_cert.public_bytes(pem))
    # AES-256 / SHA-256 protection, which current Windows, macOS and browsers import.
    p12_enc = (serialization.PrivateFormat.PKCS12.encryption_builder()
               .kdf_rounds(50000)
               .key_cert_algorithm(pkcs12.PBES.PBESv2SHA256AndAES256CBC)
               .hmac_hash(hashes.SHA256())
               .build(password.encode()))
    (path / "admin-client.p12").write_bytes(
        pkcs12.serialize_key_and_certificates(admin_name.encode(), admin_key, admin_cert, [ca_cert], p12_enc))
    log(f"Credentials saved in {path}")
    return Credentials(path, password)


def load_credentials(folder: str | Path, password: str) -> Credentials:
    """Open an existing credentials folder and check the password works."""
    from cryptography.hazmat.primitives import serialization
    creds = Credentials(Path(folder).expanduser().resolve(), password)
    for f in ("management-ca.crt.pem", "admin-client.key.pem", "admin-client.crt.pem"):
        if not (creds.folder / f).is_file():
            raise SetupError(f"{creds.folder} has no {f}. Choose the folder created when this board was claimed.")
    try:
        serialization.load_pem_private_key(creds.client_key.read_bytes(), password.encode())
    except (ValueError, TypeError) as exc:
        raise SetupError("That password does not open these credentials.") from exc
    return creds


# ---------------------------------------------------------------------------
# Talking to the board
# ---------------------------------------------------------------------------

def _fingerprint(der: bytes) -> str:
    return hashlib.sha256(der).hexdigest().upper()


class _Connection(http.client.HTTPSConnection):
    """HTTPS to `host`, with SNI and certificate name checks against `tls_name`."""

    def __init__(self, host, port, *, context, timeout, tls_name=None):
        super().__init__(host, port, context=context, timeout=timeout)
        self._tls_name = tls_name

    def connect(self):
        if not self._tls_name:
            return super().connect()
        sock = socket.create_connection((self.host, self.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self._tls_name)


class Board:
    """HTTPS to one board's management API.

    Until the board has its own Let's Encrypt certificate, its identity is
    checked by pinning the bootstrap certificate fingerprint it printed on the
    serial console. Afterwards, connect by hostname with normal verification.
    """

    def __init__(self, host: str, *, pin: Optional[str] = None,
                 credentials: Optional[Credentials] = None, timeout: float = 30.0,
                 tls_name: Optional[str] = None):
        self.host = host
        # Name the certificate must match when not pinning. Lets us connect to
        # the IP address while checking the certificate against the hostname,
        # so a local DNS that hides private addresses cannot get in the way.
        self.tls_name = tls_name
        self.pin = pin.upper() if pin else None
        self.credentials = credentials
        self.timeout = timeout

    def _context(self) -> ssl.SSLContext:
        if self.pin:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE  # replaced by the fingerprint check below
        else:
            ctx = ssl.create_default_context()
        if self.credentials:
            ctx.load_cert_chain(str(self.credentials.client_cert), str(self.credentials.client_key),
                                password=self.credentials.password)
        return ctx

    def request(self, method: str, path: str, body: Optional[bytes] = None,
                headers: Optional[dict] = None, timeout: Optional[float] = None) -> tuple[int, bytes]:
        conn = _Connection(self.host, 443, context=self._context(),
                           timeout=timeout or self.timeout, tls_name=self.tls_name)
        try:
            conn.connect()
            if self.pin:
                seen = _fingerprint(conn.sock.getpeercert(binary_form=True))
                if seen != self.pin:
                    raise SetupError(
                        "The board's certificate does not match the fingerprint it printed on the serial "
                        f"console (expected {self.pin[:16]}..., got {seen[:16]}...). Something on the "
                        "network may be intercepting the connection; nothing was sent.")
            conn.request(method, path, body=body, headers=headers or {})
            resp = conn.getresponse()
            return resp.status, resp.read()
        finally:
            conn.close()

    def json(self, method: str, path: str, payload=None, timeout: Optional[float] = None, ok=(200, 201, 202)):
        body = json.dumps(payload).encode() if payload is not None else None
        hdrs = {"Content-Type": "application/json"} if body is not None else {}
        status, data = self.request(method, path, body, hdrs, timeout)
        if status not in ok:
            text = data.decode("utf-8", "replace").strip()
            raise SetupError(f"{method} {path} was refused ({status}): {text}")
        if not data:
            return {}
        try:
            return json.loads(data)
        except ValueError:
            return {"text": data.decode("utf-8", "replace")}

    # -- enrollment -------------------------------------------------------------

    def claim(self, code: str, ca_pem: bytes) -> None:
        status, data = self.request("PUT", "/api/v1/provisioning/claim", ca_pem,
                                    {"X-Provisioning-Code": code, "Content-Type": "application/x-pem-file"})
        if status == 404:
            raise SetupError("This board is already claimed.")
        if status == 403:
            raise SetupError("The board rejected the enrollment code. Reset it and use the new code.")
        if status == 429:
            raise SetupError("Too many wrong codes: the board has locked enrollment until it is reset.")
        if status not in (200, 201, 202):
            raise SetupError(f"Claim failed ({status}): {data.decode('utf-8', 'replace').strip()}")

    # -- waiting ------------------------------------------------------------------

    def wait_ready(self, timeout: float = 180.0, log: Log = _quiet) -> dict:
        """Poll /api/v1/status until the board answers (after a reboot)."""
        deadline = time.monotonic() + timeout
        last = None
        while time.monotonic() < deadline:
            try:
                return self.json("GET", "/api/v1/status", timeout=10)
            except SetupError as exc:
                if "does not match the fingerprint" in str(exc):
                    raise
                last = exc
            except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
                last = exc
            time.sleep(3)
        raise SetupError(f"The board at {self.host} did not come back within {int(timeout)} s ({last}).")

    def reboot_and_wait(self, new_host: Optional[str] = None, log: Log = _quiet) -> dict:
        self.json("POST", "/api/v1/system/reboot")
        log("Rebooting the board...")
        time.sleep(8)
        if new_host:
            self.host = new_host
        return self.wait_ready(log=log)

    # -- commissioning ------------------------------------------------------------

    def set_identity(self, hostname: str, fqdn: str, ntp0: str, ntp1: str) -> None:
        self.json("PUT", "/api/v1/config/hostname", {"hostname": hostname})
        self.json("PUT", "/api/v1/commissioning", {"certificate_fqdn": fqdn, "ntp0": ntp0, "ntp1": ntp1})

    def set_network(self, static: bool, address: str = "", netmask: str = "",
                    gateway: str = "", dns: str = "") -> None:
        self.json("PUT", "/api/v1/config/network", {
            "static_ipv4_enabled": static, "address": address, "netmask": netmask,
            "gateway": gateway, "dns": dns})

    def set_cloudflare(self, api_token: str, zone_name: str, zone_id: str = "") -> None:
        """With no zone_id, the board looks the zone up itself, which checks the
        token from the board's own network before saving. A supplied zone_id is
        stored without that check, so the setup flow leaves it out."""
        self.json("PUT", "/api/v1/config/cloudflare",
                  {"api_token": api_token, "zone_name": zone_name, "zone_id": zone_id}, timeout=60)

    def sync_management_time(self) -> None:
        self.json("POST", "/api/v1/commissioning/time/sync", timeout=60)

    def request_certificate(self, fqdn: str, log: Log = _quiet) -> None:
        """Ask the board for its Let's Encrypt certificate and wait for it.

        Issuance takes a few minutes. The board then switches HTTPS to the new
        certificate, which can drop this connection, so success is confirmed by
        reading the stored certificate back rather than from the reply alone.
        """
        log("Requesting the certificate. This usually takes 1 to 3 minutes...")
        try:
            self.json("POST", "/api/v1/acme/production/certificate/issue", {"hostname": fqdn}, timeout=600)
        except SetupError as exc:
            if "already exists" not in str(exc):
                raise
            log("The board already has a certificate; checking it...")
        except (OSError, ssl.SSLError, http.client.HTTPException):
            log("The connection closed during issuance; checking the result...")

    def certificate_status(self) -> dict:
        return self.json("GET", "/api/v1/acme/production/certificate")

    def get_hardware(self) -> dict:
        return self.json("GET", "/api/v1/hardware/profile")

    def set_hardware(self, profile: dict) -> None:
        keys = ("board_family", "board_revision", "pps_gpio", "gnss_uart",
                "gnss_rx_gpio", "gnss_tx_gpio", "requested_cpu_mhz")
        self.json("PUT", "/api/v1/hardware/profile", {k: profile[k] for k in keys})


def wait_for_certificate(board: Board, fqdn: str, timeout: float = 600.0, log: Log = _quiet) -> dict:
    """After issuance, reconnect by hostname with normal certificate checks."""
    secure = Board(board.host, credentials=board.credentials, tls_name=fqdn)
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        try:
            # Succeeding at all proves the board now serves a publicly trusted
            # certificate for fqdn; the fields confirm what it stored.
            info = secure.certificate_status()
            if info.get("certificate_parse_valid") and info.get("hostname_matches_certificate"):
                return info
            last = info
        except (SetupError, OSError, ssl.SSLError, http.client.HTTPException) as exc:
            last = exc
        time.sleep(10)
    raise SetupError(f"The certificate was not confirmed within {int(timeout)} s ({last}). "
                     "Check the board's Certificate & ACME card; DNS validation can take longer.")


# ---------------------------------------------------------------------------
# DNS and Cloudflare (from this computer, with the same token)
# ---------------------------------------------------------------------------

CLOUDFLARE_API = "https://api.cloudflare.com/client/v4"


def _cloudflare(token: str, method: str, path: str, payload=None) -> dict:
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(CLOUDFLARE_API + path, data=data, method=method, headers={
        "Authorization": f"Bearer {token}", "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        try:
            errors = json.loads(exc.read()).get("errors", [])
            detail = "; ".join(e.get("message", "") for e in errors) or str(exc)
        except ValueError:
            detail = str(exc)
        raise SetupError(f"Cloudflare refused the request: {detail}") from exc
    except urllib.error.URLError as exc:
        raise SetupError(f"Could not reach Cloudflare: {exc.reason}") from exc


def cloudflare_zone_id(token: str, zone_name: str) -> str:
    result = _cloudflare(token, "GET", f"/zones?name={zone_name}").get("result", [])
    if not result:
        raise SetupError(f"The token cannot see a zone called {zone_name}. Check the spelling and that "
                         "the token has Zone:Read on it.")
    return result[0]["id"]


def cloudflare_set_a_record(token: str, zone_id: str, fqdn: str, ip: str, log: Log = _quiet) -> str:
    """Create or update the A record for fqdn. DNS only, never proxied."""
    existing = _cloudflare(token, "GET", f"/zones/{zone_id}/dns_records?type=A&name={fqdn}").get("result", [])
    record = {"type": "A", "name": fqdn, "content": ip, "ttl": 300, "proxied": False}
    if existing:
        if existing[0].get("content") == ip and not existing[0].get("proxied"):
            log(f"DNS already points {fqdn} at {ip}.")
            return "unchanged"
        _cloudflare(token, "PUT", f"/zones/{zone_id}/dns_records/{existing[0]['id']}", record)
        log(f"Updated DNS: {fqdn} -> {ip}")
        return "updated"
    _cloudflare(token, "POST", f"/zones/{zone_id}/dns_records", record)
    log(f"Created DNS: {fqdn} -> {ip}")
    return "created"


def resolves_to(fqdn: str, ip: str) -> bool:
    try:
        return ip in {a[4][0] for a in socket.getaddrinfo(fqdn, 443, socket.AF_INET)}
    except socket.gaierror:
        return False


# ---------------------------------------------------------------------------
# Small helpers used by both front ends
# ---------------------------------------------------------------------------

def valid_ipv4(text: str) -> bool:
    try:
        ipaddress.IPv4Address(text)
        return True
    except ValueError:
        return False


def split_dns(text: str) -> list[str]:
    """'192.168.1.1, 1.1.1.1' -> ['192.168.1.1', '1.1.1.1'] (commas, spaces or semicolons)."""
    return [p for p in re.split(r"[\s,;]+", text.strip()) if p]


def valid_hostname(text: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", text))


def valid_fqdn(text: str) -> bool:
    labels = text.rstrip(".").split(".")
    return len(labels) >= 2 and len(text) <= 253 and all(valid_hostname(l) for l in labels)


def default_credentials_folder(hostname: str) -> Path:
    return Path.home() / "Documents" / f"management-credentials-{hostname or 'board'}"


def import_into_windows_store(credentials: Credentials, log: Log = _quiet) -> str:
    """Import the administrator certificate into the current user's store so
    Edge and Chrome offer it. Returns the certificate thumbprint."""
    if os.name != "nt":
        raise SetupError("Automatic import is only available on Windows.")
    script = ("$p = ConvertTo-SecureString $env:NTP_SETUP_P12_PASSWORD -AsPlainText -Force; "
              f"$c = Import-PfxCertificate -FilePath '{credentials.p12}' "
              "-CertStoreLocation Cert:\\CurrentUser\\My -Password $p; $c.Thumbprint")
    env = dict(os.environ, NTP_SETUP_P12_PASSWORD=credentials.password)
    proc = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
                          capture_output=True, text=True, env=env)
    thumb = (proc.stdout or "").strip().splitlines()
    if proc.returncode != 0 or not thumb:
        raise SetupError("Importing the certificate failed: " + (proc.stderr or "").strip())
    log(f"Imported the administrator certificate (thumbprint {thumb[-1]}).")
    return thumb[-1]


@dataclass
class SetupRecord:
    """Non-secret notes about a board, saved beside its credentials."""
    hostname: str = ""
    fqdn: str = ""
    ip: str = ""
    bootstrap_fingerprint: str = ""
    static_ip: bool = False
    certificate: bool = False
    updated: str = ""

    def save(self, folder: Path) -> None:
        self.updated = _dt.datetime.now().isoformat(timespec="seconds")
        (Path(folder) / "board-setup.json").write_text(json.dumps(asdict(self), indent=2))

    @classmethod
    def load(cls, folder: Path) -> "SetupRecord":
        p = Path(folder) / "board-setup.json"
        if p.is_file():
            data = json.loads(p.read_text())
            return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})
        return cls()
