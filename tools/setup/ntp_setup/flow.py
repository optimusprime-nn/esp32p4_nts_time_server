"""The setup sequence, as steps both front ends run in the same order.

Each step takes the answers it needs and does its work through core.py. The
front ends decide how to ask; this module decides what happens and in which
order, so the CLI and the window cannot drift apart.

    1. flash       (new board only)
    2. read_board  (serial: enrollment code, fingerprint, IP)
    3. credentials (create new, or open the folder from an earlier run)
    4. claim       (skipped if the board is already claimed)
    5. identity    (hostname, certificate name, fallback NTP servers)
    6. network     (keep DHCP, or set a static address and reboot)
    7. cloudflare  (token check on the board; optional DNS record)
    8. certificate (Let's Encrypt; the board switches HTTPS to it)
    9. hardware    (optional: only for a different carrier board)
   10. finish      (optional certificate import, saved notes)
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from . import core
from .core import Board, BootInfo, Credentials, Log, SetupError, SetupRecord

DEFAULT_NTP = ("time.cloudflare.com", "time.google.com")


@dataclass
class Session:
    log: Log
    port: str = ""
    boot: Optional[BootInfo] = None
    credentials: Optional[Credentials] = None
    board: Optional[Board] = None
    record: Optional[SetupRecord] = None

    # 1 ---------------------------------------------------------------------
    def flash(self, firmware_dir: Optional[str]) -> None:
        variants = core.find_firmware(firmware_dir)
        self.log("Firmware available: " + "; ".join(v.describe() for v in variants))
        core.flash_new_board(self.port, variants, self.log)
        self.log("Firmware written. The board now encrypts its flash on first boot; "
                 "do not unplug it.")

    # 2 ---------------------------------------------------------------------
    def read_board(self, reset: bool = True, echo: Optional[Log] = None) -> BootInfo:
        self.log("Reading the board's console (up to 4 minutes on a first boot)...")
        self.boot = core.read_boot(self.port, reset=reset, log=self.log, echo=echo)
        b = self.boot
        if b.provisioned:
            self.log(f"Board is already claimed; address {b.ip}.")
        else:
            self.log(f"Board is waiting to be claimed; address {b.ip}.")
        return b

    # 3 ---------------------------------------------------------------------
    def new_credentials(self, folder: str, password: str, admin_name: str = "ntp-admin") -> Credentials:
        self.credentials = core.create_credentials(folder, password, admin_name, self.log)
        self.record = SetupRecord()
        return self.credentials

    def existing_credentials(self, folder: str, password: str) -> Credentials:
        self.credentials = core.load_credentials(folder, password)
        self.record = SetupRecord.load(self.credentials.folder)
        self.log(f"Opened credentials in {self.credentials.folder}")
        return self.credentials

    # 4 ---------------------------------------------------------------------
    def claim(self) -> None:
        b = self._boot()
        creds = self._creds()
        if b.provisioned:
            self.log("Skipping the claim: the board is already claimed.")
        else:
            self.log("Claiming the board...")
            Board(b.ip, pin=b.fingerprint).claim(b.enrollment_code, creds.ca_cert.read_bytes())
            self.log("Claimed. The board restarts with management locked to your certificate.")
            # Read the restart: a board that kept a production certificate from an
            # earlier claim switches to it now, and prints that certificate's
            # fingerprint instead.
            try:
                after = core.read_boot(self.port, reset=False, timeout=90, log=self.log)
                if after.fingerprint:
                    self.boot = after
                    b = after
            except SetupError as exc:
                self.log(f"Could not read the restart ({exc}); using the enrollment fingerprint.")
        self.board = self._connect(b.ip)
        self.board.wait_ready(log=self.log)
        rec = self._rec()
        rec.ip = b.ip
        rec.bootstrap_fingerprint = b.fingerprint or rec.bootstrap_fingerprint
        rec.save(creds.folder)
        self.log("Connected to the management API.")

    # 5 ---------------------------------------------------------------------
    def identity(self, hostname: str, fqdn: str, ntp0: str = DEFAULT_NTP[0], ntp1: str = DEFAULT_NTP[1]) -> None:
        if not core.valid_hostname(hostname):
            raise SetupError("The hostname must be letters, digits and hyphens, for example ts1.")
        if not core.valid_fqdn(fqdn):
            raise SetupError("The certificate name must be a full DNS name, for example ts1.example.com.")
        self._board().set_identity(hostname, fqdn, ntp0, ntp1)
        rec = self._rec()
        rec.hostname, rec.fqdn = hostname, fqdn
        rec.save(self._creds().folder)
        self.log(f"Saved identity: {hostname}, {fqdn}.")

    # 6 ---------------------------------------------------------------------
    def network(self, static: bool, address: str = "", netmask: str = "", gateway: str = "", dns: str = "") -> None:
        board = self._board()
        if static:
            for name, value in (("address", address), ("netmask", netmask), ("gateway", gateway)):
                if not core.valid_ipv4(value):
                    raise SetupError(f"The {name} must look like 192.168.1.10.")
            servers = core.split_dns(dns)
            if len(servers) > 2 or not all(core.valid_ipv4(d) for d in servers):
                raise SetupError("Enter up to two DNS server addresses separated by a comma, for example "
                                 "192.168.1.1, 1.1.1.1 (names cannot be used), or leave it blank.")
            dns = ", ".join(servers)
        board.set_network(static, address, netmask, gateway, dns)
        rec = self._rec()
        new_ip = address if static else None
        if static and address != board.host:
            self.log(f"Static address saved; restarting the board on {address}...")
            board.reboot_and_wait(new_host=address, log=self.log)
        elif static:
            self.log("Static address saved (same as now); it applies at the next restart.")
        else:
            self.log("Keeping DHCP. Reserve this address on your router so it never changes.")
        rec.ip = new_ip or board.host
        rec.static_ip = static
        rec.save(self._creds().folder)

    # 7 ---------------------------------------------------------------------
    def cloudflare(self, token: str, zone_name: str, create_dns: bool) -> None:
        board = self._board()
        rec = self._rec()
        zone_name = zone_name.strip().rstrip(".")
        if not rec.fqdn.endswith("." + zone_name) and rec.fqdn != zone_name:
            raise SetupError(f"{rec.fqdn} is not inside the zone {zone_name}.")
        zone_id = core.cloudflare_zone_id(token, zone_name)
        self.log(f"Found zone {zone_name}.")
        if create_dns:
            core.cloudflare_set_a_record(token, zone_id, rec.fqdn, board.host, self.log)
        self.log("Saving the token on the board (it checks it with Cloudflare first)...")
        # No zone_id: the board then resolves the zone itself, which proves the
        # token works from the board's network, not just from this computer.
        board.set_cloudflare(token, zone_name)
        self.log("Cloudflare is set up on the board.")

    # 8 ---------------------------------------------------------------------
    def certificate(self) -> dict:
        board = self._board()
        rec = self._rec()
        try:
            existing = board.certificate_status()
        except SetupError:
            existing = {}
        if (existing.get("certificate_parse_valid") and existing.get("hostname_matches_certificate")
                and existing.get("hostname") == rec.fqdn):
            # Re-running setup on a finished board: keep its certificate.
            self.log(f"The board already has a certificate for {rec.fqdn}; keeping it.")
            info = core.wait_for_certificate(board, rec.fqdn, log=self.log)
            self.board = Board(board.host, credentials=self._creds(), tls_name=rec.fqdn)
            rec.certificate = True
            rec.save(self._creds().folder)
            return info
        try:
            board.sync_management_time()
            self.log("Board clock set for certificate checks.")
        except SetupError as exc:
            self.log(f"Note: {exc}. Continuing; GNSS time is used once it locks.")
        board.request_certificate(rec.fqdn, self.log)
        info = core.wait_for_certificate(board, rec.fqdn, log=self.log)
        self.board = Board(board.host, credentials=self._creds(), tls_name=rec.fqdn)
        rec.certificate = True
        rec.save(self._creds().folder)
        self.log(f"Certificate issued for {rec.fqdn}, valid to {info.get('valid_to', '?')}.")
        return info

    # 9 ---------------------------------------------------------------------
    def hardware(self) -> dict:
        return self._board().get_hardware()

    def set_hardware(self, profile: dict) -> None:
        self._board().set_hardware(profile)
        self.log("Hardware profile saved; restarting the board to apply it...")
        self._board().reboot_and_wait(log=self.log)

    # 10 --------------------------------------------------------------------
    def finish(self, import_windows: bool) -> list[str]:
        creds = self._creds()
        rec = self._rec()
        notes = []
        if import_windows:
            thumb = core.import_into_windows_store(creds, self.log)
            notes.append(f"Administrator certificate thumbprint: {thumb}")
        notes += [
            f"Console: https://{rec.fqdn or rec.ip}/",
            f"Credentials: {creds.folder}",
            "Keep that folder and its password safe; there is no remote recovery without them.",
        ]
        rec.save(creds.folder)
        return notes

    def browser_steps(self, imported: bool) -> list[tuple[str, list[str]]]:
        """How to open the console in a browser with the administrator
        certificate, as (heading, numbered steps). Shown at the end of setup."""
        creds = self._creds()
        url = f"https://{self._rec().fqdn or self._rec().ip}/"
        open_steps = [
            f"Open {url}",
            "When the browser asks you to choose a certificate, pick ntp-admin "
            "(issued by ESP32-P4 Management CA) and click OK.",
            "If you get a connection error instead of that question, close every window of the "
            "browser and open it again: browsers remember a 'no certificate' choice.",
        ]
        sections: list[tuple[str, list[str]]] = []
        if os.name == "nt":
            if imported:
                sections.append(("Edge or Chrome (the certificate is already installed)", open_steps))
            else:
                sections.append(("Install the certificate for Edge and Chrome", [
                    f"Double-click {creds.p12} to open the Certificate Import Wizard.",
                    "Choose Current User, then Next, then Next again.",
                    "Enter the password you chose in setup. Leave the other options as they are. Next.",
                    "Choose 'Automatically select the certificate store', then Next and Finish.",
                ] + open_steps))
        else:
            sections.append(("Chrome or Chromium", [
                "Open Settings > Privacy and security > Security > Manage certificates.",
                f"Under Your certificates, click Import and choose {creds.p12}.",
                "Enter the password you chose in setup.",
            ] + open_steps))
        sections.append(("Firefox (keeps its own certificates on every system)", [
            "Open Settings > Privacy & Security, scroll to Certificates and click View Certificates.",
            f"On Your Certificates, click Import and choose {creds.p12}.",
            "Enter the password you chose in setup.",
        ] + open_steps))
        return sections

    # helpers -----------------------------------------------------------------
    def _connect(self, ip: str) -> Board:
        """Connect to a claimed board: pin while it is on its bootstrap
        certificate, otherwise verify the Let's Encrypt certificate by name."""
        rec = self._rec()
        pin = (self.boot.fingerprint if self.boot else None) or None
        if pin:
            return Board(ip, pin=pin, credentials=self._creds())
        if rec.fqdn:
            return Board(ip, credentials=self._creds(), tls_name=rec.fqdn)
        raise SetupError("Cannot verify this board: it is not on its bootstrap certificate and no "
                         "hostname is recorded. Choose its credentials folder from the original setup.")

    def _boot(self) -> BootInfo:
        if not self.boot:
            raise SetupError("Read the board first.")
        return self.boot

    def _creds(self) -> Credentials:
        if not self.credentials:
            raise SetupError("Create or open credentials first.")
        return self.credentials

    def _board(self) -> Board:
        if not self.board:
            raise SetupError("Claim or connect to the board first.")
        return self.board

    def _rec(self) -> SetupRecord:
        if self.record is None:
            self.record = SetupRecord()
        return self.record


def current_network(board: Board) -> tuple[str, str, str]:
    """The address, netmask and gateway the board is using now (from DHCP),
    used to prefill the static-address questions."""
    device = board.json("GET", "/api/v1/status").get("device", {})
    return device.get("ipv4", board.host), device.get("netmask", "255.255.255.0"), device.get("gateway", "")


def credentials_exist(folder: str) -> bool:
    return (Path(folder).expanduser() / "admin-client.key.pem").is_file()
