"""Guided command-line setup. Works the same on Windows and Linux.

Every question shows a sensible default in [brackets]; press Enter to accept
it. Nothing irreversible happens without a plain yes.
"""

from __future__ import annotations

import getpass
import os
import sys

from . import core, flow
from .core import SetupError

BOLD = "\033[1m" if sys.stdout.isatty() and os.name != "nt" else ""
RESET = "\033[0m" if BOLD else ""


def say(text: str = "") -> None:
    print(text, flush=True)


def heading(step: int, total: int, title: str) -> None:
    say()
    say(f"{BOLD}Step {step} of {total}: {title}{RESET}")
    say("-" * (len(title) + 14))


def ask(question: str, default: str = "", check=None, error: str = "") -> str:
    while True:
        suffix = f" [{default}]" if default else ""
        answer = input(f"{question}{suffix}: ").strip() or default
        if not answer:
            say("  Please enter a value.")
            continue
        if check and not check(answer):
            say(f"  {error or 'That does not look right; try again.'}")
            continue
        return answer


def ask_optional(question: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else " (Enter to skip)"
    return input(f"{question}{suffix}: ").strip() or default


def yes(question: str, default: bool = True) -> bool:
    hint = "Y/n" if default else "y/N"
    while True:
        answer = input(f"{question} ({hint}): ").strip().lower()
        if not answer:
            return default
        if answer in ("y", "yes"):
            return True
        if answer in ("n", "no"):
            return False


def secret(question: str, confirm: bool = False) -> str:
    while True:
        first = getpass.getpass(f"{question}: ")
        if not first:
            say("  Please enter a value.")
            continue
        if not confirm:
            return first
        if len(first) < 8:
            say("  Use at least 8 characters.")
            continue
        if getpass.getpass("Type it again: ") == first:
            return first
        say("  Those did not match; try again.")


def run(firmware_dir: str | None = None) -> int:
    total = 9
    s = flow.Session(log=lambda m: say("  " + m))
    say("ESP32-P4 time server setup")
    say("==========================")
    say("This sets up one board: firmware, ownership, network, DNS and its")
    say("certificate. Have ready: the board on USB and Ethernet, a domain on")
    say("Cloudflare, and a Cloudflare API token (Zone:Read and DNS:Edit).")

    try:
        # 1 -- serial port --------------------------------------------------------
        heading(1, total, "Connect the board")
        ports = core.list_serial_ports()
        if not ports:
            raise SetupError("No serial ports found. Connect the board's USB cable and run this again.")
        for i, (dev, desc) in enumerate(ports, 1):
            say(f"  {i}. {dev}  {desc}")
        pick = ask("Which port is the board on? Enter the number", "1",
                   lambda a: a.isdigit() and 1 <= int(a) <= len(ports), "Enter one of the numbers above.")
        s.port = ports[int(pick) - 1][0]

        # 2 -- firmware -------------------------------------------------------------
        heading(2, total, "Firmware")
        say("A new board needs the firmware written once over USB. A board that")
        say("already runs it (for example if you are re-running setup) does not.")
        if yes("Is this a new board that needs flashing?", default=True):
            say("Writing firmware turns on flash encryption at the first boot. That is")
            say("permanent: afterwards, updates go over the network, not USB.")
            if not yes("Write the firmware now?", default=True):
                raise SetupError("Stopped before flashing; nothing was changed.")
            s.flash(firmware_dir)
        s.read_board(reset=True)

        # 3 -- credentials ----------------------------------------------------------
        heading(3, total, "Your administrator certificate")
        if s.boot.provisioned:
            say("This board is already claimed. Open the credentials folder made when it was claimed.")
            folder = ask("Credentials folder", str(core.default_credentials_folder("ts1")))
            s.existing_credentials(folder, secret("Password for that folder"))
        else:
            say("Setup creates a certificate on this computer that becomes the only key to the")
            say("board's management. Keep the folder and password safe: lost, they cannot be")
            say("recovered remotely.")
            name = ask("Short name for this board (used for the folder)", "ts1", core.valid_hostname,
                       "Use letters, digits and hyphens.")
            folder = ask("Save the credentials in", str(core.default_credentials_folder(name)))
            s.new_credentials(folder, secret("Choose a password (at least 8 characters)", confirm=True))

        # 4 -- claim --------------------------------------------------------------
        heading(4, total, "Claim the board")
        s.claim()

        # 5 -- identity -----------------------------------------------------------
        heading(5, total, "Name")
        rec = s.record
        hostname = ask("Board hostname", rec.hostname or "ts1", core.valid_hostname,
                       "Use letters, digits and hyphens, for example ts1.")
        fqdn = ask("Full DNS name for its certificate", rec.fqdn or f"{hostname}.example.com",
                   core.valid_fqdn, "Enter a full name, for example ts1.example.com.")
        ntp0 = ask("Fallback NTP server 1 (only used to set the clock before GNSS locks)", flow.DEFAULT_NTP[0])
        ntp1 = ask("Fallback NTP server 2", flow.DEFAULT_NTP[1])
        s.identity(hostname, fqdn, ntp0, ntp1)

        # 6 -- network ------------------------------------------------------------
        heading(6, total, "Network address")
        ip, mask, gw = flow.current_network(s.board)
        say(f"The board got {ip} from DHCP. Its address must never change, because DNS will point at it.")
        say("Either reserve this address on your router (keep DHCP), or give the board a static address.")
        if yes("Set a static address on the board?", default=False):
            address = ask("Static address", ip, core.valid_ipv4, "Enter an address like 192.168.1.10.")
            netmask = ask("Netmask", mask, core.valid_ipv4, "Enter a mask like 255.255.255.0.")
            gateway = ask("Gateway", gw, core.valid_ipv4, "Enter an address like 192.168.1.1.")
            dns = ask_optional("DNS server", gw)
            say("If these are wrong, the board will be unreachable until it is reflashed or the")
            say("setting is changed from a computer that can still reach it.")
            if yes(f"Apply {address} / {netmask} via {gateway} and restart the board?", default=True):
                s.network(True, address, netmask, gateway, dns)
        else:
            s.network(False)

        # 7 -- Cloudflare / DNS ---------------------------------------------------
        heading(7, total, "DNS and Cloudflare")
        zone = ask("Cloudflare zone (your domain)", fqdn.split(".", 1)[1], core.valid_fqdn)
        token = secret("Cloudflare API token (input is hidden)")
        create = yes(f"Create or update the DNS record {fqdn} -> {s.board.host} for you?", default=True)
        s.cloudflare(token, zone, create)
        token = ""

        # 8 -- certificate --------------------------------------------------------
        heading(8, total, "Certificate")
        s.certificate()

        # 9 -- hardware and finish ------------------------------------------------
        heading(9, total, "Finish")
        if yes("Is this a different carrier board with GNSS on non-standard pins? (most people: no)",
               default=False):
            hw = s.hardware()
            say(f"  Current: PPS GPIO {hw['pps_gpio']}, UART {hw['gnss_uart']} "
                f"(RX {hw['gnss_rx_gpio']}, TX {hw['gnss_tx_gpio']})")
            for key, label in (("pps_gpio", "PPS GPIO"), ("gnss_uart", "GNSS UART number"),
                               ("gnss_rx_gpio", "GNSS RX GPIO (from the receiver's TXD)"),
                               ("gnss_tx_gpio", "GNSS TX GPIO (to the receiver's RXD)")):
                hw[key] = int(ask(label, str(hw[key]), str.isdigit, "Enter a number."))
            if yes("Save these pins and restart the board?", default=True):
                s.set_hardware(hw)
        do_import = os.name == "nt" and yes(
            "Install the administrator certificate in Windows so your browser can open the console?",
            default=True)
        say()
        for line in s.finish(do_import):
            say("  " + line)
        if os.name != "nt":
            say(f"  To use the console in a browser, import {s.credentials.p12} into its certificate settings.")
        say()
        say("Done. The board is serving time once its clock shows SYNCHRONIZED in the console.")
        return 0
    except SetupError as exc:
        say()
        say(f"Stopped: {exc}")
        say("You can run setup again; it picks up from an already-claimed board.")
        return 1
    except KeyboardInterrupt:
        say()
        say("Cancelled.")
        return 130
