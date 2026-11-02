"""Offline tests for the setup tool. No board, serial port or network needed.

    cd tools/setup && python -m unittest discover -s tests
"""

import json
import ssl
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from ntp_setup import core
from ntp_setup.core import Board, BootInfo, SetupError


class ConsoleParsing(unittest.TestCase):
    LOG = [
        "\x1b[0;33mW (1234) OWNERSHIP: Device is UNPROVISIONED\x1b[0m",
        "W (1235) OWNERSHIP: One-time management enrollment code: 0123456789ABCDEF0123456789ABCDEF",
        "I (4000) ETH: DHCP IPv4 acquired: 192.0.2.10",
        "W (5000) WEB: Bootstrap certificate SHA-256: " + "AB" * 32,
    ]

    def test_unclaimed_board(self):
        info = BootInfo()
        for line in self.LOG:
            self.assertFalse(info.complete())
            core.parse_console_line(line, info)
        self.assertTrue(info.complete())
        self.assertEqual(info.enrollment_code, "0123456789ABCDEF0123456789ABCDEF")
        self.assertEqual(info.ip, "192.0.2.10")
        self.assertEqual(info.fingerprint, "AB" * 32)
        self.assertFalse(info.provisioned)

    def test_claimed_board_needs_ip_and_fingerprint(self):
        info = BootInfo()
        core.parse_console_line("I (900) OWNERSHIP: Management ownership is provisioned; mTLS", info)
        core.parse_console_line("I (4000) ETH: Static IPv4 acquired: 192.0.2.11", info)
        self.assertTrue(info.provisioned)
        self.assertFalse(info.complete())
        core.parse_console_line("W (5000) WEB: Bootstrap certificate SHA-256: " + "CD" * 32, info)
        self.assertTrue(info.complete())


class Validation(unittest.TestCase):
    def test_names_and_addresses(self):
        self.assertTrue(core.valid_hostname("ts1"))
        self.assertFalse(core.valid_hostname("-bad"))
        self.assertTrue(core.valid_fqdn("ts1.example.com"))
        self.assertFalse(core.valid_fqdn("ts1"))
        self.assertTrue(core.valid_ipv4("192.0.2.10"))
        self.assertFalse(core.valid_ipv4("192.0.2.300"))


class CredentialFiles(unittest.TestCase):
    def test_create_load_and_refuse_overwrite(self):
        from cryptography import x509
        from cryptography.hazmat.primitives.serialization import pkcs12
        with tempfile.TemporaryDirectory() as d:
            creds = core.create_credentials(d, "correct horse", "ntp-admin")
            ca = x509.load_pem_x509_certificate(creds.ca_cert.read_bytes())
            admin = x509.load_pem_x509_certificate(creds.client_cert.read_bytes())
            self.assertTrue(ca.extensions.get_extension_for_class(x509.BasicConstraints).value.ca)
            self.assertEqual(admin.issuer, ca.subject)
            ca.public_key().verify(admin.signature, admin.tbs_certificate_bytes,
                                   __import__("cryptography.hazmat.primitives.asymmetric.ec",
                                              fromlist=["ECDSA"]).ECDSA(admin.signature_hash_algorithm))
            key, cert, extra = pkcs12.load_key_and_certificates(creds.p12.read_bytes(), b"correct horse")
            self.assertEqual(cert, admin)
            self.assertEqual(len(extra), 1)
            for f in ("management-ca.key.pem", "admin-client.key.pem"):
                self.assertIn(b"ENCRYPTED", (Path(d) / f).read_bytes())
            core.load_credentials(d, "correct horse")
            with self.assertRaises(SetupError):
                core.load_credentials(d, "wrong password")
            with self.assertRaises(SetupError):
                core.create_credentials(d, "correct horse")

    def test_short_password_refused(self):
        with tempfile.TemporaryDirectory() as d, self.assertRaises(SetupError):
            core.create_credentials(d, "short")


def _self_signed(directory: Path, name: str = "esp32p4-ntp-bootstrap"):
    """A server certificate standing in for the board's bootstrap certificate."""
    import datetime as dt
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
            .public_key(key.public_key()).serial_number(1)
            .not_valid_before(now - dt.timedelta(days=1)).not_valid_after(now + dt.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), critical=False)
            .sign(key, hashes.SHA256()))
    (directory / "srv.crt").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (directory / "srv.key").write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                                          serialization.PrivateFormat.PKCS8,
                                                          serialization.NoEncryption()))
    return core._fingerprint(cert.public_bytes(serialization.Encoding.DER))


class FakeBoard:
    """A local HTTPS server that behaves like the board's claim and v1 API."""

    def __init__(self, directory: Path, ca_file=None):
        self.received = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def _reply(self, status, body=b"{}"):
                self.send_response(status)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_PUT(self):
                body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
                outer.received.append(("PUT", self.path, dict(self.headers), body))
                if self.path == "/api/v1/provisioning/claim":
                    ok = self.headers.get("X-Provisioning-Code") == "0" * 32
                    return self._reply(200 if ok else 403, b"claimed" if ok else b"bad code")
                self._reply(200)

            def do_GET(self):
                outer.received.append(("GET", self.path, dict(self.headers), b""))
                if self.path == "/api/v1/status":
                    peer = self.connection.getpeercert()
                    return self._reply(200, json.dumps({"device": {"ipv4": "127.0.0.1",
                                                                    "client": bool(peer)}}).encode())
                self._reply(404, b"not found")

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(directory / "srv.crt", directory / "srv.key")
        if ca_file:
            ctx.verify_mode = ssl.CERT_REQUIRED
            ctx.load_verify_locations(str(ca_file))
        self.httpd = HTTPServer(("127.0.0.1", 0), Handler)
        self.httpd.socket = ctx.wrap_socket(self.httpd.socket, server_side=True)
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()


class PinnedConnections(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.fingerprint = _self_signed(self.dir)

    def tearDown(self):
        self.tmp.cleanup()

    def _board(self, server, **kw):
        b = Board("127.0.0.1", **kw)
        orig = core._Connection.__init__

        def init(conn, host, port, **k):
            orig(conn, host, server.port, **k)
        core._Connection.__init__ = init
        self.addCleanup(setattr, core._Connection, "__init__", orig)
        return b

    def test_claim_with_matching_pin(self):
        server = FakeBoard(self.dir)
        self.addCleanup(server.close)
        self._board(server, pin=self.fingerprint).claim("0" * 32, b"-----BEGIN CERTIFICATE-----")
        method, path, headers, body = server.received[-1]
        self.assertEqual(path, "/api/v1/provisioning/claim")
        self.assertEqual(body, b"-----BEGIN CERTIFICATE-----")

    def test_wrong_pin_sends_nothing(self):
        server = FakeBoard(self.dir)
        self.addCleanup(server.close)
        with self.assertRaisesRegex(SetupError, "does not match"):
            self._board(server, pin="00" * 32).claim("0" * 32, b"secret")
        self.assertEqual(server.received, [])

    def test_bad_code_message(self):
        server = FakeBoard(self.dir)
        self.addCleanup(server.close)
        with self.assertRaisesRegex(SetupError, "rejected the enrollment code"):
            self._board(server, pin=self.fingerprint).claim("1" * 32, b"x")

    def test_mutual_tls_after_claim(self):
        creds = core.create_credentials(self.dir / "creds", "correct horse")
        server = FakeBoard(self.dir, ca_file=creds.ca_cert)
        self.addCleanup(server.close)
        status = self._board(server, pin=self.fingerprint, credentials=creds).json("GET", "/api/v1/status")
        self.assertTrue(status["device"]["client"])
        with self.assertRaises((ssl.SSLError, OSError, SetupError)):
            self._board(server, pin=self.fingerprint).json("GET", "/api/v1/status")

    def test_name_checked_when_not_pinning(self):
        # Without a pin the certificate must chain to a trusted root and match the
        # name, so the bootstrap certificate is refused.
        server = FakeBoard(self.dir)
        self.addCleanup(server.close)
        with self.assertRaises(ssl.SSLError):
            self._board(server, tls_name="ts1.example.com").json("GET", "/api/v1/status")


class Firmware(unittest.TestCase):
    def test_find_firmware(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            with self.assertRaises(SetupError):
                core.find_firmware(d)
            (p / "flash_args").write_text("--flash-mode dio\n0x2000 bootloader/bootloader.bin\n")
            for f in core.FIRMWARE_FILES:
                (p / f).write_bytes(b"\0")
            self.assertEqual(core.find_firmware(d), p)


if __name__ == "__main__":
    unittest.main()
