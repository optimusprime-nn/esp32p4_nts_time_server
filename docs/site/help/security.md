# Security model

This page describes what protects the board in release 3.1.11, and what does
not.

## Ownership and management access

1. **Unclaimed.** A new board serves only an information page and the claim
   address on port 443. It prints a one-time enrollment code (32 hex
   characters) on the USB serial console, and a new code at every boot. The
   code is never sent over the network by the board.
2. **Claim.** Whoever has the code sends their management CA certificate with
   it. Five wrong codes lock enrollment until the board reboots.
3. **Claimed.** The board stores the CA, closes enrollment and reboots. From
   then on, port 443 accepts only TLS clients presenting a certificate signed by
   that CA (mutual TLS). There is no password login and no other way in over the
   network.

Your CA key and administrator key never leave your computer. The setup tool
writes them encrypted with your password.

## The bootstrap certificate

Until the board has a Let's Encrypt certificate, it needs some certificate for
HTTPS. From 3.1.11, each board **generates its own** bootstrap key and
self-signed certificate at first boot and keeps them in encrypted flash. The
published firmware contains no private key.

The board prints the certificate's SHA-256 fingerprint on the serial console:

```text
Bootstrap certificate SHA-256: <64 hex characters>
```

next to the enrollment code. The setup tool reads it over USB and refuses to
send anything to a board whose HTTPS certificate does not match. This protects
the claim, and the commissioning steps before Let's Encrypt, from someone on the
network pretending to be the board.

After the Let's Encrypt certificate is active, clients check the board's name in
the normal way.

## Secrets on the board

| Secret | Where |
|---|---|
| Management CA certificate | Encrypted settings |
| Bootstrap key, Let's Encrypt key, ACME account key, NTS keys | Encrypted `nvs_certs` partition |
| Cloudflare API token | Encrypted settings. Never returned by the status or config API |

The Let's Encrypt private key and ACME account key cannot be exported. The
Cloudflare token **is** included in configuration backups, so treat backups as
secrets.

## Flash encryption and Secure Boot

!!! warning "Physical access"
    **Flash encryption is in development mode and Secure Boot is off.** Someone
    with physical access to the USB serial port can still load other firmware
    onto the board. Keep boards physically secure.

    Moving to release mode or enabling Secure Boot burns further permanent
    eFuses and needs its own plan. It is not part of this release.

Flash encryption is turned on at the first boot after the first flash. That
burns a key into the chip's eFuses and cannot be reversed. After it:

- plain `idf.py flash` writes unreadable data; use `idf.py encrypted-flash`;
- erasing the `nvs_keys` partition destroys access to the stored secrets.

## Lost credentials

There is deliberately **no remote recovery**. If both the administrator
certificate and the CA key are lost, nobody can manage the board over the
network. It can only be recovered over USB by clearing its stored ownership,
which also loses its settings. That procedure has not been tested.

Keep the credentials folder and its password in a safe place, and back them up.

## Certificates and their lifetimes

| Certificate | Lifetime | Renewal |
|---|---|---|
| Let's Encrypt server certificate | About 90 days | Automatic, from 30 days before expiry |
| Administrator client certificate | 825 days | Manual: sign a new one with the CA key before it expires |
| Management CA | 10 years | Requires claiming the board again |

Keep the Cloudflare token valid, or automatic renewal fails.

## Keep these out of any repository

- credentials folders (`management-credentials-*`);
- configuration backups;
- `sdkconfig` and any private key files;
- archives of a working tree.
