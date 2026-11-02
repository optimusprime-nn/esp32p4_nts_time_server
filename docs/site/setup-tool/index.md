# Quick setup with the tool

The setup tool takes a new board from blank to serving time with a certificate.
It runs on Windows and Linux, as a window or as questions in a terminal. Both
run the same steps in the same order.

Choose your walkthrough:

| | Window | Text only |
|---|---|---|
| **Windows** | [Windows, setup window](windows-window.md) | [Windows, console](windows-console.md) |
| **Linux** | [Linux, setup window](linux-window.md) | [Linux, terminal](linux-terminal.md) |

Before you start, have ready everything in [What you need](../getting-started/what-you-need.md):
the board on USB and Ethernet, the Cloudflare token, and the names you chose.

## What the tool does

| Step | What happens | Can be skipped? |
|---|---|---|
| 1. Connect | You choose the board's serial port | No |
| 2. Firmware | Writes the firmware over USB, then resets the board and reads its serial console for the enrollment code, the bootstrap certificate fingerprint and the IP address | Writing is skipped for a board that already runs the firmware. Reading always happens |
| 3. Certificate | Creates your management certificate authority and administrator certificate in a folder on this computer, protected by a password you choose. For an already-claimed board, opens the folder from the earlier run instead | No |
| 4. Claim | Sends the CA certificate to the board with the enrollment code. The board restarts and from then on accepts management only from your certificate | Skipped if the board is already claimed |
| 5. Name | Sets the hostname, the full DNS name for the certificate and two fallback NTP servers | No |
| 6. Network | Keeps DHCP, or sets a static address and restarts the board on it | No |
| 7. DNS | Checks the Cloudflare token, optionally creates the DNS `A` record, and stores the token on the board | Creating the record is optional |
| 8. Let's Encrypt | The board requests its certificate and switches HTTPS to it. The tool then checks it the way a browser would | No |
| 9. Finish | Optional GNSS pin changes for other carrier boards, optional import of your certificate into Windows, and a summary | Both options are optional |

!!! warning "Step 2 is permanent"
    Writing the firmware to a new board turns on flash encryption at its first
    boot. This burns a key into the chip's eFuses and cannot be undone. After
    that, the board can only be updated over the network, or over USB with the
    encrypted-flash commands in [Building from source](../building.md). The tool
    refuses to write to a board that is already encrypted.

## How the board is protected during setup

- The board makes its own bootstrap TLS certificate on its first boot and prints
  its SHA-256 fingerprint on the serial console, next to the enrollment code.
  The tool reads both over USB and checks every HTTPS connection against that
  fingerprint until the Let's Encrypt certificate is in place. If the
  fingerprint does not match, the tool stops before sending anything.
- Only the CA **certificate** leaves your computer. All private keys stay in the
  credentials folder, encrypted with your password.
- Five wrong enrollment codes lock enrollment until the board is reset. The tool
  always reads a fresh code, so this only happens if something else is
  guessing.

## The credentials folder

By default the tool saves to `Documents/management-credentials-<name>` in your
home folder. It contains:

| File | What it is |
|---|---|
| `management-ca.crt.pem` | The CA certificate. A copy is on the board |
| `management-ca.key.pem` | The CA private key, encrypted. Needed to make new administrator certificates |
| `admin-client.crt.pem`, `admin-client.key.pem` | Your administrator certificate and its encrypted key, for scripts |
| `admin-client.p12` | The same certificate and key in one file, for importing into a browser or Windows |
| `board-setup.json` | Non-secret notes: hostname, DNS name, address, fingerprint |

The tool never overwrites an existing credentials folder. Use a new folder for
every board.

!!! danger "Keep the folder and its password safe"
    They are the only key to the board's management. There is **no remote
    recovery** if both the administrator certificate and the CA key are lost.
    Store the folder and its password somewhere safe, outside any code
    repository.

## Running it again

If setup stops, fix the problem it describes and run it again:

1. On the Firmware step, say the board is **not** new, so nothing is written.
2. The tool resets the board and sees that it is already claimed.
3. Open the credentials folder you created the first time, with its password.
4. Continue from the Name step.

If the board already has a valid Let's Encrypt certificate for the same name,
the Let's Encrypt step keeps it and only checks it, so running setup again on a
finished board is safe.

## Options

| Option | Effect |
|---|---|
| `--cli` | Use the questions in the terminal instead of the window |
| `--firmware <folder>` | Use firmware from another folder. It must hold `flash_args` and the four `.bin` files |

On Linux the tool uses the terminal automatically when there is no desktop
(`DISPLAY` and `WAYLAND_DISPLAY` unset), and when Tkinter is not installed.
