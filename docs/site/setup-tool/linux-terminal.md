# Linux, terminal

Use this on a server without a desktop, or over SSH. Needs Python 3.10 or newer,
`python3-venv`, and membership of the `dialout` group.

1. **Connect the board** to USB and Ethernet.
2. **Start the tool:**

    ```sh
    cd esp32p4-time-server-3.1.12/setup
    ./setup.sh --cli
    ```

    Without a desktop, `./setup.sh` alone also uses the terminal.

3. **Answer the questions.** They are the same as on Windows; each shows a
   default in `[brackets]`:

    | Step | You answer |
    |---|---|
    | 1 of 9: Connect the board | The number of the serial port, usually `/dev/ttyUSB0` or `/dev/ttyACM0` |
    | 2 of 9: Firmware | `y` twice for a new board. **Permanent:** flash encryption is turned on |
    | 3 of 9: Your administrator certificate | Short name, folder, a password of at least 8 characters, twice |
    | 4 of 9: Claim the board | Nothing. The board restarts |
    | 5 of 9: Name | Hostname, full DNS name, two fallback NTP servers |
    | 6 of 9: Network address | `n` to keep DHCP, or `y` and a static address, netmask, gateway and DNS server |
    | 7 of 9: DNS and Cloudflare | Zone, API token (hidden), whether to create the DNS record |
    | 8 of 9: Certificate | Nothing. 1 to 3 minutes |
    | 9 of 9: Finish | Whether this carrier board uses different GNSS pins (usually `n`) |

    The full prompts are shown in [Windows, console](windows-console.md).

4. **Note the summary.** The tool prints the console address, the credentials
   folder, and where `admin-client.p12` is, for importing into a browser.

!!! tip "Running over SSH"
    The machine running the tool needs the board's USB cable, and must reach
    the board on the network on port 443. To open the console from another
    computer, copy `admin-client.p12` there over a secure channel and import it
    into the browser, as in [Linux, setup window](linux-window.md#open-the-console-in-a-browser).

If a step fails the tool prints `Stopped:` and the reason. Fix it and run again;
see [Running it again](index.md#running-it-again).

Next: [Check that it works](../getting-started/verify.md).
