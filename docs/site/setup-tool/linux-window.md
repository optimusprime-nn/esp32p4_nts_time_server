# Linux, setup window

Needs a desktop session, Python 3.10 or newer, `python3-venv` and `python3-tk`,
and membership of the `dialout` group. See
[What you need](../getting-started/what-you-need.md#a-computer-to-run-setup).

1. **Connect the board** to USB and Ethernet.
2. **Start the tool** from a terminal in the unpacked release:

    ```sh
    cd esp32p4-time-server-3.1.11/setup
    ./setup.sh
    ```

    - The first run prepares the tool for about a minute.
    - If it prints *you are not in the 'dialout' group*, run
      `sudo usermod -aG dialout "$USER"`, log out and back in, and start again.
    - If it prints *The window needs Tkinter*, install `python3-tk`, or carry on
      with the terminal questions instead.

3. **Connect.** Choose the board's **Serial port**, usually `/dev/ttyUSB0` or
   `/dev/ttyACM0`. Click **Next**.
4. **Firmware.** Leave **This is a new board: write the firmware** ticked for a
   new board. Click **Start** and confirm.

    !!! warning "This cannot be undone"
        Flash encryption is turned on at the first boot. Do not unplug the board
        until the tool moves on.

5. **Certificate.** Enter a short name (`ts1`), check the folder, and choose a
   password of at least 8 characters, twice. Click **Next**.
6. **Claim.** Click **Claim**. The board restarts and the tool reconnects with
   your certificate.
7. **Name.** Enter the hostname and full DNS name. Click **Next**.
8. **Network.** Keep DHCP (and reserve the address on your router), or tick
   **Set a static address on the board**, check the fields, click **Next** and
   confirm.
9. **DNS.** Check the zone, paste the API token, and leave the DNS record box
   ticked unless you manage DNS yourself. Click **Next**.
10. **Let's Encrypt.** Click **Get certificate** and wait 1 to 3 minutes.
11. **Finish.** Tick the GNSS pins box only for a carrier board with different
    wiring. Click **Finish**.
12. **Done.** The window shows the console address and the credentials folder.

## Open the console in a browser

The tool cannot install the certificate into Linux browsers for you. Import
`admin-client.p12` from the credentials folder yourself, using the folder's
password:

- **Firefox:** Settings → Privacy & Security → Certificates → View
  Certificates → Your Certificates → Import.
- **Chrome or Chromium:** Settings → Privacy and security → Security → Manage
  certificates → Your certificates → Import.

Then browse to `https://ts1.example.com/` and choose the `ntp-admin` certificate.

Next: [Check that it works](../getting-started/verify.md).
