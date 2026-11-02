# Windows, console

The same setup as the window, as questions in a console. Every question shows a
default in `[brackets]`; press Enter to accept it. Passwords and the token are
not shown as you type.

1. **Connect the board** to USB and Ethernet.
2. **Open a console in the setup folder.** In File Explorer, open the `setup`
   folder, type `cmd` in the address bar and press Enter.
3. **Start the tool:**

    ```bat
    setup.cmd --cli
    ```

    The first run prepares the tool for about a minute.

4. **Step 1 of 9: Connect the board.** The tool lists serial ports. Enter the
   number of the board's port.
5. **Step 2 of 9: Firmware.**

    ```text
    Is this a new board that needs flashing? (Y/n): y
    Write the firmware now? (Y/n): y
    ```

    !!! warning "This cannot be undone"
        Flash encryption is turned on at the first boot. Do not unplug the board
        while the tool is working.

    The tool writes the firmware, resets the board and reads its console for up
    to 4 minutes.

6. **Step 3 of 9: Your administrator certificate.**

    ```text
    Short name for this board (used for the folder) [ts1]:
    Save the credentials in [C:\Users\you\Documents\management-credentials-ts1]:
    Choose a password (at least 8 characters):
    Type it again:
    ```

7. **Step 4 of 9: Claim the board.** No questions. The board restarts and the
   tool reconnects with your certificate.
8. **Step 5 of 9: Name.**

    ```text
    Board hostname [ts1]:
    Full DNS name for its certificate [ts1.example.com]:
    Fallback NTP server 1 (only used to set the clock before GNSS locks) [time.cloudflare.com]:
    Fallback NTP server 2 [time.google.com]:
    ```

9. **Step 6 of 9: Network address.** The tool shows the DHCP address.
    - Answer `n` to *Set a static address on the board?* to keep DHCP. Reserve
      the address on your router.
    - Answer `y` to enter a static address, netmask, gateway and DNS server.
      Up to two DNS servers can be given, separated by a comma. Confirm, and
      the board restarts on the new address.
10. **Step 7 of 9: DNS and Cloudflare.**

    ```text
    Cloudflare zone (your domain) [example.com]:
    Cloudflare API token (input is hidden):
    Create or update the DNS record ts1.example.com -> 192.0.2.10 for you? (Y/n):
    ```

11. **Step 8 of 9: Certificate.** No questions. Usually 1 to 3 minutes.
12. **Step 9 of 9: Finish.**

    ```text
    Is this a different carrier board with GNSS on non-standard pins? (most people: no) (y/N):
    Install the administrator certificate in Windows so your browser can open the console? (Y/n):
    ```

    The tool prints the certificate thumbprint, the console address and the
    credentials folder, then:

    ```text
    Done. The board is serving time once its clock shows SYNCHRONIZED in the console.
    ```

If a step fails, the tool prints `Stopped:` and the reason, and exits. Fix the
problem and run it again; see [Running it again](index.md#running-it-again).
Press Ctrl+C to cancel at any question.

Next: [Check that it works](../getting-started/verify.md).
