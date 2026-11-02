# Windows, setup window

1. **Connect the board.** Plug the USB cable into this PC and the Ethernet
   cable into your network.
2. **Start the tool.** In the unpacked release, open the `setup` folder and
   double-click `setup.cmd`.
    - The first time, a console shows *First run: preparing the setup tool* for
      about a minute.
    - If it says Python 3.10 or newer is needed, run
      `winget install --id Python.Python.3.12 -e`, open a new window and try again.

    The **ESP32-P4 Time Server Setup** window opens. The steps are listed on the
    left. Progress messages appear in the log at the bottom.

3. **Connect.** Choose the board's **Serial port** from the list (the most
   likely one is first). Press **Refresh** if you plugged it in after the
   window opened. Click **Next**.
4. **Firmware.** Leave **This is a new board: write the firmware** ticked for a
   new board. Click **Start**, then **Yes** to confirm.

    !!! warning "This cannot be undone"
        Flash encryption is turned on at the first boot. Do not unplug the board
        until the tool moves to the next step.

    Writing takes about a minute. The tool then resets the board and reads its
    console. A first boot can take up to 4 minutes, because the board encrypts
    its flash and restarts.

5. **Certificate.** Enter a **Short name for this board** (for example `ts1`).
   The folder updates to match. Choose a **Password** of at least 8 characters,
   enter it again, and click **Next**.
6. **Claim.** The window shows the board's address and the start of its
   fingerprint. Click **Claim**. The board restarts, and the tool reconnects
   using your new certificate.
7. **Name.** Enter the **Hostname** (`ts1`) and **Full DNS name**
   (`ts1.example.com`). Leave the two fallback NTP servers as they are unless
   you need others. Click **Next**.
8. **Network.** The tool shows the address the board got from DHCP.
    - To keep DHCP, leave **Set a static address on the board** unticked. Then
      reserve that address on your router.
    - To set a static address, tick the box, check the address, netmask, gateway
      and DNS server, click **Next**, and confirm. The board restarts on the new
      address.
9. **DNS.** Check the **Cloudflare zone** (your domain), paste the **API
   token**, and leave **Create or update the DNS record** ticked unless you
   manage DNS yourself. Click **Next**.
10. **Let's Encrypt.** Click **Get certificate**. This usually takes 1 to 3
    minutes. The log ends with the certificate's expiry date.
11. **Finish.** Leave **Install the administrator certificate in Windows**
    ticked so your browser can open the console. Tick the GNSS pins box only if
    your carrier board wires the receiver differently (most people: leave it
    unticked). Click **Finish**.
12. **Done.** The window lists:
    - the administrator certificate thumbprint (for the update script);
    - the console address, for example `https://ts1.example.com/`;
    - the credentials folder.

    Click **Close**.

Open the console address in Edge or Chrome and choose the `ntp-admin`
certificate when asked. Then [check that it works](../getting-started/verify.md).

If a step fails, a message explains why. Fix the problem and click **Next** to
try that step again. See [Troubleshooting](../help/troubleshooting.md#setup-tool-messages).
