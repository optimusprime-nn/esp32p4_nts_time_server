# Known limitations

None of these affect served time unless stated.

| Limitation | Effect |
|---|---|
| The NTP timestamp era rollover in 2036 is not handled | The firmware will need an update before 2036 |
| Settings spanning several stored values are not written atomically | A power cut during a save or restore can leave a partial update. Save or restore again |
| Unmounting the SD card during a log download can free memory still in use | Do not unmount the card while downloading logs |
| The ZIP log export fails if the live log grows during the download | Download again, or download single boot logs |
| Monthly NTS key rotation writes flash from the NTP task | One reply is delayed by a few milliseconds. Timestamps stay accurate |
| A small number of peer samples fall back to software timestamps | An occasional `DEGRADED` peer event |
| A real leap second has been reviewed in code but has not occurred during testing | Exact-second application and holdover across a leap are not fully covered |
| Flash encryption is in development mode and Secure Boot is off | Someone with physical access to the serial port can load other firmware. See [Security model](security.md) |
| No remote recovery if the management credentials are lost | Recovery needs USB access and loses settings. See [Lost credentials](security.md#lost-credentials) |
| systemd-timesyncd and Windows Time cannot use NTS | Use chrony or NTPsec for authenticated time |
