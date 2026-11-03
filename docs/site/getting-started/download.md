# Download

Releases are on the project's
[GitHub releases page](https://github.com/optimusprime-nn/esp32p4_nts_time_server/releases).
Each release has these files:

| File | Use it for |
|---|---|
| `esp32p4-time-server-<version>.zip` | Setting up a **new** board. Contains the setup tool and the firmware |
| `esp32p4_nts_time_server-<version>-silicon-v1.bin` | Updating a board that is **already running**, chip revision v1.x. Upload it on the board's Firmware page |
| `esp32p4_nts_time_server-<version>-silicon-v3.bin` | The same, for chip revision v3.x |
| `SHA256SUMS.txt` | Checking the downloads are complete and unaltered |

## Check the download

=== "Windows (PowerShell)"

    ```powershell
    Get-FileHash .\esp32p4-time-server-3.1.12.zip -Algorithm SHA256
    ```

=== "Linux"

    ```sh
    sha256sum -c SHA256SUMS.txt --ignore-missing
    ```

The hash must match the line for that file in `SHA256SUMS.txt`.

## Unpack

Extract the zip anywhere you can write to, for example your Documents folder. It
contains:

```text
esp32p4-time-server-3.1.12/
  README.txt
  firmware/
    silicon-v1/      images for chip revisions v1.x: four .bin files,
                     flash_args and variant.json
    silicon-v3/      the same for chip revisions v3.x
  setup/
    setup.cmd        Windows launcher
    setup.sh         Linux launcher
    requirements.txt
    ntp_setup/       the setup tool
```

Keep the `firmware` folder next to the `setup` folder. The tool looks for it
there, reads the chip's silicon revision and writes the matching variant. You do
not choose. If you move it, start the tool with `--firmware <folder>`.

The first time you start the tool it creates a `.venv` folder inside `setup` and
installs its Python packages (`cryptography`, `pyserial`, `esptool`). This takes
a minute and needs internet access. Later starts are immediate.

Next: [Quick setup with the tool](../setup-tool/index.md).
