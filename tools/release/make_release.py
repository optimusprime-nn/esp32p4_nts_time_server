"""Package a release from an ESP-IDF build directory.

    python tools/release/make_release.py BUILD_DIR OUT_DIR

Writes, for the version in CMakeLists.txt:
  esp32p4-time-server-<v>.zip      setup tool + firmware folder, for new boards
  esp32p4_nts_time_server-<v>.bin  app image, for updating a running board
  SHA256SUMS.txt

Refuses to package if the build's version does not match CMakeLists.txt, so a
stale build directory cannot be shipped under a new version number.
"""

import hashlib
import re
import shutil
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
IMAGES = {  # flash_args entry -> file name in the release's firmware folder
    "bootloader/bootloader.bin": "bootloader.bin",
    "partition_table/partition-table.bin": "partition-table.bin",
    "ota_data_initial.bin": "ota_data_initial.bin",
    "esp32p4_nts_time_server.bin": "esp32p4_nts_time_server.bin",
}
TOOL_FILES = ["requirements.txt", "setup.cmd", "setup.sh"]


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main(build: Path, out: Path) -> None:
    version = re.search(r'set\(PROJECT_VER "([^"]+)"\)', (ROOT / "CMakeLists.txt").read_text()).group(1)
    app = build / "esp32p4_nts_time_server.bin"
    if version.encode() not in app.read_bytes():
        sys.exit(f"{app} does not contain version {version}; rebuild before packaging.")
    for entry in IMAGES:
        if not (build / entry).is_file():
            sys.exit(f"missing {build / entry}")

    out.mkdir(parents=True, exist_ok=True)
    name = f"esp32p4-time-server-{version}"
    stage = out / name
    if stage.exists():
        shutil.rmtree(stage)
    (stage / "firmware").mkdir(parents=True)
    for entry, dest in IMAGES.items():
        shutil.copy2(build / entry, stage / "firmware" / dest)
    args = (build / "flash_args").read_text().split()
    (stage / "firmware" / "flash_args").write_text(
        " ".join(IMAGES.get(a, a) for a in args) + "\n")

    tool_src = ROOT / "tools" / "setup"
    shutil.copytree(tool_src / "ntp_setup", stage / "setup" / "ntp_setup",
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    for f in TOOL_FILES:
        shutil.copy2(tool_src / f, stage / "setup" / f)
    (stage / "README.txt").write_text(
        f"ESP32-P4 GNSS Time Server {version}\n\n"
        "Set up a new board:\n"
        "  Windows: open the 'setup' folder and double-click setup.cmd\n"
        "  Linux:   cd setup && ./setup.sh\n"
        "Add --cli to use the guided command line instead of the window.\n\n"
        "The 'firmware' folder is used by the setup tool. To update a board that is\n"
        "already running, upload esp32p4_nts_time_server.bin on its Firmware page.\n\n"
        "Documentation: https://optimusprime-nn.github.io/esp32p4_nts_time_server/\n")

    zip_path = out / f"{name}.zip"
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as z:
        for p in sorted(stage.rglob("*")):
            info = zipfile.ZipInfo.from_file(p, p.relative_to(out).as_posix())
            if p.name == "setup.sh":
                info.external_attr = (0o755 << 16)  # keep it executable on Linux
            if p.is_file():
                data = p.read_bytes()
                if p.suffix == ".sh":
                    data = data.replace(b"\r\n", b"\n")  # CRLF stops a script starting on Linux
                info.compress_type = zipfile.ZIP_DEFLATED
                z.writestr(info, data)
    shutil.rmtree(stage)

    ota = out / f"esp32p4_nts_time_server-{version}.bin"
    shutil.copy2(app, ota)
    (out / "SHA256SUMS.txt").write_text(
        "".join(f"{sha256(p)}  {p.name}\n" for p in (zip_path, ota)))
    print(f"Release {version} written to {out}")
    for p in (zip_path, ota):
        print(f"  {p.name}  {p.stat().st_size} bytes  sha256 {sha256(p)}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    main(Path(sys.argv[1]), Path(sys.argv[2]))
