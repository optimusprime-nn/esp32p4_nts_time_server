"""Package a release from ESP-IDF builds, one per silicon variant.

    python tools/release/make_release.py OUT_DIR BUILD_DIR [BUILD_DIR ...]

Each BUILD_DIR is one variant: a build for ESP32-P4 silicon below v3.0
(sdkconfig.defaults) and one for v3.x (sdkconfig.defaults plus
sdkconfig.defaults.v3). ESP-IDF cannot build one image for both.

Writes, for the version in CMakeLists.txt:
  esp32p4-time-server-<v>.zip
      setup/                       the setup tool
      firmware/silicon-v1/         images for chips below v3.0 (360 MHz)
      firmware/silicon-v3/         images for chips v3.0 and later (400 MHz)
      README.txt
  esp32p4_nts_time_server-<v>-silicon-v<N>.bin   app image per variant, for OTA
  SHA256SUMS.txt

The setup tool reads the chip revision and picks the matching folder. Each
folder's variant.json records the revision range it supports.
"""

import hashlib
import json
import re
import shutil
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
IMAGES = {  # flash_args entry -> file name in the variant folder
    "bootloader/bootloader.bin": "bootloader.bin",
    "partition_table/partition-table.bin": "partition-table.bin",
    "ota_data_initial.bin": "ota_data_initial.bin",
    "esp32p4_nts_time_server.bin": "esp32p4_nts_time_server.bin",
}
TOOL_FILES = ["requirements.txt", "setup.cmd", "setup.sh"]
# Variants not yet proven on hardware. The setup tool shows this and asks
# for confirmation before flashing one. Remove an entry once that silicon
# has been tested.
PREVIEW = {"silicon-v3": "This firmware is for ESP32-P4 silicon v3.x. It is built and checked, but it has not yet run on v3.x hardware, so treat this board as the first test."}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def variant_of(build: Path, version: str) -> dict:
    app = build / "esp32p4_nts_time_server.bin"
    if version.encode() not in app.read_bytes():
        sys.exit(f"{app} does not contain version {version}; rebuild before packaging.")
    for entry in IMAGES:
        if not (build / entry).is_file():
            sys.exit(f"missing {build / entry}")
    cfg = json.loads((build / "config" / "sdkconfig.json").read_text())
    lo, hi = cfg["ESP32P4_REV_MIN_FULL"], cfg["ESP32P4_REV_MAX_FULL"]
    if not cfg.get("SECURE_FLASH_ENC_ENABLED") or not cfg.get("NVS_ENCRYPTION"):
        sys.exit(f"{build} is not built with flash and NVS encryption; refusing to package it.")
    name = f"silicon-v{hi // 100}"
    variant = {"name": name, "min_rev": lo, "max_rev": hi, "cpu_mhz": cfg["ESP_DEFAULT_CPU_FREQ_MHZ"]}
    if name in PREVIEW:
        variant["preview"] = PREVIEW[name]
    return variant


def main(out: Path, builds: list[Path]) -> None:
    version = re.search(r'set\(PROJECT_VER "([^"]+)"\)', (ROOT / "CMakeLists.txt").read_text()).group(1)
    variants = [(b, variant_of(b, version)) for b in builds]
    names = [v["name"] for _, v in variants]
    if len(set(names)) != len(names):
        sys.exit(f"two builds are the same variant: {names}")

    out.mkdir(parents=True, exist_ok=True)
    name = f"esp32p4-time-server-{version}"
    stage = out / name
    if stage.exists():
        shutil.rmtree(stage)
    otas = []
    for build, v in variants:
        fw = stage / "firmware" / v["name"]
        fw.mkdir(parents=True)
        for entry, dest in IMAGES.items():
            shutil.copy2(build / entry, fw / dest)
        args = (build / "flash_args").read_text().split()
        (fw / "flash_args").write_text(" ".join(IMAGES.get(a, a) for a in args) + "\n")
        (fw / "variant.json").write_text(json.dumps(v, indent=2) + "\n")
        ota = out / f"esp32p4_nts_time_server-{version}-{v['name']}.bin"
        shutil.copy2(build / "esp32p4_nts_time_server.bin", ota)
        otas.append((ota, v))

    tool_src = ROOT / "tools" / "setup"
    shutil.copytree(tool_src / "ntp_setup", stage / "setup" / "ntp_setup",
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    for f in TOOL_FILES:
        shutil.copy2(tool_src / f, stage / "setup" / f)
    lines = [f"ESP32-P4 GNSS Time Server {version}", "",
             "Set up a new board:",
             "  Windows: open the 'setup' folder and double-click setup.cmd",
             "  Linux:   cd setup && ./setup.sh",
             "Add --cli to use the guided command line instead of the window.",
             "The tool reads the chip's silicon revision and writes the matching firmware.", "",
             "To update a board that is already running, upload the OTA image for its",
             "silicon on its Firmware page (the wrong one is refused):"]
    for ota, v in otas:
        lines.append(f"  {ota.name}  revisions v{v['min_rev'] // 100}.{v['min_rev'] % 100:02d}"
                     f" to v{v['max_rev'] // 100}.{v['max_rev'] % 100:02d}, {v['cpu_mhz']} MHz"
                     + (" (preview: not yet tested on this silicon)" if v.get("preview") else ""))
    lines += ["", "Documentation: https://optimusprime-nn.github.io/esp32p4_nts_time_server/", ""]
    (stage / "README.txt").write_text("\n".join(lines))

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

    files = [zip_path] + [o for o, _ in otas]
    (out / "SHA256SUMS.txt").write_text("".join(f"{sha256(p)}  {p.name}\n" for p in files))
    print(f"Release {version} written to {out}")
    for p in files:
        print(f"  {p.name}  {p.stat().st_size} bytes  sha256 {sha256(p)}")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    main(Path(sys.argv[1]), [Path(a) for a in sys.argv[2:]])
