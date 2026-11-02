#!/usr/bin/env sh
# ESP32-P4 time server setup (Linux).
#   ./setup.sh          opens the setup window if a desktop is available
#   ./setup.sh --cli    guided setup in this terminal
set -e
cd "$(dirname "$0")"

if ! command -v python3 >/dev/null 2>&1; then
  echo "Python 3.10 or newer is needed. On Debian or Ubuntu:"
  echo "    sudo apt install python3 python3-venv python3-tk"
  exit 1
fi

if [ ! -x .venv/bin/python ]; then
  echo "First run: preparing the setup tool. This takes a minute..."
  if ! python3 -m venv .venv; then
    echo "Could not create a virtual environment. On Debian or Ubuntu:"
    echo "    sudo apt install python3-venv"
    rm -rf .venv
    exit 1
  fi
  .venv/bin/python -m pip install --quiet --upgrade pip
  .venv/bin/python -m pip install --quiet -r requirements.txt
fi

# Reading the board's USB serial port needs membership of the dialout group.
if [ -e /dev/ttyUSB0 ] || [ -e /dev/ttyACM0 ]; then
  if ! id -nG | grep -qw dialout && [ "$(id -u)" != "0" ]; then
    echo "Note: you are not in the 'dialout' group, so the serial port may be refused."
    echo "    sudo usermod -aG dialout \"$USER\"   (then log out and back in)"
  fi
fi

exec .venv/bin/python -m ntp_setup "$@"
