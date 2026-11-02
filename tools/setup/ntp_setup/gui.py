"""Setup window (Tkinter, included with Python on Windows and most Linux).

A step-by-step wizard over the same steps as the guided CLI (flow.py). Each
step's work runs on a background thread; the window stays responsive and
shows progress in the log at the bottom.
"""

from __future__ import annotations

import os
import queue
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from . import core, flow
from .core import SetupError

STEPS = ["Connect", "Firmware", "Certificate", "Claim", "Name",
         "Network", "DNS", "Let's Encrypt", "Finish"]
PAD = {"padx": 10, "pady": 4}


class App(tk.Tk):
    def __init__(self, firmware_dir: str | None = None):
        super().__init__()
        self.title("ESP32-P4 Time Server Setup")
        self.geometry("860x620")
        self.minsize(760, 560)
        self.firmware_dir = firmware_dir
        self.events: "queue.Queue[tuple]" = queue.Queue()
        self.session = flow.Session(log=lambda m: self.events.put(("log", m)))
        self.step = 0
        self.busy = False
        self._build()
        self.show(0)
        self.after(100, self._pump)

    # -- layout -------------------------------------------------------------------
    def _build(self):
        style = ttk.Style(self)
        if "vista" in style.theme_names():
            style.theme_use("vista")
        side = ttk.Frame(self, padding=(12, 12))
        side.pack(side="left", fill="y")
        ttk.Label(side, text="Setup", font=("Segoe UI", 13, "bold")).pack(anchor="w", pady=(0, 8))
        self.step_labels = []
        for i, name in enumerate(STEPS):
            lbl = ttk.Label(side, text=f"{i + 1}. {name}")
            lbl.pack(anchor="w", pady=2)
            self.step_labels.append(lbl)

        main = ttk.Frame(self, padding=(4, 12, 12, 8))
        main.pack(side="left", fill="both", expand=True)
        self.title_var = tk.StringVar()
        ttk.Label(main, textvariable=self.title_var, font=("Segoe UI", 14, "bold")).pack(anchor="w")
        self.body = ttk.Frame(main)
        self.body.pack(fill="both", expand=True, pady=(8, 8))

        self.progress = ttk.Progressbar(main, mode="indeterminate")
        self.progress.pack(fill="x")
        logf = ttk.Frame(main)
        logf.pack(fill="both", expand=False, pady=(6, 6))
        self.log = tk.Text(logf, height=9, wrap="word", state="disabled", font=("Consolas", 9))
        sb = ttk.Scrollbar(logf, command=self.log.yview)
        self.log.configure(yscrollcommand=sb.set)
        self.log.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")

        nav = ttk.Frame(main)
        nav.pack(fill="x")
        self.next_btn = ttk.Button(nav, text="Next", command=self.next)
        self.next_btn.pack(side="right")
        ttk.Button(nav, text="Quit", command=self.destroy).pack(side="left")

    def _clear(self):
        for w in self.body.winfo_children():
            w.destroy()

    def text(self, message: str, wrap: int = 560):
        ttk.Label(self.body, text=message, wraplength=wrap, justify="left").pack(anchor="w", **PAD)

    def field(self, label: str, value: str = "", show: str = "") -> tk.StringVar:
        row = ttk.Frame(self.body)
        row.pack(fill="x", **PAD)
        ttk.Label(row, text=label, width=26).pack(side="left")
        var = tk.StringVar(value=value)
        ttk.Entry(row, textvariable=var, show=show).pack(side="left", fill="x", expand=True)
        return var

    def check(self, label: str, value: bool = False) -> tk.BooleanVar:
        var = tk.BooleanVar(value=value)
        ttk.Checkbutton(self.body, text=label, variable=var).pack(anchor="w", **PAD)
        return var

    # -- plumbing -------------------------------------------------------------------
    def _pump(self):
        try:
            while True:
                kind, *rest = self.events.get_nowait()
                if kind == "log":
                    self._append(rest[0])
                elif kind == "done":
                    self._finished(*rest)
        except queue.Empty:
            pass
        self.after(100, self._pump)

    def _append(self, message: str):
        self.log.configure(state="normal")
        self.log.insert("end", message + "\n")
        self.log.see("end")
        self.log.configure(state="disabled")

    def work(self, fn, then):
        """Run fn on a thread; call then(result) on success."""
        self.busy = True
        self.next_btn.configure(state="disabled")
        self.progress.start(12)

        def target():
            try:
                self.events.put(("done", True, fn(), then))
            except SetupError as exc:
                self.events.put(("done", False, str(exc), then))
            except Exception as exc:  # shown to the user rather than lost on a thread
                self.events.put(("done", False, f"Unexpected error: {exc!r}", then))
        threading.Thread(target=target, daemon=True).start()

    def _finished(self, ok, result, then):
        self.busy = False
        self.progress.stop()
        self.next_btn.configure(state="normal")
        if ok:
            then(result)
        else:
            self._append("Stopped: " + result)
            messagebox.showerror("Setup stopped", result + "\n\nFix the problem and press Next to try again.")

    def show(self, step: int):
        self.step = step
        for i, lbl in enumerate(self.step_labels):
            lbl.configure(font=("Segoe UI", 10, "bold" if i == step else "normal"),
                          foreground="" if i >= step else "gray40")
        self.title_var.set(STEPS[step])
        self._clear()
        self.next_btn.configure(text="Next")
        getattr(self, f"page_{step}")()

    def next(self):
        if not self.busy:
            getattr(self, f"do_{self.step}")()

    def advance(self, _result=None):
        self.show(self.step + 1)

    # -- 1. connect -----------------------------------------------------------------
    def page_0(self):
        self.text("Connect the board to this computer with USB and to your network with Ethernet. "
                  "You also need a domain on Cloudflare and an API token with Zone:Read and DNS:Edit.")
        self.ports = core.list_serial_ports()
        self.port_var = tk.StringVar()
        row = ttk.Frame(self.body)
        row.pack(fill="x", **PAD)
        ttk.Label(row, text="Serial port", width=26).pack(side="left")
        values = [f"{d}  {desc}" for d, desc in self.ports]
        box = ttk.Combobox(row, textvariable=self.port_var, values=values, state="readonly")
        box.pack(side="left", fill="x", expand=True)
        ttk.Button(row, text="Refresh", command=lambda: self.show(0)).pack(side="left", padx=4)
        if values:
            box.current(0)
        else:
            self.text("No serial ports found. Connect the USB cable, then press Refresh.")

    def do_0(self):
        if not self.port_var.get():
            messagebox.showwarning("Choose a port", "Choose the board's serial port.")
            return
        self.session.port = self.port_var.get().split()[0]
        self.advance()

    # -- 2. firmware ----------------------------------------------------------------
    def page_1(self):
        self.text("A new board needs the firmware written once over USB. Writing it turns on flash "
                  "encryption at the first boot. That is permanent: later updates go over the network.")
        self.flash_var = self.check("This is a new board: write the firmware", True)
        self.text("Untick this if the board already runs this firmware, for example when re-running "
                  "setup. Next then reads the board's console.")
        self.next_btn.configure(text="Start")

    def do_1(self):
        flash = self.flash_var.get()
        if flash and not messagebox.askyesno(
                "Write firmware?", "Write the firmware and turn on flash encryption? This cannot be undone."):
            return
        def job():
            if flash:
                self.session.flash(self.firmware_dir)
            return self.session.read_board(reset=True)
        self.work(job, self.advance)

    # -- 3. credentials -------------------------------------------------------------
    def page_2(self):
        b = self.session.boot
        if b.provisioned:
            self.text("This board is already claimed. Choose the credentials folder created when it was "
                      "claimed, and its password.")
            self.folder_var = self.field("Credentials folder", str(core.default_credentials_folder("ts1")))
        else:
            self.text("Setup creates a certificate on this computer that becomes the only key to this "
                      "board's management. Keep the folder and password safe: if both are lost, the "
                      "board cannot be recovered remotely.")
            self.name_var = self.field("Short name for this board", "ts1")
            self.folder_var = self.field("Save credentials in", "")
            self.name_var.trace_add("write", lambda *_: self.folder_var.set(
                str(core.default_credentials_folder(self.name_var.get().strip()))))
            self.folder_var.set(str(core.default_credentials_folder("ts1")))
        ttk.Button(self.body, text="Browse...", command=self._browse).pack(anchor="w", **PAD)
        self.pw_var = self.field("Password", show="*")
        if not b.provisioned:
            self.pw2_var = self.field("Password again", show="*")

    def _browse(self):
        d = filedialog.askdirectory(initialdir=os.path.expanduser("~"))
        if d:
            self.folder_var.set(d)

    def do_2(self):
        b = self.session.boot
        pw = self.pw_var.get()
        if not b.provisioned and pw != self.pw2_var.get():
            messagebox.showwarning("Passwords differ", "The two passwords do not match.")
            return
        folder = self.folder_var.get().strip()
        if b.provisioned:
            self.work(lambda: self.session.existing_credentials(folder, pw), self.advance)
        else:
            self.work(lambda: self.session.new_credentials(folder, pw), self.advance)

    # -- 4. claim -------------------------------------------------------------------
    def page_3(self):
        b = self.session.boot
        if b.provisioned:
            self.text(f"The board at {b.ip} is already claimed. Next connects to it with your certificate.")
        else:
            self.text(f"The board at {b.ip} is ready to be claimed. Its identity is checked against the "
                      f"fingerprint it printed on the serial console ({b.fingerprint[:16]}...), so nothing "
                      "is sent to an impostor.")
        self.next_btn.configure(text="Claim" if not b.provisioned else "Connect")

    def do_3(self):
        self.work(self.session.claim, self.advance)

    # -- 5. identity ----------------------------------------------------------------
    def page_4(self):
        rec = self.session.record
        self.text("Name the board. The full DNS name is what clients use for NTS and what the "
                  "certificate is issued for.")
        self.host_var = self.field("Hostname", rec.hostname or "ts1")
        self.fqdn_var = self.field("Full DNS name", rec.fqdn or "ts1.example.com")
        self.text("Fallback NTP servers set the board's clock for certificate checks before GNSS locks. "
                  "They never affect the time it serves.")
        self.ntp0_var = self.field("Fallback NTP 1", flow.DEFAULT_NTP[0])
        self.ntp1_var = self.field("Fallback NTP 2", flow.DEFAULT_NTP[1])

    def do_4(self):
        args = (self.host_var.get().strip(), self.fqdn_var.get().strip(),
                self.ntp0_var.get().strip(), self.ntp1_var.get().strip())
        self.work(lambda: self.session.identity(*args), self.advance)

    # -- 6. network -----------------------------------------------------------------
    def page_5(self):
        board = self.session.board
        self.text(f"The board's address is {board.host}. It must never change, because DNS will point at "
                  "it. Either reserve it on your router and keep DHCP, or set a static address here.")
        self.static_var = self.check("Set a static address on the board")
        self.addr_var = self.field("Address", board.host)
        self.mask_var = self.field("Netmask", "")
        self.gw_var = self.field("Gateway", "")
        self.dns_var = self.field("DNS server (optional)", "")
        def fill(result):
            ip, mask, gw = result
            self.addr_var.set(ip); self.mask_var.set(mask); self.gw_var.set(gw); self.dns_var.set(gw)
        self.work(lambda: flow.current_network(board), fill)

    def do_5(self):
        static = self.static_var.get()
        vals = [v.get().strip() for v in (self.addr_var, self.mask_var, self.gw_var, self.dns_var)]
        if static and not messagebox.askyesno(
                "Apply static address?",
                f"Restart the board on {vals[0]}? If the settings are wrong it will be unreachable until "
                "they are corrected."):
            return
        self.work(lambda: self.session.network(static, *vals), self.advance)

    # -- 7. DNS / Cloudflare ----------------------------------------------------------
    def page_6(self):
        fqdn = self.session.record.fqdn
        self.text("The board gets its certificate from Let's Encrypt by proving it controls the name, "
                  "using a Cloudflare API token limited to Zone:Read and DNS:Edit on your zone. The token "
                  "is stored encrypted on the board and never shown again.")
        self.zone_var = self.field("Cloudflare zone", fqdn.split(".", 1)[1] if "." in fqdn else "")
        self.token_var = self.field("API token", show="*")
        self.dns_var2 = self.check(f"Create or update the DNS record {fqdn} -> {self.session.board.host}", True)

    def do_6(self):
        token, zone, create = self.token_var.get().strip(), self.zone_var.get().strip(), self.dns_var2.get()
        if not token:
            messagebox.showwarning("Token needed", "Enter the Cloudflare API token.")
            return
        self.work(lambda: self.session.cloudflare(token, zone, create), self.advance)

    # -- 8. certificate ----------------------------------------------------------------
    def page_7(self):
        self.text(f"Next asks Let's Encrypt for a certificate for {self.session.record.fqdn}. It usually "
                  "takes 1 to 3 minutes. The board then switches to it, and this tool checks it the same "
                  "way a browser would.")
        self.next_btn.configure(text="Get certificate")

    def do_7(self):
        self.work(self.session.certificate, self.advance)

    # -- 9. finish -------------------------------------------------------------------
    def page_8(self):
        self.text("Almost done.")
        self.hw_var = self.check("This is a different carrier board with GNSS on non-standard pins "
                                 "(most people: leave unticked)")
        self.imp_var = self.check("Install the administrator certificate in Windows for the browser",
                                  os.name == "nt") if os.name == "nt" else None
        self.next_btn.configure(text="Finish")

    def do_8(self):
        if self.hw_var.get():
            self.work(self.session.hardware, self._hardware_page)
            return
        self._complete()

    def _hardware_page(self, hw):
        self._clear()
        self.title_var.set("GNSS pins")
        self.text("Only change these if your board wires the GNSS receiver differently. Wrong pins stop "
                  "GNSS working; the board restarts to apply them.")
        self.hw = hw
        self.hw_vars = {k: self.field(label, str(hw[k])) for k, label in (
            ("pps_gpio", "PPS GPIO"), ("gnss_uart", "GNSS UART number"),
            ("gnss_rx_gpio", "RX GPIO (receiver TXD)"), ("gnss_tx_gpio", "TX GPIO (receiver RXD)"))}
        self.next_btn.configure(text="Save pins", command=self._save_hardware)

    def _save_hardware(self):
        try:
            for k, v in self.hw_vars.items():
                self.hw[k] = int(v.get())
        except ValueError:
            messagebox.showwarning("Numbers only", "Each pin must be a number.")
            return
        self.next_btn.configure(command=self.next)
        self.work(lambda: self.session.set_hardware(self.hw), lambda _r: self._complete())

    def _complete(self):
        imp = bool(self.imp_var and self.imp_var.get())

        def done(notes):
            self._clear()
            self.title_var.set("Done")
            for n in notes:
                self.text(n)
            if os.name != "nt":
                self.text(f"To use the console in a browser, import {self.session.credentials.p12} "
                          "into its certificate settings.")
            self.text("The board serves time once the console shows the clock as SYNCHRONIZED.")
            self.next_btn.configure(text="Close", command=self.destroy)
        self.work(lambda: self.session.finish(imp), done)


def run(firmware_dir: str | None = None) -> int:
    App(firmware_dir).mainloop()
    return 0
