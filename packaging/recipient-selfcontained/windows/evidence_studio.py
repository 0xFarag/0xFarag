#!/usr/bin/env python3
# © Nasser Aldin Farag (0xFarag). All rights reserved.
"""Desktop access to the existing offline recipient verifier."""
import concurrent.futures
from pathlib import Path
import subprocess
import sys
import tkinter as tk
from tkinter import filedialog, ttk


def check(command, bundle, key):
    if not bundle or not key:
        raise ValueError("Choose both the handover folder and the trusted public key.")
    root = Path(bundle).resolve(strict=True)
    trusted = Path(key).resolve(strict=True)
    if not root.is_dir() or not trusted.is_file():
        raise ValueError("Choose a handover directory and a public key file.")
    if root == trusted or root in trusted.parents:
        raise ValueError("The trusted public key must come from outside the handover folder.")
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    result = subprocess.run(
        [*command, str(root), "--public-key", str(trusted)], capture_output=True,
        text=True, errors="replace", timeout=180, creationflags=flags, check=False,
    )
    if result.returncode == 0 and "VERIFIED:" in result.stdout:
        return "Verified", "The signature, file inventory, hashes and report anchors match the trusted key."
    if result.returncode == 1:
        return "Verification failed", (result.stderr.strip() or "The verifier rejected the handover.")[:600]
    raise RuntimeError("The verifier could not complete the check. Check the local installation.")


class Studio:
    def __init__(self, window, command):
        self.window = window
        self.command = command
        self.pool = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        self.future = None
        self.values = [tk.StringVar(), tk.StringVar()]
        self.status = tk.StringVar(value="Ready")
        self.detail = tk.StringVar(value="Obtain the sender’s public key through an independent channel.")
        window.title("AuthzLedger · Recipient Studio")
        window.minsize(560, 330)
        frame = ttk.Frame(window, padding=22)
        frame.grid(sticky="nsew")
        window.columnconfigure(0, weight=1)
        window.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)
        ttk.Label(frame, text="Verify a signed handover", font=("TkDefaultFont", 16, "bold")).grid(row=0, column=0, columnspan=2, sticky="w", pady=(0,10))
        for index, label in enumerate(("Handover folder", "Independent public key (PEM)")):
            row = 1 + 2 * index
            ttk.Label(frame, text=label).grid(row=row, column=0, sticky="w")
            ttk.Entry(frame, textvariable=self.values[index], width=47).grid(row=row+1, column=0, sticky="ew", pady=(2,8))
            ttk.Button(frame, text="Browse…", command=lambda i=index: self.choose(i)).grid(row=row+1, column=1, padx=(8,0), pady=(2,8))
        self.button = ttk.Button(frame, text="Verify handover", command=self.start)
        self.button.grid(row=5, column=0, sticky="w", pady=(0,9))
        ttk.Label(frame, textvariable=self.status, font=("TkDefaultFont", 12, "bold")).grid(row=6, column=0, columnspan=2, sticky="w")
        ttk.Label(frame, textvariable=self.detail, wraplength=540).grid(row=7, column=0, columnspan=2, sticky="w", pady=(3,9))
        ttk.Label(frame, text="© Nasser Aldin Farag (0xFarag). All rights reserved.").grid(row=8, column=0, columnspan=2, sticky="w")
        for value in self.values:
            value.trace_add("write", self.changed)

    def changed(self, *_):
        if self.future is None:
            self.status.set("Ready")
            self.detail.set("Obtain the sender’s public key through an independent channel.")

    def choose(self, index):
        if index == 0:
            path = filedialog.askdirectory(parent=self.window, mustexist=True)
        else:
            path = filedialog.askopenfilename(parent=self.window, filetypes=[("Public keys","*.pem"),("All files","*")])
        if path:
            self.values[index].set(path)

    def start(self):
        if self.future is not None:
            return
        self.inputs = tuple(value.get() for value in self.values)
        self.status.set("Verifying…")
        self.detail.set("")
        self.button.state(["disabled"])
        self.future = self.pool.submit(check, self.command, *self.inputs)
        self.window.after(50, self.finish)

    def finish(self):
        if not self.future.done():
            self.window.after(50, self.finish)
            return
        try:
            status, detail = self.future.result()
        except (OSError, RuntimeError, ValueError, subprocess.TimeoutExpired) as exc:
            status, detail = "Check incomplete", str(exc)
        self.future = None
        self.button.state(["!disabled"])
        if self.inputs != tuple(value.get() for value in self.values):
            self.changed()
        else:
            self.status.set(status)
            self.detail.set(detail)

    def close(self):
        self.pool.shutdown(wait=False, cancel_futures=True)
        self.window.destroy()


def launch(command, smoke=False):
    window = tk.Tk()
    studio = Studio(window, command)
    window.protocol("WM_DELETE_WINDOW", studio.close)
    if smoke:
        window.update_idletasks()
        studio.close()
    else:
        window.mainloop()
    return 0


if __name__ == "__main__":
    if sys.argv[1:] not in ([], ["--smoke"]):
        sys.exit("Usage: authzledger-studio [--smoke]")
    sys.exit(launch(["/usr/bin/authzledger-verify"], smoke=bool(sys.argv[1:])))
