# © Nasser Aldin Farag (0xFarag). All rights reserved.
"""Drive the installed GUI through a valid, tampered and self-trust check."""
from importlib.machinery import SourceFileLoader
from importlib.util import module_from_spec, spec_from_loader
from pathlib import Path
import shutil
import sys
import tempfile
import time
import tkinter as tk

loader = SourceFileLoader("recipient_studio", "/usr/bin/authzledger-studio")
module = module_from_spec(spec_from_loader(loader.name, loader))
loader.exec_module(module)
root = tk.Tk()
app = module.Studio(root, ["/usr/bin/authzledger-verify"])

def verify(bundle, key, expected):
    app.values[0].set(str(bundle))
    app.values[1].set(str(key))
    app.button.invoke()
    timeout = time.monotonic() + 45
    while app.future is not None and time.monotonic() < timeout:
        root.update()
        time.sleep(0.02)
    assert app.status.get() == expected, (app.status.get(), app.detail.get())

try:
    with tempfile.TemporaryDirectory() as name:
        bundle = Path(name, "bundle")
        shutil.copytree(sys.argv[1], bundle)
        verify(bundle, sys.argv[2], "Verified")
        verify(bundle, bundle / "public.pem", "Check incomplete")
        (bundle / "extra.txt").write_text("outside inventory")
        verify(bundle, sys.argv[2], "Verification failed")
finally:
    app.close()
