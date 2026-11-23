"""Desktop entry point. Keep the service private to the loopback interface."""
import argparse
import secrets
import sys
import tempfile
import threading
import urllib.request
import webbrowser
from pathlib import Path

from team.server import bootstrap, make_server, needs_bootstrap


def self_test():
    """Exercise the packaged app, SQLite, the bundled web UI and cryptography."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    key = Ed25519PrivateKey.generate()
    key.public_key().verify(key.sign(b'AuthzLedger packaging self-test'), b'AuthzLedger packaging self-test')
    with tempfile.TemporaryDirectory() as temp:
        location = Path(temp)
        assert needs_bootstrap(location)
        bootstrap(location, 'packaging-admin', secrets.token_urlsafe(32))
        server = make_server(location, host='127.0.0.1', port=0)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            url = f'http://127.0.0.1:{server.server_address[1]}/'
            with urllib.request.urlopen(url, timeout=10) as response:
                if response.status != 200 or b'AuthzLedger' not in response.read():
                    raise ValueError('Bundled workspace UI unavailable')
        finally:
            server.shutdown()
            server.server_close()
            worker.join(5)


def launch(directory, test_window=False):
    import tkinter as tk
    from tkinter import messagebox, simpledialog, ttk
    root = tk.Tk()
    root.title('AuthzLedger Team')
    root.geometry('510x260')
    root.minsize(400, 230)
    panel = ttk.Frame(root, padding=24)
    panel.pack(expand=True, fill='both')
    ttk.Label(panel, text='AuthzLedger Team', font=('TkDefaultFont', 19, 'bold')).pack(anchor='w')
    label = ttk.Label(panel, text='Privater Arbeitsbereich auf diesem Gerät', wraplength=445)
    label.pack(anchor='w', pady=(8, 16))
    try:
        if needs_bootstrap(directory):
            user = simpledialog.askstring('Ersteinrichtung', 'Benutzername für das erste Administratorkonto', parent=root)
            if not user:
                return
            password = simpledialog.askstring('Ersteinrichtung', 'Neues Administratorpasswort (12–256 Zeichen)', show='*', parent=root)
            if not password:
                return
            confirm = simpledialog.askstring('Ersteinrichtung', 'Passwort zur Bestätigung erneut eingeben', show='*', parent=root)
            if password != confirm:
                raise ValueError('Die beiden Passwörter stimmen nicht überein.')
            bootstrap(directory, user, password)
        server = make_server(directory, host='127.0.0.1', port=0)
    except Exception as error:
        if test_window:
            root.destroy()
            raise
        messages = {'invalid_username': 'Der Benutzername muss mit einem Buchstaben oder einer Ziffer beginnen. Erlaubt sind auch Punkt, Unterstrich, @, Plus und Bindestrich.',
                    'invalid_password_length': 'Das Passwort muss zwischen 12 und 256 Zeichen enthalten.'}
        messagebox.showerror('AuthzLedger Team', messages.get(str(error), str(error)), parent=root)
        root.destroy()
        return
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    url = f'http://127.0.0.1:{server.server_address[1]}/'
    label.configure(text='Der lokale Dienst läuft. Dieses Fenster geöffnet lassen, solange Sie im Arbeitsbereich arbeiten.')
    ttk.Button(panel, text='Arbeitsbereich im Browser öffnen', command=lambda: webbrowser.open(url)).pack(anchor='w')
    address = ttk.Entry(panel, width=40)
    address.insert(0, url)
    address.configure(state='readonly')
    address.pack(anchor='w',pady=(10, 0))
    errors = []
    if test_window:
        def check_window():
            try:
                if not root.winfo_ismapped():
                    raise RuntimeError('The desktop window did not open')
                with urllib.request.urlopen(url, timeout=10) as response:
                    if response.status != 200 or b'AuthzLedger' not in response.read():
                        raise RuntimeError('The desktop workspace did not respond')
            except Exception as error:
                errors.append(error)
            finally:
                root.destroy()
        root.after(300, check_window)
    else:
        root.after_idle(lambda: webbrowser.open(url))
    try:
        root.mainloop()
    finally:
        server.shutdown()
        server.server_close()
        worker.join(5)
    if errors:
        raise errors[0]


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='AuthzLedger Team desktop launcher')
    parser.add_argument('--self-test', action='store_true')
    parser.add_argument('--gui-self-test', action='store_true')
    parser.add_argument('--data-dir', type=Path, default=Path.home() / '.authzledger-team')
    args = parser.parse_args()
    if args.gui_self_test:
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            bootstrap(directory, 'packaging-admin', secrets.token_urlsafe(32))
            launch(directory, test_window=True)
    elif args.self_test:
        self_test()
    else:
        launch(args.data_dir)
