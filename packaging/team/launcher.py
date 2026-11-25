# © Nasser Aldin Farag (0xFarag). All rights reserved.
"""Desktop entry point. Keep the service private to the loopback interface."""
import argparse
import locale
import secrets
import sys
import tempfile
import threading
import urllib.request
import webbrowser
from pathlib import Path

from team.server import ApiError, bootstrap, email_identity, make_server, needs_bootstrap


def proof_self_test(db, location):
    """Run the new evidence workflow from the installed executable or package."""
    from team.proof_engine import DEPENDENCIES, evaluate, lab_after_source, lab_source, make_scope, record_retest
    from team.proof_packages import key_history, sign_package, verify_package

    intended = dict.fromkeys(DEPENDENCIES, True)
    scope = make_scope(["lab.authz.local"], "Isolated packaging fixture", 7)
    report = evaluate(scope, [lab_source()], intended)
    selected = [row["id"] for row in report["findings"][:3]]
    after = lab_after_source()
    record_retest(report, selected, after, intended)
    workspace = db.execute("SELECT id FROM teams LIMIT 1").fetchone()[0]
    archive = sign_package(db, location, workspace, report, "de")
    pinned = key_history(db, location, workspace)["keys"][0]["jwk"]
    verified = verify_package(archive, pinned, workspace)
    if [row["status"] for row in verified["retests"]] != ["resolved_check"] * 3 + ["not_retested"]:
        raise RuntimeError("Packaged Studio lost the source-bound selection")
    altered = bytearray(archive)
    altered[len(altered) // 2] ^= 1
    try:
        verify_package(bytes(altered), pinned, workspace)
    except ValueError:
        return
    raise RuntimeError("Packaged verifier accepted a modified archive")


def self_test():
    """Exercise the packaged app, SQLite, the bundled web UI and cryptography."""
    from contextlib import closing
    from team.evidence import signer
    from team.server import connect, dispatch
    from team.report_pdf import smoke_pdf
    document = smoke_pdf()
    if not document.startswith(b'%PDF-') or b'%%EOF' not in document[-32:]:
        raise RuntimeError('Packaged PDF renderer did not produce a complete document')
    with tempfile.TemporaryDirectory() as temp:
        location = Path(temp)
        assert needs_bootstrap(location)
        password = secrets.token_urlsafe(32)
        bootstrap(location, 'packaging-admin@example.test', password)
        account,token=dispatch(location, 'POST', '/api/login',
                               {'email':'packaging-admin@example.test','password':password})
        team = account['teams'][0]
        if team.get('legacyCases') is not False: raise ValueError('Unsafe first-run workspace mode')
        route='/api/teams/'+team['id']+'/proof'
        auth={'token':token,'csrf':account['csrf']}
        run=dispatch(location,'POST',route,{'mode':'lab'},**auth)[0]['run']
        if len(run['sources'][0]['observations'])!=4: raise ValueError('Bundled proof engine failed')
        message = b'AuthzLedger packaging self-test'
        with closing(connect(location)) as db, db:
            proof_self_test(db, location)
            key, first = signer(db, location)
            signature = key.sign(message)
        with closing(connect(location)) as db, db:
            reopened, current = signer(db, location)
            reopened.public_key().verify(signature, message)
            if current != first:
                raise ValueError('Packaged workspace did not retain its signing key')
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


LANGUAGES = {'de': 'Deutsch', 'en': 'English', 'fr': 'Français', 'it': 'Italiano', 'ar': 'العربية'}
DESKTOP_TEXT = {
    "guides": ["Anleitungen", "Guides", "Guides", "Guide", "الأدلة"],
    "licence": ["Lizenz und Drittanbieterhinweise", "Licence and third-party notices", "Licence et avis de tiers", "Licenza e avvisi di terzi", "الرخصة وإشعارات الأطراف الثالثة"],
    "tagline": [
        "Privater Arbeitsbereich auf diesem Gerät",
        "Private workspace on this device",
        "Espace de travail privé sur cet appareil",
        "Spazio di lavoro privato su questo dispositivo",
        "مساحة العمل الخاصة على هذا الجهاز"
    ],
    "setup": [
        "Ersteinrichtung",
        "Initial setup",
        "Première configuration",
        "Configurazione iniziale",
        "الإعداد الأولي"
    ],
    "user": [
        "E-Mail-Adresse für das erste Administratorkonto",
        "Email address of the first administrator",
        "Adresse e-mail du premier compte administrateur",
        "Indirizzo e-mail del primo amministratore",
        "البريد الإلكتروني لحساب المسؤول الأول"
    ],
    "pass": [
        "Neues Administratorpasswort (12–256 Zeichen)",
        "New administrator password (12–256 characters)",
        "Nouveau mot de passe administrateur (12 à 256 caractères)",
        "Nuova password amministratore (12–256 caratteri)",
        "كلمة مرور المسؤول الجديدة (12–256 محرفاً)"
    ],
    "confirm": [
        "Passwort zur Bestätigung erneut eingeben",
        "Re-enter the password to confirm",
        "Saisissez à nouveau le mot de passe",
        "Confermate la password",
        "أعيدوا إدخال كلمة المرور للتأكيد"
    ],
    "mismatch": [
        "Die beiden Passwörter stimmen nicht überein.",
        "The passwords do not match.",
        "Les mots de passe ne correspondent pas.",
        "Le password non coincidono.",
        "كلمتا المرور غير متطابقتين."
    ],
    "invalid_email": [
        "Geben Sie eine gültige E-Mail-Adresse ein, etwa name@firma.ch.",
        "Enter a valid email address, such as name@example.com.",
        "Saisissez une adresse e-mail valide, par exemple nom@entreprise.ch.",
        "Inserite un indirizzo e-mail valido, per esempio nome@azienda.ch.",
        "أدخل عنوان بريد إلكتروني صالحًا مثل name@example.com."
    ],
    "invalid_password_length": [
        "Das Passwort muss zwischen 12 und 256 Zeichen enthalten.",
        "The password must be 12–256 characters long.",
        "Le mot de passe doit comporter de 12 à 256 caractères.",
        "La password deve contenere da 12 a 256 caratteri.",
        "يجب أن تتكوّن كلمة المرور من 12 إلى 256 محرفاً."
    ],
    "running": [
        "Der lokale Dienst läuft. Lassen Sie dieses Fenster während der Arbeit geöffnet.",
        "The local service is running. Keep this window open while you work.",
        "Le service local est actif. Gardez cette fenêtre ouverte pendant votre travail.",
        "Il servizio locale è attivo. Tenete aperta questa finestra durante il lavoro.",
        "الخدمة المحلية قيد التشغيل. أبقوا هذه النافذة مفتوحة أثناء العمل."
    ],
    "open": [
        "Arbeitsbereich im Browser öffnen",
        "Open workspace in browser",
        "Ouvrir l’espace dans le navigateur",
        "Apri l’area di lavoro nel browser",
        "فتح مساحة العمل في المتصفح"
    ],
    "next": [
        "Weiter",
        "Continue",
        "Continuer",
        "Continua",
        "متابعة"
    ]
}

def legal_files():
    installed = Path(__file__).resolve().parent / 'legal'
    if installed.is_dir():
        return {p.relative_to(installed).as_posix(): p for p in sorted(installed.rglob('*')) if p.is_file()}
    source_root = Path(__file__).resolve().parents[2]
    return {p.name: p for p in (source_root / 'LICENSE', source_root / 'NOTICE.txt',
                                source_root / 'packaging/team/THIRD-PARTY.md') if p.is_file()}


GUIDES = ('Proof-Studio-Betrieb.md', 'Team-Login-RBAC.md', 'Burp-Export.md', 'ZAP-API-Scan-Import.md', 'Key-Rotation.md')


def guide_files():
    entry = Path(__file__).resolve()
    if getattr(sys, 'frozen', False):
        directory = entry.parent / 'docs'
    elif (entry.parents[2] / 'packaging/team/VERSION').is_file():
        directory = entry.parents[2] / 'docs'
    else:
        directory = Path('/usr/share/doc/authzledger-team')
    guides = {name: directory / name for name in GUIDES}
    source_readme = directory.parent / 'integrations/burp/README.md'
    if not guides['Burp-Export.md'].is_file() and source_readme.is_file():
        guides['Burp-Export.md'] = source_readme
    return {name: path for name, path in guides.items() if path.is_file()}


def show_documents(root, files, title):
    import tkinter as tk
    from tkinter import ttk
    view = tk.Toplevel(root)
    view.title('AuthzLedger Team · ' + title)
    view.geometry('760x500')
    frame = ttk.Frame(view, padding=12)
    frame.pack(expand=True, fill='both')
    pick = ttk.Combobox(frame, state='readonly', values=list(files), width=70)
    pick.pack(fill='x', pady=(0, 8))
    body = tk.Text(frame, wrap='word', width=85, height=22)
    body.pack(side='left', fill='both', expand=True)
    scroll = ttk.Scrollbar(frame, orient='vertical', command=body.yview)
    scroll.pack(side='right', fill='y')
    body.configure(yscrollcommand=scroll.set)

    def read_file(_event=None):
        body.configure(state='normal')
        body.delete('1.0', 'end')
        body.insert('end', files[pick.get()].read_text(encoding='utf-8', errors='replace'))
        body.configure(state='disabled')
    pick.bind('<<ComboboxSelected>>', read_file)
    pick.current(0)
    read_file()


def setup_admin(directory, root, language, tr):
    """Ask locally before opening any HTTP listener. Cancel leaves the workspace unclaimed."""
    from tkinter import messagebox, simpledialog
    address = None
    while address is None:
        entry = simpledialog.askstring(tr('setup'), tr('user'), parent=root)
        if entry is None:
            return False
        try:
            address = email_identity(entry.strip())
        except ApiError:
            messagebox.showerror('AuthzLedger Team', tr('invalid_email'), parent=root)
    while True:
        password = simpledialog.askstring(tr('setup'), tr('pass'), show='*', parent=root)
        if password is None:
            return False
        if not 12 <= len(password) <= 256:
            messagebox.showerror('AuthzLedger Team', tr('invalid_password_length'), parent=root)
            continue
        confirm = simpledialog.askstring(tr('setup'), tr('confirm'), show='*', parent=root)
        if confirm is None:
            return False
        if password != confirm:
            messagebox.showerror('AuthzLedger Team', tr('mismatch'), parent=root)
            continue
        bootstrap(directory, address, password, locale=language)
        return True


def launch(directory, test_window=False):
    import tkinter as tk
    from tkinter import messagebox, ttk
    root = tk.Tk()
    root.title('AuthzLedger Team')
    language = (locale.getlocale()[0] or 'de').split('_')[0].lower()
    if language not in LANGUAGES:
        language = 'de'
    def tr(key):
        return DESKTOP_TEXT[key][list(LANGUAGES).index(language)]
    root.geometry('560x310')
    root.minsize(480, 300)
    panel = ttk.Frame(root, padding=24)
    panel.pack(expand=True, fill='both')
    ttk.Label(panel, text='AuthzLedger Team', font=('TkDefaultFont', 19, 'bold')).pack(anchor='w')
    ttk.Label(panel, text='© Nasser Aldin Farag (0xFarag). All rights reserved.').pack(side='bottom', anchor='w')
    label = ttk.Label(panel, text=tr('tagline'), wraplength=445)
    label.pack(anchor='w', pady=(8, 16))
    if not test_window:
        picker = ttk.Frame(panel)
        picker.pack(anchor='w', fill='x', pady=(0, 8))
        selected = tk.StringVar(value=LANGUAGES[language])
        selector = ttk.Combobox(picker, state='readonly', textvariable=selected, values=list(LANGUAGES.values()), width=17)
        selector.pack(side='left')
        proceed = tk.BooleanVar(value=False)
        next_button = ttk.Button(picker, text=tr('next'), command=lambda: proceed.set(True))
        next_button.pack(side='left', padx=8)
        def set_language(_event):
            nonlocal language
            language = next(code for code, name in LANGUAGES.items() if name == selected.get())
            label.configure(text=tr('tagline'))
            next_button.configure(text=tr('next'))
        selector.bind('<<ComboboxSelected>>', set_language)
        closing = []
        def close_picker():
            closing.append(True)
            proceed.set(True)
        root.protocol('WM_DELETE_WINDOW', close_picker)
        selector.focus_set()
        root.wait_variable(proceed)
        if closing:
            root.destroy()
            return
        root.protocol('WM_DELETE_WINDOW', root.destroy)
        picker.destroy()
    try:
        if needs_bootstrap(directory) and not setup_admin(directory, root, language, tr):
            root.destroy()
            return
        server = make_server(directory, host='127.0.0.1', port=0)
    except Exception as error:
        if test_window:
            root.destroy()
            raise
        messages = {key: tr(key) for key in ('invalid_email', 'invalid_password_length')}
        messagebox.showerror('AuthzLedger Team', messages.get(str(error), str(error)), parent=root)
        root.destroy()
        return
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    url = f'http://127.0.0.1:{server.server_address[1]}/'
    label.configure(text=tr('running'))
    ttk.Button(panel, text=tr('open'), command=lambda: webbrowser.open(url)).pack(anchor='w')
    address = ttk.Entry(panel, width=40)
    address.insert(0, url)
    address.configure(state='readonly')
    address.pack(anchor='w',pady=(10, 0))
    docs_row = ttk.Frame(panel)
    docs_row.pack(anchor='w', pady=(10, 0))
    guides = guide_files()
    if guides:
        ttk.Button(docs_row, text=tr('guides'), command=lambda: show_documents(root, guides, tr('guides'))).pack(side='left', padx=(0, 8))
    notices = legal_files()
    if notices:
        ttk.Button(docs_row, text=tr('licence'), command=lambda: show_documents(root, notices, tr('licence'))).pack(side='left')
    errors = []
    if test_window:
        def check_window():
            try:
                if set(GUIDES) != guides.keys():
                    raise RuntimeError('Packaged user guides are missing')
                if not {'LICENSE','NOTICE.txt','THIRD-PARTY.md'} <= notices.keys():
                    raise RuntimeError('Packaged license or third-party notices are missing')
                if getattr(sys, 'frozen', False) and 'third-party/INVENTORY.json' not in notices:
                    raise RuntimeError('Packaged dependency license inventory is missing')
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
            bootstrap(directory, 'packaging-admin@example.test', secrets.token_urlsafe(32))
            launch(directory, test_window=True)
    elif args.self_test:
        self_test()
    else:
        launch(args.data_dir)
