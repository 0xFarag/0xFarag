# © Nasser Aldin Farag (0xFarag). All rights reserved.
"""Populate the filesystem tree used by Debian and Arch packages."""
import os
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TARGET = Path(sys.argv[1])
if not TARGET.is_absolute():
    raise SystemExit('An absolute staging directory is required')

def install_file(src, dest, mode=0o644):
    target = TARGET / dest
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(ROOT / src, target)
    os.chmod(target, mode)

for item in sorted((ROOT / 'team').rglob('*')):
    if item.is_file() and not item.is_symlink() and '__pycache__' not in item.parts and not item.name.endswith(('.pyc','.pyo')):
        install_file(item, Path('usr/lib/authzledger-team') / item.relative_to(ROOT))
install_file('packaging/team/launcher.py', 'usr/lib/authzledger-team/launcher.py')
install_file('public/dateipruefung/model.mjs', 'usr/lib/authzledger-team/public/dateipruefung/model.mjs')
for name in ['authzledger-team','authzledger-team-desktop']:
    install_file('packaging/team/' + name, 'usr/bin/' + name, 0o755)
install_file('packaging/team/authzledger-team.desktop', 'usr/share/applications/authzledger-team.desktop')
install_file('public/assets/authzledger-logo.png', 'usr/share/icons/hicolor/256x256/apps/authzledger-team.png')
install_file('LICENSE','usr/share/licenses/authzledger-team/LICENSE')
install_file('NOTICE.txt','usr/share/licenses/authzledger-team/NOTICE.txt')
install_file('packaging/team/README.md','usr/share/doc/authzledger-team/README.md')
for name in ['LICENSE', 'NOTICE.txt']:
    install_file(name, 'usr/lib/authzledger-team/legal/' + name)
    install_file(name, 'usr/share/doc/authzledger-team/' + name)
install_file('packaging/team/THIRD-PARTY.md', 'usr/lib/authzledger-team/legal/THIRD-PARTY.md')
install_file('packaging/team/THIRD-PARTY.md', 'usr/share/doc/authzledger-team/THIRD-PARTY.md')

install_file('team/static/pdf/FONT-LICENSE.txt', 'usr/lib/authzledger-team/legal/FONT-LICENSE.txt')
for name in ['Proof-Studio-Betrieb.md', 'ZAP-Ergebnisimport.md', 'Team-Login-RBAC.md', 'Key-Rotation.md', 'ZAP-API-Scan-Import.md']:
    install_file('docs/' + name, 'usr/share/doc/authzledger-team/' + name)
install_file('integrations/burp/README.md', 'usr/share/doc/authzledger-team/Burp-Export.md')
notice = TARGET / 'usr/share/doc/authzledger-team/copyright'
notice.write_text('© Nasser Aldin Farag (0xFarag). All rights reserved.\n\n'
                  + (ROOT / 'LICENSE').read_text(encoding='utf-8')
                  + '\n' + (ROOT / 'packaging/team/THIRD-PARTY.md').read_text(encoding='utf-8'), encoding='utf-8')

install_file('integrations/burp-handoff/README.md', 'usr/share/doc/authzledger-team/Burp-Handoff.md')
