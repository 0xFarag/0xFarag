"""Collect the actual installed distribution's third-party license and notice files."""
import argparse
from importlib import metadata
import json
from pathlib import Path
import re
import shutil
import sys
import sysconfig


def collect(destination, windows):
    destination.mkdir(parents=True, exist_ok=True)
    inventory = []
    runtime = ['cryptography', 'cffi', 'pycparser']
    build = ['PyInstaller', 'pyinstaller-hooks-contrib', 'altgraph', 'packaging', 'pefile', 'pywin32-ctypes']
    for name in runtime + (build if windows else []):
        try:
            dist = metadata.distribution(name)
        except metadata.PackageNotFoundError:
            if name == 'cryptography' or (windows and name == 'PyInstaller'):
                raise
            continue
        folder = re.sub(r'[^A-Za-z0-9_.-]', '_', name)
        copied = []
        for item in dist.files or ():
            parts = item.parts
            if '..' in parts or item.is_absolute():
                continue
            nested = any(part.lower() in ('license', 'licenses', 'licences') for part in parts[:-1])
            named = item.name.lower().startswith(('license', 'licence', 'copying', 'notice', 'copyright'))
            if not (nested or named):
                continue
            source = Path(dist.locate_file(item))
            if not source.is_file():
                continue
            target = destination / folder / Path(*parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
            copied.append(target.relative_to(destination).as_posix())
        if not copied:
            if name in runtime or name == 'PyInstaller':
                raise RuntimeError(f'No installed license files found for {name} {dist.version}')
            # A build-only package may expose license information through metadata.
            target = destination / folder / 'DISTRIBUTION-METADATA.txt'
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(str(dist.metadata), encoding='utf-8')
            copied.append(target.relative_to(destination).as_posix())
        inventory.append({'name': name, 'version': dist.version,
                          'use': 'runtime' if name in runtime else 'packaging tool or bootloader',
                          'files': sorted(copied)})

    prefix = Path(sys.base_prefix)
    python_license = next((file for file in (prefix / 'LICENSE.txt', Path(sysconfig.get_path('stdlib')) / 'LICENSE.txt')
                           if file.is_file()), None)
    if python_license is None:
        raise RuntimeError('Missing license from the Python installation used to build the package')
    python_folder = destination / 'CPython'
    python_folder.mkdir(exist_ok=True)
    shutil.copyfile(python_license, python_folder / 'LICENSE.txt')
    inventory.append({'name': 'CPython', 'version': sys.version.split()[0], 'use': 'runtime',
                      'files': ['CPython/LICENSE.txt']})

    if windows:
        for directory in sorted((prefix / 'tcl').glob('*')):
            if not directory.is_dir():
                continue
            for source in sorted(directory.glob('license*')):
                if source.is_file():
                    target = destination / 'Tcl-Tk' / directory.name / source.name
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(source, target)
    (destination / 'INVENTORY.json').write_text(json.dumps(inventory, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('destination', type=Path)
    parser.add_argument('--windows', action='store_true')
    options = parser.parse_args()
    collect(options.destination, options.windows)
