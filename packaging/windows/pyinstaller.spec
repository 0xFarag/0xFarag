# PyInstaller spec for AuthzLedger 1.5.0 Studio + CLI
# Build: pyinstaller packaging/windows/pyinstaller.spec
# Requires Python 3.12 + dependencies

a = Analysis(
    ['../authzledger/__main__.py'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=['authzledger'],
    hookspath=[],
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=None,
    noarchive=False,
)
pyz = PYZ(a.pure, a.zipped_data, cipher=None)
exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='AuthzLedger',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
# All rights reserved © Nasser Aldin Farag (0xFarag)