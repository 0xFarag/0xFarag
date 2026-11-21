# AuthzLedger 1.5.1 Native Packaging

All rights reserved. © Nasser Aldin Farag (0xFarag).

This directory contains reproducible build instructions and scripts for production-grade distribution of AuthzLedger 1.5.0/1.5.1.

## Platforms

- **Windows**: Self-contained EXE via PyInstaller (Studio + CLI)
- **Debian/Ubuntu**: .deb package with desktop entry
- **Arch Linux**: PKGBUILD
- **Docker**: Optimized multi-stage image (loopback Studio)

## DNA preserved
No confirmed Finding without valid Controls. Budgeted, scope-bound requests. Honest not_retested. Ed25519-signed packages. Only authorized targets.

## Build order
1. Build the Python wheel from source.
2. Run platform-specific packaging scripts.
3. Verify checksums and the independent verifier.
4. Publish assets.

See subdirectories for exact commands.
