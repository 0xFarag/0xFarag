# AuthzLedger offline recipient verifier · preview 2

These packages verify the signature and retained evidence of a delivered AuthzLedger bundle offline. Obtain the trusted public key through an independent channel. Choose the package for your platform and check its SHA-256 against the release manifest.

| Platform | Release asset |
| --- | --- |
| Windows x64, self-contained portable verifier | `AuthzLedger-Windows-x64-SelfContained.zip` (includes the portable EXE, notices and native test receipt) |
| Windows x64, launcher and installer preview | `AuthzLedger-Windows-x64-Pruefer-Preview.zip` (read the enclosed German instructions for its runtime prerequisites) |
| Debian / Ubuntu | `authzledger-verifier_1.5.0-preview1_all.deb` |
| Arch Linux | `authzledger-verifier-1.5.0pre1-1-any.pkg.tar.zst` (the PKGBUILD source is also available) |
| Docker on Linux amd64 | `authzledger-recipient-verifier-1.5.0.post1-linux-amd64.docker.tar.gz` (exported image, see `DOCKER_IMAGE_ID.txt`) |
| Python | `authzledger_recipient_verifier-1.5.0.post1-py3-none-any.whl` and matching source distribution |

The standalone Windows EXE is unsigned. A valid signature authenticates the signed inventory relative to the trusted key. The checks do not attest events on a remote system. This preview contains the recipient verifier only. The stable AuthzLedger product release is version 1.5.0.

Native verification runs: [Windows x64](https://github.com/0xFarag/0xFarag/actions/runs/44885489514), [Windows launcher and installer](https://github.com/0xFarag/0xFarag/actions/runs/44876995868), [Linux packages and Docker](https://github.com/0xFarag/0xFarag/actions/runs/44885731891). See the rights and attribution notices attached to this release and inside each package.
