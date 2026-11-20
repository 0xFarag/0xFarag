# AuthzLedger 1.6.0 · release target under review

The source and wheel are being checked for final release acceptance. The public 1.6 production release gate remains open. The wheel is retained for internal review. Version 1.5.0 is the current public stable release. The build receipt identifies the exact source commit and tree.

The supported offline readers accept local Nmap XML, ffuf JSON and Nuclei JSONL exports. The assessment retains their provenance and derives a source-linked surface index from a verified frozen snapshot. Imported assertions have an evidence ceiling of hint.

For internal verification, install the supplied wheel in a new virtual environment outside the checkout with `python -m pip install --no-index --no-deps /path/to/authzledger-1.6.0-py3-none-any.whl`. `python -I -m authzledger --version` must report 1.6.0. `python -I -m authzledger assessment federation-preview --help` shows the local input contract. `python -I -m authzledger assessment federation-index snapshot.json` reads an existing verified snapshot.

PDF output requires the pinned reports extra. The final acceptance contract covers the complete historical regression, browser suites and four demos. Historical receipts keep their original producer versions. The comparison reader explicitly supports both 1.6.0rc1 and 1.6.0.
