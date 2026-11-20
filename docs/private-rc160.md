# AuthzLedger 1.6.0rc1

Engineering release candidate for offline review. The source is available for public engineering review. Binary RC wheels are retained internally. Version 1.5.0 is the preceding stable release. The actual build receipt identifies the exact source commit and tree used for the wheel.

The review workflow reads local Nmap XML, ffuf JSON and Nuclei JSONL exports under their supported profiles. It retains reviewed receipts in an assessment and derives a source-linked index from a verified frozen snapshot. Imported assertions have an evidence ceiling of hint.

In an empty working directory with an active virtual environment, install the internally supplied wheel using `python -m pip install --no-index --no-deps /path/to/authzledger-1.6.0rc1-py3-none-any.whl`. Check the installed producer using `python -I -m authzledger --version`. Use `python -I -m authzledger assessment federation-preview --help` for the offline input contract. For an existing snapshot use `python -I -m authzledger assessment federation-index snapshot.json`.

PDF output requires the optional pinned reports extra. The public 1.6 production release gate remains open, including the complete regression and browser suites. Historical receipts retain their original producer versions.
