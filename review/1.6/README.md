# AuthzLedger 1.6 · offline engineering review

The public stable reference is [v1.5.0](https://github.com/0xFarag/0xFarag/releases/tag/v1.5.0). This branch reviews the new offline import and surface index. The distribution and runtime identify this source as `1.6.0` so final acceptance can check the exact delivery bytes. The source is under engineering review, with internal wheel verification receipts bound to the exact Git commit and tree. The 1.6 production release gate remains open.

From the repository root, run the product against the three synthetic, bundled exports in a new output directory. Standard Python and OpenSSL are required. Install the pinned reports extra for PDF output.

```sh
python review/1.6/reproduce_demo_d.py --checkout . --out /tmp/authzledger-federation-review-fresh
```

The expected result is four accepted observations, one excluded source record, one hint, and zero confirmed findings. Import reads files only. The verifier checks a clean evidence package and a copy with one modified byte. The local demonstration generates an ephemeral demonstration key.

## Release decision

The exact-candidate contract is in `release-gate.json`. The verifier and its positive and negative unit tests live alongside the contract. Mixed native and imported evidence must share an assessment and scope. The [producer compatibility notes](vendor-proof/README.md) identify which native exports have positive or negative format evidence. The complete historical regression and all historical browser suites, the release assets and an independently authenticated release signature remain requirements for stable publication. The 1.6 offline GitHub workflow checks this branch's exact source commit and is only one part of that decision. The historical verifier and release workflow are scoped to 1.5.

© Nasser Aldin Farag (0xFarag). All rights reserved.
