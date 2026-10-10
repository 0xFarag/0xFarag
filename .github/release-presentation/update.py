import json
import os
from pathlib import Path
from urllib.request import Request, urlopen

REPO = "0xFarag/0xFarag"
RELEASE_ID = 409163086
FREEZE = "a7160e13289ea0983946e03c978bc6af1841a7e6"
BASE = Path(".github/release-presentation")
expected = json.loads((BASE / "expected.json").read_text(encoding="utf-8"))
body = (BASE / "release-notes.md").read_text(encoding="utf-8")
name = "AuthzLedger 1.1.0 — Find the authorization gap. Prove the fix."

def api(path, method="GET", payload=None):
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    request = Request(
        "https://api.github.com/repos/" + REPO + "/" + path,
        data=data,
        method=method,
        headers={
            "Authorization": "Bearer " + os.environ["GH_TOKEN"],
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "Content-Type": "application/json",
            "User-Agent": "AuthzLedger-release-presentation",
        },
    )
    with urlopen(request, timeout=30) as response:
        return json.load(response)

def assets(value):
    fields = ("id", "name", "digest", "size", "state")
    return sorted(({key: a.get(key) for key in fields} for a in value["assets"]), key=lambda a: a["name"])

def verify_invariants(value):
    for field in ("id", "tag_name", "target_commitish", "draft", "prerelease"):
        if value.get(field) != expected[field]:
            raise RuntimeError("Release identity or state changed: " + field)
    if assets(value) != assets(expected):
        raise RuntimeError("Release assets changed; refusing presentation update")
    ref = api("git/ref/tags/v1.1.0")
    if ref["object"]["type"] != "commit" or ref["object"]["sha"] != FREEZE:
        raise RuntimeError("Release tag no longer matches frozen source")

before = api("releases/" + str(RELEASE_ID))
verify_invariants(before)
if before["name"] == name and before["body"] == body:
    print("Presentation already matches; all release invariants verified.")
elif before["name"] != expected["name"] or before["body"] != expected["body"]:
    raise RuntimeError("Release description changed since review; refusing to overwrite it")
else:
    # Only these two presentation fields are writable in this operation.
    api("releases/" + str(RELEASE_ID), method="PATCH", payload={"name": name, "body": body})
after = api("releases/" + str(RELEASE_ID))
verify_invariants(after)
if after["name"] != name or after["body"] != body:
    raise RuntimeError("Updated presentation did not read back exactly")
print(json.dumps({"release_id": RELEASE_ID, "url": after["html_url"], "presentation_verified": True, "tag_unchanged": FREEZE, "asset_count": len(after["assets"])}, sort_keys=True))
