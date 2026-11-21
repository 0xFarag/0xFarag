"""Exercise the packaged recipient verifier against the pinned public synthetic v1.5.0 release evidence."""
import argparse
import base64
from hashlib import sha256
from pathlib import Path
import subprocess
import tempfile
from zipfile import ZipFile

EXPECTED = "54b21858a89d498ba3b5050ad85f5969068bf79bcf5a07467297b3c3d1d5e817"

parser = argparse.ArgumentParser()
parser.add_argument("mode",choices=["installed","docker"])
parser.add_argument("archive",type=Path)
args=parser.parse_args()
if sha256(args.archive.read_bytes()).hexdigest()!=EXPECTED:
    raise SystemExit("Unexpected checksum for original evidence")
with tempfile.TemporaryDirectory() as tmp:
    root = Path(tmp)
    root.chmod(0o755)
    bundle = root/"proof"
    key = root/"trusted.pem"
    with ZipFile(args.archive) as z:
        key.write_bytes(z.read("authzledger-proof/trusted-public.pem"))
        prefix="authzledger-proof/C-retest-proof/proof/"
        for member in z.infolist():
            if not member.filename.startswith(prefix) or member.is_dir():
                continue
            rel=Path(member.filename[len(prefix):])
            if rel.is_absolute() or ".." in rel.parts:
                raise SystemExit("Unexpected archive entry")
            p=bundle/rel
            p.parent.mkdir(parents=True,exist_ok=True)
            p.write_bytes(z.read(member))

    def verify(name,trusted,expected_code,message):
        if args.mode=="docker":
            command=["docker","run","--rm","--network","none","--read-only",
                     "--tmpfs","/tmp:rw,nosuid,nodev,noexec",
                     "--mount",f"type=bind,src={bundle},dst=/input/proof,readonly",
                     "--mount",f"type=bind,src={trusted},dst=/trust/key.pem,readonly",
                     "authzledger-recipient-verifier:1.5.0.post1","/input/proof","--public-key","/trust/key.pem"]
        else:
            command=["authzledger-verify", str(bundle), "--public-key", str(trusted)]
        result=subprocess.run(command,capture_output=True,text=True,timeout=90)
        if result.returncode!=expected_code or message not in result.stdout+result.stderr:
            raise RuntimeError(f"{name} returned {result.returncode}: {result.stdout} {result.stderr}")
        print(f"{args.mode}/{name}: expected exit {expected_code}",flush=True)

    verify("valid",key,0,"VERIFIED:")
    subprocess.run(["openssl","genpkey","-algorithm","ED25519","-out",str(root/"private.pem")],check=True)
    foreign=root/"foreign.pem"
    subprocess.run(["openssl","pkey","-in",str(root/"private.pem"),"-pubout","-out",str(foreign)],check=True)
    verify("wrong-key",foreign,1,"fingerprint mismatch")
    payload = next(p for p in sorted((bundle/"attachments").iterdir()) if p.is_file() and p.stat().st_size)
    data = payload.read_bytes()
    payload.write_bytes(bytes([data[0]^1])+data[1:])
    verify("one-byte",key,1,"hash mismatch")
    payload.write_bytes(data)
    sig = bundle/"signature.base64"
    b=bytearray(base64.b64decode(sig.read_bytes()))
    b[0]^=1
    sig.write_bytes(base64.b64encode(b)+b"\n")
    verify("changed-signature",key,1,"signature verification failed")
