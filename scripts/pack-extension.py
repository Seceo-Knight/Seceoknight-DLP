#!/usr/bin/env python3
"""
Pack the browser extension into a signed .crx3 and publish it for force-install.

WHY THIS EXISTS: gap-scan of CyberSentinel-DLP (August 18, 2026) found their
extension is force-installed via Chrome/Edge enterprise policy, while
SeceoKnight's was only ever documented as a manual "Load unpacked" dev-mode
install -- something an end user can switch off in two clicks at
chrome://extensions, which is an unacceptable property for a DLP control. An
unpacked extension's id is also derived from its folder path, so it differs
on every endpoint, making ExtensionInstallForcelist (which needs one STABLE
id) impossible without a packed, signed CRX. This produces that CRX, ported
in spirit from CyberSentinel's scripts/pack-extension.py.

WHAT IT DOES

  1. Generates an RSA-2048 signing key on first run and reuses it forever
     after. The key IS the extension's identity: change it and every
     endpoint sees a DIFFERENT extension, so the old one stays
     force-installed alongside the new one. Keep it, back it up.
  2. Writes the PUBLIC half into manifest.json as ``key``. That is safe to
     commit and is what makes an unpacked dev load share the same id as the
     packed build -- otherwise you debug one extension and deploy another.
  3. Zips the extension, wraps it in a CRX3 envelope, signs it.
  4. Emits extension.json, which the agent's ApplyBrowserExtensionPolicy()
     and this project's install/manage scripts read, so nobody ever types a
     32-character extension id by hand.

The output directory is served by the server at /api/v1/extension/ (see
server/app/api/v1/extension.py) -- endpoints fetch it from the DLP server
they already talk to, no Chrome Web Store or Google account required, and it
works on an isolated network.

USAGE

    python3 scripts/pack-extension.py                    # pack + publish
    python3 scripts/pack-extension.py --print-id         # just show the id
    python3 scripts/pack-extension.py --key /path/to.pem # explicit key location

Bump "version" in agents/browser-extension/manifest.json before packing a
new build -- Chrome only upgrades when the version string increases.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
import os
import pathlib
import struct
import sys
import zipfile

try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
except ImportError:
    sys.exit("This needs the 'cryptography' package: pip install cryptography")


REPO = pathlib.Path(__file__).resolve().parent.parent
EXT_DIR = REPO / "agents" / "browser-extension"
# Served by the server. Inside the repo so a redeploy carries it, and the
# private key deliberately is NOT (see DEFAULT_KEY).
OUT_DIR = REPO / "server" / "extension_dist"
DEFAULT_KEY = pathlib.Path(
    os.environ.get("SECEOKNIGHT_EXT_KEY", "/etc/seceoknightdlp/extension-signing.pem")
)

CRX_NAME = "seceoknightdlp.crx"

# Never ship these into the packed extension.
EXCLUDE_NAMES = {".DS_Store", "Thumbs.db", ".gitignore", ".gitkeep"}
EXCLUDE_DIRS = {".git", "native-host", "__pycache__", "node_modules"}
EXCLUDE_SUFFIXES = {".md", ".ps1", ".pem", ".crx", ".zip"}


# ── protobuf (hand-rolled: four fields, no library needed) ───────────────────
def _varint(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


def _field(number: int, payload: bytes) -> bytes:
    """One length-delimited (wire type 2) protobuf field."""
    return _varint((number << 3) | 2) + _varint(len(payload)) + payload


# ── key handling ─────────────────────────────────────────────────────────────
def load_or_create_key(path: pathlib.Path):
    if path.exists():
        with path.open("rb") as fh:
            return serialization.load_pem_private_key(fh.read(), password=None)

    print(f"  no signing key at {path} -- generating one (this happens once)")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as fh:
        fh.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    # The key IS the extension's identity -- anyone holding it can publish an
    # update that every endpoint installs automatically.
    os.chmod(path, 0o600)
    print(f"  wrote {path} (mode 600) -- BACK THIS UP; losing it means every")
    print("  endpoint sees a different extension on the next release")
    return key


def public_der(key) -> bytes:
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def extension_id(pub_der: bytes) -> str:
    """Chrome's id: sha256(pubkey)[:16], hex, digits 0-f remapped to a-p."""
    digest = hashlib.sha256(pub_der).digest()[:16]
    return "".join(chr(ord("a") + int(c, 16)) for c in digest.hex())


# ── packing ──────────────────────────────────────────────────────────────────
def zip_extension(src: pathlib.Path) -> bytes:
    buf = io.BytesIO()
    count = 0
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(src.rglob("*")):
            if not path.is_file():
                continue
            rel = path.relative_to(src)
            if any(part in EXCLUDE_DIRS for part in rel.parts):
                continue
            if rel.name in EXCLUDE_NAMES:
                continue
            # Only strip docs/scripts at the TOP level.
            if len(rel.parts) == 1 and rel.suffix.lower() in EXCLUDE_SUFFIXES:
                continue
            # Deterministic timestamps so an unchanged extension packs to
            # identical bytes and endpoints do not re-download for nothing.
            info = zipfile.ZipInfo(str(rel).replace(os.sep, "/"), date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            zf.writestr(info, path.read_bytes())
            count += 1
    print(f"  zipped {count} files ({len(buf.getvalue()) / 1048576:.1f} MB)")
    return buf.getvalue()


def build_crx(zip_bytes: bytes, key) -> bytes:
    pub = public_der(key)
    crx_id = hashlib.sha256(pub).digest()[:16]

    # SignedData { bytes crx_id = 1 }
    signed_header = _field(1, crx_id)

    # The signature covers a domain-separated prefix, the length of the
    # signed header, the header itself, then the archive -- so a signature
    # cannot be lifted onto a different payload.
    payload = (
        b"CRX3 SignedData\x00"
        + struct.pack("<I", len(signed_header))
        + signed_header
        + zip_bytes
    )
    signature = key.sign(payload, padding.PKCS1v15(), hashes.SHA256())

    # AsymmetricKeyProof { bytes public_key = 1; bytes signature = 2; }
    proof = _field(1, pub) + _field(2, signature)
    # CrxFileHeader { repeated AsymmetricKeyProof sha256_with_rsa = 2;
    #                 bytes signed_header_data = 10000; }
    header = _field(2, proof) + _field(10000, signed_header)

    return b"Cr24" + struct.pack("<II", 3, len(header)) + header + zip_bytes


def write_manifest_key(manifest_path: pathlib.Path, pub: bytes) -> str:
    """Pin the public key into the manifest so packed and unpacked share an id."""
    data = json.loads(manifest_path.read_text())
    encoded = base64.b64encode(pub).decode()
    if data.get("key") != encoded:
        # The existing "key" MUST be dropped while rebuilding, not copied --
        # otherwise it can end up written at the "version" position and then
        # immediately overwritten by the old value, leaving a manifest whose
        # key disagrees with the signature (Chrome derives the id from the
        # manifest key and checks it against the signed crx_id -- that
        # mismatch fails to install with a bare "invalid" and no clue why).
        rebuilt = {}
        for k, v in data.items():
            if k == "key":
                continue
            rebuilt[k] = v
            if k == "version":
                rebuilt["key"] = encoded
        if "key" not in rebuilt:
            rebuilt["key"] = encoded
        manifest_path.write_text(json.dumps(rebuilt, indent=2) + "\n")
        print("  pinned the public key into manifest.json (safe to commit)")
    return data.get("version", "0.0.0")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--key", type=pathlib.Path, default=DEFAULT_KEY)
    ap.add_argument("--out", type=pathlib.Path, default=OUT_DIR)
    ap.add_argument("--server", default=None,
                    help="Only used to print a ready-to-paste verification URL; "
                         "the update feed itself is generated per request.")
    ap.add_argument("--print-id", action="store_true", help="print the id and exit")
    args = ap.parse_args()

    if not (EXT_DIR / "manifest.json").exists():
        sys.exit(f"no extension at {EXT_DIR}")

    key = load_or_create_key(args.key)
    pub = public_der(key)
    ext_id = extension_id(pub)

    if args.print_id:
        print(ext_id)
        return 0

    print(f"packing {EXT_DIR}")
    write_manifest_key(EXT_DIR / "manifest.json", pub)
    # Re-read: the version may live after "key" now.
    version = json.loads((EXT_DIR / "manifest.json").read_text())["version"]

    zip_bytes = zip_extension(EXT_DIR)
    crx = build_crx(zip_bytes, key)

    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / CRX_NAME).write_bytes(crx)

    # No update.xml is written here on purpose. Chrome needs an ABSOLUTE
    # codebase URL, so a file baked now would hardcode one hostname -- and
    # the same build deployed to a second server would point every endpoint
    # there back at the first. The server generates the feed per request
    # from the host the endpoint actually reached (see
    # server/app/api/v1/extension.py).

    # A rebuild that keeps the same version number is invisible to every
    # consumer downstream -- Chrome only re-downloads when the published
    # version is HIGHER, so a same-version repack leaves every managed
    # browser running the previous code while the server insists it
    # published the new one, and nothing in the chain complains. Say so
    # here, where it can still be fixed.
    prior_path = args.out / "extension.json"
    if prior_path.exists():
        try:
            prior = json.loads(prior_path.read_text())
        except Exception:
            prior = {}
        new_hash = hashlib.sha256(crx).hexdigest()
        if prior.get("version") == version and prior.get("sha256") not in (None, new_hash):
            print()
            print(f"  !! WARNING: this is a DIFFERENT build of version {version}.")
            print(f"     was  sha256 {prior.get('sha256')}")
            print(f"     now  sha256 {new_hash}")
            print("     Chrome updates only when the version goes UP, so managed browsers")
            print("     will keep running the old code. Bump \"version\" in")
            print("     agents/browser-extension/manifest.json and pack again.")

    # Consumed by the server's /extension/info route, which is what
    # agent.cpp and this project's install/manage scripts read so nobody
    # ever types an extension id by hand.
    (args.out / "extension.json").write_text(json.dumps({
        "extension_id": ext_id,
        "version": version,
        "crx": CRX_NAME,
        "size": len(crx),
        "sha256": hashlib.sha256(crx).hexdigest(),
    }, indent=2) + "\n")

    print()
    print(f"  extension id : {ext_id}")
    print(f"  version      : {version}")
    print(f"  crx          : {args.out / CRX_NAME}  ({len(crx) / 1048576:.1f} MB)")
    print()
    server = (args.server or "").rstrip("/")
    if server:
        print(f"  Verify:  curl {server}/api/v1/extension/update.xml")
    else:
        print("  Verify:  curl http://<dlp-server>:55100/api/v1/extension/update.xml")
    print("  Endpoints pick it up automatically once the agent's Browser Extension")
    print("  Guard task next runs (installed by install-agent.ps1, repeats every 2 min).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
