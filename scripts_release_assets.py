#!/usr/bin/env python3
"""Release assets of omega-health-companion built WITH the public cra-evidence tool: wheel + sdist, CycloneDX SBOM of
the wheel, the CRA evidence pack of this release with its ledger, SHA256SUMS; --kms signs the pack with the author's
AWS KMS Ed25519 key and writes the trust store. Publishes nothing.
Usage: python3 scripts_release_assets.py <version> <out_dir> [--kms] [--from-existing <dir>]"""
import hashlib, json, os, shutil, subprocess, sys, tempfile

sys.path.insert(0, os.path.expanduser("~/progetti/cra-evidence"))
from cra_evidence import CRAEvidenceLocker, SBOMComponent, SBOMRecord, verify_pack  # noqa: E402
from cra_evidence.signing import sign_pack  # noqa: E402

PRODUCT = "omega-health-companion"
REPO = "robertolocatelli81-dev/omega-health-companion"
HERE = os.path.dirname(os.path.abspath(__file__))


def main() -> int:
    version, out = sys.argv[1], os.path.abspath(sys.argv[2])
    with open(os.path.join(HERE, "pyproject.toml")) as f:
        if f'version = "{version}"' not in f.read():
            print(f"pyproject.toml non è alla versione {version}", file=sys.stderr); return 2
    tmp = tempfile.mkdtemp()
    if "--from-existing" in sys.argv:
        src = sys.argv[sys.argv.index("--from-existing") + 1]
        for n in os.listdir(src):
            if n.endswith((".whl", ".tar.gz")):
                shutil.copy(os.path.join(src, n), tmp)
    else:
        subprocess.run([sys.executable, "-m", "build", "--outdir", tmp, HERE], check=True, capture_output=True)
    os.makedirs(out, exist_ok=True)
    built = {}
    for n in sorted(os.listdir(tmp)):
        if n.endswith((".whl", ".tar.gz")):
            shutil.copy(os.path.join(tmp, n), out)
            built[n] = hashlib.sha256(open(os.path.join(tmp, n), "rb").read()).hexdigest()
    wheel = next(n for n in built if n.endswith(".whl"))
    sbom = SBOMRecord(product_id=PRODUCT, product_version=version, components=[
        SBOMComponent(name=PRODUCT, version=version, supplier="Roberto Locatelli", purl=f"pkg:github/{REPO}@v{version}",
                      sha256=built[wheel], license="AGPL-3.0-or-later")], depth="top-level-only")
    json.dump(sbom.to_cyclonedx_min(), open(os.path.join(out, f"{PRODUCT}-{version}-sbom.cdx.json"), "w"), indent=1)
    led = os.path.join(out, f"{PRODUCT}-{version}-cra.ledger.jsonl")
    if os.path.exists(led):
        os.remove(led)
    lk = CRAEvidenceLocker(led, PRODUCT, version)
    lk.record_sbom(sbom)
    pack_path = os.path.join(out, f"{PRODUCT}-{version}-cra_pack.json")
    pack = lk.evidence_pack(pack_path)
    res = {"built": built, "pack_sha3": pack["pack_sha3"]}
    if "--kms" in sys.argv:
        from cra_evidence.kms import KMSSigner, load_creds_file
        kid, region = open(os.path.expanduser("~/.omega/kms_key_id")).read().split()[:2]
        c = load_creds_file(os.path.expanduser("~/.omega/aws_kms_creds"))
        s = KMSSigner(kid, region, c.get("AWS_ACCESS_KEY_ID"), c.get("AWS_SECRET_ACCESS_KEY"), c.get("AWS_SESSION_TOKEN"))
        sign_pack(pack_path, s.as_key(), "roberto-locatelli-aws-kms")
        json.dump({"roberto-locatelli-aws-kms": s.public_key_hex}, open(os.path.join(out, f"{PRODUCT}-{version}-trust.json"), "w"), indent=1)
        v = verify_pack(pack_path, trust_store={"roberto-locatelli-aws-kms": s.public_key_hex})
    else:
        v = verify_pack(pack_path)
    with open(os.path.join(out, "SHA256SUMS"), "w") as f:
        for n, h in built.items():
            f.write(f"{h}  {n}\n")
    res.update({"verify_ok": v["ok"], "authenticity": v["authenticity"]})
    shutil.rmtree(tmp, ignore_errors=True)
    print(json.dumps(res, indent=1))
    return 0 if v["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
