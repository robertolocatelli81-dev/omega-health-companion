#!/usr/bin/env python3
"""Differential oracle for the health evidence verifiers: the Python reference (health_verify.py) and the
independent JS / Go / Rust verifiers must return the same (ok, verdict) on every fixture — intact and tampered —
built with the project's own modules in a sandbox (never the repository's real ledgers)."""
import base64, json, os, shutil, subprocess, sys, tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import audit_bridge as AB          # noqa: E402
import verbale_probatorio as VP    # noqa: E402
import mission_case as MC          # noqa: E402
import scores_emergenza as S       # noqa: E402
import health_verify as HV         # noqa: E402


def sandbox(d):
    """Route every writer to the sandbox (the guard from the self-errors organ: a test must never write production)."""
    AB.MOTORE_DISPONIBILE = False
    AB.FALLBACK_LEDGER = os.path.join(d, "audit.jsonl")
    AB.KEYS_DIR = os.path.join(d, "keys")
    S.LEDGER = os.path.join(d, "prealert.jsonl")
    os.makedirs(AB.KEYS_DIR, exist_ok=True)


def build(d):
    sandbox(d)
    AB.registra_prealert("prealert-1", "ab" * 32, "equipaggio-118-alfa")
    VP.registra_ricezione("prealert-1", "Dott.ssa Zoë Müller", "clinico_senior", "resus", "revisione_senior_immediata",
                          motivo_alternativa="resus piena — «sala 3» ≤ 2 min", ts_emissione="2026-09-15T08:00:00+00:00")
    AB.registra_conferma("prealert-1", "ok, preso in carico", "dr-b")
    AB.registra_evento_clinico("prealert-1", "aggiornamento_eta", {"eta_arrivo_min": 7, "posizione_hmac_sha256": "cd" * 32, "posizione_impegno": "HMAC-SHA256(sale in RAM, 'lat_e6,lon_e6')", "ts": "2026-09-15T08:01:00+00:00"}, "equipaggio-118-alfa")
    S.ancora_prealert({"priorita": "ALTO", "NEWS2": 9, "temp": 39.0, "note": "già in sala"}, "2026-09-15T08:00:00.123456+00:00")
    S.ancora_prealert({"priorita": "MEDIO", "NEWS2": 5, "spo2": 92.5, "big": 12345678901234567890}, "2026-09-15T08:02:00+00:00")
    fm = MC.FascicoloMissione(ledger_path=os.path.join(d, "fascicoli.jsonl"))
    fm.apri("M-1", "op", "missione — pediatrica"); fm.transita("M-1", "VALUTAZIONE", "op", "valutato"); fm.transita("M-1", "TRASPORTO", "op", "in viaggio")
    v = VP.verbale("prealert-1")
    p = VP.persisti_verbale(v, os.path.join(d, "verbali"))
    return {"audit": AB.FALLBACK_LEDGER, "keys": AB.KEYS_DIR, "chains": [S.LEDGER, fm.ledger_path], "verbale": p["path"]}


def rewrite(path, fn):
    lines = [l for l in open(path, encoding="utf-8").read().split("\n") if l.strip()]
    out = fn(lines)
    open(path, "w", encoding="utf-8").write("\n".join(out) + "\n")


def cases(base):
    out = []
    def case(name, mutate=None, **opts):
        d = os.path.join(base, name); os.makedirs(d)
        f = build(d)
        if mutate:
            mutate(f)
        out.append((name, f, opts))
    case("intact_with_registry", keys=True)
    case("intact_no_registry")
    case("intact_registry_from_verbale", trust_vr=True)
    def tamper_audit_field(f):
        rewrite(f["audit"], lambda ls: [json.dumps({**json.loads(ls[0]), "operatore": "impostore"}, ensure_ascii=False)] + ls[1:])
    case("audit_field_tampered", tamper_audit_field, keys=True)
    def delete_audit_line(f):
        rewrite(f["audit"], lambda ls: ls[:1] + ls[2:])
    case("audit_line_deleted", delete_audit_line, keys=True)
    def extra_key(f):
        rewrite(f["audit"], lambda ls: [json.dumps({**json.loads(ls[0]), "nota_in_chiaro": "Mario Rossi"}, ensure_ascii=False)] + ls[1:])
    case("audit_extra_key", extra_key, keys=True)
    def resign_with_other_key(f):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives import serialization as ser
        import hashlib
        def fn(ls):
            e = json.loads(ls[0]); e["dettaglio"] = {"prealert_sha256": "ff" * 32}
            keys = ("kind", "target", "azione", "dettaglio", "operatore", "ts", "prev_sha256", "alg")
            canon = json.dumps({k: e[k] for k in keys if k in e}, sort_keys=True, separators=(",", ":")).encode()
            dg = hashlib.sha256(canon).digest(); sk = Ed25519PrivateKey.generate()
            e["record_sha256"] = dg.hex(); e["firma_ed25519_b64"] = base64.b64encode(sk.sign(dg)).decode()
            e["pubkey_b64"] = base64.b64encode(sk.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)).decode()
            e2 = json.loads(ls[1]); e2["prev_sha256"] = dg.hex()   # re-link the chain too
            return [json.dumps(e, ensure_ascii=False), json.dumps(e2, ensure_ascii=False)] + ls[2:]
        rewrite(f["audit"], fn)
    case("audit_resigned_with_foreign_key", resign_with_other_key, keys=True)
    def wrong_registry(f):
        for n in os.listdir(f["keys"]):
            open(os.path.join(f["keys"], n), "w").write(base64.b64encode(b"\x11" * 32).decode())
    case("registry_keys_wrong", wrong_registry, keys=True)
    def nan_line(f):
        rewrite(f["audit"], lambda ls: ls + ['{"kind": "audit_locale", "target": "x", "azione": "y", "dettaglio": {"v": NaN}, "operatore": "o", "ts": "t", "prev_sha256": "z", "record_sha256": "w", "firma_ed25519_b64": "", "pubkey_b64": ""}'])
    case("audit_nan_line", nan_line, keys=True)
    def dup_key(f):
        rewrite(f["audit"], lambda ls: [ls[0][:-1] + ',"operatore":"altro"}'] + ls[1:])
    case("audit_duplicate_key", dup_key, keys=True)
    def chain_edit(f):
        def fn(ls):
            e = json.loads(ls[0]); e["prealert_sha256"] = "00" * 32; return [json.dumps(e, ensure_ascii=False)] + ls[1:]
        rewrite(f["chains"][0], fn)
    case("chain_entry_edited", chain_edit, keys=True)
    def chain_reorder(f):
        rewrite(f["chains"][1], lambda ls: [ls[0], ls[2], ls[1]])
    case("chain_reordered", chain_reorder, keys=True)
    def verbale_edit(f):
        v = json.load(open(f["verbale"])); v["firme_tutte_verificate"] = True; v["n_eventi"] = 99
        json.dump(v, open(f["verbale"], "w"), ensure_ascii=False, indent=1)
    case("verbale_edited", verbale_edit, keys=True)
    def verbale_event_missing(f):
        rewrite(f["audit"], lambda ls: ls[:2] + ls[3:])     # drop the conferma line the verbale lists
    case("verbale_event_not_in_ledger", verbale_event_missing, keys=True)
    def verbale_claims_without_registry(f):
        shutil.rmtree(f["keys"])
    case("verbale_claim_no_registry", verbale_claims_without_registry)
    def empty_audit(f):
        open(f["audit"], "w").close()
    case("audit_empty", empty_audit, keys=True)
    def amputated(f):      # council r2 (Gemini/Fable): a line without `dettaglio`, re-signed with a foreign key, must FAIL
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives import serialization as ser
        import hashlib
        def fn(ls):
            e = json.loads(ls[0]); e.pop("dettaglio")
            keys = ("kind", "target", "azione", "operatore", "ts", "prev_sha256", "alg")
            canon = json.dumps({k: e[k] for k in keys if k in e}, sort_keys=True, separators=(",", ":")).encode()
            dg = hashlib.sha256(canon).digest(); sk = Ed25519PrivateKey.generate()
            e["record_sha256"] = dg.hex(); e["firma_ed25519_b64"] = base64.b64encode(sk.sign(dg)).decode()
            e["pubkey_b64"] = base64.b64encode(sk.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)).decode()
            e2 = json.loads(ls[1]); e2["prev_sha256"] = dg.hex()
            return [json.dumps(e, ensure_ascii=False), json.dumps(e2, ensure_ascii=False)] + ls[2:]
        rewrite(f["audit"], fn)
    case("audit_line_amputated", amputated)
    def honest_verbale_no_registry(f):   # a verbale that does NOT claim verified signatures, checked without a registry → NOT-TRUSTED
        v = json.load(open(f["verbale"])); v["firme_tutte_verificate"] = False
        import hashlib
        body = {k: x for k, x in v.items() if k != "digest_verbale_sha256"}
        v["digest_verbale_sha256"] = hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
        json.dump(v, open(f["verbale"], "w"), ensure_ascii=False, indent=1)
    case("honest_verbale_no_registry", honest_verbale_no_registry)
    def neg_zero(f):        # integer lexeme kept: `-0` must round-trip (FORMAT.md)
        def fn(ls):
            e = json.loads(ls[0]); s = json.dumps(e, ensure_ascii=False)
            return [s] + ls[1:]
        rewrite(f["audit"], fn)
    case("intact_rewritten_lines", neg_zero, keys=True)
    return out


def run_cli(cmd, f, opts):
    args = list(cmd) + ["--audit", f["audit"], "--verbale", f["verbale"]]
    for c in f["chains"]:
        args += ["--chain", c]
    if opts.get("keys"):
        args += ["--keys", f["keys"]]
    if opts.get("trust_vr"):
        args += ["--trust-verbale-registry"]
    r = subprocess.run(args, capture_output=True, text=True, timeout=120)
    try:
        j = json.loads(r.stdout)
    except ValueError:
        return {"error": (r.stderr or r.stdout)[:200], "exit": r.returncode}
    return {"ok": j["ok"], "verdict": j["verdict"], "exit": r.returncode, "fails": sorted(l["layer"] for l in j["layers"] if l["status"] == "FAIL")}


def main():
    if not AB.FIRMA_LOCALE_DISPONIBILE:
        print("cryptography is required to build signed fixtures (pip install cryptography)"); return 2
    require = set((sys.argv[sys.argv.index("--require") + 1] if "--require" in sys.argv else "").split(",")) - {""}
    vs = {}
    if shutil.which("node"):
        vs["js"] = ["node", os.path.join(ROOT, "verifiers", "js", "health-verify.mjs")]
    gob = os.environ.get("HEALTH_VERIFY_GO")
    if gob:
        vs["go"] = [gob]
    rb = os.environ.get("HEALTH_VERIFY_RUST") or (os.path.join(ROOT, "verifiers", "rust", "target", "release", "health-verify") if os.path.exists(os.path.join(ROOT, "verifiers", "rust", "target", "release", "health-verify")) else None)
    if rb:
        vs["rust"] = [rb]
    missing = require - set(vs)
    if missing:
        print("required verifiers absent:", sorted(missing)); return 2
    base = tempfile.mkdtemp(prefix="hv_oracle_")
    saved = (AB.MOTORE_DISPONIBILE, AB.FALLBACK_LEDGER, AB.KEYS_DIR, S.LEDGER)
    diverg, n = [], 0
    try:
        for name, f, opts in cases(base):
            ref = HV.run(f["audit"], f["chains"], f["verbale"], f["keys"] if opts.get("keys") else None, bool(opts.get("trust_vr")))
            exp = (ref["ok"], ref["verdict"])
            row = {"python": exp[1]}
            for lang, cmd in vs.items():
                r = run_cli(cmd, f, opts)
                got = (r.get("ok"), r.get("verdict"))
                row[lang] = got[1]
                if got != exp or (r.get("exit", 1) == 0) != ref["ok"]:
                    diverg.append((name, lang, exp, r))
            n += 1
            print(f"{name:32s} " + " ".join(f"{k}={v}" for k, v in row.items()))
    finally:
        AB.MOTORE_DISPONIBILE, AB.FALLBACK_LEDGER, AB.KEYS_DIR, S.LEDGER = saved
        shutil.rmtree(base, ignore_errors=True)
    print(f"\ncases={n} verifiers={sorted(vs)} divergences={len(diverg)}")
    for d in diverg:
        print("DIVERGENCE", d)
    return 1 if diverg else 0


if __name__ == "__main__":
    sys.exit(main())
