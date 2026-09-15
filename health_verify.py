#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""health_verify.py — OFFLINE, third-party verification of the evidence this project produces (reference
implementation; independent re-implementations live in verifiers/{js,go,rust} and must agree — see
verifiers/differential.py).

What it checks, layer by layer (each PASS/FAIL/SKIP), and ONE verdict:
  * --audit  <audit_locale_ledger.jsonl>   the signed audit ledger: record_sha256 recomputed from the canonical
                                            record (ASCII profile: sort_keys, compact, ensure_ascii) over
                                            kind/target/azione/dettaglio/operatore/ts/prev_sha256; the prev_sha256
                                            chain from "GENESIS"; every Ed25519 signature over the 32 raw digest
                                            bytes checked against the operator's REGISTERED key (--keys dir of
                                            fb-<slug>.pub, base64 raw), never against the key the line carries.
  * --chain  <ledger.jsonl> (repeatable)     a self_hash/prev_hash ledger (pre-alert anchors, mission case files):
                                            UTF-8 profile (ensure_ascii=False), genesis 64 zeros; numbers are kept
                                            exactly as written in the file (Python's repr), so a float never changes.
  * --verbale <verbale.json>                 digest_verbale_sha256 recomputed over the body (UTF-8 profile); each
                                            event's record_sha256 must exist in --audit and verify there; the
                                            verbale's own `firme_tutte_verificate` must not exceed what we verified.
Honest scope: no registry → signatures are "present, NOT trusted" (SKIP, never PASS); the registry inside a verbale
is accepted only with --trust-verbale-registry and is then declared as such; a truncated tail of a chain is
invisible to any snapshot verifier (declared) — a timestamped, persisted verbale is what covers it.
Exit 0 only if every layer that ran is PASS.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import sys
from typing import Any, Dict, List, Optional, Tuple

GENESIS64 = "0" * 64
AUDIT_KEYS = ("kind", "target", "azione", "dettaglio", "operatore", "ts", "prev_sha256", "alg")
AUDIT_UNSIGNED = ("record_sha256", "firma_ed25519_b64", "pubkey_b64")


class RawNumber(float):
    """A JSON number that remembers its exact text (what Python wrote = its repr): re-emitted verbatim."""
    def __new__(cls, text: str):
        o = float.__new__(cls, float(text)); o.text = text; return o


def _parse_number(text: str):
    return int(text) if re.fullmatch(r"-?\d+", text) else RawNumber(text)


def _no_dup(pairs):
    d = {}
    for k, v in pairs:
        if k in d:
            raise ValueError(f"duplicate key {k!r}")
        d[k] = v
    return d


def loads(text: str):
    """Strict: duplicate keys refused, NaN/Infinity refused, numbers keep their text."""
    def bad(name):
        raise ValueError(f"non-JSON constant {name}")
    return json.loads(text, object_pairs_hook=_no_dup, parse_float=RawNumber, parse_int=int, parse_constant=bad)


def _canon_value(v: Any, ascii_only: bool) -> str:
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, RawNumber):
        return v.text
    if isinstance(v, int):
        return str(v)
    if isinstance(v, float):
        return repr(v)
    if isinstance(v, str):
        return json.dumps(v, ensure_ascii=ascii_only)
    if isinstance(v, list):
        return "[" + ",".join(_canon_value(x, ascii_only) for x in v) + "]"
    if isinstance(v, dict):
        for k in v:
            if not isinstance(k, str):
                raise TypeError("non-string key")
        return "{" + ",".join(json.dumps(k, ensure_ascii=ascii_only) + ":" + _canon_value(v[k], ascii_only) for k in sorted(v)) + "}"
    raise TypeError(f"unserialisable {type(v).__name__}")


def canonical(obj: Any, ascii_only: bool) -> bytes:
    """Byte-identical to json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=ascii_only)."""
    return _canon_value(obj, ascii_only).encode("utf-8")


def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _slug(op: str) -> str:
    return "".join(c if c.isalnum() or c in "-_" else "-" for c in str(op).strip().lower())[:40]


def load_registry(keys_dir: Optional[str]) -> Dict[str, str]:
    reg: Dict[str, str] = {}
    if keys_dir and os.path.isdir(keys_dir):
        for n in sorted(os.listdir(keys_dir)):
            if n.startswith("fb-") and n.endswith(".pub"):
                with open(os.path.join(keys_dir, n), encoding="utf-8") as f:
                    reg[n[3:-4]] = f.read().strip()
    return reg


def _ed_verify(pub_b64: str, sig_b64: str, msg: bytes) -> Optional[bool]:
    """True / False, or None when no Ed25519 implementation is available (then the signature is NOT verified —
    never reported as invalid, never as valid)."""
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError:
        return None
    try:
        Ed25519PublicKey.from_public_bytes(base64.b64decode(pub_b64)).verify(base64.b64decode(sig_b64), msg)
        return True
    except Exception:  # noqa: BLE001 — any failure is one verdict
        return False


def _layer(name: str, status: str, detail: str = "") -> Dict[str, str]:
    return {"layer": name, "status": status, "detail": detail}


def _read_lines(path: str) -> List[Tuple[int, Any]]:
    out = []
    with open(path, encoding="utf-8") as f:
        for n, line in enumerate(f, 1):
            if line.strip():
                out.append((n, loads(line)))
    return out


def verify_audit(path: str, registry: Dict[str, str], registry_source: str) -> Tuple[Dict[str, str], Dict[str, Dict]]:
    """Returns the layer and {record_sha256: {"ok": bool, "operatore": …}} for the verbale cross-check."""
    records: Dict[str, Dict] = {}
    try:
        lines = _read_lines(path)
    except (OSError, ValueError, RecursionError) as e:
        return _layer("audit-ledger", "FAIL", f"unreadable: {type(e).__name__}: {str(e)[:100]}"), records
    prev, n_sig_ok, n_sig_untrusted, failures = "GENESIS", 0, 0, []
    started = False
    registry_source_note = [registry_source]
    for n, e in lines:
        if not isinstance(e, dict) or e.get("kind") != "audit_locale":
            failures.append(f"line {n}: not an audit_locale object"); break
        if "prev_sha256" not in e:
            if started:
                failures.append(f"line {n}: no prev_sha256 after the chain started (insertion/replacement?)")
            prev = e.get("record_sha256") or prev
        else:
            started = True
            if e["prev_sha256"] != prev:
                failures.append(f"line {n}: prev_sha256 does not link (deletion/reorder?)")
            prev = e.get("record_sha256") or prev
        # the key set is EXACT: an extra field (e.g. clear text added later) is a failure, not ignored
        extra = set(e) - set(AUDIT_KEYS) - set(AUDIT_UNSIGNED)
        if extra:
            failures.append(f"line {n}: unexpected keys {sorted(extra)}")
        if e.get("alg", "ed25519") != "ed25519":
            failures.append(f"line {n}: unsupported alg {e.get('alg')!r}")
        rec = {k: e[k] for k in AUDIT_KEYS if k in e}
        try:
            digest = hashlib.sha256(canonical(rec, ascii_only=True)).digest()
        except TypeError as ex:
            failures.append(f"line {n}: not canonicalisable: {ex}"); continue
        ok_digest = digest.hex() == e.get("record_sha256")
        if not ok_digest:
            failures.append(f"line {n}: record_sha256 does not match the canonical record")
        pub = registry.get(_slug(e.get("operatore", "")) or "anonimo")
        sig_ok = None
        if pub:
            sig_ok = _ed_verify(pub, str(e.get("firma_ed25519_b64", "")), digest)
            if sig_ok is None:
                n_sig_untrusted += 1
                registry_source_note[0] = "cryptography not installed: signatures NOT verified"
            elif sig_ok:
                n_sig_ok += 1
            else:
                failures.append(f"line {n}: signature invalid for the REGISTERED key of {e.get('operatore')}")
        else:
            n_sig_untrusted += 1
        records[str(e.get("record_sha256"))] = {"ok": ok_digest and bool(sig_ok), "operatore": e.get("operatore"), "registered": bool(pub)}
    if not lines:
        failures.append("empty ledger")
    if failures:
        return _layer("audit-ledger", "FAIL", "; ".join(failures[:3])), records
    if n_sig_untrusted and not n_sig_ok:
        return _layer("audit-ledger", "SKIP", f"{len(lines)} records, digests and chain PASS, signatures present but NOT trusted ({registry_source_note[0]})"), records
    return _layer("audit-ledger", "PASS", f"{len(lines)} records, chain from GENESIS, {n_sig_ok} signatures verified against registered keys ({registry_source}), {n_sig_untrusted} operators without registered key"), records


def verify_chain(path: str) -> Dict[str, str]:
    try:
        lines = _read_lines(path)
    except (OSError, ValueError, RecursionError) as e:
        return _layer("chain-ledger", "FAIL", f"{os.path.basename(path)}: unreadable: {type(e).__name__}")
    prev, failures = GENESIS64, []
    for n, r in lines:
        if not isinstance(r, dict):
            failures.append(f"line {n}: not an object"); break
        if r.get("prev_hash") != prev:
            failures.append(f"line {n}: prev_hash does not link")
        body = {k: v for k, v in r.items() if k != "self_hash"}
        try:
            h = sha256_hex(canonical(body, ascii_only=False))
        except TypeError as ex:
            failures.append(f"line {n}: not canonicalisable: {ex}"); continue
        if h != r.get("self_hash"):
            failures.append(f"line {n}: self_hash mismatch")
        prev = r.get("self_hash") if isinstance(r.get("self_hash"), str) else prev
    if not lines:
        failures.append("empty ledger")
    name = os.path.basename(path)
    return _layer("chain-ledger", "FAIL" if failures else "PASS", f"{name}: " + ("; ".join(failures[:3]) if failures else f"{len(lines)} entries, chain from genesis, every self_hash recomputed"))


def verify_verbale(path: str, audit_records: Optional[Dict[str, Dict]], registry_present: bool) -> List[Dict[str, str]]:
    layers = []
    try:
        v = loads(open(path, encoding="utf-8").read())
    except (OSError, ValueError, RecursionError) as e:
        return [_layer("verbale-json", "FAIL", f"{type(e).__name__}: {str(e)[:100]}")]
    if not isinstance(v, dict) or v.get("kind") != "verbale_probatorio_prealert":
        return [_layer("verbale-json", "FAIL", "not a verbale_probatorio_prealert object")]
    layers.append(_layer("verbale-json", "PASS"))
    body = {k: x for k, x in v.items() if k != "digest_verbale_sha256"}
    try:
        d = sha256_hex(canonical(body, ascii_only=False))
        layers.append(_layer("verbale-digest", "PASS" if d == v.get("digest_verbale_sha256") else "FAIL", f"declared {str(v.get('digest_verbale_sha256'))[:16]}… computed {d[:16]}…"))
    except TypeError as ex:
        layers.append(_layer("verbale-digest", "FAIL", f"not canonicalisable: {ex}"))
    events = v.get("eventi") if isinstance(v.get("eventi"), list) else []
    if audit_records is None:
        layers.append(_layer("verbale-events", "SKIP", f"{len(events)} events listed; give --audit to check them against the signed ledger"))
    else:
        missing = [e.get("record_sha256") for e in events if isinstance(e, dict) and e.get("record_sha256") not in audit_records]
        bad = [e.get("record_sha256") for e in events if isinstance(e, dict) and e.get("record_sha256") in audit_records and not audit_records[e["record_sha256"]]["ok"]]
        claimed = v.get("firme_tutte_verificate") is True
        if missing:
            layers.append(_layer("verbale-events", "FAIL", f"{len(missing)} event(s) of the verbale are NOT in the audit ledger"))
        elif bad:
            layers.append(_layer("verbale-events", "FAIL", f"{len(bad)} event(s) do not verify in the ledger against the registered keys"))
        elif claimed and not registry_present:
            layers.append(_layer("verbale-events", "FAIL", "the verbale claims firme_tutte_verificate but no registry was given to re-verify them (a claim is not a verification)"))
        elif not events:
            layers.append(_layer("verbale-events", "FAIL", "no events"))
        else:
            layers.append(_layer("verbale-events", "PASS", f"{len(events)} events present in the ledger and verified there" if registry_present else f"{len(events)} events present in the ledger (signatures not trusted: no registry)"))
    return layers


def run(audit: Optional[str], chains: List[str], verbale: Optional[str], keys: Optional[str], trust_verbale_registry: bool) -> Dict[str, Any]:
    layers: List[Dict[str, str]] = []
    registry, source = load_registry(keys), (f"keys dir {keys}" if keys else "none")
    if not registry and verbale and trust_verbale_registry:
        try:
            vv = loads(open(verbale, encoding="utf-8").read())
            if isinstance(vv, dict) and isinstance(vv.get("registro_chiavi"), dict):
                registry = {str(k): str(x) for k, x in vv["registro_chiavi"].items()}
                source = "the verbale's own registro_chiavi (NOT out-of-band: declared)"
        except (OSError, ValueError):
            pass
    audit_records = None
    if audit:
        lay, audit_records = verify_audit(audit, registry, source)
        layers.append(lay)
    for c in chains:
        layers.append(verify_chain(c))
    if verbale:
        layers += verify_verbale(verbale, audit_records, bool(registry))
    if not layers:
        layers.append(_layer("input", "FAIL", "nothing to verify"))
    ok = all(l["status"] == "PASS" for l in layers)
    return {"ok": ok, "verdict": "PASS" if ok else ("FAIL" if any(l["status"] == "FAIL" for l in layers) else "NOT-TRUSTED"),
            "registry": source, "layers": layers}


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="offline verification of omega-health-companion evidence")
    p.add_argument("--audit"); p.add_argument("--chain", action="append", default=[]); p.add_argument("--verbale")
    p.add_argument("--keys", help="directory of registered operator keys (fb-<slug>.pub)")
    p.add_argument("--trust-verbale-registry", action="store_true", help="accept the registry embedded in the verbale (declared, not out-of-band)")
    a = p.parse_args(argv)
    r = run(a.audit, a.chain, a.verbale, a.keys, a.trust_verbale_registry)
    print(json.dumps(r, ensure_ascii=False, indent=1))
    return 0 if r["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
