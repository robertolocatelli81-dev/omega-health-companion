#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Measure CH EMS conformance of the OMEGA pre-alert document with the OFFICIAL HL7 FHIR validator.

    python3 chems_validate.py --sample examples/chems_document_sample.json      # write the sample document only
    python3 chems_validate.py --strict                                            # build + validate, exit 1 on any error

The validator (validator_cli.jar, pinned version) is taken from $FHIR_VALIDATOR_JAR or downloaded once into
~/.fhir/validator_cli-<version>.jar; the IG package ch.fhir.ig.ch-ems#<version> is fetched by the validator itself
into ~/.fhir/packages (network needed the first time). Warnings are printed and counted, errors fail the run.
This is the measurement behind every "CH EMS" sentence in the README: no green run, no claim."""
from __future__ import annotations
import argparse
import json
import os
import subprocess
import sys
import urllib.request

import ambulanza_intelligente as A
import fhir_chems as C

VALIDATOR_VERSION = "6.10.4"
VALIDATOR_URL = f"https://github.com/hapifhir/org.hl7.fhir.core/releases/download/{VALIDATOR_VERSION}/validator_cli.jar"
IG = f"ch.fhir.ig.ch-ems#{C.IG_VERSION}"

SAMPLE_MISSION = {
    "numero_missione": "ZH-2026-000123", "sistema_oid": "urn:oid:2.16.756.5.30.1.999.1",
    "organizzazione": {"nome": "Rettungsdienst Beispiel", "gln": "7601002155939",
                       "indirizzo": {"line": ["Musterstrasse 1"], "city": "Zürich", "postalCode": "8005", "country": "CH"}},
    "richiedente": {"nome": "Sanitätsnotrufzentrale 144 Beispiel", "gln": "7601002155939"},
    "destinazione": {"nome": "USZ", "gln": "7601002155939"},
    "tempi": {"allarme": "2026-09-16T10:12:00+02:00", "partenza": "2026-09-16T10:14:00+02:00",
              "arrivo_sul_posto": "2026-09-16T10:25:00+02:00", "arrivo_paziente": "2026-09-16T10:27:00+02:00",
              "partenza_dal_posto": "2026-09-16T10:38:00+02:00"},
    "triage_colore": "rosso", "urgenza": "sirena", "incidente_id": 42, "prealert_id": "prealert-7", "lingua": "de",
}   # the GLN is the one of the IG's own example organisation (format-valid); real deployments use their own


def build_sample() -> dict:
    """The full pre-alert (all vitals, alert, triage colour, destination, event id, ledger anchor)."""
    vit = dict(rr=28, spo2=89, su_ossigeno=True, sbp=85, hr=135, alert_coscienza=True, temp=39.4)
    out = A.valuta_paziente(vit, ["warfarin", "aspirina"], 67, 8)
    return C.prealert_to_chems_document(out["PRE_ALERT_INTEGRATO"], vit, "2026-09-16T10:40:00+02:00", SAMPLE_MISSION,
                                        provenienza_omega={"ancorato": True, "self_hash": "ab" * 32})


def build_minimal() -> dict:
    """The EARLIEST pre-alert (council 16/09: the not-alert / no-triage / no-destination path must be measured too):
    alarm time only, one vital, patient not alert (no AVPU code exported), no colour, no destination, no anchor."""
    vit = dict(hr=135, alert_coscienza=False)
    out = A.valuta_paziente(vit, [], None, 12)
    m = {k: v for k, v in SAMPLE_MISSION.items() if k in ("numero_missione", "sistema_oid", "organizzazione", "richiedente")}
    m["tempi"] = {"allarme": SAMPLE_MISSION["tempi"]["allarme"]}; m["lingua"] = "fr"; m["prealert_id"] = "prealert-3"
    return C.prealert_to_chems_document(out["PRE_ALERT_INTEGRATO"], vit, "2026-09-16T10:15:00+02:00", m)


def validator_jar() -> str:
    jar = os.environ.get("FHIR_VALIDATOR_JAR")
    if jar and os.path.exists(jar):
        return jar
    cache = os.path.join(os.path.expanduser("~/.fhir"), f"validator_cli-{VALIDATOR_VERSION}.jar")
    if not os.path.exists(cache):
        os.makedirs(os.path.dirname(cache), exist_ok=True)
        print(f"downloading {VALIDATOR_URL}", file=sys.stderr)
        urllib.request.urlretrieve(VALIDATOR_URL, cache + ".part")
        os.replace(cache + ".part", cache)
    return cache


def validate(path: str, out_json: str) -> dict:
    cmd = ["java", "-Xmx2g", "-jar", validator_jar(), path, "-version", "4.0.1", "-ig", IG,
           "-profile", C.PROFILE["document"], "-output", out_json]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
    if not os.path.exists(out_json):
        return {"ran": False, "returncode": r.returncode, "stderr": (r.stdout + r.stderr)[-2000:]}
    oo = json.load(open(out_json, encoding="utf-8"))
    issues = oo.get("issue", [])
    sev = {}
    for i in issues:
        sev[i["severity"]] = sev.get(i["severity"], 0) + 1
    return {"ran": True, "returncode": r.returncode, "counts": sev,
            "errors": [{"where": (i.get("expression") or [""])[0], "text": (i.get("details") or {}).get("text", "")}
                       for i in issues if i["severity"] in ("error", "fatal")],
            "warnings": [{"where": (i.get("expression") or [""])[0], "text": (i.get("details") or {}).get("text", "")[:160]}
                         for i in issues if i["severity"] == "warning"]}


SAMPLE_KEY_SEED = b"omega-health-companion published sample key - NOT A SECRET - anyone can derive it from this sentence"


def build_signed_sample() -> dict:
    """The full sample with Composition.attester and Bundle.signature (0.7.3), signed by a key DERIVED FROM A PUBLIC
    SENTENCE so that the published file is deterministic and verifiable by anyone (the JWK travels in the header).
    That key proves the format, never an identity: `chiave_registrata` is False outside a registry that lists it."""
    import hashlib, tempfile, shutil, base64 as b64
    import audit_bridge as AB
    d = build_sample()
    tmp = tempfile.mkdtemp(prefix="omega-sample-key-"); orig = AB.KEYS_DIR
    try:
        AB.KEYS_DIR = tmp
        with open(os.path.join(tmp, "fb-esempio.key"), "w") as f:
            f.write(b64.b64encode(hashlib.sha256(SAMPLE_KEY_SEED).digest()).decode())
        return C.firma_documento(d, "esempio", "2026-09-19T09:11:00+02:00")
    finally:
        AB.KEYS_DIR = orig; shutil.rmtree(tmp, ignore_errors=True)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sample", help="write the sample CH EMS documents (full, minimal, signed) here and exit")
    ap.add_argument("--verify-signature", help="print the four-state verdict on Bundle.signature of this document and exit (0 = OK)")
    ap.add_argument("--strict", action="store_true", help="run the validator; exit 1 on any error")
    ap.add_argument("--doc", help="validate this document instead of the built sample")
    a = ap.parse_args(argv)
    if a.verify_signature:
        v = C.verifica_firma_documento(open(a.verify_signature, "rb").read())
        print(json.dumps(v, ensure_ascii=False)); return 0 if v["stato"] == "OK" else 1
    if a.sample:
        json.dump(build_sample(), open(a.sample, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
        mp = a.sample.replace(".json", "_minimal.json")
        json.dump(build_minimal(), open(mp, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
        sp = a.sample.replace(".json", "_signed.json")
        json.dump(build_signed_sample(), open(sp, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
        print("samples written:", a.sample, mp, sp)
        return 0
    docs = [a.doc] if a.doc else []
    if not a.doc:
        for name, builder in (("chems_document.json", build_sample), ("chems_document_minimal.json", build_minimal)):
            json.dump(builder(), open(name, "w", encoding="utf-8"), ensure_ascii=False, indent=1); docs.append(name)
    rc = 0
    for path in docs:
        res = validate(path, "chems_validation.json")
        print(path, json.dumps({k: v for k, v in res.items() if k != "warnings"}, ensure_ascii=False, indent=1))
        for w in res.get("warnings", []):
            print("  WARN", w["where"][:60], "|", w["text"])
        if not res["ran"]:
            return 2
        if a.strict and res["errors"]:
            rc = 1
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
