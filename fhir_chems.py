#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""OMEGA — pre-alert as a CH EMS document (FHIR R4, ch.fhir.ig.ch-ems 2.0.0-ballot).

CH EMS is the Swiss exchange format for the emergency-medical-service mission protocol (IVR / HL7
Switzerland, eCH-0207). `prealert_to_chems_document()` renders the OMEGA pre-alert as a
**CHEmsDocument**: a `document` Bundle whose first entry is a **CHEmsComposition** with
`status: preliminary` (the pre-alert is written *before* handover, the protocol is completed later),
the mandatory *mission* section (CHEmsEncounter with the mission number, mission-time observations),
*findings* (heart rate / blood pressure under "Circulation", AVPU under "Disability"), *handover*
(patient status priority as the START colour, destination organisation) and an *annotation* section
that carries what CH EMS has no slot for yet: the NEWS2 risk assessment, the drug-interaction flags
and the OMEGA Provenance (hash-chain anchor + record-bound signature).

HONEST SCOPE
- The patient stays anonymous (CHEmsPatient allows it; identity is joined in the hospital flow).
- Only what OMEGA measures is exported: no NACA score, no GCS, no diagnosis — those profiles exist
  in CH EMS but we do not compute them, so they are not faked.
- The GLN of the organisations is validated for FORMAT (13 digits, GS1 check digit) only; whether it
  is a registered GLN is not something this module can know.
- Conformance is a MEASUREMENT: `chems_validate.py` runs the official HL7 validator against the IG
  (also in CI). Nothing here claims "CH EMS conformant" without that run being green.
- The multi-patient *event* identifier (CH EMS issue #56, open) is exported as an additional
  Encounter identifier typed by an OMEGA code system: a proposal, not an IG element.
"""
from __future__ import annotations
import base64
import binascii
import json
import os
import re
from datetime import datetime, timezone
import uuid
from typing import Any, Dict, List, Optional

from fhir_export import CS_LOCALE, LOINC, UCUM, _obs

IG_URL = "http://fhir.ch/ig/ch-ems"
IG_VERSION = "2.0.0-ballot"
PROFILE = {k: f"{IG_URL}/StructureDefinition/ch-ems-{v}" for k, v in {
    "document": "document", "composition": "composition", "patient": "patient", "encounter": "encounter",
    "organization": "organization", "servicerequest": "servicerequest", "observation": "observation",
    "heartrate": "observation-heartrate", "bloodpressure": "observation-bloodpressure", "avpu": "observation-avpu",
    "missiontime": "observation-missiontimestatus", "statuspriority": "observation-statuspriority"}.items()}
CS_IVR = f"{IG_URL}/CodeSystem/IVR"
SNOMED = "http://snomed.info/sct"
LOINC_SYS = "http://loinc.org"
OID_GLN = "urn:oid:2.51.1.3"
OID_EPR_SPID = "urn:oid:2.16.756.5.30.1.127.3.10.3"     # forbidden in a document (ch-core-patient-epr)
OID_AHVN13 = "urn:oid:2.16.756.5.32"                   # idem

TITLES = {  # wording suggested by the profile's short descriptions per language (free 1..1 strings; only the
            # findings/procedures sub-section titles "Circulation", "Disability", … are fixedString in the IG)
    "de": {"doc": "Einsatzprotokoll Rettungsdienst", "mission": "Einsatz", "findings": "Befund", "handover": "Übergabe", "annotation": "Kommentar"},
    "fr": {"doc": "Protocole d'intervention des services de sauvetage", "mission": "Intervention", "findings": "Résultats", "handover": "Remise", "annotation": "Commentaire"},
    "it": {"doc": "Protocollo d'intervento servizi di salvataggio", "mission": "Intervento", "findings": "Risultati", "handover": "Consegna", "annotation": "Osservazione"},
    "en": {"doc": "Emergency Medical Service protocol", "mission": "intervention", "findings": "findings", "handover": "handover", "annotation": "Comment"},
}
SECTION_CODE = {"mission": ("1100001", "intervention"), "findings": ("1100006", "findings"), "handover": ("1100011", "handover")}
TEXTS = {  # narrative sentences per document language (council 16/09: texts must follow Composition.language)
    "de": {"nota_profilo": "Profil Kommunikation: keine Scores berechnet; Vitalwerte wie übermittelt; die Beurteilung obliegt der Klinik", "mission": "Einsatz {mn} · {org} · angefordert von {req}", "times": "Zeiten", "findings": "Vitalparameter während des Transports",
           "circ": "Herzfrequenz und Blutdruck im Rettungswagen gemessen", "dis": "AVPU: Patient wach (A)", "handover": "Patientenpriorität",
           "dest": "Zielspital {dest}", "patient": "anonymer Patient{age}", "age": ", Alter {eta}", "ann": "OMEGA-Voranmeldung: Priorität {prio}, NEWS2 {news}; Hinweise: {avvisi}; Pfade: {percorsi}. Die Voranmeldung ist an ein hash-verkettetes OMEGA-Ledger verankert (Provenance).",
           "none": "keine", "sr": "Einsatzanforderung von {req}"},
    "fr": {"nota_profilo": "Profil communication : aucun score calculé ; signes vitaux tels que transmis ; l'évaluation appartient au clinicien", "mission": "Intervention {mn} · {org} · demandée par {req}", "times": "Heures", "findings": "Paramètres vitaux pendant le transport",
           "circ": "Fréquence cardiaque et pression artérielle mesurées dans l'ambulance", "dis": "AVPU : patient alerte (A)", "handover": "Priorité du patient",
           "dest": "hôpital de destination {dest}", "patient": "patient anonyme{age}", "age": ", âge {eta}", "ann": "Pré-alerte OMEGA : priorité {prio}, NEWS2 {news} ; alertes : {avvisi} ; filières : {percorsi}. La pré-alerte est ancrée à un registre OMEGA chaîné par hachage (Provenance).",
           "none": "aucune", "sr": "Demande d'intervention de {req}"},
    "it": {"nota_profilo": "profilo comunicazione: nessun punteggio calcolato; vitali come inviati; la valutazione è del clinico", "mission": "Missione {mn} · {org} · richiesta da {req}", "times": "tempi", "findings": "Parametri vitali rilevati durante il trasporto",
           "circ": "Frequenza cardiaca e pressione arteriosa misurate in ambulanza", "dis": "AVPU: paziente Alert (A)", "handover": "Priorità del paziente",
           "dest": "destinazione {dest}", "patient": "paziente anonimo{age}", "age": ", età {eta}", "ann": "Pre-alert OMEGA: priorità {prio}, NEWS2 {news}; avvisi: {avvisi}; percorsi: {percorsi}. Il pre-alert è ancorato a un ledger hash-chained OMEGA (Provenance).",
           "none": "nessuno", "sr": "Richiesta di intervento da {req}"},
    "en": {"nota_profilo": "communication profile: no score computed; vitals as sent; the assessment is the clinician's", "mission": "Mission {mn} · {org} · requested by {req}", "times": "times", "findings": "Vital signs measured during transport",
           "circ": "Heart rate and blood pressure measured in the ambulance", "dis": "AVPU: patient alert (A)", "handover": "Patient priority",
           "dest": "destination {dest}", "patient": "anonymous patient{age}", "age": ", age {eta}", "ann": "OMEGA pre-alert: priority {prio}, NEWS2 {news}; flags: {avvisi}; pathways: {percorsi}. The pre-alert is anchored to a hash-chained OMEGA ledger (Provenance).",
           "none": "none", "sr": "Service request from {req}"},
}
MISSION_TYPE = {"primaria": ("1000001", "primary mission"), "secondaria": ("1000002", "secondary mission"), "standby": ("1000003", "stand-by mission")}
_ID_SAFE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
MISSION_TIME_ROLE = {  # OMEGA mission-time keys → IVR-VS-missionTimeRole
    "allarme": ("1000033", "alarm"), "partenza": ("1000035", "rollout"), "arrivo_sul_posto": ("1000036", "arrival on scene"),
    "arrivo_paziente": ("1000037", "arrival patient"), "partenza_dal_posto": ("1000038", "departure from scene"),
    "arrivo_destinazione": ("1000039", "arrival at target"), "consegna_paziente": ("1000040", "handover patient"),
}
START_TO_SNOMED = {"rosso": ("371240000", "red"), "giallo": ("371244009", "yellow"), "verde": ("371246006", "green")}
URGENCY = {"sirena": ("1000007", "with siren"), "senza_sirena": ("1000008", "without siren")}
def _frazione6(iso: str) -> str:
    """ISO 8601 instant → same instant with the fraction padded/truncated to 6 digits and Z → +00:00 (fromisoformat-safe on 3.9+)."""
    m = re.match(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d+))?(Z|[+-]\d{2}:\d{2})$", iso)
    if not m:
        raise ValueError(f"CH EMS: not an ISO 8601 instant with timezone: {iso!r}")
    frac = (m.group(2) or "")[:6].ljust(6, "0")
    return f"{m.group(1)}.{frac}{'+00:00' if m.group(3) == 'Z' else m.group(3)}"


_ISO = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$")


def gln_valida(gln: str) -> bool:
    """GS1 GLN: 13 digits with a mod-10 check digit (format only — registration is not checked)."""
    if not isinstance(gln, str) or not re.fullmatch(r"\d{13}", gln):
        return False
    digits = [int(c) for c in gln]
    weights = [1, 3] * 6
    total = sum(d * w for d, w in zip(digits[:12], weights))
    return (10 - total % 10) % 10 == digits[12]


def _b64_of(s: Any, n: int) -> Optional[bytes]:
    """Strict standard base64 of exactly n bytes, or None."""
    if not isinstance(s, str) or len(s) != ((n + 2) // 3) * 4:
        return None
    try:
        raw = base64.b64decode(s, validate=True)
    except (ValueError, binascii.Error):
        return None
    return raw if len(raw) == n and base64.b64encode(raw).decode() == s else None


def _xhtml(text: str, lang: Optional[str] = None) -> Dict:
    esc = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    attrs = f' lang="{lang}" xml:lang="{lang}"' if lang else ""
    return {"status": "generated", "div": f'<div xmlns="http://www.w3.org/1999/xhtml"{attrs}>{esc}</div>'}


_NOME = re.compile(r"[^\x00-\x1f<>]{1,80}")           # apostrophes and ampersands are names; the narrative escapes them


def _paziente_identificato(spec: Dict, base: Dict) -> Dict:
    """Handover stage, OPT-IN (0.7.3): the crew identified the patient and the receiving hospital wants an EPR-conformant
    document. `spec` = {cognome, nome, sesso male|female|other|unknown, data_nascita YYYY-MM-DD, identificatore
    {system: 'urn:oid:…' of the local MPI, value}}. What ch-core-patient-epr requires (identifier 1..*, name with family,
    gender, birthDate) is validated here; EPR-SPID and AHVN13 are REFUSED (the profile forbids them in a document,
    max 0). The identity goes into THIS document only — the OMEGA ledger stays digest-only, the board stays PII-free."""
    if not isinstance(spec, dict):
        raise ValueError("CH EMS: paziente must be an object")
    cog, nom, sesso, dn, ident = spec.get("cognome"), spec.get("nome"), spec.get("sesso"), spec.get("data_nascita"), spec.get("identificatore")
    if not isinstance(cog, str) or not _NOME.fullmatch(cog.strip()):
        raise ValueError("CH EMS: paziente.cognome (family name) is required: 1-80 printable characters")
    if nom is not None and (not isinstance(nom, str) or not _NOME.fullmatch(nom.strip())):
        raise ValueError("CH EMS: paziente.nome must be 1-80 printable characters")
    if sesso not in ("male", "female", "other", "unknown"):
        raise ValueError("CH EMS: paziente.sesso must be male | female | other | unknown (FHIR administrative-gender)")
    if not isinstance(dn, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", dn):
        raise ValueError("CH EMS: paziente.data_nascita must be YYYY-MM-DD")
    try:
        datetime.strptime(dn, "%Y-%m-%d")
    except ValueError:
        raise ValueError("CH EMS: paziente.data_nascita is not a calendar date") from None
    if not isinstance(ident, dict) or not isinstance(ident.get("system"), str) or not isinstance(ident.get("value"), str) \
            or not re.fullmatch(r"urn:oid:[0-2](\.(0|[1-9]\d*))+", ident["system"]) or not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", ident["value"]):
        raise ValueError("CH EMS: paziente.identificatore must be {system: 'urn:oid:…' of the local patient index, value: token}")
    if ident["system"] in (OID_EPR_SPID, OID_AHVN13):
        raise ValueError("CH EMS: EPR-SPID and AHVN13 must not be carried in a document (ch-core-patient-epr: max 0)")
    if re.fullmatch(r"756\d{10}", ident["value"]):        # an AHVN13-shaped value under a "local" system is still the AHVN13
        raise ValueError("CH EMS: identificatore.value looks like an AHVN13 (756 + 10 digits): refused under any system")
    nome_txt = (cog.strip() + (", " + nom.strip() if nom else ""))
    out = dict(base)
    out["identifier"] = [{"system": ident["system"], "value": ident["value"]}]
    out["name"] = [{"family": cog.strip(), **({"given": [nom.strip()]} if nom else {})}]
    out["gender"] = sesso
    out["birthDate"] = dn
    out["text"] = _xhtml(nome_txt + " · " + dn)
    return out


# ── JCS (RFC 8785) — copied from omega-evidence interop/aat.py (2026-09-14, checked against RFC 8785 Appendix B there) ──
def _es6_number(f: float) -> str:
    if f == 0:
        return "0"
    sign = "-" if f < 0 else ""
    r = repr(abs(f))
    if "e" in r:
        mant, exp = r.split("e"); exp = int(exp)
    else:
        mant, exp = r, 0
    ip, fp = (mant.split(".") + [""])[:2]
    fp = fp.rstrip("0") if fp != "0" else ""
    digits = (ip + fp).lstrip("0")
    n = len(ip.lstrip("0")) + exp if ip.lstrip("0") else exp - (len(fp) - len(fp.lstrip("0")))
    if not ip.lstrip("0"):
        digits = fp.lstrip("0")
    digits = digits.rstrip("0") or "0"
    k = len(digits)
    if k <= n <= 21:
        out = digits + "0" * (n - k)
    elif 0 < n <= 21:
        out = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        out = "0." + "0" * (-n) + digits
    else:
        e = n - 1
        out = (digits[0] + ("." + digits[1:] if k > 1 else "")) + "e" + ("+" if e >= 0 else "-") + str(abs(e))
    return sign + out


def jcs(obj: Any) -> bytes:
    """JSON Canonicalization Scheme (RFC 8785): keys sorted by UTF-16 code units, no whitespace, ES6 numbers."""
    def enc(x: Any) -> str:
        if x is None:
            return "null"
        if x is True:
            return "true"
        if x is False:
            return "false"
        if isinstance(x, int):
            if abs(x) > 2 ** 53:
                raise ValueError("JCS: integers beyond 2^53 lose precision in ES6")
            return str(x)
        if isinstance(x, float):
            if x != x or x in (float("inf"), float("-inf")):
                raise ValueError("JCS: NaN/Infinity are not JSON")
            return _es6_number(x)
        if isinstance(x, str):
            return json.dumps(x, ensure_ascii=False)
        if isinstance(x, (list, tuple)):
            return "[" + ",".join(enc(i) for i in x) + "]"
        if isinstance(x, dict):
            return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + enc(x[k]) for k in sorted(x, key=lambda k: k.encode("utf-16-be"))) + "}"
        raise TypeError(f"JCS: unsupported type {type(x).__name__}")
    return enc(obj).encode("utf-8")


# ── Bundle.signature (0.7.3): a FHIR Signature OVER THE DOCUMENT BYTES, verifiable offline ─────────────────────────
# Base FHIR defines Bundle.signature (0..1) and the Signature datatype; CH EMS 2.0.0-ballot does not profile or require
# it. The signed bytes are the JCS canonical form of the Bundle WITHOUT the `signature` element (as the FHIR
# "Digital Signatures" guidance: the signature covers the resource with the signature removed). Format: a detached
# JWS (RFC 7515 Appendix F) with unencoded payload (RFC 7797, "b64": false), alg EdDSA (RFC 8037, Ed25519), the public
# key embedded as a JWK in the header so any JWS library can verify; TRUST is a separate question the verifier answers
# by looking the key up in the OMEGA operator registry (fb-<slug>.pub). This is not the OMEGA audit-record signature
# (which stays in Provenance as entities): it is a signature of THIS document by the operator's key.
SIG_TYPE = {"system": "urn:iso-astm:E1762-95:2013", "code": "1.2.840.10065.1.12.1.1", "display": "Author's Signature"}
# The canonicalization is named in targetFormat in the parameter form the FHIR "Digital Signatures" page uses, with a URI
# WE define (FORMAT.md): FHIR R4's own "canonical JSON" is not RFC 8785 (no number rewriting, and it does not say to remove
# the signature member); the current FHIR build adopts RFC 8785, but CH EMS is R4. Labelling our bytes with the FHIR URI
# would let a verifier following that page rebuild different bytes (review Opus r1). The same URI travels in the JWS
# header ("canon"), so the payload rule is discoverable from the signature itself.
CANON_URI = "https://omega.example/fhir/canonicalization/rfc8785-bundle-without-signature"
TARGET_FORMAT = "application/fhir+json;canonicalization=" + CANON_URI
_KID = re.compile(r"omega:fb-([a-z0-9-]{1,64})")


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _b64u_dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def firma_documento(doc: Dict, operatore: str, ts: str, who_id: str = "soccorso", attester: Optional[str] = "professional") -> Dict:
    """Return a copy of `doc` with Bundle.signature by the operator's registered Ed25519 key (audit_bridge registry) and,
    unless attester=None, a Composition.attester by the same party (mode professional for a pre-alert, legal for the
    final protocol — the eCH-0207 use case). Refuses to sign a Bundle that already carries a signature (one signature
    per document; re-signing is an explicit act, not a silent overwrite)."""
    import audit_bridge as AB
    if not AB.FIRMA_LOCALE_DISPONIBILE:
        raise AB.FirmaNonDisponibile("Bundle.signature needs the local Ed25519 signer (`cryptography`)")
    if not isinstance(doc, dict) or doc.get("resourceType") != "Bundle":
        raise ValueError("firma_documento: a Bundle is required")
    if "signature" in doc:
        raise ValueError("firma_documento: the Bundle already carries a signature")
    if not _ISO.match(ts or ""):
        raise ValueError("firma_documento: ts must be an ISO 8601 instant with timezone")
    if attester not in (None, "professional", "legal"):
        raise ValueError("firma_documento: attester must be professional | legal | None")
    slug = AB._slug(operatore) or "anonimo"
    if not _KID.fullmatch(f"omega:fb-{slug}"):
        raise ValueError("firma_documento: operator slug must be [a-z0-9-]{1,64}")
    sk = AB._fb_key(operatore)
    pub = sk.public_key().public_bytes(AB._ser.Encoding.Raw, AB._ser.PublicFormat.Raw)
    who = None
    for e in doc.get("entry", []):
        r = e.get("resource", {})
        if r.get("resourceType") == "Organization" and r.get("id") == who_id:
            who = {"reference": e["fullUrl"]}; break
    if who is None:
        raise ValueError(f"firma_documento: signer Organization {who_id!r} not in the Bundle")
    out = json.loads(json.dumps(doc))                    # deep copy: the caller's Bundle is never mutated
    if attester:                                          # the attestation is INSIDE the signed bytes: added before signing
        comp = out["entry"][0]["resource"]
        if comp.get("resourceType") != "Composition":
            raise ValueError("firma_documento: entry[0] must be the Composition")
        comp.setdefault("attester", []).append({"mode": attester, "time": ts, "party": who})
    # header per FHIR "Digital Signatures" (build of 2026-09, normative track; R4 text is looser): kid (no X.509 here),
    # sigT equal to Signature.when, srCms = the same ASTM purpose as Signature.type (JAdES-shaped; no JAdES conformance
    # is claimed), the verifying key as a JWK (public part only), plus two private parameters that bind what the Signature
    # datatype leaves outside the signed bytes: "canon" (the payload rule) and "who" (the signer reference)
    header = {"alg": "EdDSA", "b64": False, "crit": ["b64"], "kid": f"omega:fb-{slug}", "sigT": ts,
              "srCms": [{"commId": {"id": "urn:oid:" + SIG_TYPE["code"], "desc": SIG_TYPE["display"]}}],
              "jwk": {"kty": "OKP", "crv": "Ed25519", "x": _b64u(pub)}, "canon": CANON_URI, "who": who["reference"]}
    h = _b64u(json.dumps(header, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    sig = sk.sign(h.encode("ascii") + b"." + jcs(out))   # signed ONCE, over the final content
    jws = f"{h}..{_b64u(sig)}"                       # detached: payload omitted, reconstructed by the verifier from the Bundle
    out["signature"] = {"type": [dict(SIG_TYPE)], "when": ts, "who": who, "targetFormat": TARGET_FORMAT,
                        "sigFormat": "application/jose", "data": base64.b64encode(jws.encode("ascii")).decode("ascii")}
    return out


def verifica_firma_documento(doc: Any, keys_dir: Optional[str] = None) -> Dict:
    """Verdict on Bundle.signature, five states, structure checked BEFORE cryptography:
      OK_REGISTRATA          — the bytes verify AND the embedded key equals the operator's registered key (`kid`) in
                               `keys_dir` (default: this machine's `.audit_keys/`); the only state a consumer may accept
      OK_CHIAVE_NON_REGISTRATA — the bytes verify against the key embedded in the header, which is NOT (or cannot be) matched
                               to a registered operator key: anyone can produce such a signature with a fresh key
      NON_VALIDA             — present but malformed, unbound, or the bytes do not verify
      NON_VERIFICATA         — structurally sound, no Ed25519 implementation here to check the bytes
      ASSENTE                — no signature
    The signature proves the bytes; the registry proves only that the key matches the LOCAL operator record of the verifying
    machine — there is no key distribution in 0.7.3, so on a machine without that registry the best verdict is
    OK_CHIAVE_NON_REGISTRATA. `doc` may be the parsed Bundle or its raw bytes (strict JSON: duplicate keys refused)."""
    out = {"stato": "ASSENTE", "kid": None, "chiave_registrata": None, "motivo": None}
    def _no(m):
        out.update(stato="NON_VALIDA", motivo=m); return out
    try:
        if isinstance(doc, (bytes, bytearray)):
            doc = json.loads(bytes(doc).decode("utf-8"), object_pairs_hook=_no_dup)
        if not isinstance(doc, dict) or doc.get("resourceType") != "Bundle":
            return _no("not a Bundle")
        sig = doc.get("signature")
        if sig is None:
            return out
        if not isinstance(sig, dict) or sig.get("sigFormat") != "application/jose" or not isinstance(sig.get("data"), str):
            return _no("signature is not an application/jose Signature with data")
        if sig.get("targetFormat") != TARGET_FORMAT:
            return _no("targetFormat must be exactly " + TARGET_FORMAT)
        jws = base64.b64decode(sig["data"], validate=True).decode("ascii")
        parts = jws.split(".")
        if len(parts) != 3 or parts[1] != "":
            return _no("not a detached compact JWS (header..signature)")
        header = json.loads(_b64u_dec(parts[0]).decode("utf-8"), object_pairs_hook=_no_dup)
        if not isinstance(header, dict):
            return _no("protected header is not an object")
        kid = header.get("kid")
        out["kid"] = kid if isinstance(kid, str) else None
        if not isinstance(kid, str) or not _KID.fullmatch(kid):
            return _no("kid must be omega:fb-<slug> with slug [a-z0-9-]{1,64}")
        if header.get("alg") != "EdDSA" or header.get("b64") is not False or header.get("crit") != ["b64"]:
            return _no("header must be alg EdDSA, b64:false, crit exactly [\"b64\"]")
        if header.get("canon") != CANON_URI:
            return _no("header canon must name the payload rule " + CANON_URI)
        if not isinstance(header.get("sigT"), str) or not isinstance(sig.get("when"), str) or header["sigT"] != sig["when"]:
            return _no("sigT (header) and Signature.when must both be present and equal")
        types = sig.get("type") if isinstance(sig.get("type"), list) else []
        srcms = header.get("srCms") if isinstance(header.get("srCms"), list) else []
        codes = {t.get("code") for t in types if isinstance(t, dict) and t.get("system") == SIG_TYPE["system"]}
        comm = {str(c.get("commId", {}).get("id", "")).replace("urn:oid:", "", 1) for c in srcms if isinstance(c, dict) and isinstance(c.get("commId"), dict)}
        if not codes or codes != comm:
            return _no("Signature.type (ASTM E1762-95) and the header srCms commitments must carry the same codes")
        who = sig.get("who") if isinstance(sig.get("who"), dict) else {}
        if not isinstance(who.get("reference"), str) or header.get("who") != who["reference"]:
            return _no("Signature.who.reference must equal the signed header who")
        if not any(e.get("fullUrl") == who["reference"] and isinstance(e.get("resource"), dict) and e["resource"].get("resourceType") == "Organization"
                   for e in (doc.get("entry") or []) if isinstance(e, dict)):
            return _no("Signature.who must reference an Organization entry of this Bundle")
        comp = (doc.get("entry") or [{}])[0].get("resource", {}) if isinstance(doc.get("entry"), list) and doc["entry"] else {}
        for a in (comp.get("attester") or []) if isinstance(comp, dict) and isinstance(comp.get("attester"), list) else []:
            if isinstance(a, dict) and a.get("time") == sig["when"] and (a.get("party") or {}).get("reference") != who["reference"]:
                return _no("a Composition.attester at the signing time names a different party than Signature.who")
        jwk = header.get("jwk") or {}
        if not isinstance(jwk, dict) or set(jwk) != {"kty", "crv", "x"} or jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519" or not isinstance(jwk.get("x"), str):
            return _no("header must embed a PUBLIC OKP/Ed25519 JWK with exactly kty, crv, x")
        pub = _b64u_dec(jwk["x"])
        if len(pub) != 32:
            return _no("JWK x is not a 32-byte Ed25519 key")
        raw_sig = _b64u_dec(parts[2])
        if len(raw_sig) != 64:
            return _no("signature is not 64 bytes")
        senza = {k: v for k, v in doc.items() if k != "signature"}
        payload = jcs(senza)
        # trust, decided from the LOCAL registry before the mathematics (so a missing implementation still reports it)
        import audit_bridge as AB
        path = os.path.join(keys_dir or AB.KEYS_DIR, f"fb-{_KID.fullmatch(kid).group(1)}.pub")
        registrata = False
        if os.path.exists(path):
            try:
                registrata = base64.b64decode(open(path).read().strip()) == pub
            except Exception:      # noqa: BLE001 — a corrupt registry file is "not registered", never a crash
                registrata = False
        out["chiave_registrata"] = registrata
        ok = _ed25519_verify(pub, raw_sig, parts[0].encode("ascii") + b"." + payload)
        if ok is None:                                    # no Ed25519 implementation here: NOT verified, never "valid"/"invalid"
            out.update(stato="NON_VERIFICATA", motivo="no Ed25519 implementation available (`cryptography` missing)"); return out
        if not ok:
            return _no("Ed25519 verification failed over JCS(Bundle without signature)")
        out["stato"] = "OK_REGISTRATA" if registrata else "OK_CHIAVE_NON_REGISTRATA"
        return out
    except Exception as e:             # noqa: BLE001 — input from the network: every malformation is a verdict
        return _no(f"{type(e).__name__}: {str(e)[:120]}")

def _no_dup(pairs):
    d = {}
    for k, v in pairs:
        if k in d:
            raise ValueError(f"duplicate key {k!r}")
        d[k] = v
    return d


def _ed25519_verify(pub: bytes, sig: bytes, msg: bytes) -> Optional[bool]:
    """True / False, or None when no Ed25519 implementation is available (same contract as health_verify._ed_verify)."""
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.exceptions import InvalidSignature
    except ImportError:
        return None
    try:
        Ed25519PublicKey.from_public_bytes(pub).verify(sig, msg); return True
    except (InvalidSignature, ValueError):
        return False


def _org(oid_: str, spec: Dict, what: str) -> Dict:
    nome, gln = spec.get("nome"), spec.get("gln")
    if not isinstance(nome, str) or not nome.strip():
        raise ValueError(f"CH EMS: {what}: 'nome' is required")
    if not gln_valida(gln):
        raise ValueError(f"CH EMS: {what}: a 13-digit GLN with a valid check digit is required (got {gln!r})")
    r = {"resourceType": "Organization", "id": oid_, "meta": {"profile": [PROFILE["organization"]]},
         "identifier": [{"system": OID_GLN, "value": gln}], "name": nome.strip()}
    if isinstance(spec.get("indirizzo"), dict):
        r["address"] = [{k: v for k, v in spec["indirizzo"].items() if k in ("line", "city", "postalCode", "country")}]
    return r


def prealert_to_chems_document(prealert_integrato: Dict, vitali: Dict, ts: str, missione: Dict,
                               provenienza_omega: Optional[Dict] = None, stato: str = "preliminary") -> Dict:
    """OMEGA pre-alert → CH EMS document Bundle.

    `missione` (fail-closed: what CH EMS requires must be given, nothing is invented):
      numero_missione (str), sistema_oid ('urn:oid:…' of the dispatch/IMC numbering), organizzazione
      {nome, gln[, indirizzo]} (responding EMS: author + custodian), richiedente {nome, gln} (requesting
      organisation → ServiceRequest.requester), tempi {allarme|partenza|arrivo_sul_posto|arrivo_paziente|
      partenza_dal_posto|arrivo_destinazione|consegna_paziente: ISO 8601} (optional), triage_colore
      rosso|giallo|verde (optional → status priority), destinazione {nome, gln} (optional → handover),
      urgenza sirena|senza_sirena (optional), tipo_missione primaria|secondaria|standby (optional), incidente_id
      (optional, OMEGA event id: letters/digits/._- only, never a person identifier), prealert_id (REQUIRED: opaque
      per-patient token, same charset — it keeps Composition.identifier distinct for each patient of a mission),
      lingua de|fr|it|en.
      `tempi.allarme` is REQUIRED: CHEmsEncounter.period.start is 1..1 and is never defaulted (council 16/09).
      `provenienza_omega` = {ancorato, self_hash} anchors the ledger digest in Provenance.entity; a real signature
      (firma_b64 64-byte Ed25519 over the OMEGA audit record, pubkey_b64, record_sha256) adds the signature material
      as Provenance entities and Composition.attester — never a FHIR Signature, which by definition covers the targets."""
    p = prealert_integrato
    mn, sysoid = missione.get("numero_missione"), missione.get("sistema_oid")
    if not isinstance(mn, str) or not mn.strip():
        raise ValueError("CH EMS: 'numero_missione' (Einsatznummer) is required")
    if not isinstance(sysoid, str) or not re.fullmatch(r"urn:oid:[0-2](\.(0|[1-9]\d*))+", sysoid):
        raise ValueError("CH EMS: 'sistema_oid' must be the numbering OID as 'urn:oid:…'")
    if not _ISO.match(ts or ""):
        raise ValueError("CH EMS: ts must be an ISO 8601 instant with timezone")
    if stato not in ("preliminary", "final", "amended"):
        raise ValueError("CH EMS: stato must be preliminary | final | amended")
    lang = missione.get("lingua", "it")
    if lang not in TITLES:
        raise ValueError("CH EMS: lingua must be de | fr | it | en")
    T, X = TITLES[lang], TEXTS[lang]
    ns = f"chems/{mn.strip()}/{ts}/{stato}/"        # one identifier per document instance (status included)
    urn = lambda rid: "urn:uuid:" + str(uuid.uuid5(uuid.NAMESPACE_URL, "omega-prealert/" + ns + rid))
    ref = lambda rid: {"reference": urn(rid)}

    eta = p.get("eta_paziente")
    paz_id = "anon" if missione.get("paziente") is None else "paziente"  # an identified patient is not "anon" (review Opus r1)
    patient = {"resourceType": "Patient", "id": paz_id, "meta": {"profile": [PROFILE["patient"]]},
               "text": _xhtml(X["patient"].format(age=X["age"].format(eta=eta) if isinstance(eta, int) and not isinstance(eta, bool) else ""))}
    if missione.get("paziente") is not None:
        patient = _paziente_identificato(missione["paziente"], patient)
    soccorso = _org("soccorso", missione.get("organizzazione") or {}, "organizzazione (responding EMS)")
    centrale = _org("centrale", missione.get("richiedente") or {}, "richiedente (requesting organisation)")
    entries: List[Dict] = []

    tempi = missione.get("tempi") or {}
    for k, v in tempi.items():
        if k not in MISSION_TIME_ROLE:
            raise ValueError(f"CH EMS: unknown mission time {k!r}; use {sorted(MISSION_TIME_ROLE)}")
        if not _ISO.match(str(v)):
            raise ValueError(f"CH EMS: mission time {k!r} must be an ISO 8601 instant with timezone")
    if "allarme" not in tempi:
        raise ValueError("CH EMS: tempi.allarme (alarm time) is required — Encounter.period.start is 1..1 and is not invented")
    period = {"start": tempi["allarme"]}
    if "consegna_paziente" in tempi:
        if tempi["consegna_paziente"] < tempi["allarme"] and datetime.fromisoformat(tempi["consegna_paziente"].replace("Z", "+00:00")) < datetime.fromisoformat(tempi["allarme"].replace("Z", "+00:00")):
            raise ValueError("CH EMS: consegna_paziente precedes allarme")
        period["end"] = tempi["consegna_paziente"]
    encounter = {"resourceType": "Encounter", "id": "missione", "meta": {"profile": [PROFILE["encounter"]]},
                 "identifier": [{"type": {"coding": [{"system": CS_IVR, "code": "MN", "display": "Mission number"}]},
                                 "system": sysoid, "value": mn.strip()}],
                 # status: a preliminary document describes a mission still running; class AMB is the IG's own
                 # short ("AMB | IMP", BFS mapping) for a pre-hospital mission — both are the profile's semantics
                 "status": "in-progress" if stato == "preliminary" else "finished",
                 "class": {"system": "http://terminology.hl7.org/CodeSystem/v3-ActCode", "code": "AMB"},
                 "subject": ref(paz_id), "basedOn": [ref("richiesta")], "period": period}
    if missione.get("tipo_missione") is not None:      # never assumed: primary / secondary / stand-by is an input
        if missione["tipo_missione"] not in MISSION_TYPE:
            raise ValueError("CH EMS: tipo_missione must be primaria | secondaria | standby")
        c, d = MISSION_TYPE[missione["tipo_missione"]]
        encounter["serviceType"] = {"coding": [{"system": CS_IVR, "code": c, "display": d}]}
    if missione.get("incidente_id") is not None:
        # CH EMS issue #56 ("Event" field, open): OMEGA's server-issued incident id for multi-patient missions.
        # Shape-guarded: an opaque token, never free text or a person identifier (council 16/09)
        inc = str(missione["incidente_id"])
        if isinstance(missione["incidente_id"], bool) or not _ID_SAFE.match(inc):
            raise ValueError("CH EMS: incidente_id must be an opaque event token (letters, digits, . _ -; max 64)")
        encounter["identifier"].append({"type": {"coding": [{"system": CS_LOCALE, "code": "EVENT", "display": "OMEGA incident (event) id"}]},
                                        "system": CS_LOCALE + "/incident", "value": inc})
    if missione.get("urgenza") is not None:
        if missione["urgenza"] not in URGENCY:
            raise ValueError("CH EMS: urgenza must be sirena | senza_sirena")
        c, d = URGENCY[missione["urgenza"]]
        encounter["priority"] = {"coding": [{"system": CS_IVR, "code": c, "display": d}]}
    # CHEmsServiceRequest.requester is declared with aggregation "contained": the requesting organisation lives
    # INSIDE the ServiceRequest (measured with the HL7 validator 16/09: a bundle-level reference is an error)
    richiesta = {"resourceType": "ServiceRequest", "id": "richiesta", "meta": {"profile": [PROFILE["servicerequest"]]},
                 "text": _xhtml(X["sr"].format(req=centrale["name"])),
                 "contained": [centrale], "status": "active", "intent": "order", "subject": ref(paz_id),
                 "encounter": ref("missione"), "requester": {"reference": "#centrale"}}

    # vitals (OMEGA measures) — every CH EMS observation is bound to the patient AND the mission encounter
    vit_ids: Dict[str, str] = {}
    for k, code in LOINC.items():
        if k in vitali and vitali[k] is not None:
            o = _obs(f"vit-{k}", code, float(vitali[k]), UCUM[k], ts)
            o["subject"], o["encounter"] = ref(paz_id), ref("missione")
            if k == "hr":
                o["meta"] = {"profile": [PROFILE["heartrate"]]}
            elif k == "sbp":   # the CH EMS blood-pressure profile is the LOINC 85354-9 panel (systolic component; diastolic absent)
                sbp = o.pop("valueQuantity")
                o["meta"] = {"profile": [PROFILE["bloodpressure"]]}
                o["code"] = {"coding": [{"system": LOINC_SYS, "code": "85354-9", "display": "Blood pressure panel with all children optional"}]}
                o["component"] = [{"code": {"coding": [{"system": LOINC_SYS, "code": "8480-6", "display": "Systolic blood pressure"}]}, "valueQuantity": sbp},
                                  {"code": {"coding": [{"system": LOINC_SYS, "code": "8462-4", "display": "Diastolic blood pressure"}]},
                                   "dataAbsentReason": {"coding": [{"system": "http://terminology.hl7.org/CodeSystem/data-absent-reason", "code": "not-performed", "display": "Not Performed"}]}}]
            elif k == "spo2":
                o["code"] = {"coding": [{"system": LOINC_SYS, "code": "2708-6", "display": "Oxygen saturation in Arterial blood"},
                                        {"system": LOINC_SYS, "code": "59408-5", "display": "Oxygen saturation in Arterial blood by Pulse oximetry"}]}
                o["meta"] = {"profile": [PROFILE["observation"]]}
            else:
                o["meta"] = {"profile": [PROFILE["observation"]]}
            entries.append(o); vit_ids[k] = f"vit-{k}"
    avpu = None
    if vitali.get("alert_coscienza") is True:   # OMEGA knows only "alert / not alert": V, P, U are not distinguishable → exported only when A
        avpu = {"resourceType": "Observation", "id": "vit-avpu", "meta": {"profile": [PROFILE["avpu"]]}, "status": "final",
                "code": {"coding": [{"system": LOINC_SYS, "code": "11454-6"}]},
                "subject": ref(paz_id), "encounter": ref("missione"), "effectiveDateTime": ts,
                "valueCodeableConcept": {"coding": [{"system": CS_IVR, "code": "A", "display": "wach, ansprechbar und orientiert"}]}}
        entries.append(avpu)

    times: List[Dict] = []
    for k, v in tempi.items():
        c, d = MISSION_TIME_ROLE[k]
        times.append({"resourceType": "Observation", "id": "tempo-" + k.replace("_", "-"), "meta": {"profile": [PROFILE["missiontime"]]}, "status": "final",
                      "code": {"coding": [{"system": CS_IVR, "code": c, "display": d}]}, "subject": ref(paz_id),
                      "encounter": ref("missione"), "effectiveDateTime": v, "valueDateTime": v})
    entries.extend(times)

    priority = None
    if missione.get("triage_colore") is not None:
        if missione["triage_colore"] not in START_TO_SNOMED:
            raise ValueError("CH EMS: triage_colore must be rosso | giallo | verde (SNOMED hospital priority)")
        c, d = START_TO_SNOMED[missione["triage_colore"]]
        priority = {"resourceType": "Observation", "id": "stato-paziente", "meta": {"profile": [PROFILE["statuspriority"]]}, "status": "final",
                    "code": {"coding": [{"system": LOINC_SYS, "code": "77941-3"}]},
                    "subject": ref(paz_id), "encounter": ref("missione"), "effectiveDateTime": ts,
                    "valueCodeableConcept": {"coding": [{"system": SNOMED, "code": c, "display": d}]}}
        entries.append(priority)
    destinazione = None
    if missione.get("destinazione"):
        destinazione = _org("destinazione", missione["destinazione"], "destinazione (receiving hospital)")

    comunicazione = p.get("profilo") == "comunicazione"      # 0.7.0: nessun RiskAssessment senza punteggi calcolati (review Opus 18/09)
    rischio = None if comunicazione else {"resourceType": "RiskAssessment", "id": "prealert", "status": "final", "subject": ref(paz_id),
               "encounter": ref("missione"), "occurrenceDateTime": ts,
               "method": {"coding": [{"system": CS_LOCALE, "code": "news2", "display": "NEWS2 (RCP 2017) + percorsi tempo-dipendenti"}]},
               "basis": [ref(v) for v in vit_ids.values()],
               "prediction": [{"outcome": {"text": f"priorità {p.get('priorita')} · NEWS2 {p.get('NEWS2')}"},
                               "qualitativeRisk": {"coding": [{"system": CS_LOCALE, "code": str(p.get("priorita")).lower()}]}}],
               "note": [{"text": a} for a in ([p.get("azione_raccomandata")] + list(p.get("percorsi_attivare") or [])) if a]}
    flags = [{"resourceType": "Flag", "id": f"avviso-{i}", "status": "active", "code": {"text": a}, "subject": ref(paz_id),
              "encounter": ref("missione")} for i, a in enumerate([] if comunicazione else (p.get("avvisi") or []))]   # nessun Flag in comunicazione
    prov = attester = None
    if provenienza_omega and provenienza_omega.get("firma_b64") is not None and not provenienza_omega.get("ancorato"):
        raise ValueError("CH EMS: a signature without an anchored ledger entry (ancorato=True, self_hash) is refused, not ignored")
    if provenienza_omega and provenienza_omega.get("ancorato"):
        sh = str(provenienza_omega.get("self_hash", ""))
        if not re.fullmatch(r"[0-9a-f]{64}", sh):
            raise ValueError("CH EMS: provenienza_omega.self_hash must be the 64-hex ledger digest")
        # the ANCHOR is an entity (the ledger entry this pre-alert is chained to) — a digest is never a signature
        prov = {"resourceType": "Provenance", "id": "omega-anchor", "target": [ref("composition")] + ([ref("prealert")] if rischio else []), "recorded": ts,
                "agent": [{"type": {"coding": [{"system": "http://terminology.hl7.org/CodeSystem/provenance-participant-type", "code": "author"}]},
                           "who": ref("soccorso")}],
                "entity": [{"role": "source", "what": {"identifier": {"system": CS_LOCALE + "/ledger", "value": sh}}}]}
        firma = provenienza_omega.get("firma_b64")
        if firma is not None:
            # a REAL record-bound signature (FORMAT.md: Ed25519 over the raw SHA-256 of the canonical OMEGA audit
            # record; the signed bytes are that record, not this FHIR JSON — targetFormat says so)
            rs = str(provenienza_omega.get("record_sha256", ""))
            if (_b64_of(firma, 64) is None or _b64_of(provenienza_omega.get("pubkey_b64"), 32) is None
                    or not re.fullmatch(r"[0-9a-f]{64}", rs)):
                raise ValueError("CH EMS: firma_b64 (64-byte Ed25519), pubkey_b64 (32 bytes) and record_sha256 (64 hex) are required together")
            # council r3: FHIR `Provenance.signature` is defined OVER THE TARGETS (this Composition); the OMEGA signature
            # covers the audit record, not this JSON — so it is NOT emitted as a FHIR Signature (that would be the
            # signature-over-something-else antipattern). Record digest, signature and verifying key travel as entities,
            # verifiable with the OMEGA verifiers against the audit ledger; the crew's attestation is Composition.attester.
            prov["entity"].append({"role": "source", "what": {"identifier": {"system": CS_LOCALE + "/audit-record", "value": rs}}})
            prov["entity"].append({"role": "source", "what": {"identifier": {"system": CS_LOCALE + "/audit-record-ed25519-signature", "value": firma}}})
            prov["entity"].append({"role": "source", "what": {"identifier": {"system": CS_LOCALE + "/ed25519-pubkey", "value": provenienza_omega["pubkey_b64"]}}})
            attester = {"mode": "professional", "time": ts, "party": ref("soccorso")}

    def section(key: str, text: str, entry_ids: List[str], sub: Optional[List[Dict]] = None) -> Dict:
        c, d = SECTION_CODE[key]
        s = {"title": T[key], "code": {"coding": [{"system": CS_IVR, "code": c, "display": d}]}, "text": _xhtml(text)}
        if entry_ids:
            s["entry"] = [ref(i) for i in entry_ids]
        if sub:
            s["section"] = sub
        return s
    mission_text = X["mission"].format(mn=mn.strip(), org=soccorso["name"], req=centrale["name"]) + \
        (" · " + X["times"] + ": " + ", ".join(f"{MISSION_TIME_ROLE[k][1]} {v}" for k, v in tempi.items()))
    sections = [section("mission", mission_text, ["missione"] + [t["id"] for t in times])]
    # findings: heart rate / blood pressure in the fixed-title "Circulation" sub-section, AVPU in "Disability";
    # respiratory rate, SpO2 and temperature have NO CH EMS profile (ch-ems-observation-breathing is the SNOMED
    # obstruction finding, not a rate) — they are entries of the findings section itself (open slicing), so a CH EMS
    # reader finds them under findings, not in a comment (council 16/09)
    circ = [vit_ids[k] for k in ("hr", "sbp") if k in vit_ids]
    other = [vit_ids[k] for k in ("rr", "spo2", "temp") if k in vit_ids]
    if circ or avpu or other:
        sub = []
        if circ:
            sub.append({"title": "Circulation", "text": _xhtml(X["circ"]), "entry": [ref(i) for i in circ]})
        if avpu:
            sub.append({"title": "Disability", "text": _xhtml(X["dis"]), "entry": [ref("vit-avpu")]})
        sections.append(section("findings", X["findings"], other, sub))
    hand_ids = ([priority["id"]] if priority else []) + (["destinazione"] if destinazione else [])
    if hand_ids:
        sections.append(section("handover", X["handover"] + (" · " + X["dest"].format(dest=destinazione["name"]) if destinazione else ""), hand_ids))
    ann_ids = ([] if rischio is None else ["prealert"]) + [f["id"] for f in flags] + (["omega-anchor"] if prov else [])
    sections.append({"title": T["annotation"], "code": {"coding": [{"system": LOINC_SYS, "code": "48767-8"}]},   # no display: tx.fhir.org has none per language (fr failed)
                     "text": _xhtml(X["nota_profilo"] if comunicazione else                             # per lingua (review Opus r2)                       # comunicazione: nessun punteggio nel narrativo
                                    X["ann"].format(prio=p.get("priorita"), news=p.get("NEWS2"), avvisi="; ".join(p.get("avvisi") or []) or X["none"],
                                                    percorsi=", ".join(p.get("percorsi_attivare") or []) or X["none"])),
                     **({"entry": [ref(i) for i in ann_ids]} if ann_ids else {})})   # mai "entry": [] (il validator lo rifiuta — review Opus r2)
    # Composition.identifier is the VERSION-INDEPENDENT id (FHIR documents): same mission number + alarm time (normalised to
    # UTC, so +02:00 and Z spell the same instant) + the per-patient `prealert_id` → same value across preliminary/final/
    # amended and across re-exports. NOT seeded with `ts` (the export instant) — Gemini Pro's review of 18/09 caught that —
    # and NOT shared between patients of one multi-patient mission — Opus' review caught that: when `incidente_id` is given
    # the caller MUST also give an opaque `prealert_id`, otherwise two patients of the same mission would get one identifier.
    # Bundle.identifier (below) is per instance (status + ts included).
    pid = missione.get("prealert_id")
    if pid is None or isinstance(pid, bool) or not _ID_SAFE.match(str(pid)):
        # ALWAYS required (Opus review r2, 18/09): mission number + alarm time are per MISSION, and a mission can carry
        # several patients whether or not the caller opened an OMEGA incident — without a per-patient token two
        # patients' documents would look like two versions of one document to an EPR. Nothing is invented.
        raise ValueError("CH EMS: prealert_id (opaque per-patient token: letters, digits, . _ -; max 64) is required — "
                         "it keeps Composition.identifier distinct for each patient of a mission")
    pid = str(pid)
    # tz-aware is enforced above (_ISO) for every mission time; the fraction is normalised to 6 digits because Python 3.9/3.10
    # fromisoformat accepts only 3 or 6 (review r3) — the string written to period.start stays as given
    _alarm_dt = datetime.fromisoformat(_frazione6(tempi["allarme"]))
    _alarm_utc = _alarm_dt.astimezone(timezone.utc).isoformat()
    _comp_seed = f"omega-prealert/chems/{mn.strip()}/{_alarm_utc}/{pid}/composition"
    # CH EMS does not require identifier or confidentiality; CH Core's EPR composition profile does, so both are set.
    # confidentiality: FHIR "N" + the CH Core EPR confidentiality extension (SNOMED 17621005, NO display: tx.fhir.org
    # rejects "Normal" for de-CH — the very error the IG's own examples show).
    composition = {"resourceType": "Composition", "id": "composition", "meta": {"profile": [PROFILE["composition"]]},
                   "identifier": {"system": "urn:ietf:rfc:3986",
                                  "value": "urn:uuid:" + str(uuid.uuid5(uuid.NAMESPACE_URL, _comp_seed))},
                   "language": lang, "status": stato,
                   "confidentiality": "N",
                   "_confidentiality": {"extension": [{"url": "http://fhir.ch/ig/ch-core/StructureDefinition/ch-ext-epr-confidentialitycode",
                                                       "valueCodeableConcept": {"coding": [{"system": "http://snomed.info/sct", "code": "17621005"}]}}]},
                   "type": {"coding": [{"system": LOINC_SYS, "code": "67796-3"}]},
                   "subject": ref(paz_id), "encounter": ref("missione"), "date": ts, "author": [ref("soccorso")],
                   "title": T["doc"], "custodian": ref("soccorso"), "section": sections}
    if attester:
        composition["attester"] = [attester]        # the eCH-0207 use case: the crew "unterzeichnet das Dokument"

    for r in entries + ([rischio] if rischio else []) + flags:   # dom-6 narrative on every resource; observations name their performer
        r.setdefault("text", _xhtml(f"{r['resourceType']} {r['id']} (OMEGA pre-alert, missione {mn.strip()})"))
        if r["resourceType"] == "Observation":
            r.setdefault("performer", [ref("soccorso")])
    composition["text"] = _xhtml(f"{T['doc']} — {mn.strip()} ({stato})", lang)   # the resource declares a language: so must its XHTML
    for r in (patient, soccorso, encounter) + ((destinazione,) if destinazione else ()):
        r.setdefault("text", _xhtml(f"{r['resourceType']} {r['id']} — missione {mn.strip()}"))
    if prov:
        prov.setdefault("text", _xhtml("OMEGA Provenance: hash-chain anchor" + (" + record-bound signature" if attester else "")))
    ordered = [composition, patient, soccorso] + ([destinazione] if destinazione else []) + [encounter, richiesta] + entries + ([rischio] if rischio else []) + flags + ([prov] if prov else [])
    bundle_entries = [{"fullUrl": urn(r["id"]), "resource": r} for r in ordered]
    return {"resourceType": "Bundle", "id": "chems-" + str(uuid.uuid5(uuid.NAMESPACE_URL, "omega-prealert/" + ns)),
            "meta": {"profile": [PROFILE["document"]], "tag": [{"system": CS_LOCALE, "code": "prealert-ambulanza"}]},
            "identifier": {"system": "urn:ietf:rfc:3986", "value": urn("document")},
            "type": "document", "timestamp": ts, "entry": bundle_entries}


_RESTFUL = re.compile(r"^(https?://.+?/)([A-Z][A-Za-z]+/[A-Za-z0-9.\-]{1,64})(/_history/[A-Za-z0-9.\-]+)?$")
_RELATIVE = re.compile(r"^[A-Z][A-Za-z]+/[A-Za-z0-9.\-]{1,64}(/_history/[A-Za-z0-9.\-]+)?$")


def risolvi_riferimento(ref: str, sorgente_fullurl: str, by_url: Dict[str, Dict]) -> Optional[str]:
    """FHIR R4 Bundle resolution (§2.36.4.1), measured on the IG's own examples (16/09: they use absolute RESTful
    fullUrls `http://test.fhir.ch/r4/Patient/x` with RELATIVE references `Patient/x`): an absolute reference must
    equal a fullUrl; a relative one resolves against the BASE of the referencing entry's RESTful fullUrl; a relative
    reference from a `urn:` fullUrl is not resolvable (the spec says so) and a `#id` is a contained resource."""
    if not isinstance(ref, str) or ref.startswith("#"):
        return None
    if ref in by_url:
        return ref
    m = _RESTFUL.match(sorgente_fullurl or "")
    if m and _RELATIVE.match(ref):
        cand = m.group(1) + ref.split("/_history/")[0]
        if cand in by_url:
            return cand
    return None


def raggiungibili_dalla_composition(bundle: Dict) -> Dict[str, bool]:
    """Document rule (FHIR R4 §3.3): every entry should be reachable from the Composition by following references.
    Returns {fullUrl: reachable} — the exporter's own check, independent of the validator."""
    by_url = {e["fullUrl"]: e["resource"] for e in bundle.get("entry", [])}
    seen, todo = set(), [bundle["entry"][0]["fullUrl"]] if bundle.get("entry") else []
    def refs(obj):
        if isinstance(obj, dict):
            if "reference" in obj and isinstance(obj["reference"], str):
                yield obj["reference"]
            for v in obj.values():
                yield from refs(v)
        elif isinstance(obj, list):
            for v in obj:
                yield from refs(v)
    while todo:
        u = todo.pop()
        if u in seen or u not in by_url:
            continue
        seen.add(u)
        for r in refs(by_url[u]):
            t = risolvi_riferimento(r, u, by_url)
            if t:
                todo.append(t)
    return {u: (u in seen) for u in by_url}
