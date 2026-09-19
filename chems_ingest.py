#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""OMEGA — reader + evidence layer for CH EMS documents produced by ANYONE (ch.fhir.ig.ch-ems 2.0.0-ballot).

What it does with a CHEmsDocument coming from any Swiss ePCR (or from `fhir_chems.py`):
  1. `leggi_documento`  — strict load (no duplicate keys), document rules (type `document`, Composition first,
                          every reference resolvable, every entry reachable from the Composition), the profile
                          claims found in `meta.profile`. Fail-closed: a malformed document is refused, not guessed.
  2. `estrai_vitali`    — the vitals CH EMS codes: heart rate LOINC 8867-4, blood-pressure panel 85354-9 (systolic
                          component 8480-6), respiratory rate 9279-1, SpO2 2708-6 / 59408-5, temperature 8310-5,
                          AVPU 11454-6 (IVR A/V/P/U), GCS 9269-2, NACA 88076-5 (IVR 0…VII), cardiac arrest SNOMED
                          410429000, patient status priority 77941-3 (SNOMED colours), IVR mission times, mission
                          number (IVR type MN). Units are checked (UCUM); a value in another unit is NOT converted.
  3. `valuta_documento` — runs the OMEGA scoring engine (`ambulanza_intelligente.valuta_paziente`: NEWS2, pathways,
                          priority) on the extracted vitals and SAYS which inputs were missing or assumed.
  4. `ancora_documento` — evidence: SHA-256 of the exact document bytes, recorded as a signed, hash-chained audit
                          record (`audit_bridge`, same format the four independent verifiers check offline); the
                          audit line carries the digest, the mission number, the IG version and the validator
                          outcome if one was run — never patient data.

HONEST SCOPE: the eCH-0207 use cases say the final protocol is signed by the paramedic and archived in a legally
binding way; the FHIR IG carries no mechanism for that. This module gives a verifiable digest + signature chain
for a document; it does not make the document itself signed by its author (that is `Composition.attester` and the
producer's job), and it is not a legal archive. Drug interactions are not screened here (CH EMS medication lists
are not read yet). Nothing is a medical decision: the physician decides.
"""
from __future__ import annotations
import hashlib
import json
import os
import re
import sys
from datetime import date, datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import fhir_chems as C
from health_verify import loads as loads_strict

LOINC_SYS, SNOMED, CS_IVR = C.LOINC_SYS, C.SNOMED, C.CS_IVR
UCUM = "http://unitsofmeasure.org"
ROLE_BY_CODE = {v[0]: k for k, v in C.MISSION_TIME_ROLE.items()}
START_BY_SNOMED = {v[0]: k for k, v in C.START_TO_SNOMED.items()}


class DocumentoNonValido(ValueError):
    pass


# ── 1. strict reading ────────────────────────────────────────────────────────────────────────────────────────────
def leggi_documento(src) -> Dict[str, Any]:
    """`src` = path, bytes or dict. Returns {bundle, bytes_sha256 (None for a dict), profili, composition,
    per_tipo, avvisi}. Raises DocumentoNonValido on any document-rule violation."""
    raw: Optional[bytes] = None
    if isinstance(src, (bytes, bytearray)):
        raw = bytes(src)
    elif isinstance(src, str):
        with open(src, "rb") as f:
            raw = f.read()
    if raw is not None:
        try:
            bundle = loads_strict(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as e:
            raise DocumentoNonValido(f"JSON non valido o chiavi duplicate: {e}") from e
    elif isinstance(src, dict):
        bundle = src
    else:
        raise DocumentoNonValido("sorgente non supportata (path, bytes o dict)")
    if not isinstance(bundle, dict) or bundle.get("resourceType") != "Bundle":
        raise DocumentoNonValido("non è un Bundle FHIR")
    if bundle.get("type") != "document":
        raise DocumentoNonValido(f"Bundle.type = {bundle.get('type')!r}, atteso 'document'")
    entries = bundle.get("entry")
    if not isinstance(entries, list) or not entries:
        raise DocumentoNonValido("Bundle senza entry")
    by_url: Dict[str, Dict] = {}
    for i, e in enumerate(entries):
        if not isinstance(e, dict) or not isinstance(e.get("resource"), dict) or not isinstance(e.get("fullUrl"), str):
            raise DocumentoNonValido(f"entry {i}: fullUrl o resource mancanti")
        if e["fullUrl"] in by_url:
            raise DocumentoNonValido(f"fullUrl duplicato: {e['fullUrl']}")
        by_url[e["fullUrl"]] = e["resource"]
    comp = entries[0]["resource"]
    if comp.get("resourceType") != "Composition":
        raise DocumentoNonValido("la prima entry di un documento deve essere la Composition")
    # every reference (outside contained resources) must resolve inside the bundle or be a contained '#id'
    def refs(obj, contained_ids):
        if isinstance(obj, dict):
            if "reference" in obj and isinstance(obj["reference"], str):
                yield obj["reference"], contained_ids
            cids = contained_ids | {c.get("id") for c in obj.get("contained", []) if isinstance(c, dict)}
            for k, v in obj.items():
                if k != "reference":
                    yield from refs(v, cids)
        elif isinstance(obj, list):
            for v in obj:
                yield from refs(v, contained_ids)
    for url, res in by_url.items():
        for r, cids in refs(res, frozenset()):
            if r.startswith("#"):
                if r[1:] not in cids:
                    raise DocumentoNonValido(f"{res.get('resourceType')}: riferimento contained {r} non trovato")
            elif C.risolvi_riferimento(r, url, by_url) is None:      # absolute, or relative against a RESTful fullUrl
                raise DocumentoNonValido(f"{res.get('resourceType')}: riferimento non risolvibile {r[:60]}")
    reach = C.raggiungibili_dalla_composition(bundle)
    orfani = [u for u, ok in reach.items() if not ok]
    if orfani:
        raise DocumentoNonValido(f"{len(orfani)} entry non raggiungibili dalla Composition")
    profili = sorted({p for e in entries for p in (e["resource"].get("meta") or {}).get("profile", []) if isinstance(p, str)})
    per_tipo: Dict[str, int] = {}
    for e in entries:
        t = e["resource"].get("resourceType", "?"); per_tipo[t] = per_tipo.get(t, 0) + 1
    avvisi = []
    if raw is None:
        avvisi.append("sorgente dict: chiavi duplicate non verificabili (già collassate dal parser del chiamante); digest sul JSON canonico")
    if C.PROFILE["document"] not in (bundle.get("meta") or {}).get("profile", []):
        avvisi.append("il Bundle non dichiara il profilo CHEmsDocument (letto comunque: la conformità la misura il validatore)")
    # 0.7.3: what the document says about who stands behind it — Composition.attester (who attested, in which mode)
    # and Bundle.signature (a FHIR Signature over the bytes: verified here, four-state verdict, trust from the registry)
    attestazioni = []
    for a in (comp.get("attester") or []) if isinstance(comp.get("attester"), list) else []:
        if isinstance(a, dict):
            party = a.get("party") if isinstance(a.get("party"), dict) else {}
            attestazioni.append({"mode": a.get("mode"), "time": a.get("time"), "party": party.get("reference") or party.get("display")})
    firma = C.verifica_firma_documento(raw if raw is not None else bundle)   # OK_REGISTRATA is the only accepting state
    return {"bundle": bundle, "bytes_sha256": hashlib.sha256(raw).hexdigest() if raw is not None else None,
            "profili": profili, "composition": comp, "per_tipo": per_tipo, "avvisi": avvisi, "_by_url": by_url,
            "attestazioni": attestazioni, "firma": firma}


# ── 2. vitals extraction ─────────────────────────────────────────────────────────────────────────────────────────
def _codes(cc: Any) -> List[Tuple[str, str]]:
    if not isinstance(cc, dict):
        return []
    return [(c.get("system", ""), str(c.get("code", ""))) for c in cc.get("coding", []) if isinstance(c, dict)]


def _has(cc: Any, system: str, code: str) -> bool:
    return (system, code) in _codes(cc)


def _qty(q: Any, units: Tuple[str, ...], what: str, problemi: List[str]) -> Optional[float]:
    """A Quantity is used only if it is a dict with a numeric value, NO comparator, `system` == UCUM explicitly and
    `code` in `units` (council r2: a missing system used to pass as UCUM; `<40` used to read as 40)."""
    if not isinstance(q, dict) or not isinstance(q.get("value"), (int, float)) or isinstance(q.get("value"), bool):
        problemi.append(f"{what}: valore assente o non numerico"); return None
    if q.get("comparator"):
        problemi.append(f"{what}: valore con comparatore {q['comparator']!r} — non è una misura puntuale"); return None
    if q.get("system") != UCUM:
        problemi.append(f"{what}: unità senza system UCUM ({q.get('system')!r}) — non accettata"); return None
    if q.get("code") not in units:
        problemi.append(f"{what}: unità {q.get('code')!r} diversa da {units} — non convertita"); return None
    return float(q["value"])


def _istante(o: Dict, problemi: List[str], what: str) -> Optional[datetime]:
    """effectiveDateTime (or effectivePeriod.end/start) as an AWARE datetime; a value without timezone or a date-only
    value is not usable for ordering (FHIR: a dateTime with a time must carry a timezone)."""
    v = o.get("effectiveDateTime")
    if v is None:
        v = o.get("effectiveInstant")                       # R4 allows an instant too (council r4)
    if v is None and isinstance(o.get("effectivePeriod"), dict):
        v = o["effectivePeriod"].get("end") or o["effectivePeriod"].get("start")
    if not isinstance(v, str):
        return None
    try:
        dt = datetime.fromisoformat(v.replace("Z", "+00:00"))
    except ValueError:
        problemi.append(f"{what}: effective non parsabile {v!r}"); return None
    if "T" not in v:
        problemi.append(f"{what}: effective è una data senza ora {v!r} — non ordinabile"); return None
    if dt.tzinfo is None:
        problemi.append(f"{what}: effective senza fuso orario {v!r}"); return None
    return dt


def _eta(patient: Optional[Dict], at: str, assunzioni: Optional[List[str]] = None) -> Optional[int]:
    """Age at Composition.date from birthDate. Partial dates: YYYY-MM → day 1, YYYY → 1 July (declared)."""
    bd = (patient or {}).get("birthDate")
    if not isinstance(bd, str) or not re.fullmatch(r"\d{4}(-\d{2}(-\d{2})?)?", bd):
        return None
    parts = bd.split("-")
    if len(parts) == 1:
        y, m, d = parts[0], "07", "01"
        if assunzioni is not None: assunzioni.append("birthDate solo anno: età calcolata al 1 luglio")
    elif len(parts) == 2:
        y, m = parts; d = "01"
        if assunzioni is not None: assunzioni.append("birthDate solo anno-mese: età calcolata al giorno 1")
    else:
        y, m, d = parts
    try:
        born = date(int(y), int(m), int(d)); ref = datetime.fromisoformat(at.replace("Z", "+00:00")).date()
    except ValueError:
        return None
    return ref.year - born.year - ((ref.month, ref.day) < (born.month, born.day))


def estrai_vitali(doc: Dict[str, Any]) -> Dict[str, Any]:
    """Vitals and mission facts from a read document (see `leggi_documento`). Returns {vitali, mancanti, problemi,
    missione, gcs, naca, arresto, colore, tempi, eta, ...}. Rules (council r2): only Observations whose `subject`
    resolves to the Composition's subject count (a stray or other-patient observation is skipped and SAID); status
    final|preliminary|amended|corrected only (R4: `corrected` is a child of `amended`); duplicates are resolved on the
    whole set, independently of the Bundle order: the
    single most recent dated observation wins, a tie on the instant or undated-only duplicates give NO value."""
    by_url = doc["_by_url"]; comp = doc["composition"]
    problemi: List[str] = []; assunzioni: List[str] = []
    comp_url = next(u for u, r in by_url.items() if r is comp)
    subj = comp.get("subject"); pat_ref = subj.get("reference") if isinstance(subj, dict) else None   # forma ostile: nessun crash
    pat_url = C.risolvi_riferimento(pat_ref, comp_url, by_url) if isinstance(pat_ref, str) else None
    patient = by_url.get(pat_url) if pat_url else None
    if patient is None or patient.get("resourceType") != "Patient":
        problemi.append("Composition.subject non risolve a un Patient del Bundle (contained o assente): nessuna osservazione attribuibile")
        patient = None; pat_url = None
    # ── two-pass, ORDER-INDEPENDENT selection (council r5: any incremental "keep the latest" rule depends on the
    # Bundle order once undated / tied observations enter). Pass 1 collects every candidate per key; pass 2 chooses:
    # the single most recent dated candidate wins; a tie on the same instant, or two or more candidates with no
    # orderable instant and no dated one, yield NO value (picking by position would be arbitrary) and say so.
    KEYS = {"8867-4": ("hr", "frequenza cardiaca"), "85354-9": ("sbp", "pressione"), "9279-1": ("rr", "frequenza respiratoria"),
            "2708-6": ("spo2", "SpO2"), "59408-5": ("spo2", "SpO2"), "8310-5": ("temp", "temperatura"), "11454-6": ("avpu", "AVPU"),
            "9269-2": ("gcs", "GCS"), "88076-5": ("naca", "NACA"), "77941-3": ("colore", "priorità")}
    cands: Dict[str, List[Tuple[Optional[datetime], str, Dict]]] = {}
    what_of: Dict[str, str] = {}
    obs = [(u, r) for u, r in by_url.items() if r.get("resourceType") == "Observation" and r.get("status") in ("final", "preliminary", "amended", "corrected")]
    scartate = 0
    for u, o in obs:
        s_ref = (o.get("subject") or {}).get("reference")
        if patient is None or not s_ref or C.risolvi_riferimento(s_ref, u, by_url) != pat_url:
            scartate += 1; continue
        code = o.get("code"); key = what = None
        for s, c in _codes(code):
            if s == LOINC_SYS and c in KEYS:
                key, what = KEYS[c]; break
            if s == SNOMED and c == "410429000":
                key, what = "arresto", "arresto cardiaco"; break
            if s == CS_IVR and c in ROLE_BY_CODE:
                key, what = "tempo:" + c, "tempo di missione " + ROLE_BY_CODE[c]; break
        if key is None:
            continue
        what_of[key] = what
        cands.setdefault(key, []).append((_istante(o, problemi, what), str(o.get("id")), o))
    def choose(key: str) -> Optional[Dict]:
        cs = cands[key]; what = what_of[key]
        if len(cs) == 1:
            return cs[0][2]
        dated = [c for c in cs if c[0] is not None]
        if not dated:
            problemi.append(f"{what}: {len(cs)} osservazioni ({', '.join(sorted(c[1] for c in cs))}) senza istante ordinabile — nessun valore usato"); return None
        best = max(c[0] for c in dated); top = [c for c in dated if c[0] == best]
        if len(top) > 1:
            problemi.append(f"{what}: {len(top)} osservazioni ({', '.join(sorted(c[1] for c in top))}) allo stesso istante — nessun valore usato"); return None
        others = sorted(c[1] for c in cs if c is not top[0])
        problemi.append(f"{what}: tenuta {top[0][1]} (più recente); scartate {', '.join(others)}")
        return top[0][2]
    vit: Dict[str, Any] = {}
    slots: Dict[str, Any] = {}
    for key in sorted(cands):
        o = choose(key)
        if o is None:
            continue
        if key == "hr":
            v = _qty(o.get("valueQuantity"), ("/min",), "frequenza cardiaca", problemi)
            if v is not None: vit["hr"] = v
        elif key == "sbp":
            comps = o.get("component") if isinstance(o.get("component"), list) else []
            syst = [comp_ for comp_ in comps if isinstance(comp_, dict) and _has(comp_.get("code"), LOINC_SYS, "8480-6")]
            if len(syst) == 1:
                v = _qty(syst[0].get("valueQuantity"), ("mm[Hg]",), "pressione sistolica", problemi)
                if v is not None: vit["sbp"] = v
            else:                         # none or several systolic components: malformed panel, no value (council r7)
                problemi.append(f"pressione: {len(syst)} componenti sistoliche nel pannello — nessun valore usato")
        elif key == "rr":
            v = _qty(o.get("valueQuantity"), ("/min",), "frequenza respiratoria", problemi)
            if v is not None: vit["rr"] = v
        elif key == "spo2":
            v = _qty(o.get("valueQuantity"), ("%",), "SpO2", problemi)
            if v is not None: vit["spo2"] = v
        elif key == "temp":
            v = _qty(o.get("valueQuantity"), ("Cel",), "temperatura", problemi)
            if v is not None: vit["temp"] = v
        elif key == "avpu":
            avpu = [c for s, c in _codes(o.get("valueCodeableConcept")) if s == CS_IVR and c in ("A", "V", "P", "U")]
            if avpu:                      # first MAPPED coding, whatever comes before it (council r6)
                vit["alert_coscienza"] = avpu[0] == "A"; vit["avpu"] = avpu[0]
            else:
                problemi.append("AVPU: nessun valore del value set IVR nel valueCodeableConcept")
        elif key == "gcs":
            if isinstance(o.get("valueInteger"), int) and not isinstance(o.get("valueInteger"), bool):
                v = float(o["valueInteger"])
            else:
                v = _qty(o.get("valueQuantity"), ("{score}", "1"), "GCS", problemi)
            if v is not None and 3 <= v <= 15 and v == int(v): slots["gcs"] = int(v)
            elif v is not None: problemi.append("GCS fuori intervallo 3-15 o non intero")
        elif key == "naca":
            n = [c for s, c in _codes(o.get("valueCodeableConcept")) if s == CS_IVR and c in ("0", "I", "II", "III", "IV", "V", "VI", "VII")]
            if n: slots["naca"] = n[0]
            else: problemi.append("NACA: nessun valore del value set IVR nel valueCodeableConcept")
        elif key == "arresto":
            if isinstance(o.get("valueBoolean"), bool): slots["arresto"] = o["valueBoolean"]
            else: problemi.append("arresto cardiaco: valore non booleano — ignorato")
        elif key == "colore":
            col = [START_BY_SNOMED[c] for s, c in _codes(o.get("valueCodeableConcept")) if s == SNOMED and c in START_BY_SNOMED]
            if col: slots["colore"] = col[0]
            else: problemi.append("priorità: nessun colore SNOMED del value set IVR nel valueCodeableConcept")
        elif key.startswith("tempo:"):
            if isinstance(o.get("valueDateTime"), str): slots[key] = o["valueDateTime"]
            else: problemi.append(f"{what_of[key]}: senza valueDateTime — ignorato")
    gcs, naca, arresto, colore = slots.get("gcs"), slots.get("naca"), slots.get("arresto"), slots.get("colore")
    tempi = {ROLE_BY_CODE[k[6:]]: v for k, v in slots.items() if k.startswith("tempo:")}
    if scartate:
        problemi.append(f"{scartate} osservazioni non attribuite al soggetto della Composition: ignorate")
    if "alert_coscienza" not in vit and gcs is not None:
        vit["alert_coscienza"] = gcs == 15; assunzioni.append("coscienza derivata dal GCS (15 = Alert): AVPU assente")
    enc = None
    enco = comp.get("encounter"); enc_ref = enco.get("reference") if isinstance(enco, dict) else None   # forma ostile: nessun crash
    if isinstance(enc_ref, str) and enc_ref:   # Composition.encounter given: it must resolve to an Encounter, no fallback (council r8)
        enc_url = C.risolvi_riferimento(enc_ref, comp_url, by_url)
        target = by_url.get(enc_url) if enc_url else None
        if target is not None and target.get("resourceType") == "Encounter":
            enc = target
        else:
            problemi.append("missione: Composition.encounter non risolve a un Encounter del Bundle — numero di missione non attribuibile")
    else:                                 # no Composition.encounter (0..1 in the IG): use the Encounter only if it is unique
        encs = [r for r in by_url.values() if r.get("resourceType") == "Encounter"]
        if len(encs) == 1:
            enc = encs[0]
        elif encs:
            problemi.append(f"missione: {len(encs)} Encounter e nessun Composition.encounter — numero di missione non attribuibile")
    if enc is not None:                   # the Encounter must be the Composition subject's (council r9), like every Observation
        enc_url_ = next(u for u, r in by_url.items() if r is enc)
        e_ref = (enc.get("subject") or {}).get("reference")
        if not e_ref or pat_url is None or C.risolvi_riferimento(e_ref, enc_url_, by_url) != pat_url:
            problemi.append("missione: Encounter.subject non è il soggetto della Composition — numero di missione non attribuibile"); enc = None
    missione: Dict[str, Any] = {}
    ids = (enc or {}).get("identifier")
    mn = {}; ev = {}
    for idn in ids if isinstance(ids, list) else []:
        if not isinstance(idn, dict):
            continue
        is_mn, is_ev = _has(idn.get("type"), CS_IVR, "MN"), _has(idn.get("type"), C.CS_LOCALE, "EVENT")
        if not (is_mn or is_ev):
            continue
        if not isinstance(idn.get("value"), str) or not idn["value"]:     # Identifier.value is 0..1: absent = unusable, said
            problemi.append(f"missione: identificatore {'MN' if is_mn else 'EVENT'} senza value — ignorato"); continue
        (mn if is_mn else ev)[(idn.get("system"), idn["value"])] = True
    if len(mn) == 1:                      # several MN identifiers with different (system, value): no number, said (council r8)
        (missione["sistema"], missione["numero"]), = mn.keys()
    elif mn:
        problemi.append(f"missione: {len(mn)} identificatori MN diversi sull'Encounter — numero di missione non attribuibile")
    if len(ev) == 1:
        missione["evento"] = next(iter(ev))[1]
    elif ev:
        problemi.append(f"missione: {len(ev)} identificatori EVENT diversi — evento non attribuibile")
    eta = _eta(patient, str(comp.get("date") or ""), assunzioni)
    mancanti = [k for k in ("rr", "spo2", "sbp", "hr", "temp", "alert_coscienza") if k not in vit]
    problemi = sorted(set(problemi))                     # deterministic, order-independent (council r6)
    return {"vitali": vit, "mancanti": mancanti, "problemi": problemi, "assunzioni": assunzioni, "missione": missione, "gcs": gcs,
            "naca": naca, "arresto": arresto, "colore": colore, "tempi": tempi, "eta": eta,
            "stato_documento": comp.get("status"), "data_documento": comp.get("date")}


# ── 3. scoring on someone else's document ────────────────────────────────────────────────────────────────────────
def estrai_farmaci(doc: Dict[str, Any]) -> Dict[str, Any]:
    """Farmaci del SOGGETTO della Composition da MedicationStatement (terapia in corso: status active) e
    MedicationAdministration (somministrati in missione: status completed/in-progress), risolvendo
    medicationReference → Medication contenuta o del Bundle. Ritorna il nome come scritto (display del GTIN o
    text), la classe riconosciuta o None, e l'elenco dei NON riconosciuti: il motore interazioni lavora solo su
    ciò che riconosce e lo dice (0.7.0)."""
    import interazioni_farmaci as IF
    by_url, comp = doc["_by_url"], doc["composition"]
    comp_url = next(u for u, r in by_url.items() if r is comp)
    subj = comp.get("subject"); pat_ref = subj.get("reference") if isinstance(subj, dict) else None
    pat_url = C.risolvi_riferimento(pat_ref, comp_url, by_url) if isinstance(pat_ref, str) else None
    enco = comp.get("encounter"); enc_ref = enco.get("reference") if isinstance(enco, dict) else None
    enc_url = C.risolvi_riferimento(enc_ref, comp_url, by_url) if isinstance(enc_ref, str) else None
    out: List[Dict[str, Any]] = []; scartati: List[Dict[str, str]] = []
    for u, r in by_url.items():
        rt = r.get("resourceType")
        if rt not in ("MedicationStatement", "MedicationAdministration"):
            continue
        rid = f"{rt}/{r.get('id')}"
        ok_status = (rt == "MedicationStatement" and r.get("status") == "active") or \
                    (rt == "MedicationAdministration" and r.get("status") in ("completed", "in-progress"))
        subj = r.get("subject"); s_ref = subj.get("reference") if isinstance(subj, dict) else None   # JSON di terzi: mai .get su non-dict (review Opus r2)
        if not ok_status:                                      # gli scarti sono NOMINATI, non solo contati (review Opus 18/09)
            scartati.append({"risorsa": rid, "motivo": f"status {r.get('status')!r} non considerato"}); continue
        if pat_url is None or not isinstance(s_ref, str) or C.risolvi_riferimento(s_ref, u, by_url) != pat_url:
            scartati.append({"risorsa": rid, "motivo": "soggetto diverso dalla Composition o non risolvibile"}); continue
        ctxo = r.get("context") if rt == "MedicationAdministration" else None
        ctx = ctxo.get("reference") if isinstance(ctxo, dict) else None
        contesto = "non dichiarato"
        if enc_url and isinstance(ctx, str):
            if C.risolvi_riferimento(ctx, u, by_url) != enc_url:
                scartati.append({"risorsa": rid, "motivo": "somministrazione di un altro encounter"}); continue   # review Sonnet 18/09
            contesto = "encounter della Composition"
        cc = r.get("medicationCodeableConcept")
        if not isinstance(cc, dict) and isinstance(r.get("medicationReference"), dict):
            ref = r["medicationReference"].get("reference") or ""
            med = None
            if isinstance(ref, str) and ref.startswith("#"):
                med = next((c for c in (r.get("contained") or []) if isinstance(c, dict) and c.get("resourceType") == "Medication" and c.get("id") == ref[1:]), None)
            elif isinstance(ref, str):
                mu = C.risolvi_riferimento(ref, u, by_url); med = by_url.get(mu) if mu else None
            else:
                med = None
            cc = (med or {}).get("code") if isinstance(med, dict) else None
        nome = None; gtin = None
        if isinstance(cc, dict):                          # JSON di terzi: coding può essere null o contenere scalari (review Gemini 18/09)
            coding = [c for c in (cc.get("coding") or []) if isinstance(c, dict)] if isinstance(cc.get("coding"), list) else []
            nome = next((c.get("display") for c in coding if isinstance(c.get("display"), str)), None) or (cc.get("text") if isinstance(cc.get("text"), str) else None)
            gtin = next((c.get("code") for c in coding if c.get("system") in IF.GTIN_SYSTEMS and isinstance(c.get("code"), str)), None)
        if not nome and not gtin:
            scartati.append({"risorsa": rid, "motivo": "medicinale senza nome né codice"}); continue
        # 1) GTIN → ATC (Swissmedic, dato ufficiale) → classe; 2) se il GTIN è ignoto, nome commerciale; 3) altrimenti
        # dichiarato non riconosciuto. Un ATC ufficiale «fuori tabella» NON viene scavalcato dal nome (review Opus 18/09).
        classi, atc, da = None, None, None
        if gtin:
            hit = IF.riconosci_gtin(gtin)
            if hit:
                classi, atc = hit; da = "gtin-swissmedic" if classi else None
        if not classi and not atc and nome:
            c = IF.riconosci_commerciale(nome)
            if c:
                classi, da = c, "nome-commerciale"
        out.append({"nome": str(nome or gtin)[:80], "gtin": gtin, "atc": atc, "origine": rt,
                    **({"contesto": contesto} if rt == "MedicationAdministration" else {}),   # dichiarato, non presunto (review Sonnet r2)
                    "classi": sorted(classi) if classi else None, "riconosciuto_da": da})
    return {"farmaci": out, "riconosciuti": [f for f in out if f["classi"]],
            "non_riconosciuti": [f["nome"] + (f" (ATC {f['atc']}: fuori dalla tabella interazioni)" if f["atc"] else "") for f in out if not f["classi"]],
            "scartati": scartati,
            "fonte_gtin": (IF._gtin_atc().get("_provenienza") or {}).get("stand")}


def interazioni_documento(doc: Dict[str, Any]) -> Dict[str, Any]:
    """Interazioni gravi note fra i farmaci RICONOSCIUTI del documento; i non riconosciuti sono elencati, non
    ignorati in silenzio. Informativo: il medico decide."""
    import interazioni_farmaci as IF
    f = estrai_farmaci(doc)
    res = IF.controlla_classi([(x["nome"], set(x["classi"])) for x in f["riconosciuti"]]) if len(f["riconosciuti"]) >= 2 else \
        {"n_farmaci": len(f["riconosciuti"]), "interazioni_note_trovate": [], "nessun_allarme": True, "honest_scope": IF._DISCLAIMER}
    res.pop("privacy", None)                              # frase scritta per l'input libero, non per questo percorso (review Opus r2)
    err = (IF._gtin_atc().get("_provenienza") or {}).get("errore")
    if not f["farmaci"] and f["scartati"]:
        nota = f"nessun farmaco valutato: {len(f['scartati'])} risorse scartate (vedi scartati)"
    elif not f["farmaci"]:
        nota = "nessun farmaco nel documento"
    elif f["non_riconosciuti"]:
        nota = ("controllo solo sui farmaci riconosciuti (GTIN ufficiale Swissmedic o nome commerciale); "
                f"{len(f['non_riconosciuti'])} non riconosciuti NON sono stati valutati")
    else:
        nota = "tutti i farmaci letti sono stati valutati (GTIN ufficiale Swissmedic o nome commerciale)"
    if err:                                                # modulo dati Swissmedic non caricato: detto, non taciuto (review Opus r3)
        nota += f"; ATTENZIONE: tabella GTIN Swissmedic non caricata ({err}): riconoscimento solo per nome"
    return {**res, "farmaci_letti": f["farmaci"], "non_riconosciuti": f["non_riconosciuti"], "scartati": f["scartati"], "nota": nota,
            **({"fonte_gtin_errore": err} if err else {})}


def valuta_documento(doc: Dict[str, Any], eta_arrivo_min: int = 0, eta: Optional[int] = None) -> Dict[str, Any]:
    """OMEGA scores computed from the document's own vitals. `assunzioni` lists every input the engine needed and
    the document did not carry (supplemental O2 is not a CH EMS observation: assumed absent and SAID). The engine
    REQUIRES the age (paediatric gate): an anonymous document without birthDate is scored only if the caller passes
    `eta` (e.g. from the radio call); otherwise the result is NON_VALUTABILE with the reason, never a guess."""
    import ambulanza_intelligente as A
    ex = estrai_vitali(doc)
    vit = {k: v for k, v in ex["vitali"].items() if k != "avpu"}; assunzioni = list(ex["assunzioni"])
    limite_inferiore = False
    if "su_ossigeno" not in vit:
        # NEWS2 adds 2 for supplemental oxygen; CH EMS has no such observation → the score is a LOWER BOUND, said as such
        vit["su_ossigeno"] = False; assunzioni.append("su_ossigeno=False (CH EMS non porta l'ossigeno supplementare): NEWS2 è un limite inferiore"); limite_inferiore = True
    eta_usata = ex["eta"] if ex["eta"] is not None else eta
    motivi: List[str] = []                        # ALL blocking reasons, never one overwriting another (council r3)
    if "alert_coscienza" not in vit:
        # never assumed in the unsafe direction (council r2): without AVPU or GCS the document is not scorable
        motivi.append("coscienza assente (né AVPU né GCS nel documento): non si assume Alert")
    if ex["eta"] is None and eta is not None:
        assunzioni.append(f"età {eta} fornita dal chiamante (Patient senza birthDate)")
    elif ex["eta"] is None:
        motivi.append("età assente (Patient anonimo senza birthDate e nessuna età fornita): il motore non valuta senza gate pediatrico")
    core = [k for k in ("rr", "spo2", "sbp", "hr", "temp") if k in ex["mancanti"]]
    if core:      # a CH EMS protocol may simply not carry the NEWS2 inputs (measured on the IG's own examples)
        motivi.append("vitali NEWS2 mancanti nel documento: " + ", ".join(core))
    motivo = "; ".join(motivi) if motivi else None
    if motivo is not None:
        return {"estratto": {k: v for k, v in ex.items() if k != "vitali"}, "vitali_usati": vit, "assunzioni": assunzioni,
                "valutabile": False, "motivo_non_valutabile": motivo, "PRE_ALERT_INTEGRATO": {}, "problemi_dati": None,
                "news2_limite_inferiore": limite_inferiore, "nota": "documento non valutabile: nessun punteggio calcolato",
                "interazioni_farmaci": interazioni_documento(doc)}
    out = A.valuta_paziente(vit, [], eta_usata, eta_arrivo_min)
    pa = out.get("PRE_ALERT_INTEGRATO") or {}
    valutabile = pa.get("priorita") not in (None, "NON_VALUTABILE_DATI_INVALIDI", "NON_VALUTABILE_PEDIATRICO")
    return {"estratto": {k: v for k, v in ex.items() if k != "vitali"}, "vitali_usati": vit, "assunzioni": assunzioni,
            "valutabile": valutabile,
            "motivo_non_valutabile": None if valutabile else str(out.get("problemi_dati") or pa.get("priorita")),
            "PRE_ALERT_INTEGRATO": pa, "problemi_dati": out.get("problemi_dati"), "news2_limite_inferiore": limite_inferiore,
            "nota": "punteggi calcolati dal documento CH EMS ricevuto; il medico decide",
            "interazioni_farmaci": interazioni_documento(doc)}


# ── 4. evidence ──────────────────────────────────────────────────────────────────────────────────────────────────
def ancora_documento(src, operatore: str, validazione: Optional[Dict] = None, identita: str = "dichiarata") -> Dict[str, Any]:
    """Signed, hash-chained audit record of the document's SHA-256 (exact bytes when `src` is a path/bytes; the
    canonical ASCII JSON otherwise). Never patient data: digest, mission number, IG version, validator counts."""
    import audit_bridge as AB
    doc = leggi_documento(src)
    if doc["bytes_sha256"]:
        digest, base = doc["bytes_sha256"], "bytes"
    else:
        canon = json.dumps(doc["bundle"], sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()
        digest, base = hashlib.sha256(canon).hexdigest(), "canonical-ascii-json"
    ex = estrai_vitali(doc)
    orig = str(ex["missione"].get("numero") or "")
    num = re.sub(r"[^A-Za-z0-9_-]", "-", orig)[:32]        # stringa di terzi: charset e lunghezza limitati; il suffisso hash rende
    suff = hashlib.sha256(orig.encode("utf-8")).hexdigest()[:8]   # distinti numeri diversi che collassano uguali (review Sonnet r2)
    target = f"chems/{num}-{suff}" if num else f"chems/{digest[:16]}"
    STATI = ("preliminary", "final", "amended", "entered-in-error")
    stato_doc = ex["stato_documento"] if ex["stato_documento"] in STATI else "non-valido"   # solo il value set FHIR nel ledger (review Opus r2)
    dettaglio: Dict[str, Any] = {"doc_sha256": digest, "digest_di": base, "ig": f"ch.fhir.ig.ch-ems#{C.IG_VERSION}",
                                 "stato_documento": stato_doc, "missione_numero": (f"{num}-{suff}" if num else ""),   # forma sanificata, mai la stringa grezza (review Opus r2)
                                 "entries": sum(doc["per_tipo"].values()),
                                 "identita": identita}       # autenticata (token operatore) o dichiarata: nel record FIRMATO (review Opus r3)
    if validazione and validazione.get("ran"):
        dettaglio["validator_errori"] = int(len(validazione.get("errors", [])))
        dettaglio["validator_warning"] = int(len(validazione.get("warnings", [])))
    rec = AB.registra_evento_clinico(target, "ingest_chems", dettaglio, operatore)
    return {"doc_sha256": digest, "digest_di": base, "target": target, "audit": rec}


def main(argv=None) -> int:
    import argparse
    ap = argparse.ArgumentParser(description="read / score / anchor a CH EMS document")
    ap.add_argument("doc"); ap.add_argument("--validate", action="store_true", help="run the official validator (chems_validate)")
    ap.add_argument("--anchor", metavar="OPERATORE", help="record a signed audit line with the document digest")
    ap.add_argument("--eta-arrivo-min", type=int, default=0)
    ap.add_argument("--eta", type=int, help="patient age when the document is anonymous (the engine needs it)")
    a = ap.parse_args(argv)
    if a.anchor:
        AB.esigi_firma_o_optin("chems_ingest --anchor")   # fail-closed (0.6.1): say it before reading, not at the end
    raw = open(a.doc, "rb").read()                 # read ONCE: scoring, validation and anchor see the same bytes
    doc = leggi_documento(raw)
    out: Dict[str, Any] = {"letto": {k: v for k, v in doc.items() if k in ("bytes_sha256", "profili", "per_tipo", "avvisi")}}
    out["valutazione"] = valuta_documento(doc, a.eta_arrivo_min, a.eta)
    val = None
    if a.validate:
        import chems_validate as V
        import tempfile
        with tempfile.NamedTemporaryFile("wb", suffix=".json", delete=False) as fh:
            fh.write(raw); snap = fh.name
        try:
            val = V.validate(snap, "chems_validation.json")
        finally:
            os.unlink(snap)
        out["validator"] = {k: v for k, v in val.items() if k != "warnings"}
    if a.anchor:
        out["ancora"] = ancora_documento(raw, a.anchor, val)
    print(json.dumps(out, ensure_ascii=False, indent=1, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())
