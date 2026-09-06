#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""OMEGA — export FHIR R4 del pre-alert + handover ATMIST + allegato ECG (provenienza).

PERCHÉ (competitor mondiali, ricerca 2026-09-06): Pulsara/ESO/ImageTrend vincono
sull'INTEGRAZIONE (EMS↔EHR↔registri). Lo standard con cui il mondo si integra è
HL7 FHIR, e in Europa è il futuro DATATO: regolamento EHDS in vigore dal
26/03/2025, scambio primario dei dati sanitari in applicazione da marzo 2029
(fonte: health.ec.europa.eu). Un pre-alert esportabile in FHIR oggi = un sistema
che nel 2029 parla con gli ospedali senza riscritture.

COSA FA:
  • prealert_to_fhir() — il pre-alert integrato → Bundle FHIR R4 (collection):
    Observations dei vitali con codici LOINC ufficiali, RiskAssessment
    (NEWS2/priorità/percorsi), Flag per gli avvisi (⛔ nitrati, ⚠️ anticoagulato),
    Provenance col hash del ledger OMEGA → la provenienza hash-chained viaggia
    DENTRO lo standard, non accanto.
  • atmist() — handover pre-ospedaliero strutturato ATMIST (Age, Time, Mechanism,
    Injuries, Signs, Treatment): il formato di consegna che i PS conoscono.
  • allega_ecg() — allegato ECG 12 derivazioni come DocumentReference con SHA-256
    del file: il tracciato viaggia col pre-alert, INTATTO e verificabile.

ONESTO: il paziente nel Bundle è ANONIMO (età sola, niente nome/ID — il
collegamento identità avviene in ospedale nel flusso di cura); i codici LOINC
sono usati solo dove CERTI (vitali standard), gli score usano un CodeSystem
locale dichiarato (niente codici inventati); l'ECG è allegato con hash, MAI
interpretato automaticamente (nessuna pretesa di lettura STEMI algoritmica).
Profilo target: FHIR R4 base — la profilazione IPS/EHDS fine è lavoro del pilota.
"""
from __future__ import annotations
import hashlib
import json
import os
import re
from typing import Dict, List, Optional
import uuid

FHIR_VERSION = "4.0.1"

def _urn(rid: str) -> str:
    """fullUrl deterministico per la risorsa (richiesto dal validatore FHIR per
    ogni entry di un Bundle non-transaction; i riferimenti interni usano l'URN)."""
    return "urn:uuid:" + str(uuid.uuid5(uuid.NAMESPACE_URL, "omega-prealert/" + rid))
CS_LOCALE = "https://omega.example/fhir/CodeSystem/prealert"   # dichiarato, non finto LOINC

# LOINC ufficiali dei segni vitali (usati solo dove la corrispondenza è certa)
LOINC = {
    "rr":   ("9279-1",  "Respiratory rate"),
    "hr":   ("8867-4",  "Heart rate"),
    "sbp":  ("8480-6",  "Systolic blood pressure"),
    "spo2": ("59408-5", "Oxygen saturation in Arterial blood by Pulse oximetry"),
    "temp": ("8310-5",  "Body temperature"),
}
UCUM = {"rr": "/min", "hr": "/min", "sbp": "mm[Hg]", "spo2": "%", "temp": "Cel"}


def _obs(oid: str, code: tuple, value: float, unit: str, ts: str) -> Dict:
    return {"resourceType": "Observation", "id": oid, "status": "final",
            "category": [{"coding": [{"system": "http://terminology.hl7.org/CodeSystem/observation-category",
                                      "code": "vital-signs"}]}],
            "code": {"coding": [{"system": "http://loinc.org", "code": code[0], "display": code[1]}]},
            "subject": {"reference": _urn("anon")},
            "effectiveDateTime": ts,
            "valueQuantity": {"value": value, "unit": unit,
                              "system": "http://unitsofmeasure.org", "code": unit}}


def prealert_to_fhir(prealert_integrato: Dict, vitali: Dict, ts: str,
                     provenienza_omega: Optional[Dict] = None) -> Dict:
    """Pre-alert integrato (ambulanza_intelligente) → Bundle FHIR R4 anonimo."""
    p = prealert_integrato
    entries: List[Dict] = [{"resource": {
        "resourceType": "Patient", "id": "anon",
        "text": {"status": "generated",
                 "div": f"<div xmlns=\"http://www.w3.org/1999/xhtml\">pre-alert anonimo, età {p.get('eta_paziente')}</div>"}}}]
    for k, code in LOINC.items():
        if k in vitali and vitali[k] is not None:
            entries.append({"resource": _obs(f"vit-{k}", code, float(vitali[k]), UCUM[k], ts)})
    # coscienza (AVPU collassato) e ossigeno: CodeSystem locale dichiarato
    entries.append({"resource": {
        "resourceType": "Observation", "id": "vit-coscienza", "status": "final",
        "code": {"coding": [{"system": CS_LOCALE, "code": "avpu-alert",
                             "display": "paziente Alert (AVPU)"}]},
        "subject": {"reference": _urn("anon")}, "effectiveDateTime": ts,
        "valueBoolean": bool(vitali.get("alert_coscienza"))}})
    entries.append({"resource": {
        "resourceType": "Observation", "id": "vit-o2", "status": "final",
        "code": {"coding": [{"system": CS_LOCALE, "code": "o2-suppl",
                             "display": "ossigeno supplementare"}]},
        "subject": {"reference": _urn("anon")}, "effectiveDateTime": ts,
        "valueBoolean": bool(vitali.get("su_ossigeno"))}})
    rischio = {"resourceType": "RiskAssessment", "id": "prealert", "status": "final",
               "subject": {"reference": _urn("anon")}, "occurrenceDateTime": ts,
               "method": {"coding": [{"system": CS_LOCALE, "code": "news2",
                                      "display": "NEWS2 (RCP 2017) + percorsi tempo-dipendenti"}]},
               "basis": [{"reference": _urn(f"vit-{k}")} for k in LOINC if k in vitali],
               "prediction": [{"outcome": {"text": f"priorità {p.get('priorita')} · NEWS2 {p.get('NEWS2')}"},
                               "qualitativeRisk": {"coding": [{"system": CS_LOCALE,
                                                               "code": str(p.get("priorita")).lower()}]}}],
               "note": [{"text": a} for a in ([p.get("azione_raccomandata")] +
                                              list(p.get("percorsi_attivare") or [])) if a]}
    entries.append({"resource": rischio})
    for i, avviso in enumerate(p.get("avvisi") or []):
        entries.append({"resource": {"resourceType": "Flag", "id": f"avviso-{i}",
                                     "status": "active",
                                     "code": {"text": avviso},
                                     "subject": {"reference": _urn("anon")}}})
    if provenienza_omega and provenienza_omega.get("ancorato"):
        entries.append({"resource": {
            "resourceType": "Provenance", "id": "omega-anchor",
            "target": [{"reference": _urn("prealert")}],
            "recorded": ts,
            "agent": [{"who": {"display": "OMEGA prealert ledger (hash-chained, append-only)"}}],
            "signature": [{"type": [{"system": CS_LOCALE, "code": "sha256-chain"}],
                           "when": ts, "who": {"display": "OMEGA ledger"},
                           "data": provenienza_omega.get("self_hash", "")}]}})
    for e in entries:
        e["fullUrl"] = _urn(e["resource"]["id"])
    return {"resourceType": "Bundle", "type": "collection",
            "meta": {"tag": [{"system": CS_LOCALE, "code": "prealert-ambulanza"}]},
            "timestamp": ts, "entry": entries}


def atmist(eta: Optional[int], orario_evento: str, meccanismo_o_esordio: str,
           lesioni_o_problema: str, prealert_integrato: Dict,
           trattamenti: List[str]) -> Dict:
    """Handover ATMIST — il formato standard di consegna pre-ospedaliera che i
    PS già conoscono (Age, Time, Mechanism, Injuries, Signs, Treatment)."""
    p = prealert_integrato
    segni = (f"priorità {p.get('priorita')} · NEWS2 {p.get('NEWS2')} · "
             f"qSOFA {p.get('qSOFA')} · BE-FAST {p.get('BE_FAST')}")
    st = {"A_eta": eta, "T_orario_evento": orario_evento,
          "M_meccanismo_esordio": meccanismo_o_esordio,
          "I_lesioni_problema": lesioni_o_problema,
          "S_segni": segni, "T_trattamenti": trattamenti,
          "avvisi": p.get("avvisi") or [], "percorsi": p.get("percorsi_attivare") or []}
    testo = (f"ATMIST — A: {eta} anni · T: {orario_evento} · M: {meccanismo_o_esordio} · "
             f"I: {lesioni_o_problema} · S: {segni} · T: {', '.join(trattamenti) or 'nessuno'}")
    return {"ATMIST": st, "testo_consegna": testo}


def allega_ecg(path_ecg: str, ts: str) -> Dict:
    """Allega un ECG (pdf/immagine/xml del monitor) con SHA-256: il tracciato
    viaggia col pre-alert VERIFICABILE. Nessuna interpretazione automatica —
    la lettura resta a chi la sa fare (l'onestà qui è il confine)."""
    if not os.path.isfile(path_ecg):
        return {"allegato": False, "errore": "file ECG inesistente"}
    raw = open(path_ecg, "rb").read()
    sha = hashlib.sha256(raw).hexdigest()
    return {"allegato": True, "sha256": sha, "bytes": len(raw),
            "document_reference": {
                "resourceType": "DocumentReference", "id": "ecg-12d",
                "status": "current",
                "description": "ECG pre-ospedaliero (allegato, NON interpretato automaticamente)",
                "content": [{"attachment": {"title": os.path.basename(path_ecg),
                                            "hash": sha, "size": len(raw)}}]}}


# ── banco che SA FALLIRE ──────────────────────────────────────────────────────
def banco_controllo() -> Dict:
    import ambulanza_intelligente as A
    vit = dict(rr=28, spo2=89, su_ossigeno=True, sbp=85, hr=135,
               alert_coscienza=False, temp=39.4)
    out = A.valuta_paziente(vit, ["warfarin", "aspirina"], 67, 8)
    ts = "2026-09-06T12:00:00Z"
    b = prealert_to_fhir(out["PRE_ALERT_INTEGRATO"], vit, ts,
                         provenienza_omega={"ancorato": True, "self_hash": "ab" * 32})
    tipi = [e["resource"]["resourceType"] for e in b["entry"]]
    blob = json.dumps(b, ensure_ascii=False)
    loinc_ok = all(code in blob for code, _ in LOINC.values())
    fulls = {e.get("fullUrl") for e in b["entry"]}
    refs = set(re.findall(r'"reference": "(urn:uuid:[0-9a-f-]+)"', blob))
    positivo = (b["resourceType"] == "Bundle" and tipi.count("Observation") == 7
                and "RiskAssessment" in tipi and "Provenance" in tipi and loinc_ok
                and all(f for f in fulls) and refs <= fulls)
    # null 1: NIENTE PII — nessun campo name/identifier sul Patient, che resta
    # anonimo e referenziato via URN (la grandezza primaria: le CHIAVI del
    # resource Patient, non una substring nel blob)
    patient = next(e["resource"] for e in b["entry"]
                   if e["resource"]["resourceType"] == "Patient")
    no_pii = (set(patient.keys()) <= {"resourceType", "id", "text"}
              and _urn("anon") in blob)
    # null 2: ECG inesistente → rifiuto, non un hash inventato
    ecg_no = not allega_ecg("/percorso/inesistente.pdf", ts)["allegato"]
    at = atmist(67, "11:40", "dolore toracico a riposo", "sospetto STEMI",
                out["PRE_ALERT_INTEGRATO"], ["ASA 250mg ev"])
    atmist_ok = "A: 67" in at["testo_consegna"] and at["ATMIST"]["S_segni"].startswith("priorità")
    return {"bundle_completo": positivo, "loinc_vitali": loinc_ok,
            "anonimo_no_pii": no_pii, "ecg_inesistente_rifiutato": ecg_no,
            "atmist": atmist_ok,
            "banco_sa_fallire": positivo and no_pii and ecg_no and atmist_ok}


if __name__ == "__main__":
    print(json.dumps(banco_controllo(), ensure_ascii=False, indent=1))
