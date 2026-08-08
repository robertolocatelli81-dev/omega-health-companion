#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""OMEGA — score di emergenza VALIDATI + provenienza hash-chained (OMEGA in appoggio).

Due score standard, tempo-dipendenti (dove i minuti salvano la vita):
  • FAST  — screening ICTUS (Face-Arm-Speech-Time), validato mondialmente.
  • qSOFA — screening SEPSI (quick SOFA, Sepsis-3, 2016), validato.

E l'appoggio OMEGA: ogni pre-alert viene INCATENATO (SHA-256, prev_hash) in un
ledger append-only → provenienza auditabile e non-ripudiabile. In emergenza conta:
«a che ora è stata lanciata l'allerta, con quali dati, non alterabile dopo».

CONFINE: score clinici standard riconosciuti, NON diagnosi. Attivano un PERCORSO
(stroke team / percorso sepsi), il medico conferma. Aggrego standard, non invento.
"""
from __future__ import annotations
import hashlib, json, os
from datetime import datetime, timezone
from typing import Dict

LEDGER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "prealert_ledger.jsonl")
GENESIS = "0" * 64


# ── FAST: screening ictus (Face, Arm, Speech) ─────────────────────────────────
def fast(face_asimmetrica: bool, braccio_debole: bool, linguaggio_disturbato: bool) -> Dict:
    pos = sum([face_asimmetrica, braccio_debole, linguaggio_disturbato])
    sospetto = pos >= 1     # anche UN segno positivo → sospetto ictus, tempo critico
    return {"score": "FAST", "segni_positivi": pos,
            "sospetto_ictus": sospetto,
            "azione": "SOSPETTO ICTUS: attiva STROKE TEAM, finestra terapeutica critica" if sospetto
                      else "nessun segno FAST",
            "fonte": "FAST · screening ictus validato (Stroke Association)"}


# ── qSOFA: screening sepsi (Sepsis-3, 2016) ───────────────────────────────────
def qsofa(freq_resp: float, coscienza_alterata: bool, sbp: float) -> Dict:
    pts = sum([freq_resp >= 22, coscienza_alterata, sbp <= 100])
    sospetto = pts >= 2     # qSOFA >=2 → alto rischio sepsi
    return {"score": "qSOFA", "punti": pts,
            "sospetto_sepsi": sospetto,
            "azione": "SOSPETTO SEPSI: percorso sepsi, emocolture + antibiotico precoce" if sospetto
                      else "qSOFA basso",
            "fonte": "qSOFA · Sepsis-3 (JAMA 2016), validato"}


# ── TRAUMA: criteri fisiologici di attivazione trauma team (ATLS/CDC) ─────────
def trauma(gcs: int, sbp: float, freq_resp: float, meccanismo_maggiore: bool = False,
           contesto_trauma: bool = False) -> Dict:
    """Attivazione trauma team. FIX 2026-08-08 (bug trovato eseguendo la demo:
    la fisiologia alterata è ASPECIFICA — sepsi/shock non-traumatico hanno SBP<90
    e RR>29 senza essere traumi). I criteri fisiologici attivano il trauma team
    SOLO in CONTESTO TRAUMATICO noto (incidente, caduta, ferita). Senza contesto
    trauma, non è trauma — sarà un altro percorso (sepsi/cardio)."""
    fisio = (gcs <= 13) or (sbp < 90) or (freq_resp < 10) or (freq_resp > 29)
    attiva = contesto_trauma and (fisio or meccanismo_maggiore)
    return {"score": "TRAUMA", "criterio_fisiologico": fisio, "contesto_trauma": contesto_trauma,
            "attiva_trauma_team": attiva,
            "azione": "TRAUMA MAGGIORE: attiva TRAUMA TEAM, shock room, sangue pronto" if attiva
                      else "nessun criterio di trauma maggiore",
            "fonte": "criteri fisiologici ATLS / CDC field triage (validati)"}


# ── ACR: arresto cardiorespiratorio (stato, non score) ────────────────────────
def acr(assenza_respiro: bool, assenza_polso: bool) -> Dict:
    """Arresto cardiorespiratorio → priorità massima assoluta, percorso ACR."""
    arresto = assenza_respiro and assenza_polso
    return {"score": "ACR", "arresto": arresto,
            "azione": "ARRESTO CARDIORESPIRATORIO: RCP in corso, pre-alert ACR, "
                      "defibrillatore/ALS, valutare ECMO se disponibile" if arresto
                      else "nessun arresto",
            "fonte": "ERC/ILCOR (linee guida rianimazione)"}


# ── STEMI / dolore toracico: percorso cardio-emodinamica ──────────────────────
def cardio(dolore_toracico_ischemico: bool, ecg_stemi: bool = False) -> Dict:
    """Dolore toracico ischemico (+ ECG STEMI se disponibile) → allerta cardio.
    Con ECG STEMI: emodinamica diretta (bypass PS)."""
    if ecg_stemi:
        return {"score": "CARDIO", "sospetto": True, "stemi": True,
                "azione": "STEMI CONFERMATO ECG: EMODINAMICA diretta, bypass PS, door-to-balloon",
                "fonte": "linee guida ESC STEMI (validate)"}
    if dolore_toracico_ischemico:
        return {"score": "CARDIO", "sospetto": True, "stemi": False,
                "azione": "DOLORE TORACICO ISCHEMICO: allerta cardio, ECG appena possibile",
                "fonte": "linee guida ESC ACS (validate)"}
    return {"score": "CARDIO", "sospetto": False, "stemi": False, "azione": "nessun segno cardio",
            "fonte": "—"}


# ── appoggio OMEGA: incatena il pre-alert (provenienza non-ripudiabile) ───────
def _hash(rec: Dict) -> str:
    blob = json.dumps(rec, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return hashlib.sha256(blob).hexdigest()

def ancora_prealert(prealert: Dict, ts: str) -> Dict:
    """Aggiunge il pre-alert al ledger hash-chained. Ritorna il record ancorato.
    (ts passato dall'esterno per determinismo/testabilità.)"""
    try:
        prev = GENESIS
        if os.path.exists(LEDGER):
            with open(LEDGER, encoding="utf-8") as f:
                righe = [r for r in f if r.strip()]
                if righe:
                    prev = json.loads(righe[-1])["self_hash"]
        rec = {"ts": ts, "prealert": prealert, "prev_hash": prev}
        rec["self_hash"] = _hash(rec)
        with open(LEDGER, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        return {"ancorato": True, "self_hash": rec["self_hash"], "prev_hash": prev}
    except Exception as e:
        return {"ancorato": False, "error": f"{type(e).__name__}: {e}"}


# ── banco che SA FALLIRE ──────────────────────────────────────────────────────
def banco_controllo() -> Dict:
    tests = {
        "FAST": (fast(True, True, False)["sospetto_ictus"], not fast(False, False, False)["sospetto_ictus"]),
        "qSOFA": (qsofa(28, True, 85)["sospetto_sepsi"], not qsofa(16, False, 125)["sospetto_sepsi"]),
        "TRAUMA": (trauma(8, 80, 32, contesto_trauma=True)["attiva_trauma_team"],
                   not trauma(26, 88, 26, contesto_trauma=False)["attiva_trauma_team"]),  # settico non-trauma → NO
        "ACR": (acr(True, True)["arresto"], not acr(False, False)["arresto"]),
        "CARDIO": (cardio(True, True)["sospetto"], not cardio(False, False)["sospetto"]),
    }
    out = {k: {"positivo->sospetto": p, "nullo->no": n} for k, (p, n) in tests.items()}
    out["banco_sa_fallire"] = all(p and n for p, n in tests.values())
    return out


if __name__ == "__main__":
    print("═══ BANCO score emergenza ═══")
    print(json.dumps(banco_controllo(), ensure_ascii=False, indent=1))
    print("\nFAST (viso storto + braccio debole):", json.dumps(fast(True, True, False), ensure_ascii=False))
    print("qSOFA (RR28, coscienza alterata, PA85):", json.dumps(qsofa(28, True, 85), ensure_ascii=False))
