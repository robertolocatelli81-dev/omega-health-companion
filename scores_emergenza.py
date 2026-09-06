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


# ── BE-FAST: screening ictus (Balance, Eyes, Face, Arm, Speech) ───────────────
def fast(face_asimmetrica: bool, braccio_debole: bool, linguaggio_disturbato: bool,
         equilibrio_alterato: bool = False, disturbo_visivo_acuto: bool = False) -> Dict:
    """FIX 2026-09-06 (attacco 4-menti): il FAST da solo perde il circolo
    POSTERIORE (vertigini/atassia, disturbi visivi acuti) — 15-30% degli ictus.
    Esteso a BE-FAST (Balance, Eyes opzionali, retro-compatibile). Limite
    DICHIARATO nell'output: nessuno screening pre-ospedaliero prende tutto."""
    pos = sum([face_asimmetrica, braccio_debole, linguaggio_disturbato,
               equilibrio_alterato, disturbo_visivo_acuto])
    sospetto = pos >= 1     # anche UN segno positivo → sospetto ictus, tempo critico
    return {"score": "BE-FAST", "segni_positivi": pos,
            "sospetto_ictus": sospetto,
            "azione": "SOSPETTO ICTUS: attiva STROKE TEAM, finestra terapeutica critica" if sospetto
                      else "nessun segno BE-FAST",
            "limite": "screening: un BE-FAST negativo NON esclude l'ictus (specie posteriore)",
            "fonte": "BE-FAST · estensione validata del FAST (Stroke Association / letteratura BE-FAST)"}


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
           contesto_trauma: bool = False, lesione_penetrante: bool = False) -> Dict:
    """Attivazione trauma team (CDC field triage / ATLS).

    Due fix successivi, entrambi da difetti trovati eseguendo/attaccando:
      1) (demo 2026-08-08) la fisiologia alterata è ASPECIFICA — sepsi/shock non
         traumatico hanno SBP<90 e RR>29 senza essere trauma: la fisiologia da sola
         NON attiva il trauma team.
      2) (agente avversariale 2026-08-08) il fix #1 aveva incassato TUTTO dietro
         `contesto_trauma` (default False, non documentato) → il percorso trauma era
         di fatto MORTO via interfaccia integrata, e un politrauma con vitali ancora
         compensati (trauma occulto) usciva a priorità BASSA. ERRORE.

    Logica corretta: il MECCANISMO maggiore (eiezione, caduta >6 m, morte stesso
    abitacolo — Step 3) e la LESIONE penetrante (Step 2) SONO di per sé contesto
    traumatico: non vanno nascosti dietro un flag. La fisiologia grave (Step 1)
    attiva il trauma team SOLO se c'è un contesto traumatico (esplicito, meccanismo
    o lesione). Senza alcun contesto trauma, la fisiologia va ad altro percorso."""
    fisio = (gcs <= 13) or (sbp < 90) or (freq_resp < 10) or (freq_resp > 29)
    # meccanismo/lesione = contesto traumatico intrinseco (anamnesi/anatomia)
    contesto = bool(contesto_trauma or meccanismo_maggiore or lesione_penetrante)
    attiva = contesto and (fisio or meccanismo_maggiore or lesione_penetrante)
    return {"score": "TRAUMA", "criterio_fisiologico": fisio, "contesto_trauma": contesto,
            "meccanismo_maggiore": bool(meccanismo_maggiore),
            "lesione_penetrante": bool(lesione_penetrante),
            "attiva_trauma_team": attiva,
            "azione": "TRAUMA MAGGIORE: attiva TRAUMA TEAM, shock room, sangue pronto" if attiva
                      else "nessun criterio di trauma maggiore",
            "fonte": "CDC field triage Step 1-3 / ATLS (validati)"}


# ── ACR: arresto cardiorespiratorio (stato, non score) ────────────────────────
def acr(assenza_respiro: bool, assenza_polso: bool,
        coscienza_assente: bool = False) -> Dict:
    """Arresto → priorità massima assoluta, percorso ACR.

    FIX 2026-09-06 (attacco 4-menti): la vecchia logica richiedeva assenza di
    respiro E di polso. ERC/ILCOR dicono l'opposto: il controllo del polso è
    INAFFIDABILE — non-responsivo + respiro assente/anormale = trattare come
    arresto, iniziare RCP. E il respiro assente CON polso percepito (arresto
    respiratorio) non è «nessun arresto»: è peri-arresto, vie aeree subito.
    Prima questo caso usciva instradato al percorso SEPSI (misurato). ERRORE."""
    arresto = assenza_respiro and (assenza_polso or coscienza_assente)
    arresto_respiratorio = assenza_respiro and not arresto
    if arresto:
        azione = ("ARRESTO (ERC: non-responsivo + respiro assente = RCP, il polso "
                  "non è affidabile): RCP, pre-alert ACR, defibrillatore/ALS, "
                  "valutare ECMO se disponibile")
    elif arresto_respiratorio:
        azione = ("ARRESTO RESPIRATORIO (respiro assente, polso presente): vie aeree "
                  "+ ventilazione IMMEDIATE, pre-alert, pronto a RCP — peri-arresto")
    else:
        azione = "nessun arresto"
    return {"score": "ACR", "arresto": arresto,
            "arresto_respiratorio": arresto_respiratorio,
            "azione": azione,
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

def ancora_prealert(prealert: Dict, ts: str, payload: str = "digest") -> Dict:
    """Aggiunge il pre-alert al ledger hash-chained. Ritorna il record ancorato.
    (ts passato dall'esterno per determinismo/testabilità.)

    FIX 2026-09-06 (attacco 4-menti, MISURATO sul ledger reale): il default
    persisteva vitali+età+farmaci IN CHIARO mentre le docstring promettevano
    «dati effimeri» — dato sanitario su disco non cifrato, promessa contraddetta.
    Ora il default ancora SOLO il digest SHA-256 del pre-alert (provenienza e
    non-ripudio restano: chi ha il pre-alert ricalcola l'hash e trova il match);
    payload="full" resta possibile ma è una SCELTA esplicita di ritenzione dati,
    da fare solo con base giuridica e cifratura a valle."""
    try:
        prev = GENESIS
        if os.path.exists(LEDGER):
            with open(LEDGER, encoding="utf-8") as f:
                righe = [r for r in f if r.strip()]
                if righe:
                    prev = json.loads(righe[-1])["self_hash"]
        if payload == "full":
            corpo = {"prealert": prealert, "payload": "full"}
        else:
            corpo = {"prealert_sha256": _hash(prealert), "payload": "digest",
                     "privacy": "solo digest: nessun dato sanitario nel ledger"}
        rec = {"ts": ts, **corpo, "prev_hash": prev}
        rec["self_hash"] = _hash(rec)
        with open(LEDGER, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        return {"ancorato": True, "payload": corpo["payload"],
                "self_hash": rec["self_hash"], "prev_hash": prev}
    except Exception as e:
        return {"ancorato": False, "error": f"{type(e).__name__}: {e}"}


# ── banco che SA FALLIRE ──────────────────────────────────────────────────────
def banco_controllo() -> Dict:
    tests = {
        "FAST": (fast(True, True, False)["sospetto_ictus"], not fast(False, False, False)["sospetto_ictus"]),
        "qSOFA": (qsofa(28, True, 85)["sospetto_sepsi"], not qsofa(16, False, 125)["sospetto_sepsi"]),
        # positivo copre i punti ciechi dell'agente: politrauma OCCULTO (vitali
        # compensati, solo meccanismo) E trauma evidente col meccanismo → team ON;
        # nullo = settico non-trauma con fisiologia alterata → team OFF (va a sepsi).
        "TRAUMA": (trauma(15, 120, 16, meccanismo_maggiore=True)["attiva_trauma_team"]      # occulto
                   and trauma(8, 70, 32, meccanismo_maggiore=True)["attiva_trauma_team"]     # evidente
                   and trauma(14, 110, 18, lesione_penetrante=True)["attiva_trauma_team"],   # penetrante
                   not trauma(13, 88, 26, contesto_trauma=False)["attiva_trauma_team"]),      # settico → NO
        "ACR": (acr(True, True)["arresto"]
                and acr(True, False, coscienza_assente=True)["arresto"]        # ERC: no polso affidabile
                and acr(True, False)["arresto_respiratorio"],                  # respiratorio ≠ "nessun arresto"
                not acr(False, False)["arresto"] and not acr(False, False)["arresto_respiratorio"]),
        "BEFAST_posteriore": (fast(False, False, False, equilibrio_alterato=True)["sospetto_ictus"],
                              not fast(False, False, False)["sospetto_ictus"]),
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
