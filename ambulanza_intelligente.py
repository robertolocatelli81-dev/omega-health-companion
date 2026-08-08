#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""OMEGA — AMBULANZA INTELLIGENTE: i tre moduli in un solo flusso di emergenza.

Durante il trasporto, da un unico input (vitali + farmaci del paziente + età +
ETA all'ospedale) produce UN pre-alert integrato per il pronto soccorso:
  • NEWS2 + priorità        (barella_prealert)  — quanto è critico, ora
  • interazioni farmaci     (interazioni_farmaci) — cosa prende e quali rischi
  • verifica informazioni   (companion_seed)     — disponibile per dubbi del cittadino
così l'ospedale sa PRIMA dell'arrivo: gravità, terapie in corso, rischi.

CONFINE: aggrega e comunica standard clinici validati (NEWS2, interazioni note).
NON diagnostica, NON decide la terapia: il medico decide, ma arriva preparato.
PRIVACY: dati sanitari effimeri; trasmessi solo all'ospedale di destinazione.
"""
from __future__ import annotations
import os, sys
from typing import Dict, List, Optional
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import barella_prealert as B
import interazioni_farmaci as F
import companion_seed as C
import scores_emergenza as S
from datetime import datetime, timezone


def valuta_paziente(vitali: Dict, farmaci: List[str], eta: Optional[int],
                    eta_arrivo_min: int, fast_segni: Optional[Dict] = None,
                    clinica: Optional[Dict] = None, ancora: bool = False) -> Dict:
    """Il flusso completo dell'ambulanza intelligente → pre-alert integrato.
    fast_segni: {'face','arm','speech'}.
    clinica (tutte opzionali): {'gcs', 'meccanismo_maggiore', 'lesione_penetrante',
    'contesto_trauma', 'assenza_respiro', 'assenza_polso', 'dolore_toracico',
    'ecg_stemi'}. meccanismo_maggiore e lesione_penetrante attivano da soli il
    contesto traumatico (CDC field triage Step 2-3) — vedi scores_emergenza.trauma."""
    cl = clinica or {}
    pa = B.prealert(eta, vitali, eta_arrivo_min)
    inter = F.controlla(farmaci) if farmaci else {"interazioni_note_trovate": [],
                                                  "nessun_allarme": True}
    # tutti i percorsi tempo-dipendenti validati (attivano squadre dedicate)
    qs = S.qsofa(vitali["rr"], not vitali["alert_coscienza"], vitali["sbp"])
    fs = S.fast(fast_segni.get("face", False), fast_segni.get("arm", False),
                fast_segni.get("speech", False)) if fast_segni else None
    tr = S.trauma(cl.get("gcs", 15), vitali["sbp"], vitali["rr"],
                  cl.get("meccanismo_maggiore", False), cl.get("contesto_trauma", False),
                  cl.get("lesione_penetrante", False))
    ar = S.acr(cl.get("assenza_respiro", False), cl.get("assenza_polso", False))
    ca = S.cardio(cl.get("dolore_toracico", False), cl.get("ecg_stemi", False))
    percorsi = []
    if ar["arresto"]:               percorsi.append(ar["azione"])   # priorità assoluta
    if fs and fs["sospetto_ictus"]: percorsi.append(fs["azione"])
    if ca["sospetto"]:              percorsi.append(ca["azione"])
    if tr["attiva_trauma_team"]:    percorsi.append(tr["azione"])
    # FIX 2026-08-08 (agente avversariale): qSOFA instrada a SEPSI solo FUORI da un
    # contesto traumatico. In un trauma, lo shock è emorragico fino a prova
    # contraria: mandare un emorragico a colture+antibiotici è il percorso SBAGLIATO
    # e ritarda sangue/chirurgia. Il trauma team ha la precedenza.
    if qs["sospetto_sepsi"] and not tr["attiva_trauma_team"]:
        percorsi.append(qs["azione"])
    # FIX 2026-08-08 (bug trovato in demo): un percorso tempo-critico attivo
    # eleva la PRIORITÀ anche se NEWS2 è basso (es. ictus con vitali normali).
    priorita = pa["PRE_ALERT_OSPEDALE"]["priorita"]
    if percorsi and priorita != "ALTO":
        priorita = "ALTO"
    prealert_integrato = {
        **pa["PRE_ALERT_OSPEDALE"], "priorita": priorita,
        "farmaci_in_uso": farmaci,
        "interazioni_note": inter["interazioni_note_trovate"],
        "flag_farmacologico": not inter.get("nessun_allarme", True),
        "qSOFA": qs["punti"], "FAST": (fs["segni_positivi"] if fs else None),
        "trauma_team": tr["attiva_trauma_team"], "arresto": ar["arresto"],
        "cardio": ca["sospetto"],
        "percorsi_attivare": percorsi,
    }
    out = {
        "PRE_ALERT_INTEGRATO": prealert_integrato,
        "dettaglio_score": pa["score"], "dettaglio_interazioni": inter,
        "dettaglio_qsofa": qs, "dettaglio_fast": fs,
        "confine": "NEWS2/FAST/qSOFA e interazioni sono standard validati, NON diagnosi; il medico decide",
        "privacy": "dati effimeri, trasmessi solo all'ospedale di destinazione",
    }
    if ancora:   # appoggio OMEGA: provenienza hash-chained non-ripudiabile
        ts = datetime.now(timezone.utc).isoformat()
        out["provenienza_omega"] = S.ancora_prealert(prealert_integrato, ts)
    return out


def verifica_informazione(domanda: str) -> Dict:
    """Componente companion: verifica una claim sanitaria (per il cittadino)."""
    return C.rispondi(domanda)


# ── banco che SA FALLIRE: integrazione dei tre ────────────────────────────────
def banco_controllo() -> Dict:
    critico = dict(rr=28, spo2=89, su_ossigeno=True, sbp=85, hr=135,
                   alert_coscienza=False, temp=39.4)
    stabile = dict(rr=16, spo2=98, su_ossigeno=False, sbp=125, hr=72,
                   alert_coscienza=True, temp=36.7)
    # paziente critico che prende warfarin+aspirina (interazione grave)
    r1 = valuta_paziente(critico, ["warfarin", "aspirina"], 67, 8)
    # paziente stabile senza interazioni
    r2 = valuta_paziente(stabile, ["paracetamolo"], 40, 15)
    b_score = B.banco_controllo()["banco_sa_fallire"]
    f_score = F.banco_controllo()["banco_sa_fallire"]
    integrazione_ok = (r1["PRE_ALERT_INTEGRATO"]["priorita"] == "ALTO"
                       and r1["PRE_ALERT_INTEGRATO"]["flag_farmacologico"] is True
                       and r2["PRE_ALERT_INTEGRATO"]["priorita"] == "BASSO"
                       and r2["PRE_ALERT_INTEGRATO"]["flag_farmacologico"] is False)
    # caso trauma (punto cieco dell'agente): politrauma OCCULTO (vitali compensati,
    # solo meccanismo) → team ON + priorità ALTO; ed EMORRAGICO da trauma → team ON
    # ma percorso SEPSI assente (non instradare un emorragico ad antibiotici).
    occulto = valuta_paziente(dict(rr=16, spo2=98, su_ossigeno=False, sbp=120, hr=88,
                                   alert_coscienza=True, temp=36.8), [], 25, 12,
                              clinica={"gcs": 15, "meccanismo_maggiore": True})
    emorr = valuta_paziente(dict(rr=32, spo2=92, su_ossigeno=False, sbp=70, hr=130,
                                 alert_coscienza=False, temp=36.5), [], 30, 10,
                            clinica={"gcs": 8, "meccanismo_maggiore": True})
    ep = emorr["PRE_ALERT_INTEGRATO"]
    trauma_ok = (occulto["PRE_ALERT_INTEGRATO"]["trauma_team"] is True
                 and occulto["PRE_ALERT_INTEGRATO"]["priorita"] == "ALTO"
                 and ep["trauma_team"] is True
                 and not any("SEPSI" in p for p in ep["percorsi_attivare"]))
    return {
        "sotto-banco NEWS2 sa fallire": b_score,
        "sotto-banco interazioni sa fallire": f_score,
        "integrazione (critico+interazione->ALTO+flag; stabile->BASSO+no-flag)": integrazione_ok,
        "trauma (occulto->team+ALTO; emorragico->team e NO sepsi)": trauma_ok,
        "banco_sa_fallire": b_score and f_score and integrazione_ok and trauma_ok,
    }


if __name__ == "__main__":
    import json
    print("═══ BANCO INTEGRATO (i tre moduli insieme) ═══")
    print(json.dumps(banco_controllo(), ensure_ascii=False, indent=1))
    print("\n═══ AMBULANZA: paziente critico su warfarin+aspirina, arrivo 8 min ═══")
    vit = dict(rr=28, spo2=89, su_ossigeno=True, sbp=85, hr=135,
               alert_coscienza=False, temp=39.4)
    out = valuta_paziente(vit, ["warfarin", "aspirina", "ramipril"], 67, 8)
    print(json.dumps(out["PRE_ALERT_INTEGRATO"], ensure_ascii=False, indent=1))
