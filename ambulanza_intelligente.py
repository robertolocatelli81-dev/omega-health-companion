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


def valuta_paziente(vitali: Dict, farmaci: List[str], eta: Optional[int],
                    eta_arrivo_min: int) -> Dict:
    """Il flusso completo dell'ambulanza intelligente → pre-alert integrato."""
    pa = B.prealert(eta, vitali, eta_arrivo_min)
    inter = F.controlla(farmaci) if farmaci else {"interazioni_note_trovate": [],
                                                  "nessun_allarme": True}
    # il pre-alert integrato che l'ospedale riceve PRIMA dell'arrivo
    prealert_integrato = {
        **pa["PRE_ALERT_OSPEDALE"],
        "farmaci_in_uso": farmaci,
        "interazioni_note": inter["interazioni_note_trovate"],
        "flag_farmacologico": not inter.get("nessun_allarme", True),
    }
    return {
        "PRE_ALERT_INTEGRATO": prealert_integrato,
        "dettaglio_score": pa["score"],
        "dettaglio_interazioni": inter,
        "confine": "NEWS2 e interazioni sono standard validati, NON diagnosi; il medico decide",
        "privacy": "dati effimeri, trasmessi solo all'ospedale di destinazione",
    }


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
    return {
        "sotto-banco NEWS2 sa fallire": b_score,
        "sotto-banco interazioni sa fallire": f_score,
        "integrazione (critico+interazione->ALTO+flag; stabile->BASSO+no-flag)": integrazione_ok,
        "banco_sa_fallire": b_score and f_score and integrazione_ok,
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
