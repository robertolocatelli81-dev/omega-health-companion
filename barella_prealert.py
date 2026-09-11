#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""OMEGA — cervello della BARELLA/AMBULANZA intelligente: NEWS2 + pre-alert ospedale.

Durante il trasporto raccoglie i parametri vitali, calcola il NEWS2 (National
Early Warning Score 2, standard VALIDATO del Royal College of Physicians UK) e
genera un PRE-ALERT strutturato per l'ospedale, così il pronto soccorso è pronto
all'arrivo. Riduce il tempo door-to-treatment — dimostrato salvare vite in
ictus/infarto/sepsi/trauma.

CONFINE: NON diagnostica e NON decide la terapia. Calcola uno SCORE clinico
standard (aritmetica riconosciuta, non un algoritmo AI inventato) e comunica i
dati. Il medico dell'ospedale decide — ma arriva preparato. Lo score orienta la
PRIORITÀ, non pone la diagnosi.

PROVENIENZA: NEWS2, Royal College of Physicians (2017), adottato SSN/NHS.
PRIVACY: i vitali sono dato sanitario; la trasmissione all'ospedale è il flusso
di cura legittimo (in produzione: canale cifrato verso il DEA di destinazione).
"""
from __future__ import annotations
from typing import Dict, Optional

# ── NEWS2: tabella ufficiale (Royal College of Physicians 2017) ───────────────
def _p_resp(rr: float) -> int:
    if rr <= 8: return 3
    if rr <= 11: return 1
    if rr <= 20: return 0
    if rr <= 24: return 2
    return 3

def _p_spo2(spo2: float) -> int:      # scala 1 (senza BPCO cronica)
    if spo2 <= 91: return 3
    if spo2 <= 93: return 2
    if spo2 <= 95: return 1
    return 0

def _p_o2(su_ossigeno: bool) -> int:
    return 2 if su_ossigeno else 0

def _p_sbp(sbp: float) -> int:
    if sbp <= 90: return 3
    if sbp <= 100: return 2
    if sbp <= 110: return 1
    if sbp <= 219: return 0
    return 3

def _p_hr(hr: float) -> int:
    if hr <= 40: return 3
    if hr <= 50: return 1
    if hr <= 90: return 0
    if hr <= 110: return 1
    if hr <= 130: return 2
    return 3

def _p_avpu(alert: bool) -> int:      # Alert=0; V/P/U (coscienza alterata)=3
    return 0 if alert else 3

def _p_temp(t: float) -> int:
    if t <= 35.0: return 3
    if t <= 36.0: return 1
    if t <= 38.0: return 0
    if t <= 39.0: return 1
    return 2


# ── validazione fisiologica FAIL-CLOSED (FIX 2026-09-06, attacco 4-menti) ─────
# Prima: rr=-5, spo2=150, temp=45 producevano un NEWS2=11 plausibile (misurato).
# In clinica un dato impossibile è un SENSORE ROTTO o un errore di unità
# (°F/frazione): va RIFIUTATO con i campi nominati, mai trasformato in un alert.
_RANGE_PLAUSIBILE = {              # min, max fisiologicamente possibili (larghi)
    "rr": (0, 80), "spo2": (40, 100), "sbp": (30, 300),
    "hr": (0, 300), "temp": (24.0, 43.5),
}

def valida_vitali(vitali: Dict) -> list:
    """Ritorna la lista dei problemi (vuota = vitali utilizzabili). Nominativa:
    l'equipaggio deve sapere QUALE sensore/dato è sospetto."""
    if not isinstance(vitali, dict):
        # attacco 06/09: vitali stringa/lista crashava con AttributeError —
        # un tipo sbagliato è un problema NOMINATO, mai un'eccezione
        return [f"vitali non è un oggetto (ricevuto {type(vitali).__name__})"]
    attesi = ("rr", "spo2", "su_ossigeno", "sbp", "hr", "alert_coscienza", "temp")
    problemi = [f"campo mancante: {k}" for k in attesi if k not in vitali]
    # TIPI STRETTI (FIX 2026-09-11, red-team 4-menti sul repo pubblico): i due flag clinici devono
    # essere booleani JSON veri. Prima una STRINGA passava per il suo valore di verità Python:
    # alert_coscienza="no" → True → paziente "cosciente" (INVERSIONE clinica);
    # su_ossigeno="false" → True → punteggio SpO2 da paziente in ossigeno. Misurato via API.
    # `bpco_scala2` (SpO2 scala 2 per insufficienza ipercapnica) è un flag OPZIONALE che passa a news2():
    # non era validato (round 3 bis, 11/09): "no" → True → scala 2 → NEWS2 da 2 a 5. Stessa classe.
    for k in ("su_ossigeno", "alert_coscienza", "bpco_scala2"):
        v = vitali.get(k)
        if k in vitali and not isinstance(v, bool):
            problemi.append(f"non booleano: {k}={v!r} (atteso true/false JSON, non stringa né numero)")
    # Chiavi IGNOTE in vitali: rifiutate per nome. Una chiave non prevista che arriva a news2(**vitali)
    # è un TypeError (400 generico) o, peggio, un parametro che cambia lo score senza essere validato.
    for k in vitali:
        if k not in attesi and k != "bpco_scala2":
            problemi.append(f"vitali.{k}: campo non riconosciuto")
    for k, (lo, hi) in _RANGE_PLAUSIBILE.items():
        v = vitali.get(k)
        if v is None and f"campo mancante: {k}" not in problemi:
            problemi.append(f"campo nullo: {k}")
        elif v is not None:
            # bool è sottoclasse di int: rr=true diventava 1.0 = RR 1/min (priorità MEDIO da un
            # flag). Un booleano dove serve un numero è un dato sbagliato, non un numero.
            if isinstance(v, bool) or not isinstance(v, (int, float)):
                problemi.append(f"non numerico: {k}={v!r} (atteso numero JSON)")
                continue
            x = float(v)
            if x != x or x in (float("inf"), float("-inf")):
                problemi.append(f"non finito: {k}={v!r}")
                continue
            if not (lo <= x <= hi):
                extra = ""
                if k == "temp" and 90 <= x <= 110:
                    extra = " (sembra °F: attesi °C)"
                if k == "spo2" and 0 < x <= 1:
                    extra = " (sembra frazione: attesa percentuale)"
                problemi.append(f"fuori range plausibile: {k}={x} [{lo}-{hi}]{extra}")
    return problemi


def _p_spo2_scala2(spo2: float, su_ossigeno: bool) -> int:
    """NEWS2 SpO2 SCALA 2 (insufficienza respiratoria ipercapnica/BPCO,
    target 88-92%) — tabella ufficiale RCP 2017. Con la sola scala 1 un BPCO
    in target veniva sovra-punteggiato sistematicamente (attacco 4-menti)."""
    if spo2 <= 83: return 3
    if spo2 <= 85: return 2
    if spo2 <= 87: return 1
    if spo2 <= 92: return 0
    if not su_ossigeno: return 0          # >=93 in aria ambiente
    if spo2 <= 94: return 1               # >=93 SOTTO ossigeno: iperossia punita
    if spo2 <= 96: return 2
    return 3


def news2(rr: float, spo2: float, su_ossigeno: bool, sbp: float,
          hr: float, alert_coscienza: bool, temp: float,
          bpco_scala2: bool = False) -> Dict:
    """Calcola il NEWS2 e il livello di rischio + pre-alert. Privacy: input
    effimero, trasmesso solo all'ospedale di destinazione (flusso di cura).
    bpco_scala2: SpO2 in scala 2 (RCP) per insufficienza respiratoria
    ipercapnica nota — la scelta della scala è CLINICA, non del software."""
    comp = {
        "freq_respiratoria": _p_resp(rr),
        "spo2": (_p_spo2_scala2(spo2, su_ossigeno) if bpco_scala2 else _p_spo2(spo2)),
        "ossigeno_suppl": _p_o2(su_ossigeno), "pressione_sist": _p_sbp(sbp),
        "freq_cardiaca": _p_hr(hr), "coscienza": _p_avpu(alert_coscienza),
        "temperatura": _p_temp(temp),
    }
    tot = sum(comp.values())
    singolo_rosso = any(v == 3 for v in comp.values())   # un parametro a 3 = rosso
    if tot >= 7:
        livello, azione = "ALTO", "EMERGENZA: pre-alert ospedale, equipe pronta all'arrivo"
    elif tot >= 5 or singolo_rosso:
        livello, azione = "MEDIO", "URGENTE: pre-alert ospedale, valutazione rapida"
    else:
        livello, azione = "BASSO", "monitoraggio; comunicazione ordinaria"
    return {
        "NEWS2": tot, "livello": livello, "parametro_singolo_critico": singolo_rosso,
        "spo2_scala": 2 if bpco_scala2 else 1,
        "componenti": comp, "azione": azione,
        # deviazione DICHIARATA (4-menti 2026-09-06): RCP mette il singolo rosso
        # nel gradino basso-medio; qui lo eleviamo a MEDIO (sovra-triage voluto
        # in pre-ospedaliero). Dichiarato, non nascosto.
        "deviazione_dichiarata": ("singolo parametro a 3 → MEDIO (RCP: basso-medio); "
                                  "scelta conservativa pre-ospedaliera" if singolo_rosso and tot < 5 else None),
        "score_fonte": "NEWS2 · Royal College of Physicians 2017 (standard validato)",
        "confine": "score clinico standard, NON diagnosi; il medico dell'ospedale decide",
        "privacy": "vitali effimeri, trasmessi solo all'ospedale di destinazione",
    }


def prealert(paziente_eta: Optional[int], vitali: Dict, eta_arrivo_min: int) -> Dict:
    """Genera il pacchetto di pre-alert per l'ospedale."""
    s = news2(**vitali)
    return {
        "PRE_ALERT_OSPEDALE": {
            "priorita": s["livello"], "NEWS2": s["NEWS2"],
            "eta_paziente": paziente_eta, "eta_arrivo_stimato_min": eta_arrivo_min,
            "vitali": vitali, "azione_raccomandata": s["azione"],
        },
        "score": s,
    }


# ── il banco che SA FALLIRE (positivo: critico->ALTO; null: stabile->BASSO) ───
def banco_controllo() -> Dict:
    critico = dict(rr=28, spo2=89, su_ossigeno=True, sbp=85, hr=135,
                   alert_coscienza=False, temp=39.4)      # shock/sepsi
    stabile = dict(rr=16, spo2=98, su_ossigeno=False, sbp=125, hr=72,
                   alert_coscienza=True, temp=36.7)        # normale
    medio = dict(rr=22, spo2=94, su_ossigeno=False, sbp=108, hr=95,
                 alert_coscienza=True, temp=38.2)          # intermedio
    c = news2(**critico)["livello"]; s = news2(**stabile)["livello"]; m = news2(**medio)["livello"]
    return {"critico->": c, "stabile->": s, "intermedio->": m,
            "positivo_passa": c == "ALTO", "null_passa": s == "BASSO",
            "banco_sa_fallire": c == "ALTO" and s == "BASSO" and m in ("MEDIO", "ALTO")}


if __name__ == "__main__":
    import json
    print("═══ BANCO (critico->ALTO, stabile->BASSO) ═══")
    print(json.dumps(banco_controllo(), ensure_ascii=False, indent=1))
    print("\n═══ PRE-ALERT: paziente critico, arrivo in 8 min ═══")
    vit = dict(rr=28, spo2=89, su_ossigeno=True, sbp=85, hr=135,
               alert_coscienza=False, temp=39.4)
    print(json.dumps(prealert(67, vit, 8)["PRE_ALERT_OSPEDALE"], ensure_ascii=False, indent=1))
