# -*- coding: utf-8 -*-
"""news2_certificate — certificato di concordanza del NEWS2, 2026-09-08.

Metodo QRAFT-RA portato nel companion (ordine Roberto 08/09 «aggiorna tutto
e testali»): un GIUDICE INDIPENDENTE table-driven (stessa fonte: Royal
College of Physicians 2017, Scala 1) ricalcola punteggio e componenti su una
GRIGLIA dei confini clinici (tutti i bordi delle bande ±1 passo) e deve
concordare con `barella_prealert.news2` su OGNI vettore; il banco dimostra
di saper fallire (una tabella con un bordo spostato viene beccata).

COSA GIUDICA: score totale e componenti (Scala 1). COSA NON GIUDICA: le
bande d'azione (il companion ha una deviazione DICHIARATA: singolo rosso →
MEDIO, sovra-triage pre-ospedaliero voluto) e la Scala 2 BPCO (scelta
clinica, fuori scope). Indipendenza STRUTTURALE (tabella vs ternari), non
clean-room: stesso autore. Decision-support, NON diagnosi.

Self-contained, solo stdlib — come il resto del companion.
"""
from __future__ import annotations

import itertools
from typing import Dict, List, Tuple

from barella_prealert import news2

# (bordo_superiore_incluso, punti) — RCP 2017, Scala 1
_TABELLA = {
    "rr":   [(8, 3), (11, 1), (20, 0), (24, 2), (float("inf"), 3)],
    "spo2": [(91, 3), (93, 2), (95, 1), (float("inf"), 0)],
    "sbp":  [(90, 3), (100, 2), (110, 1), (219, 0), (float("inf"), 3)],
    "hr":   [(40, 3), (50, 1), (90, 0), (110, 1), (130, 2), (float("inf"), 3)],
    "temp": [(35.0, 3), (36.0, 1), (38.0, 0), (39.0, 1), (float("inf"), 2)],
}
_CHIAVI_COMP = {"rr": "freq_respiratoria", "spo2": "spo2", "sbp":
                "pressione_sist", "hr": "freq_cardiaca", "temp": "temperatura"}


def _punti(param: str, valore: float, tabella=None) -> int:
    for bordo, punti in (tabella or _TABELLA)[param]:
        if valore <= bordo:
            return punti
    raise AssertionError("tabella senza bordo infinito")


def news2_indipendente(rr, spo2, su_ossigeno, sbp, hr, alert_coscienza,
                       temp, tabella=None) -> Dict:
    comp = {p: _punti(p, v, tabella) for p, v in
            (("rr", rr), ("spo2", spo2), ("sbp", sbp), ("hr", hr),
             ("temp", temp))}
    comp["o2"] = 2 if su_ossigeno else 0
    comp["coscienza"] = 0 if alert_coscienza else 3
    return {"score": sum(comp.values()), "comp": comp,
            "rosso": any(v == 3 for v in comp.values())}


def _griglia_confini() -> List[Tuple]:
    """Bordi clinici ±1 passo; parametri accoppiati ciclicamente dove il
    prodotto pieno esploderebbe (la somma e' di funzioni indipendenti:
    basta coprire ogni bordo in ogni posizione)."""
    rr = [7, 8, 9, 11, 12, 20, 21, 24, 25]
    sp = [90, 91, 92, 93, 94, 95, 96]
    bp = [89, 90, 91, 100, 101, 110, 111, 219, 220]
    hr = [39, 40, 41, 50, 51, 90, 91, 110, 111, 130, 131]
    tp = [34.9, 35.0, 35.1, 36.0, 36.1, 38.0, 38.1, 39.0, 39.1]
    vettori = []
    for r, s_, b in itertools.product(rr, sp, bp):
        vettori.append((r, s_, (r + b) % 2 == 0, b,
                        hr[(r + s_ + b) % len(hr)],
                        (s_ + b) % 2 == 0, tp[(r * 3 + s_) % len(tp)]))
    for h in hr:
        vettori.append((15, 97, False, 120, h, True, 37.0))
    for t in tp:
        vettori.append((15, 97, False, 120, 70, True, t))
    return vettori


def _concordanza(tabella=None) -> Tuple[bool, Dict]:
    disaccordi = []
    vettori = _griglia_confini()
    for v in vettori:
        rr, sp, o2, bp, h, al, t = v
        a = news2(rr, sp, o2, bp, h, al, t)
        b = news2_indipendente(rr, sp, o2, bp, h, al, t, tabella)
        if (a["NEWS2"], a["parametro_singolo_critico"]) != \
           (b["score"], b["rosso"]):
            disaccordi.append({"v": v, "companion": a["NEWS2"],
                               "giudice": b["score"]})
            continue
        for p, chiave in _CHIAVI_COMP.items():
            if a["componenti"][chiave] != b["comp"][p]:
                disaccordi.append({"v": v, "param": p})
                break
    return (not disaccordi), {"vettori": len(vettori),
                              "disaccordi": len(disaccordi),
                              "primi": disaccordi[:3]}


def certifica() -> Dict:
    """Certificato completo: concordanza sulla griglia + banco che sa
    fallire (tabella mutata: bordo spo2 95->96 DEVE essere beccato)."""
    ok, det = _concordanza()
    rotta = dict(_TABELLA)
    rotta["spo2"] = [(91, 3), (93, 2), (96, 1), (float("inf"), 0)]
    ok_finto, _ = _concordanza(rotta)
    banco_sa_fallire = not ok_finto
    return {"concordanza": ok, "vettori": det["vettori"],
            "disaccordi": det["disaccordi"],
            "banco_sa_fallire": banco_sa_fallire,
            "scope": ("score e componenti RCP Scala 1; le bande d'azione "
                      "hanno la deviazione DICHIARATA del companion e non "
                      "sono giudicate; Scala 2 BPCO fuori scope; "
                      "indipendenza strutturale, non clean-room"),
            "ok": bool(ok and banco_sa_fallire)}


if __name__ == "__main__":
    import json
    print(json.dumps(certifica(), indent=1, ensure_ascii=False))
