#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""OMEGA Health Companion — SEME dimostrativo (2026-08-08).

Assistente sanitario INFORMATIVO e VERIFICATORE — NON diagnostico. Nasce dalla
richiesta di Roberto (disinformazione sanitaria + medico-online-sicuro), tenuto
nel confine con honest-scope fortissimo.

COSA FA (nel confine):
  1. verifica una claim/domanda sanitaria contro uno snapshot di fatti da fonti
     UFFICIALI (ancorato SHA-256) → anti-disinformazione;
  2. aggiunge il contesto epidemiologico da dati APERTI (stato di epiwatch, se
     presente) → informazione di contesto, non diagnosi;
  3. RIMANDA SEMPRE al medico e dichiara l'honest-scope in ogni risposta.

COSA NON FA (mai): diagnosi, prescrizione, sostituzione del medico. Non è un
dispositivo medico. Non tratta i dati come cartella clinica.

PRIVACY: tutto in memoria, effimero. Nessuna persistenza, nessun egress. L'input
non viene salvato né trasmesso — questo seme non scrive né manda nulla fuori.
"""
from __future__ import annotations

import hashlib
import re
from typing import Dict, List

# ── snapshot curato di fatti sanitari da FONTI UFFICIALI (seed, ancorato) ─────
# Ogni voce: pattern della claim, verdetto rispetto al consenso ufficiale, fonte.
# È un SEME dimostrativo: nel prodotto reale, alimentato da ISS/AIFA/EMA/OMS via
# il verify-router. Dichiarato come snapshot, non esaustivo.
FATTI_UFFICIALI: List[Dict] = [
    {"pattern": r"vaccin.*(autismo|causa.*autism)",
     "verdetto": "FALSO", "consenso": "Nessun legame vaccini-autismo; lo studio del 1998 fu ritirato per frode.",
     "fonte": "ISS / OMS / EMA"},
    {"pattern": r"(antibiotic).*(virus|influenz|raffreddore)",
     "verdetto": "FALSO", "consenso": "Gli antibiotici NON agiscono sui virus (influenza, raffreddore).",
     "fonte": "AIFA / OMS"},
    {"pattern": r"(vitamina c|zinco).*(cura|guarisce).*(covid|cancro)",
     "verdetto": "FALSO", "consenso": "Nessuna vitamina/integratore cura COVID o cancro.",
     "fonte": "EMA / ISS"},
    {"pattern": r"paracetamolo.*(febbre|abbassa)",
     "verdetto": "SUPPORTATO", "consenso": "Il paracetamolo è un antipiretico: abbassa la febbre alle dosi indicate.",
     "fonte": "AIFA (foglio illustrativo)"},
    {"pattern": r"(lavare le mani|igiene mani).*(riduc|previen).*(infezion|contagi)",
     "verdetto": "SUPPORTATO", "consenso": "L'igiene delle mani riduce la trasmissione di infezioni.",
     "fonte": "OMS"},
]

_DISCLAIMER = ("⚠️ Informazione, NON diagnosi. Questo assistente verifica affermazioni "
               "e dà contesto da fonti pubbliche — non sostituisce il medico. Per la tua "
               "salute, consulta sempre un medico o il 112/pronto soccorso in urgenza.")


def _sha(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()[:16]


def verifica_claim(testo: str) -> Dict:
    """Verifica una claim sanitaria contro lo snapshot ufficiale. Onesto: se non
    è nello snapshot → INCERTO (non inventa un verdetto)."""
    t = testo.lower()
    for f in FATTI_UFFICIALI:
        if re.search(f["pattern"], t):
            return {"status": f["verdetto"], "consenso": f["consenso"],
                    "fonte": f["fonte"], "provenienza_sha": _sha(f["consenso"] + f["fonte"])}
    return {"status": "INCERTO", "consenso": "Non presente nello snapshot verificato: "
            "non do un verdetto che non posso fondare. Chiedi al medico o a fonti ufficiali (ISS/AIFA).",
            "fonte": "—", "provenienza_sha": None}


def contesto_epidemiologico(area: str = "") -> Dict:
    """Legge il contesto epidemico da dati APERTI (stato di epiwatch se presente).
    Informazione di CONTESTO, non diagnosi."""
    import os, json, glob
    for p in sorted(glob.glob(os.path.expanduser("~/progetti/omega-epiwatch/*latest*.json"))):
        try:
            r = json.load(open(p, encoding="utf-8"))
            d = r.get("data") or r.get("verdict") or "segnale presente"
            return {"disponibile": True, "segnale": str(d)[:120],
                    "nota": "contesto da fonti aperte (epiwatch), non riferito a te personalmente"}
        except Exception:
            pass
    return {"disponibile": False, "segnale": None,
            "nota": "nessun contesto epidemiologico locale disponibile ora"}


def rispondi(domanda: str, area: str = "") -> Dict:
    """La risposta completa: verifica + contesto + rimando al medico. Privacy:
    l'input NON viene salvato né trasmesso da questo seme."""
    v = verifica_claim(domanda)
    epi = contesto_epidemiologico(area)
    return {
        "verifica": v,
        "contesto_epidemiologico": epi,
        "rimando_medico": True,
        "honest_scope": _DISCLAIMER,
        "privacy": "input effimero: non salvato, non trasmesso da questo seme",
    }


# ── il banco che SA FALLIRE (controllo positivo + null) ───────────────────────
def banco_controllo() -> Dict:
    """Controllo positivo: claim FALSE note devono dare FALSO, claim VERE SUPPORTATO.
    Null: una frase non-sanitaria deve dare INCERTO (non inventa)."""
    pos = [
        ("i vaccini causano l'autismo?", "FALSO"),
        ("gli antibiotici curano l'influenza?", "FALSO"),
        ("il paracetamolo abbassa la febbre?", "SUPPORTATO"),
        ("lavare le mani riduce le infezioni?", "SUPPORTATO"),
    ]
    ok = sum(1 for q, atteso in pos if verifica_claim(q)["status"] == atteso)
    null_out = verifica_claim("che tempo fa domani a milano?")["status"]
    return {"controllo_positivo": f"{ok}/{len(pos)}",
            "positivo_passa": ok == len(pos),
            "null (frase non-sanitaria)": null_out,
            "null_passa": null_out == "INCERTO",
            "banco_sa_fallire": ok == len(pos) and null_out == "INCERTO"}


if __name__ == "__main__":
    import json
    print("═══ BANCO (il seme deve saper fallire) ═══")
    print(json.dumps(banco_controllo(), ensure_ascii=False, indent=1))
    print("\n═══ ESEMPIO: claim di disinformazione ═══")
    print(json.dumps(rispondi("è vero che i vaccini causano l'autismo?"),
                     ensure_ascii=False, indent=1))
    print("\n═══ ESEMPIO: domanda non nello snapshot (onesto: INCERTO) ═══")
    print(json.dumps(rispondi("il mio mal di testa è un tumore?")["verifica"],
                     ensure_ascii=False, indent=1))
