#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""OMEGA — verificatore di INTERAZIONI FARMACOLOGICHE (informativo, non sostitutivo).

Prende la lista di farmaci di una persona e segnala le interazioni GRAVI note,
con gravità e fonte. NON prescrive, NON decide terapie: rimanda SEMPRE a medico
e farmacista, che conoscono il quadro completo (allergie, reni, gravidanza,
dosaggi). Uno strumento che rende il professionista più veloce, non che lo
sostituisce.

Privacy: la lista farmaci è dato sanitario sensibile → tutto in memoria,
effimero, nulla esce, nulla persiste.

FONTE: seed curato di interazioni gravi note (linee guida / FDA drug labels /
AIFA). Nel prodotto reale, alimentato da openFDA / DrugBank via API + il quadro
clinico dal medico. Dichiarato come snapshot NON esaustivo: l'assenza di un
alert NON significa 'sicuro' — solo 'non nel registro'. Chiedi al farmacista.
"""
from __future__ import annotations
import hashlib
from itertools import combinations
from typing import Dict, List

# Interazioni GRAVI note (classi di farmaci). Reali, da linee guida cliniche.
# forma: (classe_A, classe_B, gravità, effetto, fonte)
INTERAZIONI = [
    ("warfarin", "fans", "GRAVE", "rischio emorragico aumentato", "FDA label / linee guida anticoagulazione"),
    ("warfarin", "chinolonici", "GRAVE", "aumento INR, rischio sanguinamento", "AIFA / FDA"),
    ("ace-inibitori", "potassio", "GRAVE", "iperkaliemia (potassio alto pericoloso)", "linee guida cardio"),
    ("ace-inibitori", "diuretici-risparmiatori-k", "GRAVE", "iperkaliemia", "linee guida cardio"),
    ("statine", "macrolidi", "GRAVE", "rabdomiolisi (danno muscolare)", "FDA label statine"),
    ("statine", "azoli-antifungini", "GRAVE", "rabdomiolisi", "FDA label statine"),
    ("ssri", "imao", "GRAVE", "sindrome serotoninergica", "linee guida psichiatria"),
    ("nitrati", "inibitori-pde5", "GRAVE", "ipotensione grave (crollo pressione)", "FDA label nitrati/sildenafil"),
    ("oppioidi", "benzodiazepine", "GRAVE", "depressione respiratoria (rischio morte)", "FDA boxed warning"),
    ("metformina", "mezzo-di-contrasto", "MODERATO-GRAVE", "acidosi lattica", "linee guida radiologia"),
]

# Sinonimi comuni → classe (seed; il prodotto reale usa RxNorm)
SINONIMI = {
    "aspirina": "fans", "acido acetilsalicilico": "fans", "ibuprofene": "fans", "ketoprofene": "fans",
    "coumadin": "warfarin", "warfarin": "warfarin",
    "ciprofloxacina": "chinolonici", "levofloxacina": "chinolonici",
    "enalapril": "ace-inibitori", "ramipril": "ace-inibitori", "lisinopril": "ace-inibitori",
    "spironolattone": "diuretici-risparmiatori-k",
    "integratore di potassio": "potassio", "cloruro di potassio": "potassio",
    "atorvastatina": "statine", "simvastatina": "statine", "rosuvastatina": "statine",
    "claritromicina": "macrolidi", "eritromicina": "macrolidi", "azitromicina": "macrolidi",
    "ketoconazolo": "azoli-antifungini", "fluconazolo": "azoli-antifungini",
    "sertralina": "ssri", "paroxetina": "ssri", "fluoxetina": "ssri", "citalopram": "ssri",
    "nitroglicerina": "nitrati", "isosorbide": "nitrati",
    "sildenafil": "inibitori-pde5", "viagra": "inibitori-pde5", "tadalafil": "inibitori-pde5",
    "morfina": "oppioidi", "ossicodone": "oppioidi", "tramadolo": "oppioidi", "fentanyl": "oppioidi",
    "lorazepam": "benzodiazepine", "diazepam": "benzodiazepine", "alprazolam": "benzodiazepine",
    "metformina": "metformina",
}

_DISCLAIMER = ("⚠️ Informazione, non prescrizione. Questo elenco di interazioni NOTE non è "
               "esaustivo: l'assenza di allarme NON significa 'sicuro'. Solo medico e "
               "farmacista conoscono il tuo quadro completo (allergie, reni, dosi, gravidanza). "
               "In caso di sintomi gravi: 112 / pronto soccorso.")


def _classe(farmaco: str) -> str:
    f = farmaco.strip().lower()
    return SINONIMI.get(f, f)


def _sha(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()[:16]


def controlla(farmaci: List[str]) -> Dict:
    """Segnala le interazioni gravi note fra i farmaci dati. Privacy: input
    effimero, non salvato né trasmesso."""
    classi = [(f, _classe(f)) for f in farmaci]
    trovate = []
    for (fa, ca), (fb, cb) in combinations(classi, 2):
        for a, b, grav, eff, fonte in INTERAZIONI:
            if {ca, cb} == {a, b}:
                trovate.append({"farmaci": [fa, fb], "gravita": grav, "effetto": eff,
                                "fonte": fonte, "provenienza_sha": _sha(a + b + fonte)})
    return {
        "n_farmaci": len(farmaci),
        "interazioni_note_trovate": trovate,
        "nessun_allarme": len(trovate) == 0,
        "honest_scope": _DISCLAIMER,
        "privacy": "input effimero: non salvato, non trasmesso",
    }


# ── il banco che SA FALLIRE (controllo positivo + null) ───────────────────────
def banco_controllo() -> Dict:
    pos = [
        (["warfarin", "aspirina"], True),         # coppia grave nota
        (["ramipril", "spironolattone"], True),   # iperkaliemia
        (["atorvastatina", "claritromicina"], True),  # rabdomiolisi
        (["nitroglicerina", "viagra"], True),     # ipotensione
        (["morfina", "lorazepam"], True),         # depressione respiratoria
    ]
    null = [
        (["paracetamolo", "vitamina c"], False),  # nessuna interazione grave nota
        (["atorvastatina"], False),               # farmaco singolo → nessuna coppia
    ]
    pos_ok = sum(1 for f, atteso in pos if (not controlla(f)["nessun_allarme"]) == atteso)
    null_ok = sum(1 for f, atteso in null if (not controlla(f)["nessun_allarme"]) == atteso)
    return {"controllo_positivo": f"{pos_ok}/{len(pos)} coppie gravi rilevate",
            "positivo_passa": pos_ok == len(pos),
            "null": f"{null_ok}/{len(null)} casi sicuri senza falso allarme",
            "null_passa": null_ok == len(null),
            "banco_sa_fallire": pos_ok == len(pos) and null_ok == len(null)}


if __name__ == "__main__":
    import json
    print("═══ BANCO (deve saper fallire: rileva le gravi, non allarma le sicure) ═══")
    print(json.dumps(banco_controllo(), ensure_ascii=False, indent=1))
    print("\n═══ ESEMPIO reale: 4 farmaci di una persona ═══")
    print(json.dumps(controlla(["ramipril", "spironolattone", "atorvastatina", "claritromicina"]),
                     ensure_ascii=False, indent=1))
