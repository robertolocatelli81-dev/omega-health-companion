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
    # FIX 2026-09-06 (4-menti): coppia classica mancante — tramadolo è oppioide
    # MA anche serotoninergico: con SSRI → sindrome serotoninergica.
    ("tramadolo-serotoninergico", "ssri", "GRAVE", "sindrome serotoninergica", "FDA label tramadolo"),
    ("doac", "fans", "GRAVE", "rischio emorragico aumentato", "FDA/EMA label DOAC"),
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
    "morfina": "oppioidi", "ossicodone": "oppioidi", "fentanyl": "oppioidi",
    # tramadolo: oppioide E serotoninergico (doppia classe, vedi MULTICLASSE)
    "tramadolo": "oppioidi",
    "lorazepam": "benzodiazepine", "diazepam": "benzodiazepine", "alprazolam": "benzodiazepine",
    "metformina": "metformina",
    "apixaban": "doac", "rivaroxaban": "doac", "edoxaban": "doac", "dabigatran": "doac",
    "eliquis": "doac", "xarelto": "doac",
}

# farmaci che appartengono a PIÙ classi (un solo mapping perdeva le coppie della
# seconda classe — fix 2026-09-06 assieme alla coppia tramadolo+SSRI)
MULTICLASSE = {
    "tramadolo": {"oppioidi", "tramadolo-serotoninergico"},
}

_DISCLAIMER = ("⚠️ Informazione, non prescrizione. Questo elenco di interazioni NOTE non è "
               "esaustivo: l'assenza di allarme NON significa 'sicuro'. Solo medico e "
               "farmacista conoscono il tuo quadro completo (allergie, reni, dosi, gravidanza). "
               "In caso di sintomi gravi: 112 / pronto soccorso.")


# Nomi COMMERCIALI (CH/DE/IT) → classe, per i farmaci come compaiono in un documento CH EMS (Medication.code.display
# di un GTIN, o code.text): il principio attivo NON è nel documento. Mappa esplicita e corta: ciò che non è qui
# viene dichiarato «non riconosciuto» (mai indovinato da una sottostringa). Chiave = prima parola in minuscolo.
COMMERCIALI_CH = {
    "nitrolingual": "nitrati", "nitroglycerin": "nitrati", "isoket": "nitrati",
    "aspirin": "fans", "aspégic": "fans", "aspegic": "fans", "alcacyl": "fans",
    "fentanyl": "oppioidi", "morphin": "oppioidi", "morphine": "oppioidi", "oxynorm": "oppioidi", "targin": "oppioidi",
    "tramal": "tramadolo", "temesta": "benzodiazepine", "dormicum": "benzodiazepine", "valium": "benzodiazepine",
    "midazolam": "benzodiazepine", "marcoumar": "warfarin", "sintrom": "warfarin", "xarelto": "doac", "eliquis": "doac",
    "lixiana": "doac", "pradaxa": "doac", "viagra": "inibitori-pde5", "cialis": "inibitori-pde5",
    "sortis": "statine", "crestor": "statine", "zocor": "statine", "klacid": "macrolidi", "zithromax": "macrolidi",
    "ciproxin": "chinolonici", "tavanic": "chinolonici", "glucophage": "metformina",
}


# ATC (WHO) → classe della tabella interazioni. Prefissi, dal più specifico: la prima corrispondenza vince.
# Fonte del codice ATC per un farmaco svizzero: Swissmedic «Zugelassene Packungen» via GTIN (data/swissmedic_gtin_atc.json).
# Prefissi STRETTI (review Opus 18/09): V08A = solo mezzi iodati (V08C gadolinio NON interagisce con metformina);
# G04BE = solo i PDE5 veri (03 sildenafil, 08 tadalafil, 09 vardenafil, 11 avanafil; NON 01 alprostadil);
# M01A per sottogruppo FANS (NON M01AX glucosamina/condroitina); B01AE07 = solo dabigatran (NON irudine/argatroban);
# niente N05CF (z-drugs: non sono benzodiazepine, l'etichetta sarebbe falsa).
ATC_CLASSE = [
    ("C01DA", "nitrati"),
    ("G04BE03", "inibitori-pde5"), ("G04BE08", "inibitori-pde5"), ("G04BE09", "inibitori-pde5"), ("G04BE11", "inibitori-pde5"),
    ("N01AH", "oppioidi"), ("N02A", "oppioidi"), ("N02AX02", "tramadolo"),
    ("N05BA", "benzodiazepine"), ("N05CD", "benzodiazepine"),
    ("B01AA", "warfarin"), ("B01AE07", "doac"), ("B01AF", "doac"),
    ("M01AB", "fans"), ("M01AC", "fans"), ("M01AE", "fans"), ("M01AG", "fans"), ("M01AH", "fans"), ("N02BA", "fans"), ("B01AC06", "fans"),
    ("C10AA", "statine"), ("J01FA", "macrolidi"), ("J01MA", "chinolonici"),
    ("C09A", "ace-inibitori"), ("C09B", "ace-inibitori"), ("C03DA", "diuretici-risparmiatori-k"),
    ("A10BA02", "metformina"), ("N06AB", "ssri"), ("N06AF", "imao"), ("N06AG", "imao"),
    ("J02AB", "azoli-antifungini"), ("J02AC", "azoli-antifungini"), ("A12BA", "potassio"),
    ("V08A", "mezzo-di-contrasto"),
]

_GTIN_ATC = None
GTIN_SYSTEMS = ("urn:oid:2.51.1.1", "https://www.gs1.org/gtin")   # GS1 GTIN: OID (esempi IG CH EMS) e URI HL7


def _gtin_atc() -> dict:
    global _GTIN_ATC
    if _GTIN_ATC is None:
        try:
            import swissmedic_gtin_atc as D                    # modulo generato (scripts/build_swissmedic_atc.py)
            _GTIN_ATC = {"_provenienza": D.PROVENIENZA, "gtin": D.GTIN_ATC}
        except Exception as e:  # noqa: BLE001 — anche SyntaxError/AttributeError di un modulo scritto a metà (review Sonnet 18/09)
            _GTIN_ATC = {"_provenienza": {"errore": f"{type(e).__name__}: modulo dati non caricato"}, "gtin": {}}
    return _GTIN_ATC


def classe_da_atc(atc: str):
    a = (atc or "").strip().upper()
    for pref, cl in sorted(ATC_CLASSE, key=lambda x: -len(x[0])):     # prefisso più lungo prima (N02AX02 prima di N02A)
        if a.startswith(pref):
            return {"oppioidi", "tramadolo-serotoninergico"} if cl == "tramadolo" else {cl}
    return None


def riconosci_gtin(gtin: str):
    """GTIN svizzero → (classi, atc) via Swissmedic, o None. Dato ufficiale con provenienza nel file dati.
    GTIN-14 con zeri iniziali (forma GS1) normalizzato a 13 cifre; solo cifre."""
    g = str(gtin).strip()
    if not g.isdigit():
        return None
    g = g.lstrip("0") if len(g) > 13 else g
    atc = _gtin_atc()["gtin"].get(g)
    if not atc:
        return None
    cl = classe_da_atc(atc)
    return (cl, atc) if cl else (None, atc)


def riconosci_commerciale(nome: str):
    """Nome commerciale/display di un documento CH EMS → INSIEME di classi (via MULTICLASSE: Tramal = oppioide E
    serotoninergico, come dal GTIN — review Opus/Sonnet 18/09), o None (dichiarato, non inferito)."""
    if not isinstance(nome, str) or not nome.strip():
        return None
    prima = nome.strip().lower().split()[0].strip(",.;()®™")   # «Aspirin® protect» → aspirin (review Gemini 18/09)
    if prima in MULTICLASSE:                                    # principio attivo (sertralina, tramadolo…) o nome commerciale CH
        return set(MULTICLASSE[prima])
    c = SINONIMI.get(prima) or COMMERCIALI_CH.get(prima)
    if not c:
        return None
    return set(MULTICLASSE.get(c, {c}))


def _classi(farmaco: str) -> set:
    f = farmaco.strip().lower()
    if f in MULTICLASSE:
        return set(MULTICLASSE[f])
    if f in SINONIMI:
        return {SINONIMI[f]}
    return riconosci_commerciale(f) or {f}


def _classe(farmaco: str) -> str:      # retro-compatibilità (prima classe)
    return sorted(_classi(farmaco))[0]


def _sha(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()[:16]


def controlla(farmaci: List[str]) -> Dict:
    """Segnala le interazioni gravi note fra i farmaci dati. Privacy: input
    effimero, non salvato né trasmesso."""
    return controlla_classi([(f, _classi(f)) for f in farmaci])


def controlla_classi(classi: List[tuple]) -> Dict:
    """Come `controlla`, ma con le classi GIÀ risolte: [(nome, {classi})]. Usato dal lettore CH EMS, dove la classe
    viene dal codice ATC Swissmedic (GTIN) e non dal nome."""
    farmaci = [f for f, _ in classi]
    trovate = []
    for (fa, ca), (fb, cb) in combinations(classi, 2):
        for a, b, grav, eff, fonte in INTERAZIONI:
            if (a in ca and b in cb) or (a in cb and b in ca):
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
        (["tramadolo", "sertralina"], True),      # serotoninergica (multiclasse)
        (["tramadolo", "lorazepam"], True),       # tramadolo resta anche oppioide
        (["apixaban", "ibuprofene"], True),       # DOAC + FANS
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
