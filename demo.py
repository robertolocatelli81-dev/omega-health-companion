#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""OMEGA Ambulanza Intelligente — DEMO leggibile (come l'ospedale vede il pre-alert).

Gira quattro casi clinici realistici e stampa il pre-alert nel formato che il
pronto soccorso riceverebbe. Solo per dimostrazione — score validati, non diagnosi.
"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ambulanza_intelligente as A

CASI = [
    ("Uomo 72, malessere, stabile", dict(rr=16, spo2=98, su_ossigeno=False, sbp=130,
        hr=74, alert_coscienza=True, temp=36.8), ["ramipril"], 72, 20, None, None),
    ("Donna 68, viso storto e braccio debole (sospetto ICTUS)",
        dict(rr=18, spo2=96, su_ossigeno=False, sbp=165, hr=88, alert_coscienza=True, temp=36.9),
        ["warfarin", "aspirina"], 68, 10, {"face": True, "arm": True, "speech": True}, None),
    ("Uomo 59, febbre alta, confuso, ipoteso (sospetto SEPSI)",
        dict(rr=26, spo2=92, su_ossigeno=True, sbp=88, hr=120, alert_coscienza=False, temp=39.6),
        ["metformina"], 59, 12, None, None),  # sepsi: NO contesto trauma
    ("Uomo 45, incidente stradale, arresto (POLITRAUMA + ACR)",
        dict(rr=4, spo2=78, su_ossigeno=True, sbp=60, hr=30, alert_coscienza=False, temp=35.0),
        ["nessuno"], 45, 7, None,
        {"gcs": 3, "meccanismo_maggiore": True, "contesto_trauma": True, "assenza_respiro": True, "assenza_polso": True}),
]


def _riga(t): print("─" * 64); print(t); print("─" * 64)


def demo():
    print("\n" + "=" * 64)
    print("  OMEGA AMBULANZA INTELLIGENTE — pre-alert al pronto soccorso")
    print("  (score validati · non diagnosi · provenienza hash-chained)")
    print("=" * 64)
    for nome, vit, farm, eta, arrivo, fast_s, clin in CASI:
        out = A.valuta_paziente(vit, farm, eta, arrivo, fast_segni=fast_s,
                                clinica=clin, ancora=True)
        pa = out["PRE_ALERT_INTEGRATO"]
        _riga(f"📟 {nome}")
        print(f"   PRIORITÀ: {pa['priorita']}   NEWS2={pa['NEWS2']}   arrivo in {pa['eta_arrivo_stimato_min']} min")
        if pa["percorsi_attivare"]:
            print("   ⚡ PERCORSI DA ATTIVARE:")
            for p in pa["percorsi_attivare"]:
                print(f"      → {p}")
        else:
            print("   (nessun percorso tempo-critico; monitoraggio ordinario)")
        if pa["flag_farmacologico"]:
            for it in pa["interazioni_note"]:
                print(f"   💊 interazione: {' + '.join(it['farmaci'])} → {it['effetto']} [{it['gravita']}]")
        prov = out.get("provenienza_omega", {})
        print(f"   🔒 provenienza OMEGA: {'ancorato ' + prov.get('self_hash','')[:16]+'…' if prov.get('ancorato') else 'n/d'}")
    print("\n" + "=" * 64)
    print("  Confine: il medico dell'ospedale decide. Il sistema lo prepara.")
    print("=" * 64 + "\n")


if __name__ == "__main__":
    demo()
