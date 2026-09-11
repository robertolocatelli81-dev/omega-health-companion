#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""OMEGA — CLI dell'AMBULANZA: manda i dati grezzi al server team-comms, che
calcola il pre-alert (unica fonte di verità) e risponde con priorità/percorsi.

Uso (dal mezzo, qualunque device con Python):
  python3 ambulanza_cli.py --rr 28 --spo2 89 --o2 --sbp 85 --hr 135 --non-alert \\
      --temp 39.4 --eta 67 --arrivo 8 --farmaci warfarin aspirina \\
      [--fast face,arm] [--clinica dolore_toracico] [--server http://127.0.0.1:8097]

Il token è letto da team_token.txt accanto al server (stessa macchina) o da
OMEGA_TEAM_TOKEN (device remoto). Stampa il pre-alert calcolato dal server.
"""
from __future__ import annotations
import argparse
import json
import os
import sys
import urllib.request

_HERE = os.path.dirname(os.path.abspath(__file__))


def _token(args) -> str:
    if args.token:
        return args.token
    env = os.environ.get("OMEGA_TEAM_TOKEN")
    if env:
        return env
    tf = os.path.join(_HERE, "team_token.txt")
    if os.path.exists(tf):
        return open(tf).read().strip()
    sys.exit("token mancante: usa --token, OMEGA_TEAM_TOKEN o team_token.txt")


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="ambulanza", description=__doc__.splitlines()[0])
    p.add_argument("--rr", type=float, required=True, help="frequenza respiratoria /min")
    p.add_argument("--spo2", type=float, required=True, help="SpO2 %%")
    p.add_argument("--o2", action="store_true", help="ossigeno supplementare in corso")
    p.add_argument("--sbp", type=float, required=True, help="pressione sistolica mmHg")
    p.add_argument("--hr", type=float, required=True, help="frequenza cardiaca /min")
    p.add_argument("--non-alert", action="store_true",
                   help="coscienza ALTERATA (AVPU: non Alert)")
    p.add_argument("--temp", type=float, required=True, help="temperatura °C")
    p.add_argument("--eta", type=int, help="età del paziente (anni)")
    p.add_argument("--arrivo", type=int, required=True, help="ETA all'ospedale (min)")
    p.add_argument("--farmaci", nargs="*", default=[], help="farmaci in uso")
    p.add_argument("--fast", default="", help="segni BE-FAST: face,arm,speech,balance,eyes")
    p.add_argument("--clinica", default="",
                   help="flag clinici: gcs=N,meccanismo_maggiore,lesione_penetrante,"
                        "contesto_trauma,assenza_respiro,assenza_polso,dolore_toracico,ecg_stemi")
    p.add_argument("--server", default="http://127.0.0.1:8097")
    p.add_argument("--token")
    a = p.parse_args(argv)

    fast = None
    if a.fast:
        segni = {s.strip() for s in a.fast.split(",") if s.strip()}
        fast = {"face": "face" in segni, "arm": "arm" in segni, "speech": "speech" in segni,
                "balance": "balance" in segni, "eyes": "eyes" in segni}
    clinica = {}
    for tokp in filter(None, (t.strip() for t in a.clinica.split(","))):
        if "=" in tokp:
            k, v = tokp.split("=", 1)
            clinica[k] = int(v)
        else:
            clinica[tokp] = True
    payload = {"vitali": {"rr": a.rr, "spo2": a.spo2, "su_ossigeno": a.o2,
                          "sbp": a.sbp, "hr": a.hr,
                          "alert_coscienza": not a.non_alert, "temp": a.temp},
               "farmaci": a.farmaci, "eta": a.eta, "eta_arrivo_min": a.arrivo,
               "fast_segni": fast, "clinica": clinica or None}
    req = urllib.request.Request(a.server.rstrip("/") + "/valuta",
                                 data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json",
                                          "X-Omega-Token": _token(a)})
    try:
        r = json.loads(urllib.request.urlopen(req, timeout=15).read())
    except Exception as e:  # noqa: BLE001 — sul mezzo serve l'errore, non il traceback
        print(json.dumps({"ok": False, "errore": f"{type(e).__name__}: {e}",
                          "fallback": "comunicazione VOCALE diretta col PS"}, ensure_ascii=False))
        return 1
    pre = r.get("prealert", {})
    print(json.dumps({"ok": r.get("ok"), "id": r.get("id"),
                      "priorita": pre.get("priorita"), "NEWS2": pre.get("NEWS2"),
                      "azione": pre.get("azione_raccomandata"),
                      "percorsi": pre.get("percorsi_attivare"),
                      "avvisi": pre.get("avvisi"),
                      "provenienza": (r.get("provenienza") or {}).get("self_hash", "")[:16]},
                     ensure_ascii=False, indent=1))
    return 0 if r.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
