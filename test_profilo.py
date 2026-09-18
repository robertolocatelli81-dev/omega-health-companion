#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Profilo d'uso (0.7.0, INTENDED_USE.md): in `comunicazione` NESSUN campo decisionale esce dal server e i campi tolti
sono elencati; in `punteggi` tutto come prima; un profilo sconosciuto ferma l'avvio."""
import json
import os
import tempfile
import threading
import unittest
import urllib.request
from http.server import ThreadingHTTPServer
from unittest import mock

os.environ.setdefault("OMEGA_PACKAGE_DIR", "/nonexistent")
import ambulanza_intelligente as A
import audit_bridge as AB
import scores_emergenza as S
import team_comms as T

VIT = {"vitali": {"rr": 28, "spo2": 89, "su_ossigeno": True, "sbp": 85, "hr": 135, "alert_coscienza": True, "temp": 39.4}, "eta": 67, "eta_arrivo_min": 8,
       "farmaci": ["warfarin", "ibuprofene"]}


class TestProfilo(unittest.TestCase):
    def test_applica_profilo(self):
        out = A.valuta_paziente(VIT["vitali"], VIT["farmaci"], 67, 8)["PRE_ALERT_INTEGRATO"]
        with mock.patch.dict(os.environ, {T.PROFILO_ENV: "comunicazione"}):
            p = T.applica_profilo(dict(out))
            for k in T.CAMPI_DECISIONALI:
                self.assertNotIn(k, p, k)
            self.assertEqual(p["profilo"], "comunicazione"); self.assertIn("NEWS2", p["campi_non_calcolati"]); self.assertIn("interazioni_note", p["campi_non_calcolati"])
            self.assertEqual(p["vitali"], out["vitali"])                     # i vitali restano come inviati
            senza_elenco = {k: v for k, v in p.items() if k != "campi_non_calcolati"}
            for tell in ('"NEWS2":', '"priorita":', "GRAVE", "ALTO", "azione_raccomandata"):   # nessun VALORE decisionale, nemmeno annidato
                self.assertNotIn(tell, json.dumps(senza_elenco), tell)
        with mock.patch.dict(os.environ, {T.PROFILO_ENV: "punteggi"}):
            self.assertEqual(T.applica_profilo(dict(out)), out)
        with mock.patch.dict(os.environ, {T.PROFILO_ENV: "diagnosi"}):
            with self.assertRaises(SystemExit):
                T.profilo()


@unittest.skipUnless(AB.FIRMA_LOCALE_DISPONIBILE, "cryptography assente: questi test leggono il ledger locale FIRMATO")
class TestE2EProfilo(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="e2e_prof_")
        cls._orig = (S.LEDGER, T.TOKEN_FILE, AB.MOTORE_DISPONIBILE, AB.FALLBACK_LEDGER, AB.KEYS_DIR)
        S.LEDGER = os.path.join(cls.tmp, "ledger.jsonl"); T.TOKEN_FILE = os.path.join(cls.tmp, "token.txt")
        AB.MOTORE_DISPONIBILE = False; AB.FALLBACK_LEDGER = os.path.join(cls.tmp, "fb.jsonl"); AB.KEYS_DIR = os.path.join(cls.tmp, "keys")
        T.BOARD.clear()
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), T.H)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.base = f"http://127.0.0.1:{cls.srv.server_address[1]}"; cls.token = T._token()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown(); S.LEDGER, T.TOKEN_FILE, AB.MOTORE_DISPONIBILE, AB.FALLBACK_LEDGER, AB.KEYS_DIR = cls._orig

    def _req(self, method, path, obj=None):
        req = urllib.request.Request(self.base + path, data=json.dumps(obj).encode() if obj is not None else None, method=method,
                                     headers={"Content-Type": "application/json", "X-Omega-Token": self.token})
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.loads(r.read())

    def test_comunicazione_end_to_end(self):
        with mock.patch.dict(os.environ, {T.PROFILO_ENV: "comunicazione"}):
            st, out = self._req("POST", "/valuta", VIT)
            self.assertEqual(st, 200); p = out["prealert"]
            self.assertEqual(p["profilo"], "comunicazione"); self.assertNotIn("NEWS2", p); self.assertNotIn("priorita", p)
            st, board = self._req("GET", "/api/board")
            testo = json.dumps(board)
            for tell in ('"NEWS2":', '"priorita":', '"azione_raccomandata":', '"percorsi_attivare":'):
                self.assertNotIn(tell, testo, tell)
            st, fhir = self._req("GET", f"/fhir/{out['id']}")     # l'export FHIR R4 non contiene RiskAssessment nel profilo comunicazione
            self.assertNotIn("RiskAssessment", json.dumps(fhir))
        # nel ledger firmato non c'è comunque mai un punteggio (digest-only): controllo che regge in entrambi i profili
        self.assertNotIn('"NEWS2":', open(AB.FALLBACK_LEDGER).read())


if __name__ == "__main__":
    unittest.main()
