#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Identità degli operatori (0.7.0): registro con token hashati, creazione/revoca solo con token admin, l'identità
autenticata vince sul body, modalità pilota OMEGA_REQUIRE_OPERATOR=1 (403 senza operatore), controlli nulli."""
import json
import os
import tempfile
import threading
import unittest
import urllib.request
from http.server import ThreadingHTTPServer
from unittest import mock

os.environ.setdefault("OMEGA_PACKAGE_DIR", "/nonexistent")
import audit_bridge as AB
import operatori as OP
import scores_emergenza as S
import team_comms as T

VIT = {"vitali": {"rr": 28, "spo2": 89, "su_ossigeno": True, "sbp": 85, "hr": 135, "alert_coscienza": True, "temp": 39.4}, "eta": 67, "eta_arrivo_min": 8}


class TestRegistro(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(); self._o = OP.REGISTRO; OP.REGISTRO = os.path.join(self.d, "operatori.json")

    def tearDown(self):
        OP.REGISTRO = self._o

    def test_crea_autentica_revoca(self):
        out = OP.crea("eq-12", "equipaggio"); tok = out["token"]
        raw = open(OP.REGISTRO).read(); self.assertNotIn(tok, raw)           # sul disco solo l'hash
        self.assertEqual(oct(os.stat(OP.REGISTRO).st_mode & 0o777), "0o600")
        self.assertEqual(OP.autentica(tok), {"slug": "eq-12", "ruolo": "equipaggio"})
        self.assertIsNone(OP.autentica(tok[:-1] + "x")); self.assertIsNone(OP.autentica("")); self.assertIsNone(OP.autentica(None))
        self.assertTrue(OP.revoca("eq-12")); self.assertIsNone(OP.autentica(tok)); self.assertFalse(OP.revoca("nessuno"))
        for bad in (("EQ 12", "equipaggio"), ("x", "equipaggio"), ("eq-1", "dio"), (None, "ps")):
            with self.assertRaises(ValueError):
                OP.crea(*bad)


@unittest.skipUnless(AB.FIRMA_LOCALE_DISPONIBILE, "cryptography assente: questi test leggono il ledger locale FIRMATO")
class TestE2EOperatori(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="e2e_op_")
        cls._orig = (S.LEDGER, T.TOKEN_FILE, AB.MOTORE_DISPONIBILE, AB.FALLBACK_LEDGER, AB.KEYS_DIR, OP.REGISTRO)
        S.LEDGER = os.path.join(cls.tmp, "ledger.jsonl"); T.TOKEN_FILE = os.path.join(cls.tmp, "token.txt")
        AB.MOTORE_DISPONIBILE = False; AB.FALLBACK_LEDGER = os.path.join(cls.tmp, "fb.jsonl"); AB.KEYS_DIR = os.path.join(cls.tmp, "keys")
        OP.REGISTRO = os.path.join(cls.tmp, "operatori.json")
        T.BOARD.clear(); T.INCIDENTI.clear()
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), T.H)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.base = f"http://127.0.0.1:{cls.srv.server_address[1]}"; cls.admin = T._token()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown(); S.LEDGER, T.TOKEN_FILE, AB.MOTORE_DISPONIBILE, AB.FALLBACK_LEDGER, AB.KEYS_DIR, OP.REGISTRO = cls._orig

    def _post(self, path, obj, headers):
        req = urllib.request.Request(self.base + path, data=json.dumps(obj).encode(), method="POST", headers={"Content-Type": "application/json", **headers})
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"{}")

    def test_identita_autenticata_vince_sul_body(self):
        st, out = self._post("/operatori", {"slug": "eq-7", "ruolo": "equipaggio"}, {"X-Omega-Token": self.admin})
        self.assertEqual(st, 200, out); tok = out["token"]
        # con il token operatore, il body dice "impostore" ma il ledger firma come eq-7
        st, out = self._post("/valuta", {**VIT, "operatore": "impostore"}, {"X-Omega-Operatore-Token": tok})
        self.assertEqual(st, 200, out); self.assertEqual(out["identita"], "autenticata")
        led = open(AB.FALLBACK_LEDGER, encoding="utf-8").read().strip().splitlines()
        last = json.loads(led[-1]); self.assertEqual(last["operatore"], "eq-7"); self.assertNotIn("impostore", open(AB.FALLBACK_LEDGER).read())
        # con il solo token admin (retro-compatibile): identità DICHIARATA, e lo dice
        st, out = self._post("/valuta", {**VIT, "operatore": "eq-99"}, {"X-Omega-Token": self.admin})
        self.assertEqual(st, 200); self.assertEqual(out["identita"], "dichiarata")
        # un token operatore NON gestisce gli operatori; un token revocato non entra
        st, _ = self._post("/operatori", {"slug": "eq-8", "ruolo": "ps"}, {"X-Omega-Operatore-Token": tok}); self.assertEqual(st, 403)
        st, _ = self._post("/operatori/revoca", {"slug": "eq-7"}, {"X-Omega-Token": self.admin}); self.assertEqual(st, 200)
        st, _ = self._post("/valuta", VIT, {"X-Omega-Operatore-Token": tok}); self.assertEqual(st, 401)
        st, _ = self._post("/valuta", VIT, {"X-Omega-Operatore-Token": "x" * 43}); self.assertEqual(st, 401)

    def test_modalita_pilota_richiede_operatore(self):
        st, out = self._post("/operatori", {"slug": "ps-1", "ruolo": "ps"}, {"X-Omega-Token": self.admin}); tok = out["token"]
        with mock.patch.dict(os.environ, {OP.REQUIRE_ENV: "1"}):
            st, out = self._post("/valuta", {**VIT, "operatore": "eq-1"}, {"X-Omega-Token": self.admin})
            self.assertEqual(st, 403); self.assertIn("token operatore", out["error"])
            st, out = self._post("/valuta", VIT, {"X-Omega-Operatore-Token": tok}); self.assertEqual(st, 200); self.assertEqual(out["identita"], "autenticata")
            rid = out["id"]
            st, out = self._post("/triage", {"id": rid, "triage_start": "rosso", "operatore": "chiunque"}, {"X-Omega-Token": self.admin}); self.assertEqual(st, 403)
            st, out = self._post("/triage", {"id": rid, "triage_start": "rosso"}, {"X-Omega-Operatore-Token": tok}); self.assertEqual(st, 200, out)
            # la gestione operatori resta possibile con l'admin anche in modalità pilota
            st, _ = self._post("/operatori", {"slug": "eq-2", "ruolo": "equipaggio"}, {"X-Omega-Token": self.admin}); self.assertEqual(st, 200)
        # nessun evento clinico "chiunque" nel ledger
        self.assertNotIn("chiunque", open(AB.FALLBACK_LEDGER).read())


if __name__ == "__main__":
    unittest.main()
