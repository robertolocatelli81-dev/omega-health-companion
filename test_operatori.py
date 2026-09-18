#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Identità degli operatori (0.7.0): registro con token hashati, creazione/revoca solo con token admin, l'identità
autenticata vince sul body, modalità pilota OMEGA_REQUIRE_OPERATOR=1 (403 senza operatore), controlli nulli."""
import json
import os
import shutil
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
        OP.REGISTRO = self._o; shutil.rmtree(self.d, ignore_errors=True)

    def test_crea_autentica_revoca(self):
        out = OP.crea("eq-12", "equipaggio"); tok = out["token"]
        raw = open(OP.REGISTRO).read(); self.assertNotIn(tok, raw)           # sul disco solo l'hash
        self.assertEqual(oct(os.stat(OP.REGISTRO).st_mode & 0o777), "0o600")
        self.assertEqual(OP.autentica(tok), {"slug": "eq-12", "ruolo": "equipaggio"})
        self.assertIsNone(OP.autentica(tok[:-1] + "x")); self.assertIsNone(OP.autentica("")); self.assertIsNone(OP.autentica(None))
        self.assertTrue(OP.revoca("eq-12")); self.assertIsNone(OP.autentica(tok)); self.assertFalse(OP.revoca("nessuno"))
        os.chmod(OP.REGISTRO, 0o644)
        with self.assertRaises(PermissionError):          # registro con permessi larghi: rifiutato
            OP.autentica("qualsiasi")
        os.chmod(OP.REGISTRO, 0o600)
        for bad in (("EQ 12", "equipaggio"), ("x", "equipaggio"), ("eq-1", "dio"), (None, "ps"), ("eq.12", "ps"), ("admin", "ps"), ("equipaggio-ambulanza", "equipaggio")):
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
        cls.srv.shutdown(); cls.srv.server_close(); S.LEDGER, T.TOKEN_FILE, AB.MOTORE_DISPONIBILE, AB.FALLBACK_LEDGER, AB.KEYS_DIR, OP.REGISTRO = cls._orig
        shutil.rmtree(cls.tmp, ignore_errors=True)

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
        self.assertEqual(last["dettaglio"]["identita"], "autenticata")          # l'identità è nel record FIRMATO, non solo nella risposta
        # con il solo token admin (retro-compatibile): identità DICHIARATA, e lo dice
        st, out = self._post("/valuta", {**VIT, "operatore": "eq-99"}, {"X-Omega-Token": self.admin})
        self.assertEqual(st, 200); self.assertEqual(out["identita"], "dichiarata")
        self.assertEqual(json.loads(open(AB.FALLBACK_LEDGER, encoding="utf-8").read().strip().splitlines()[-1])["dettaglio"]["identita"], "dichiarata")
        # eq-99 ha ora una chiave nata "dichiarata": registrarlo come operatore è rifiutato senza adotta_chiave (review Opus r2)
        st, out = self._post("/operatori", {"slug": "eq-99", "ruolo": "equipaggio"}, {"X-Omega-Token": self.admin}); self.assertEqual(st, 400); self.assertIn("era dichiarata", out["error"])
        st, out = self._post("/operatori", {"slug": "eq-99", "ruolo": "equipaggio", "adotta_chiave": True}, {"X-Omega-Token": self.admin})
        self.assertEqual(st, 200); self.assertEqual(out["evento"], "creazione_operatore_con_chiave_preesistente")
        # ENTRAMBI gli header: il token operatore decide (banco 18/09: prima vinceva l'admin → identità "dichiarata")
        st, out = self._post("/valuta", {**VIT, "operatore": "impostore"}, {"X-Omega-Token": self.admin, "X-Omega-Operatore-Token": tok})
        self.assertEqual(st, 200); self.assertEqual(out["identita"], "autenticata")
        self.assertEqual(json.loads(open(AB.FALLBACK_LEDGER, encoding="utf-8").read().strip().splitlines()[-1])["operatore"], "eq-7")
        # token operatore presente ma NON valido + admin valido → 401 (nessun declassamento silenzioso)
        st, _ = self._post("/valuta", VIT, {"X-Omega-Token": self.admin, "X-Omega-Operatore-Token": "x" * 43}); self.assertEqual(st, 401)
        # un nome DICHIARATO uguale a uno slug registrato è rifiutato (firmerebbe con la chiave di eq-7)
        st, out = self._post("/valuta", {**VIT, "operatore": "eq-7"}, {"X-Omega-Token": self.admin}); self.assertEqual(st, 403); self.assertIn("registrato", out["error"])
        st, out = self._post("/valuta", {**VIT, "operatore": "EQ.7"}, {"X-Omega-Token": self.admin}); self.assertEqual(st, 403)   # collassa sullo stesso slug
        # un token operatore NON ruota il token di amministrazione (review Opus 18/09)
        st, out = self._post("/ruota-token", {}, {"X-Omega-Operatore-Token": tok}); self.assertEqual(st, 403)
        self.assertEqual(T._token(), self.admin)
        # ri-registrare lo stesso slug è un atto esplicito
        st, out = self._post("/operatori", {"slug": "eq-7", "ruolo": "equipaggio"}, {"X-Omega-Token": self.admin}); self.assertEqual(st, 409)
        st, out = self._post("/operatori", {"slug": "eq-7", "ruolo": "equipaggio", "riemetti": True}, {"X-Omega-Token": self.admin})
        self.assertEqual(st, 200); self.assertEqual(out["evento"], "riemissione_token"); self.assertNotEqual(out["token"], tok); tok = out["token"]
        st, out = self._post("/operatori", {"slug": "eq-7", "ruolo": "ps", "riemetti": True}, {"X-Omega-Token": self.admin}); self.assertEqual(st, 400)   # la riemissione non cambia il ruolo
        # un token operatore NON gestisce gli operatori; un token revocato non entra
        st, _ = self._post("/operatori", {"slug": "eq-8", "ruolo": "ps"}, {"X-Omega-Operatore-Token": tok}); self.assertEqual(st, 403)
        st, _ = self._post("/operatori/revoca", {"slug": "eq-7"}, {"X-Omega-Token": self.admin}); self.assertEqual(st, 200)
        st, _ = self._post("/valuta", VIT, {"X-Omega-Operatore-Token": tok}); self.assertEqual(st, 401)
        st, out = self._post("/operatori", {"slug": "eq-7", "ruolo": "equipaggio", "riemetti": True}, {"X-Omega-Token": self.admin})
        self.assertEqual(out["evento"], "riattivazione_operatore")                            # riattivare un revocato è un evento NOMINATO
        self.assertEqual(OP.elenco()["eq-7"]["storia"][-1]["evento"], "riattivazione_operatore"); self.assertIn("revocato_il", OP.elenco()["eq-7"]["storia"][-1])
        st, _ = self._post("/valuta", VIT, {"X-Omega-Operatore-Token": "x" * 43}); self.assertEqual(st, 401)

    def test_registro_non_leggibile_nominato(self):
        st, out = self._post("/operatori", {"slug": "tmp-1", "ruolo": "ps"}, {"X-Omega-Token": self.admin}); tok = out["token"]
        os.chmod(OP.REGISTRO, 0o644)
        try:
            st, out = self._post("/valuta", VIT, {"X-Omega-Operatore-Token": tok}); self.assertEqual(st, 503); self.assertIn("registro", out["error"])
            req = urllib.request.Request(self.base + "/api/board", headers={"X-Omega-Operatore-Token": tok})
            try:
                urllib.request.urlopen(req, timeout=30); self.fail("GET accettata con registro illeggibile")
            except urllib.error.HTTPError as e:
                self.assertEqual(e.code, 503)
        finally:
            os.chmod(OP.REGISTRO, 0o600)

    def test_modalita_pilota_richiede_operatore(self):
        st, out = self._post("/operatori", {"slug": "ps-1", "ruolo": "ps"}, {"X-Omega-Token": self.admin}); tok = out["token"]
        with mock.patch.dict(os.environ, {OP.REQUIRE_ENV: "1"}):
            st, out = self._post("/valuta", {**VIT, "operatore": "eq-1"}, {"X-Omega-Token": self.admin})
            self.assertEqual(st, 403); self.assertIn("token operatore", out["error"])
            st, out = self._post("/valuta", VIT, {"X-Omega-Operatore-Token": tok}); self.assertEqual(st, 200); self.assertEqual(out["identita"], "autenticata")
            rid = out["id"]
            st, out = self._post("/triage", {"id": rid, "triage_start": "rosso", "operatore": "chiunque"}, {"X-Omega-Token": self.admin}); self.assertEqual(st, 403)
            st, out = self._post("/triage", {"id": rid, "triage_start": "rosso"}, {"X-Omega-Operatore-Token": tok}); self.assertEqual(st, 200, out)
            # il form /conferma e l'upload /allegato non aggirano la modalità pilota (review Opus 18/09)
            import urllib.parse
            form = urllib.parse.urlencode({"token": self.admin, "id": rid, "nota": "ok", "operatore": "dr-impostore"}).encode()
            req = urllib.request.Request(self.base + "/conferma", data=form, method="POST", headers={"Content-Type": "application/x-www-form-urlencoded"})
            try:
                urllib.request.urlopen(req, timeout=30); self.fail("conferma accettata senza operatore")
            except urllib.error.HTTPError as e:
                self.assertEqual(e.code, 403)
            png = (b"\x89PNG\r\n\x1a\n" + b"\x00\x00\x00\rIHDR" + b"\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00" + b"\x90wS\xde"
                   + b"\x00\x00\x00\x00IEND\xaeB`\x82")                   # PNG minimo con i magic byte veri
            req = urllib.request.Request(self.base + f"/allegato/{rid}", data=png, method="POST",
                                         headers={"Content-Type": "image/png", "X-Omega-Token": self.admin, "X-Omega-Operatore": "dr-impostore", "X-Omega-Tipo": "ecg"})
            try:
                urllib.request.urlopen(req, timeout=30); self.fail("allegato accettato senza operatore")
            except urllib.error.HTTPError as e:
                self.assertEqual(e.code, 403)
            self.assertNotIn("dr-impostore", open(AB.FALLBACK_LEDGER).read())
            # in modalità pilota la pagina di loopback NON contiene il token admin e offre un campo per il token operatore
            req = urllib.request.Request(self.base + "/"); page = urllib.request.urlopen(req, timeout=30).read().decode()
            self.assertNotIn(self.admin, page); self.assertIn("token operatore", page)
            # e il form funziona con il token operatore nel campo token
            import urllib.parse
            form = urllib.parse.urlencode({"token": tok, "id": rid, "nota": "stroke team pronto"}).encode()
            req = urllib.request.Request(self.base + "/conferma", data=form, method="POST", headers={"Content-Type": "application/x-www-form-urlencoded"})
            try:
                urllib.request.urlopen(req, timeout=30)
            except urllib.error.HTTPError as e:
                self.assertEqual(e.code, 303)
            # la gestione operatori resta possibile con l'admin anche in modalità pilota; e la rotazione del token non si auto-blocca
            st, out = self._post("/operatori", {"slug": "eq-2", "ruolo": "equipaggio"}, {"X-Omega-Token": self.admin}); self.assertEqual(st, 200); tok_eq = out["token"]
            # atti del PS: un operatore equipaggio NON può registrare la ricezione / lo stato PS; uno con ruolo ps sì
            st, out = self._post("/stato_ps", {"stato": "saturo"}, {"X-Omega-Operatore-Token": tok_eq}); self.assertEqual(st, 403)
            st, out = self._post("/stato_ps", {"stato": "saturo"}, {"X-Omega-Operatore-Token": tok}); self.assertEqual(st, 200, out)
            st, out = self._post("/ruota-token", {}, {"X-Omega-Token": self.admin}); self.assertEqual(st, 200); self.__class__.admin = out["nuovo_token"]
        # nessun evento clinico "chiunque" nel ledger
        self.assertNotIn("chiunque", open(AB.FALLBACK_LEDGER).read())


if __name__ == "__main__":
    unittest.main()
