#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Ricevuta CH EMS verificabile offline (0.7.0): emissione ancorata nel ledger firmato, verifica a tre stati,
controlli nulli (byte diversi, record alterato, firma alterata, chiave non registrata, ricevuta di altro formato);
end-to-end via HTTP (/chems/ingest, /chems/verifica) sui DOCUMENTI PUBBLICATI DALL'IG (copie nel repo)."""
import base64
import json
import os
import tempfile
import threading
import unittest
import urllib.request
from http.server import ThreadingHTTPServer

os.environ.setdefault("OMEGA_PACKAGE_DIR", "/nonexistent")
import audit_bridge as AB
import chems_receipt as CR
import scores_emergenza as S
import team_comms as T

HERE = os.path.dirname(os.path.abspath(__file__))
IG1 = os.path.join(HERE, "examples", "chems_conformance", "ig-Bundle-1-Einsatzprotokoll.json")
OURS = os.path.join(HERE, "examples", "chems_document_sample_minimal.json")


@unittest.skipUnless(AB.FIRMA_LOCALE_DISPONIBILE, "cryptography assente: la ricevuta autosufficiente esiste solo col ledger locale firmato")
class TestRicevuta(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="rcpt_")
        cls._orig = (AB.MOTORE_DISPONIBILE, AB.FALLBACK_LEDGER, AB.KEYS_DIR)
        AB.MOTORE_DISPONIBILE = False
        AB.FALLBACK_LEDGER = os.path.join(cls.tmp, "fb.jsonl"); AB.KEYS_DIR = os.path.join(cls.tmp, "keys")
        cls.doc = open(IG1, "rb").read()

    @classmethod
    def tearDownClass(cls):
        AB.MOTORE_DISPONIBILE, AB.FALLBACK_LEDGER, AB.KEYS_DIR = cls._orig

    def test_emissione_e_verifica_ok(self):
        r = CR.emetti_ricevuta(self.doc, "epcr-nida-test")
        self.assertTrue(r["ok"], r); self.assertEqual(r["digest_di"], "bytes")
        self.assertEqual(r["record"]["azione"], "ingest_chems"); self.assertEqual(r["record"]["alg"], "ed25519")
        self.assertNotIn("patient", json.dumps(r).lower())      # nella ricevuta non viaggia nulla di clinico
        v = CR.verifica_ricevuta(r, self.doc)
        self.assertEqual(v["stato"], "OK", v); self.assertEqual(v["operatore"], "epcr-nida-test"); self.assertEqual(v["chiave"], "registrata")
        # la stessa ricevuta, letta da JSON (come farebbe un terzo), verifica uguale
        v2 = CR.verifica_ricevuta(json.loads(json.dumps(r)), self.doc); self.assertEqual(v2["stato"], "OK")

    def test_controlli_nulli(self):
        r = CR.emetti_ricevuta(self.doc, "epcr-nida-test")
        # byte diversi (un solo carattere): NON verificata, col motivo giusto
        v = CR.verifica_ricevuta(r, self.doc[:-1] + b" ")
        self.assertEqual(v["stato"], "NON_VERIFICATA"); self.assertTrue(any("sha256 dei byte" in p for p in v["problemi"]))
        # record alterato (operatore cambiato dopo la firma)
        r2 = json.loads(json.dumps(r)); r2["record"]["operatore"] = "impostore"
        v = CR.verifica_ricevuta(r2, self.doc); self.assertEqual(v["stato"], "NON_VERIFICATA"); self.assertTrue(any("record alterato" in p for p in v["problemi"]))
        # firma alterata
        r3 = json.loads(json.dumps(r)); sig = bytearray(base64.b64decode(r3["record"]["firma_ed25519_b64"])); sig[0] ^= 1
        r3["record"]["firma_ed25519_b64"] = base64.b64encode(bytes(sig)).decode()
        v = CR.verifica_ricevuta(r3, self.doc); self.assertEqual(v["stato"], "NON_VERIFICATA"); self.assertTrue(any("firma" in p for p in v["problemi"]))
        # chiave sostituita con una valida ma NON registrata → INCONCLUSIVA (firma coerente, operatore non ancorato)
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives import serialization as ser
        sk = Ed25519PrivateKey.generate(); rec = json.loads(json.dumps(r["record"])); rec["operatore"] = "sconosciuto-x"
        canon = CR._canon(rec); import hashlib; d = hashlib.sha256(canon).digest()
        rec["record_sha256"] = d.hex(); rec["firma_ed25519_b64"] = base64.b64encode(sk.sign(d)).decode()
        rec["pubkey_b64"] = base64.b64encode(sk.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)).decode()
        r4 = {**r, "record": rec}; v = CR.verifica_ricevuta(r4, self.doc); self.assertEqual(v["stato"], "INCONCLUSIVA")
        # chiave DIVERSA da quella registrata per un operatore noto → NON verificata
        rec5 = json.loads(json.dumps(rec)); rec5["operatore"] = "epcr-nida-test"
        d5 = hashlib.sha256(CR._canon(rec5)).digest(); rec5["record_sha256"] = d5.hex(); rec5["firma_ed25519_b64"] = base64.b64encode(sk.sign(d5)).decode()
        v = CR.verifica_ricevuta({**r, "record": rec5}, self.doc); self.assertEqual(v["stato"], "NON_VERIFICATA"); self.assertTrue(any("registrata" in p for p in v["problemi"]))
        # formato sconosciuto
        self.assertEqual(CR.verifica_ricevuta({"formato": "x"}, self.doc)["stato"], "NON_VERIFICATA")

    def test_health_verify_vede_la_riga(self):
        CR.emetti_ricevuta(self.doc, "epcr-nida-test")
        import health_verify as HV
        layer, recs = HV.verify_audit(AB.FALLBACK_LEDGER, HV.load_registry(AB.KEYS_DIR), "keys_dir")
        self.assertEqual(layer["status"], "PASS", layer)


@unittest.skipUnless(AB.FIRMA_LOCALE_DISPONIBILE, "cryptography assente")
class TestE2EChems(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="e2e_chems_")
        cls._orig = (S.LEDGER, T.TOKEN_FILE, AB.MOTORE_DISPONIBILE, AB.FALLBACK_LEDGER, AB.KEYS_DIR)
        S.LEDGER = os.path.join(cls.tmp, "ledger.jsonl"); T.TOKEN_FILE = os.path.join(cls.tmp, "token.txt")
        AB.MOTORE_DISPONIBILE = False; AB.FALLBACK_LEDGER = os.path.join(cls.tmp, "fb.jsonl"); AB.KEYS_DIR = os.path.join(cls.tmp, "keys")
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), T.H)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.base = f"http://127.0.0.1:{cls.srv.server_address[1]}"; cls.token = T._token()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown(); S.LEDGER, T.TOKEN_FILE, AB.MOTORE_DISPONIBILE, AB.FALLBACK_LEDGER, AB.KEYS_DIR = cls._orig

    def _post(self, path, data, token=True, headers=None):
        h = {"Content-Type": "application/fhir+json", **({"X-Omega-Token": self.token} if token else {}), **(headers or {})}
        req = urllib.request.Request(self.base + path, data=data, method="POST", headers=h)
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"{}")

    def test_ingest_ig_document_then_verify(self):
        doc = open(IG1, "rb").read()
        st, out = self._post("/chems/ingest", doc, headers={"X-Omega-Operatore": "nida-demo"})
        self.assertEqual(st, 200, out); self.assertTrue(out["ricevuta"]["ok"]); self.assertEqual(out["letto"]["missione"]["numero"], "S12345678")
        self.assertEqual(out["letto"]["stato_documento"], "final")
        st, v = self._post("/chems/verifica", json.dumps({"ricevuta": out["ricevuta"], "documento_b64": base64.b64encode(doc).decode()}).encode(),
                           headers={"Content-Type": "application/json"})
        self.assertEqual(st, 200); self.assertEqual(v["stato"], "OK", v); self.assertEqual(v["operatore"], "nida-demo")
        # byte diversi → NON verificata
        st, v = self._post("/chems/verifica", json.dumps({"ricevuta": out["ricevuta"], "documento_b64": base64.b64encode(doc + b"\n").decode()}).encode(),
                           headers={"Content-Type": "application/json"})
        self.assertEqual(v["stato"], "NON_VERIFICATA")
        # il documento NON è stato conservato dal server: la bacheca non lo contiene, il ledger ha solo digest+campi non clinici
        self.assertFalse(any("S12345678" in json.dumps(r) for r in T.BOARD))
        led = open(AB.FALLBACK_LEDGER, encoding="utf-8").read()
        self.assertIn("ingest_chems", led); self.assertNotIn("Petra", led); self.assertNotIn("Muster", led)

    def test_rifiuti(self):
        self.assertEqual(self._post("/chems/ingest", b"{}", token=False)[0], 401)
        st, out = self._post("/chems/ingest", b'{"resourceType":"Bundle","type":"collection","entry":[]}')
        self.assertEqual(st, 422, out)
        st, out = self._post("/chems/ingest", b"\xff\xfe not json")
        self.assertEqual(st, 422)
        st, out = self._post("/chems/verifica", b"not json", headers={"Content-Type": "application/json"})
        self.assertEqual(st, 400)
        ours = open(OURS, "rb").read()                  # anche il NOSTRO documento passa dall'endpoint di terzi
        st, out = self._post("/chems/ingest", ours); self.assertEqual(st, 200, out); self.assertEqual(out["letto"]["stato_documento"], "preliminary")


if __name__ == "__main__":
    unittest.main()
