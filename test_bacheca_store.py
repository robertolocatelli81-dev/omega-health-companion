#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Journal cifrato OPT-IN della bacheca (0.7.0): ciò che torna dopo un riavvio, ciò che NON torna per design, la
cifratura a riposo, il TTL al ripristino, i controlli nulli (manomissione, chiave con permessi larghi, senza store)."""
import json
import os
import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

os.environ.setdefault("OMEGA_PACKAGE_DIR", "/nonexistent")
import audit_bridge as AB
import bacheca_store as BS
import team_comms as TC

SAMPLE_REC = {"id": 7, "ts": None, "prealert": {"priorita": "ALTO", "eta_paziente": 67}, "vitali": {"hr": 135, "sbp": 85},
              "provenienza": {"sha256": "ab" * 32}, "audit": {"livello": "firma-locale"}, "incidente_id": None,
              "tipo_paziente": "sepsi", "triage_start": "rosso", "triage": [{"triage_start": "rosso"}], "ricezioni": [],
              "esiti": [], "messaggi": [{"testo": "TESTO LIBERO SEGRETO"}], "conferme": [{"nota": "NOTA SEGRETA"}],
              "allegati": [{"sha256": "cd" * 32}], "posizioni": [{"lat": 46.9, "lon": 7.4}]}


def _ha_crypto():
    try:
        import cryptography  # noqa: F401
        return True
    except ImportError:
        return False


@unittest.skipUnless(_ha_crypto(), "cryptography assente: il journal cifrato non è disponibile (rifiuta l'apertura)")
class TestStore(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.path = os.path.join(self.d, "board.sqlite")

    def _rec(self, **over):
        r = json.loads(json.dumps(SAMPLE_REC)); r["ts"] = datetime.now(timezone.utc).isoformat(); r.update(over); return r

    def test_round_trip_senza_i_campi_solo_memoria(self):
        st = BS.Store(self.path); st.salva_record(self._rec()); st.salva_incidente({"id": 3, "ts": datetime.now(timezone.utc).isoformat(), "descrizione": "VIA ROSSI 12 TARGA XY", "aperto_da": "centrale"})
        st.salva_stato_ps({"stato": "saturo", "ts": "t", "operatore_ps": "dr", "destinazione_alternativa": "H2", "sale": "SALT"}); st.close()
        snap = BS.Store(self.path).ripristina()
        r = snap["board"][0]
        self.assertEqual(r["vitali"], {"hr": 135, "sbp": 85}); self.assertEqual(r["triage_start"], "rosso")
        for k in BS.NON_PERSISTITI:                       # testi liberi, note, byte, coordinate: MAI su disco
            self.assertEqual(r[k], [])
        self.assertEqual(r["ripristinato_senza"], list(BS.NON_PERSISTITI))
        i = snap["incidenti"][0]; self.assertNotIn("VIA ROSSI", i["descrizione"]); self.assertEqual(i["ripristinato_senza"], ["descrizione"])
        self.assertEqual(snap["stato_ps"]["stato"], "saturo"); self.assertNotIn("sale", snap["stato_ps"])
        self.assertIsNone(snap["stato_ps"]["destinazione_alternativa"])      # testo libero: mai su disco (review Opus 18/09)
        with open(self.path, "rb") as fh:
            self.assertNotIn(b"H2", fh.read())
        self.assertEqual(oct(os.stat(self.path).st_mode & 0o777), "0o600")

    def test_niente_in_chiaro_sul_disco(self):
        st = BS.Store(self.path); st.salva_record(self._rec()); st.close()
        with open(self.path, "rb") as fh:
            raw = fh.read()
        for needle in (b"135", b"ALTO", b"sepsi", b"rosso", b"SEGRET", b"prealert", b"46.9"):
            self.assertNotIn(needle, raw, needle)
        rows = sqlite3.connect(self.path).execute("SELECT k, length(nonce), length(blob) FROM kv").fetchall()
        self.assertEqual(rows[0][0], "rec:7"); self.assertEqual(rows[0][1], 12); self.assertGreater(rows[0][2], 16)

    def test_manomissione_rilevata(self):
        st = BS.Store(self.path); st.salva_record(self._rec()); st.close()
        db = sqlite3.connect(self.path); k, nonce, blob = db.execute("SELECT k, nonce, blob FROM kv").fetchone()
        b = bytearray(blob); b[5] ^= 0x01
        db.execute("UPDATE kv SET blob=? WHERE k=?", (bytes(b), k)); db.commit(); db.close()
        with self.assertRaises(Exception):                # AEAD: un bit cambiato = nessun dato, non dati sbagliati
            BS.Store(self.path).ripristina()
        # controllo positivo: la voce intatta si legge
        st2 = BS.Store(os.path.join(self.d, "b2.sqlite")); st2.salva_record(self._rec()); self.assertEqual(len(st2.ripristina()["board"]), 1)

    def test_chiave_permessi_larghi_rifiutata(self):
        st = BS.Store(self.path); st.close()
        os.chmod(self.path + ".key", 0o644)
        with self.assertRaises(PermissionError):
            BS.Store(self.path)

    def test_secondo_processo_rifiutato(self):
        st = BS.Store(self.path)
        import subprocess, sys
        r = subprocess.run([sys.executable, "-c", f"import bacheca_store as BS; BS.Store({self.path!r})"], capture_output=True, text=True,
                           cwd=os.path.dirname(os.path.abspath(BS.__file__)))
        self.assertNotEqual(r.returncode, 0); self.assertIn("un altro processo", r.stderr)
        st.close()
        r = subprocess.run([sys.executable, "-c", f"import bacheca_store as BS; BS.Store({self.path!r}).close()"], capture_output=True, text=True,
                           cwd=os.path.dirname(os.path.abspath(BS.__file__)))
        self.assertEqual(r.returncode, 0, r.stderr)                     # rilasciato il lock, il file si riapre

    def test_senza_variabile_nessuno_store(self):
        with mock.patch.dict(os.environ, {k: v for k, v in os.environ.items() if k != BS.STORE_ENV}, clear=True):
            self.assertIsNone(BS.apri_da_ambiente())


class TestStoreSenzaCrypto(unittest.TestCase):
    @unittest.skipIf(_ha_crypto(), "con cryptography il journal si apre")
    def test_senza_cryptography_rifiuta_apertura(self):
        with self.assertRaises(SystemExit):
            BS.Store(os.path.join(tempfile.mkdtemp(), "b.sqlite"))


@unittest.skipUnless(_ha_crypto() and AB.FIRMA_LOCALE_DISPONIBILE, "serve cryptography (journal cifrato + ledger firmato)")
class TestRipristinoBacheca(unittest.TestCase):
    """team_comms con OMEGA_BOARD_STORE: pubblica → 'riavvio' (svuota la RAM) → ripristino; poi TTL al ripristino."""
    def setUp(self):
        self.d = tempfile.mkdtemp(); self.path = os.path.join(self.d, "board.sqlite")
        self._env = mock.patch.dict(os.environ, {BS.STORE_ENV: self.path}); self._env.start()
        with TC._LOCK:
            TC.BOARD.clear(); TC.INCIDENTI.clear(); TC._BOARD_SEQ[0] = 0; TC._INCIDENTE_SEQ[0] = 0
        TC._ripristina_da_store()

    def tearDown(self):
        if TC._STORE[0]: TC._STORE[0].close()
        TC._STORE[0] = None; self._env.stop()
        with TC._LOCK:
            TC.BOARD.clear(); TC.INCIDENTI.clear()

    def test_pubblica_riavvia_ripristina(self):
        rec = TC._pubblica({"priorita": "ALTO", "eta_paziente": 67, "NEWS2": 9}, {"hr": 135, "sbp": 85}, operatore="eq-1")
        TC._evento_su_record(rec["id"], "messaggi", "messaggio", {"digest": "x"}, "eq-1", {"testo": "TESTO LIBERO"})
        rid = rec["id"]
        with TC._LOCK:                                   # "riavvio": la RAM sparisce
            TC.BOARD.clear(); TC._BOARD_SEQ[0] = 0
        TC._STORE[0].close(); TC._STORE[0] = None
        rip = TC._ripristina_da_store()
        self.assertEqual(rip["record"], 1)
        r = TC._find(rid)
        self.assertIsNotNone(r); self.assertEqual(r["vitali"], {"hr": 135, "sbp": 85}); self.assertEqual(r["prealert"]["priorita"], "ALTO")
        self.assertEqual(r["messaggi"], [])              # il testo libero NON torna, per design
        self.assertIn("messaggi", r["ripristinato_senza"])
        self.assertEqual(TC._BOARD_SEQ[0], rid)          # il contatore riparte dall'ultimo id, non da 0
        rec2 = TC._pubblica({"priorita": "BASSO", "eta_paziente": 30}, {"hr": 70}, operatore="eq-2")
        self.assertEqual(rec2["id"], rid + 1)

    def test_ttl_applicato_al_ripristino(self):
        rec = TC._pubblica({"priorita": "ALTO", "eta_paziente": 67}, {"hr": 135}, operatore="eq-1")
        TC._evento_su_record(rec["id"], "esiti", "esito_clinico", {"diagnosi": "x"}, "ps-1", {"diagnosi_confermata": "STEMI", "operatore_ps": "ps-1"})
        with TC._LOCK:
            rec["ts"] = (datetime.now(timezone.utc) - timedelta(hours=TC.BOARD_TTL_H + 1)).isoformat(); TC._persisti_record(rec)
            TC._scadenza_bacheca()                       # alla scadenza il journal dimentica ANCHE gli esiti (review Opus/Sonnet 18/09)
            TC.BOARD.clear(); TC._BOARD_SEQ[0] = 0
        TC._STORE[0].close(); TC._STORE[0] = None        # il lock di processo ammette UN solo Store aperto: chiudo prima di leggere
        st = BS.Store(self.path); self.assertEqual(st.ripristina()["board"][0]["esiti"], []); st.close()
        with open(self.path, "rb") as f:
            self.assertNotIn(b"STEMI", f.read())          # (cifrato comunque, ma il dato non c'è più)
        TC._ripristina_da_store()
        rec = TC._pubblica({"priorita": "ALTO", "eta_paziente": 67}, {"hr": 135}, operatore="eq-1")
        with TC._LOCK:
            rec["ts"] = (datetime.now(timezone.utc) - timedelta(hours=TC.BOARD_TTL_H + 1)).isoformat()
            TC._persisti_record(rec); TC.BOARD.clear(); TC._BOARD_SEQ[0] = 0
        TC._STORE[0].close(); TC._STORE[0] = None
        rip = TC._ripristina_da_store()
        self.assertEqual(rip["scaduti_al_ripristino"], 1)
        r = TC.BOARD[0]; self.assertIsNone(r["vitali"]); self.assertIsNone(r["prealert"]); self.assertTrue(r["scaduto"])
        # e il journal ha dimenticato i vitali: un secondo ripristino non li fa riapparire (chiudo prima: un solo Store aperto)
        TC._STORE[0].close(); TC._STORE[0] = None
        st = BS.Store(self.path); self.assertIsNone(st.ripristina()["board"][0]["vitali"]); st.close()


if __name__ == "__main__":
    unittest.main()
