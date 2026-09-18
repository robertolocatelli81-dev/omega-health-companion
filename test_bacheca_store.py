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
_PROFILO_PRIMA = [None]


def setUpModule():                         # questi test esercitano il profilo punteggi (default = comunicazione dal 0.7.2). Assegnazione ESPLICITA
    _PROFILO_PRIMA[0] = os.environ.get("OMEGA_PROFILO")   # (non setdefault: un OMEGA_PROFILO esportato non deve cambiare cosa si testa — Gemini+Opus 18/09)
    os.environ["OMEGA_PROFILO"] = "punteggi"              # e in setUpModule, non a livello di modulo: `unittest discover` importa TUTTI i file prima di
                                                          # eseguirli, e un set a import-time vale per il processo intero (misurato 18/09, review Sonnet)


def tearDownModule():                      # ripristino: il profilo non trapela nei file eseguiti dopo
    if _PROFILO_PRIMA[0] is None:
        os.environ.pop("OMEGA_PROFILO", None)
    else:
        os.environ["OMEGA_PROFILO"] = _PROFILO_PRIMA[0]
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
        self.assertEqual(snap["stato_ps"]["stato"], "saturo"); self.assertIsNone(snap["stato_ps"]["sale"])   # chiave presente, valore None
        self.assertIsNone(snap["stato_ps"]["destinazione_alternativa"])      # testo libero: mai su disco (review Opus 18/09)
        with open(self.path, "rb") as fh:
            self.assertNotIn(b"H2", fh.read())
        self.assertEqual(oct(os.stat(self.path).st_mode & 0o777), "0o600")

    def test_sale_esiti_e_chiave_altrove(self):
        r = self._rec(esiti=[{"esito": "percorso_confermato", "operatore_ps": "ps-1", "sale": "SALE-SEGRETO-16B"}])
        st = BS.Store(self.path); st.salva_record(r); st.close()
        st = BS.Store(self.path); e = st.ripristina()["board"][0]["esiti"][0]; st.close()
        self.assertNotIn("sale", e); self.assertEqual(e["esito"], "percorso_confermato")     # il sale del commitment resta in RAM
        self.assertEqual(oct(os.stat(self.path).st_mode & 0o777), "0o600")                    # nato 0600, non chmod dopo
        os.chmod(self.path, 0o644)
        with self.assertRaises(PermissionError):                                               # journal preesistente largo: rifiutato
            BS.Store(self.path)
        os.chmod(self.path, 0o600)
        try:
            os.unlink(self.path + ".lock")                                                     # il tentativo fallito non deve lasciare lock
        except FileNotFoundError:
            pass
        # chiave su un altro percorso (altro supporto)
        k = os.path.join(self.d, "elsewhere.key")
        with mock.patch.dict(os.environ, {BS.KEY_ENV: k}):
            st = BS.Store(os.path.join(self.d, "b2.sqlite")); st.salva_record(self._rec()); st.close()
            self.assertTrue(os.path.exists(k)); self.assertFalse(os.path.exists(os.path.join(self.d, "b2.sqlite.key")))

    def test_niente_in_chiaro_sul_disco(self):
        st = BS.Store(self.path); st.salva_record(self._rec()); st.close()
        with open(self.path, "rb") as fh:
            raw = fh.read()
        for needle in (b"TESTO LIBERO SEGRETO", b"NOTA SEGRETA", b"prealert", b"alert_coscienza", b'"priorita"', b"sepsi"):
            self.assertNotIn(needle, raw, needle)                       # aghi lunghi: nessuna collisione casuale col ciphertext
        chiaro = json.dumps(BS.Store(self.path).ripristina()["board"][0]).encode()
        self.assertIn(b"prealert", chiaro); self.assertIn(b"sepsi", chiaro)   # controllo positivo: in chiaro gli stessi aghi ci sono
        rows = sqlite3.connect(self.path).execute("SELECT k, length(nonce), length(blob) FROM kv").fetchall()
        self.assertEqual(rows[0][0], "rec:7"); self.assertEqual(rows[0][1], 12); self.assertGreater(rows[0][2], 16)

    def test_manomissione_rilevata(self):
        st = BS.Store(self.path); st.salva_record(self._rec()); st.close()
        db = sqlite3.connect(self.path); k, nonce, blob = db.execute("SELECT k, nonce, blob FROM kv").fetchone()
        b = bytearray(blob); b[5] ^= 0x01
        db.execute("UPDATE kv SET blob=? WHERE k=?", (bytes(b), k)); db.commit(); db.close()
        from cryptography.exceptions import InvalidTag
        st = BS.Store(self.path)
        with self.assertRaises(InvalidTag):               # AEAD: un bit cambiato = nessun dato, non dati sbagliati (eccezione PRECISA)
            st.ripristina()
        st.close()
        # controllo positivo: la voce intatta si legge
        st2 = BS.Store(os.path.join(self.d, "b2.sqlite")); st2.salva_record(self._rec()); self.assertEqual(len(st2.ripristina()["board"]), 1)

    def test_nonce_unici_e_chiave_mancante(self):
        st = BS.Store(self.path)
        for i in range(50):
            st.salva_record(self._rec(id=7))                # 50 riscritture della STESSA voce: 50 nonce diversi
        st.salva_incidente({"id": 1, "ts": "t", "aperto_da": "c"}); st.close()
        nonces = [r[0] for r in sqlite3.connect(self.path).execute("SELECT nonce FROM kv").fetchall()]
        self.assertEqual(len(set(nonces)), len(nonces))
        st = BS.Store(self.path); st.salva_record(self._rec(id=7)); st.close()          # riapertura: ancora un nonce nuovo
        n2 = sqlite3.connect(self.path).execute("SELECT nonce FROM kv WHERE k='rec:7'").fetchone()[0]
        self.assertNotIn(n2, nonces[:-1])
        os.rename(self.path + ".key", self.path + ".key.away")                            # chiave assente, journal presente: nessuna chiave nuova
        with self.assertRaises(FileNotFoundError):
            BS.Store(self.path)
        self.assertFalse(os.path.exists(self.path + ".key"))

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
        import scores_emergenza as S
        self._orig = (S.LEDGER, AB.FALLBACK_LEDGER, AB.KEYS_DIR, TC.TOKEN_FILE, AB.MOTORE_DISPONIBILE)   # mai i ledger di produzione (review Opus r2)
        S.LEDGER = os.path.join(self.d, "ledger.jsonl"); AB.FALLBACK_LEDGER = os.path.join(self.d, "fb.jsonl"); AB.KEYS_DIR = os.path.join(self.d, "keys")
        TC.TOKEN_FILE = os.path.join(self.d, "token.txt"); AB.MOTORE_DISPONIBILE = False
        self._env = mock.patch.dict(os.environ, {BS.STORE_ENV: self.path}); self._env.start()
        with TC._LOCK:
            TC.BOARD.clear(); TC.INCIDENTI.clear(); TC._BOARD_SEQ[0] = 0; TC._INCIDENTE_SEQ[0] = 0
        TC._ripristina_da_store()

    def tearDown(self):
        import scores_emergenza as S, shutil
        if TC._STORE[0]: TC._STORE[0].close()
        TC._STORE[0] = None; self._env.stop()
        with TC._LOCK:
            TC.BOARD.clear(); TC.INCIDENTI.clear()
        S.LEDGER, AB.FALLBACK_LEDGER, AB.KEYS_DIR, TC.TOKEN_FILE, AB.MOTORE_DISPONIBILE = self._orig
        shutil.rmtree(self.d, ignore_errors=True)

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
        # cambio di profilo fra un avvio e l'altro: il record scritto in `punteggi` torna SENZA valori decisionali (banco 18/09)
        with TC._LOCK:
            TC.BOARD.clear(); TC._BOARD_SEQ[0] = 0
        TC._STORE[0].close(); TC._STORE[0] = None
        with mock.patch.dict(os.environ, {k: v for k, v in os.environ.items() if k != TC.PROFILO_ENV}, clear=True):   # DEFAULT reale (0.7.2): variabile ASSENTE
            TC._ripristina_da_store()
        r = TC._find(rid); self.assertIsNone(r["tipo_paziente"]); self.assertEqual(r["prealert"]["profilo"], "comunicazione")
        for k in set(TC.CAMPI_DECISIONALI) - {"avvisi"}:   # TUTTA la lista assente (review Opus 18/09) …
            self.assertNotIn(k, r["prealert"], k)
        self.assertEqual(r["prealert"]["avvisi"], [])     # … e avvisi presente ma vuoto (la pagina legge la chiave)
        rec2 = TC._pubblica({"priorita": "BASSO", "eta_paziente": 30}, {"hr": 70}, operatore="eq-2")
        self.assertEqual(rec2["id"], rid + 1)

    def test_errore_journal_dichiarato_in_ogni_risposta(self):
        """Un journal che fallisce dopo la firma non fa cadere la richiesta: la risposta lo DICHIARA e il contatore non si azzera."""
        import threading, urllib.request
        from http.server import ThreadingHTTPServer
        rec = TC._pubblica({"priorita": "ALTO", "eta_paziente": 67}, {"hr": 135}, operatore="eq-1")
        with mock.patch.object(TC._STORE[0], "salva_record", side_effect=OSError("disco pieno")):
            self.assertFalse(TC._persisti_record(rec)); self.assertFalse(TC._persisti_record(rec))
        self.assertEqual(TC._STORE_ERR_N[0], 2); self.assertIn("disco pieno", TC._STORE_ERR[0])
        self.assertTrue(TC._persisti_record(rec)); self.assertEqual(TC._STORE_ERR_N[0], 2)   # il successo non azzera il conteggio
        srv = ThreadingHTTPServer(("127.0.0.1", 0), TC.H); threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            req = urllib.request.Request(f"http://127.0.0.1:{srv.server_address[1]}/stato_ps", data=json.dumps({"stato": "saturo", "operatore_ps": "dr-ps"}).encode(), method="POST",
                                         headers={"Content-Type": "application/json", "X-Omega-Token": TC._token()})
            with urllib.request.urlopen(req, timeout=30) as r:
                body = json.loads(r.read()); hdr = r.headers.get("X-Omega-Journal-Error")
            self.assertIn("disco pieno", body["journal_error"]); self.assertEqual(body["journal_errori_totali"], 2); self.assertEqual(hdr, "2")
            self.assertNotIn("sale", json.dumps(body))                                  # il sale non esce mai da un'API
        finally:
            srv.shutdown(); srv.server_close()
        TC._STORE_ERR[0] = None; TC._STORE_ERR_N[0] = 0

    def test_stato_ps_ripristinato_valido(self):
        """«dirotta» senza destinazione (mai su disco) non torna come tale; uno stato più vecchio del TTL non è attuale."""
        st = TC._STORE[0]
        st.salva_stato_ps({"stato": "dirotta", "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"), "operatore_ps": "dr",
                           "destinazione_alternativa": "Ospedale X", "sale": "S"})
        st.close(); TC._STORE[0] = None
        TC._ripristina_da_store()
        self.assertEqual(TC.STATO_PS["stato"], "saturo"); self.assertTrue(any("dirotta" in x for x in TC.STATO_PS["ripristinato_senza"]))   # direzione prudente
        TC._STORE[0].salva_stato_ps({"stato": "saturo", "ts": (datetime.now(timezone.utc) - timedelta(hours=TC.BOARD_TTL_H + 2)).isoformat(timespec="seconds"),
                                     "operatore_ps": "dr", "destinazione_alternativa": None})
        TC._STORE[0].close(); TC._STORE[0] = None
        TC._ripristina_da_store(); self.assertEqual(TC.STATO_PS["stato"], "accetta")

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
