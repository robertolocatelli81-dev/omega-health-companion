#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""OMEGA health — persistenza OPT-IN e CIFRATA della bacheca (0.7.0).

Per DESIGN la bacheca è effimera (RAM + TTL). Chi opera un pilota però non può perdere i pre-alert in corso a
ogni riavvio (classificazione 18/09/2026: «stato in RAM» = tetto operativo). Questo modulo aggiunge un journal
SQLite che NON cambia la natura del prodotto:

- opt-in: esiste solo se `OMEGA_BOARD_STORE=<file.sqlite>` è impostato; senza, tutto resta come prima;
- cifrato a riposo: ogni voce è AES-256-GCM (chiave 32 byte in `<file>.key`, permessi 0600, generata al primo
  uso) — sul disco non c'è un solo campo clinico in chiaro;
- MAI su disco ciò che oggi è promesso «solo in memoria»: testi liberi (messaggi, note di conferma, descrizione
  incidente), byte degli allegati, coordinate esatte. Al ripristino questi campi tornano vuoti e il record lo
  DICHIARA (`ripristinato_senza`);
- il TTL della bacheca vale anche al ripristino: un record scaduto non torna con i vitali;
- il ledger firmato resta la fonte di verità: il journal è una copia di lavoro, non evidenza. L'AEAD rileva byte
  modificati; NON rileva la cancellazione o il ripristino di una voce a una versione precedente valida (nessun
  MAC d'insieme): chi può scrivere sul file può far sparire un record dalla bacheca, mai dal ledger firmato;
- minaccia coperta: dati a riposo (furto del supporto, smaltimento, copia del solo file). NON coperta: host compromesso
  (chiave e file stanno insieme);
- UN processo: i lock sono di thread. Il server è il ThreadingHTTPServer della libreria standard, non un WSGI
  multi-worker; con più processi sullo stesso file il journal (e operatori.json) si corromperebbero (review 18/09).
"""
from __future__ import annotations
import json
import os
import secrets
import sqlite3
import threading
from typing import Any, Dict, List, Optional, Tuple

STORE_ENV = "OMEGA_BOARD_STORE"

# campi di un record di bacheca che POSSONO andare nel journal (cifrati); tutto il resto NON viene persistito
CAMPI_RECORD = ("id", "ts", "prealert", "vitali", "provenienza", "audit", "incidente_id", "tipo_paziente",
                "triage_start", "triage", "ricezioni", "esiti", "scaduto")
NON_PERSISTITI = ("messaggi", "conferme", "allegati", "posizioni")       # testi liberi, byte, coordinate
CAMPI_INCIDENTE = ("id", "ts", "aperto_da")                                # la descrizione resta SOLO in RAM
STATO_PS_NON_PERSISTITI = ("sale", "destinazione_alternativa")             # il sale del commitment e il testo libero della destinazione


def _aesgcm():
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM   # dipendenza dichiarata dal 0.6.1
    except ImportError as e:
        raise SystemExit(f"{STORE_ENV}: il journal della bacheca è cifrato (AES-256-GCM) e richiede `cryptography`: {e}")
    return AESGCM


class Store:
    def __init__(self, path: str):
        self.path = path
        self.key_path = path + ".key"
        self._lock = threading.Lock()
        # UN processo per journal: lock esclusivo sul file <path>.lock tenuto aperto per tutta la vita dello Store; un secondo
        # processo (worker WSGI, doppio avvio) si ferma subito invece di corrompere sqlite in silenzio (review Haiku 18/09)
        import fcntl
        self._lock_fd = os.open(path + ".lock", os.O_WRONLY | os.O_CREAT, 0o600)
        try:
            fcntl.flock(self._lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            os.close(self._lock_fd)
            raise SystemExit(f"{STORE_ENV}: {path} è già aperto da un altro processo (un solo processo per journal)")
        self._key = self._load_or_create_key()
        self._cipher = _aesgcm()(self._key)               # fail-closed all'apertura; UN solo key schedule (review Gemini 18/09)
        nuovo = not os.path.exists(path)
        self._db = sqlite3.connect(path, check_same_thread=False)
        if nuovo:
            os.chmod(path, 0o600)                             # come la chiave: solo il proprietario (review Opus 18/09)
        self._db.execute("CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, nonce BLOB NOT NULL, blob BLOB NOT NULL)")
        self._db.commit()

    # ── chiave ────────────────────────────────────────────────────────────────────────────────────────────────
    def _load_or_create_key(self) -> bytes:
        if not os.path.exists(self.key_path):
            try:
                fd = os.open(self.key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            except FileExistsError:                        # un altro avvio l'ha appena creata: si legge quella (TOCTOU chiuso da O_EXCL)
                fd = None
            if fd is not None:
                with os.fdopen(fd, "wb") as f:
                    f.write(secrets.token_bytes(32))
        st = os.stat(self.key_path)
        if st.st_mode & 0o077:
            raise PermissionError(f"{self.key_path}: permessi troppo larghi ({oct(st.st_mode & 0o777)}); attesi 0600")
        with open(self.key_path, "rb") as f:
            key = f.read()
        if len(key) != 32:
            raise ValueError(f"{self.key_path}: chiave di {len(key)} byte, attesi 32")
        return key

    # ── primitive cifrate ─────────────────────────────────────────────────────────────────────────────────────
    def _put(self, k: str, obj: Any) -> None:
        nonce = secrets.token_bytes(12)
        data = json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        blob = self._cipher.encrypt(nonce, data, k.encode("utf-8"))   # la chiave della voce è dato associato
        with self._lock:
            self._db.execute("INSERT OR REPLACE INTO kv (k, nonce, blob) VALUES (?, ?, ?)", (k, nonce, blob))
            self._db.commit()

    def _get_all(self, prefix: str) -> List[Tuple[str, Any]]:
        out = []
        with self._lock:
            rows = self._db.execute("SELECT k, nonce, blob FROM kv WHERE k LIKE ?", (prefix + "%",)).fetchall()
        for k, nonce, blob in rows:
            data = self._cipher.decrypt(bytes(nonce), bytes(blob), k.encode("utf-8"))   # AEAD: manomissione = eccezione
            out.append((k, json.loads(data.decode("utf-8"))))
        return out

    def _get_one(self, k: str):
        with self._lock:
            row = self._db.execute("SELECT nonce, blob FROM kv WHERE k = ?", (k,)).fetchone()   # chiave esatta, non LIKE
        if row is None:
            return None
        return json.loads(self._cipher.decrypt(bytes(row[0]), bytes(row[1]), k.encode("utf-8")).decode("utf-8"))

    def _del(self, k: str) -> None:
        with self._lock:
            self._db.execute("DELETE FROM kv WHERE k = ?", (k,))
            self._db.commit()

    # ── API di bacheca ────────────────────────────────────────────────────────────────────────────────────────
    def salva_record(self, rec: Dict[str, Any]) -> None:
        self._put(f"rec:{int(rec['id'])}", {k: rec.get(k) for k in CAMPI_RECORD})

    def dimentica_record(self, rid: int) -> None:
        self._del(f"rec:{int(rid)}")

    def salva_incidente(self, inc: Dict[str, Any]) -> None:
        self._put(f"inc:{int(inc['id'])}", {k: inc.get(k) for k in CAMPI_INCIDENTE})

    def dimentica_incidente(self, iid: int) -> None:
        self._del(f"inc:{int(iid)}")

    def salva_stato_ps(self, stato: Dict[str, Any]) -> None:
        self._put("stato_ps", {k: v for k, v in stato.items() if k not in STATO_PS_NON_PERSISTITI})

    def ripristina(self) -> Dict[str, Any]:
        """Ritorna {"board": [...], "incidenti": [...], "stato_ps": {...}|None}. I record tornano con i campi non
        persistiti VUOTI e con `ripristinato_senza` che lo dichiara; la scadenza (TTL) la applica il chiamante."""
        board = []; senza_ts = 0
        for _, r in sorted(self._get_all("rec:"), key=lambda kv: int(kv[0].split(":")[1])):
            if not isinstance(r.get("ts"), str):           # senza istante il TTL non può decidere: il record NON torna (review Haiku 18/09)
                senza_ts += 1; continue
            r.update({k: [] for k in NON_PERSISTITI})
            r["ripristinato_senza"] = list(NON_PERSISTITI)
            board.append(r)
        incidenti = []
        for _, i in sorted(self._get_all("inc:"), key=lambda kv: int(kv[0].split(":")[1])):
            i["descrizione"] = "(non ripristinata: la descrizione vive solo in memoria)"
            i["ripristinato_senza"] = ["descrizione"]
            incidenti.append(i)
        st = self._get_one("stato_ps")
        if st is not None:
            st["destinazione_alternativa"] = None
            st["ripristinato_senza"] = ["destinazione_alternativa"]
        return {"board": board, "incidenti": incidenti, "stato_ps": st, "scartati_senza_ts": senza_ts}

    def close(self) -> None:
        with self._lock:
            self._db.close()
        try:
            import fcntl
            fcntl.flock(self._lock_fd, fcntl.LOCK_UN); os.close(self._lock_fd)
        except OSError:
            pass


def apri_da_ambiente() -> Optional[Store]:
    path = os.environ.get(STORE_ENV)
    return Store(path) if path else None
