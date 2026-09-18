#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""OMEGA health — IDENTITÀ degli operatori (0.7.0). Chiude il buco «token condiviso + nome dichiarato nel body»
(classificazione 18/09: la firma prova l'integrità del record, non CHI era l'operatore).

- Registro `operatori.json` (0600) accanto al server: slug → {sha256 del token, ruolo, creato, attivo}. Il token
  in chiaro esiste solo nella risposta di creazione (una volta) e nella testa dell'operatore.
- Il token del server (team_token.txt) diventa il token di AMMINISTRAZIONE: crea/revoca operatori.
- Con token operatore valido, il nome usato per la FIRMA (chiave Ed25519 per operatore) è quello del registro, non
  quello scritto nel body: il body non può più impersonare.
- Modalità pilota `OMEGA_REQUIRE_OPERATOR=1`: ogni evento clinico richiede un operatore autenticato; il solo token
  admin non basta (403 nominato). Senza la variabile il comportamento resta quello di prima (retro-compatibile) e la
  risposta DICHIARA `identita: "dichiarata"`.
- Limite dichiarato: è identità a livello di servizio (chi possiede il token). Il non-ripudio legale verso terzi
  richiede eID/QTSP: non è qui e non viene promesso.
"""
from __future__ import annotations
import hashlib
import json
import os
import re
import secrets
import threading
from datetime import datetime, timezone
from typing import Dict, Optional

_HERE = os.path.dirname(os.path.abspath(__file__))
REGISTRO = os.path.join(_HERE, "operatori.json")
REQUIRE_ENV = "OMEGA_REQUIRE_OPERATOR"
RUOLI = ("equipaggio", "centrale", "ps", "admin")
_SLUG = re.compile(r"^[a-z0-9][a-z0-9._-]{1,39}$")
_LOCK = threading.Lock()


def _h(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _load() -> Dict[str, dict]:
    if not os.path.exists(REGISTRO):
        return {}
    with open(REGISTRO, encoding="utf-8") as f:
        return json.load(f)


def _save(reg: Dict[str, dict]) -> None:
    tmp = REGISTRO + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(reg, f, ensure_ascii=False, indent=1)
    os.replace(tmp, REGISTRO)


def richiesto() -> bool:
    return os.environ.get(REQUIRE_ENV) == "1"


def crea(slug: str, ruolo: str) -> dict:
    """Crea (o ri-emette il token di) un operatore. Ritorna il token IN CHIARO una sola volta."""
    if not isinstance(slug, str) or not _SLUG.match(slug):
        raise ValueError("slug operatore: minuscole, cifre, . _ - ; 2-40 caratteri")
    if ruolo not in RUOLI:
        raise ValueError(f"ruolo non ammesso: {ruolo!r} (ammessi: {', '.join(RUOLI)})")
    token = secrets.token_urlsafe(32)
    with _LOCK:
        reg = _load()
        reg[slug] = {"token_sha256": _h(token), "ruolo": ruolo, "attivo": True,
                     "creato": datetime.now(timezone.utc).isoformat(timespec="seconds")}
        _save(reg)
    return {"slug": slug, "ruolo": ruolo, "token": token}


def revoca(slug: str) -> bool:
    with _LOCK:
        reg = _load()
        if slug not in reg:
            return False
        reg[slug]["attivo"] = False
        reg[slug]["revocato"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        _save(reg)
    return True


def autentica(token: Optional[str]) -> Optional[dict]:
    """Token operatore → {"slug", "ruolo"} se attivo, altrimenti None. Confronto a tempo costante sull'hash."""
    if not token:
        return None
    h = _h(token)
    with _LOCK:
        reg = _load()
    for slug, rec in reg.items():
        if rec.get("attivo") and secrets.compare_digest(rec.get("token_sha256", ""), h):
            return {"slug": slug, "ruolo": rec["ruolo"]}
    return None


def elenco() -> Dict[str, dict]:
    with _LOCK:
        reg = _load()
    return {s: {k: v for k, v in r.items() if k != "token_sha256"} for s, r in reg.items()}
