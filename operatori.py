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
- UN processo (lock di thread; file riscritto atomicamente): non eseguire più worker sullo stesso registro.
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
_SLUG = re.compile(r"^[a-z0-9][a-z0-9_-]{1,39}$")     # niente '.': audit_bridge._slug lo mapperebbe a '-' → due operatori, una chiave
# nomi che il server usa come firmatario di sistema o come default dichiarato: registrarli come operatori confonderebbe
# il ledger (chiave condivisa con «admin») o bloccherebbe ogni chiamata in modalità default (review Opus r2)
RISERVATI = frozenset({"admin", "anonimo", "equipaggio-ambulanza", "team-ps", "centrale", "epcr-esterno", "ps", "sistema"})
_LOCK = threading.Lock()


def _h(token: str) -> str:
    # SHA-256 semplice, senza KDF: il token è un segreto casuale a 256 bit (token_urlsafe(32)), non una password;
    # una KDF lenta protegge segreti a bassa entropia, qui non aggiunge sicurezza e rallenterebbe ogni richiesta.
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class _FileLock:
    """Lock di FILE (fcntl) attorno a read-modify-write del registro: due processi sullo stesso registro non si
    sovrascrivono (review Sonnet/Haiku r2). Breve, non esclusivo per la vita del processo."""
    def __init__(self, path: str):
        self.path = path + ".lock"; self.fd = None

    def __enter__(self):
        import fcntl
        self.fd = os.open(self.path, os.O_WRONLY | os.O_CREAT, 0o600)
        fcntl.flock(self.fd, fcntl.LOCK_EX)
        return self

    def __exit__(self, *a):
        import fcntl
        fcntl.flock(self.fd, fcntl.LOCK_UN); os.close(self.fd)


def _load() -> Dict[str, dict]:
    if not os.path.exists(REGISTRO):
        return {}
    st = os.stat(REGISTRO)
    if st.st_mode & 0o077:                              # come la chiave del journal: permessi larghi = rifiuto (review Haiku 18/09)
        raise PermissionError(f"{REGISTRO}: permessi troppo larghi ({oct(st.st_mode & 0o777)}); attesi 0600")
    with open(REGISTRO, encoding="utf-8") as f:
        return json.load(f)


def _save(reg: Dict[str, dict]) -> None:
    tmp = f"{REGISTRO}.{os.getpid()}.{secrets.token_hex(4)}.tmp"      # nome unico + O_EXCL: niente symlink pre-piantati (review Sonnet 18/09)
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(reg, f, ensure_ascii=False, indent=1)
    os.replace(tmp, REGISTRO)


def richiesto() -> bool:
    return os.environ.get(REQUIRE_ENV) == "1"


class SlugEsistente(Exception):
    """Operatore già registrato: la ri-emissione del token è un atto esplicito (riemetti=True)."""


def esiste(nome: str) -> bool:
    """True se `nome` è (o collassa sullo slug di) un operatore registrato, attivo o revocato."""
    if not isinstance(nome, str) or not nome:
        return False
    import audit_bridge as AB
    with _LOCK:
        reg = _load()
    n = AB._slug(nome)
    return any(AB._slug(s) == n for s in reg)


def chiave_preesistente(slug: str) -> bool:
    """True se esiste già una chiave di firma per questo slug nata nell'era «dichiarata» (0.6.x): registrarlo la adotterebbe."""
    import audit_bridge as AB
    return os.path.exists(os.path.join(AB.KEYS_DIR, f"fb-{AB._slug(slug)}.key"))


def crea(slug: str, ruolo: str, riemetti: bool = False, adotta_chiave: bool = False) -> dict:
    """Crea un operatore; con riemetti=True ri-emette il token (e riattiva) di uno esistente, come evento distinto.
    Ritorna il token IN CHIARO una sola volta."""
    if not isinstance(slug, str) or not _SLUG.match(slug):
        raise ValueError("slug operatore: minuscole, cifre, _ - ; 2-40 caratteri")
    if ruolo not in RUOLI:
        raise ValueError(f"ruolo non ammesso: {ruolo!r} (ammessi: {', '.join(RUOLI)})")
    if slug in RISERVATI:
        raise ValueError(f"slug riservato al sistema: {slug!r}")
    import audit_bridge as AB
    token = secrets.token_urlsafe(32)
    while token.startswith("-"):                    # mai un '-' iniziale: `--token <tok>` lo leggerebbe come opzione
        token = secrets.token_urlsafe(32)
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    with _LOCK, _FileLock(REGISTRO):
        reg = _load()
        collisi = [s for s in reg if s != slug and AB._slug(s) == AB._slug(slug)]
        if collisi:
            raise ValueError(f"slug {slug!r} collassa sulla stessa chiave di firma di {collisi[0]!r}")
        if slug in reg and not riemetti:
            raise SlugEsistente(slug)
        prev = reg.get(slug)
        if prev is None and chiave_preesistente(slug) and not adotta_chiave:
            # la chiave esiste già da eventi DICHIARATI (0.6.x): adottarla renderebbe indistinguibili le firme di prima e di
            # dopo. Scelta esplicita dell'amministratore (adotta_chiave=True), registrata nell'evento (review Opus r2)
            raise ValueError(f"per {slug!r} esiste già una chiave di firma dell'era dichiarata: passare adotta_chiave=true per adottarla")
        if prev is None:
            evento = "creazione_operatore" + ("_con_chiave_preesistente" if chiave_preesistente(slug) else ""); ruolo_eff = ruolo
        elif prev.get("attivo"):
            ruolo_eff = prev["ruolo"]                   # ATTIVO: la riemissione NON cambia il ruolo (review Gemini r2)
            if ruolo != ruolo_eff:
                raise ValueError(f"operatore {slug!r} è attivo con ruolo {ruolo_eff!r}: la riemissione non lo cambia (revoca, poi riemetti col nuovo ruolo)")
            evento = "riemissione_token"
        else:
            ruolo_eff = ruolo                           # REVOCATO: riattivazione, anche con un altro ruolo, evento nominato (review Opus r3)
            evento = "riattivazione_operatore" if ruolo == prev["ruolo"] else "riattivazione_operatore_con_cambio_ruolo"
        storia = list((prev or {}).get("storia") or [])
        if prev is not None:
            storia.append({"evento": evento, "ts": now, **({"revocato_il": prev["revocato"]} if prev.get("revocato") else {}),
                           **({"ruolo_precedente": prev["ruolo"]} if ruolo_eff != prev["ruolo"] else {})})
        reg[slug] = {"token_sha256": _h(token), "ruolo": ruolo_eff, "attivo": True,
                     "creato": (prev or {}).get("creato") or now, **({"storia": storia} if storia else {})}
        _save(reg)
    return {"slug": slug, "ruolo": ruolo_eff, "token": token, "evento": evento}


def revoca(slug: str) -> bool:
    with _LOCK, _FileLock(REGISTRO):
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
