#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""OMEGA — ponte OPZIONALE verso il motore Part 11 (audit trail + firme elettroniche).

PERCHÉ (Roberto, 2026-09-06: «e se uno dei 6 motori servisse qui dentro»): il
flusso health aveva conferme ANONIME (stringhe) — nessun chi/quando/firma. Il
motore `part11_audit_enterprise` (FDA 21 CFR Part 11, privato) dà esattamente
questo: audit trail §11.10(e) hash-chained e firme elettroniche LEGATE al record
col loro significato (§11.50/§11.70) — la catena medico-legale del pre-alert:
chi l'ha emesso (authorship), chi ha preso in carico i percorsi (responsibility).

CONFINE (stesso di NLnet): il motore è PRIVATO e NON entra nel deliverable open
di health-companion. Questo ponte INTEROPERA: se il motore c'è sul sistema
(deploy OMEGA di Roberto), il livello di audit sale a «part11»; se non c'è,
degrado ONESTO a «base» (le conferme restano, senza firma) — mai un finto verde.

Identità firmatarie: per-operatore, chiavi Ed25519 persistite in `.audit_keys/`
(0600). È un enrollment LEGGERO da pilota (la chiave nasce al primo uso
dell'operatore); in produzione l'enrollment è formale (badge/IAM §11.200) —
dichiarato, non nascosto.
"""
from __future__ import annotations
import base64
import json
import os
import sys
from typing import Dict, Optional

_HERE = os.path.dirname(os.path.abspath(__file__))
# Motore Part 11 OPZIONALE e privato: percorso configurabile (OMEGA_PACKAGE_DIR); senza, firma locale Ed25519
# (`cryptography`); senza nemmeno quella, FirmaNonDisponibile (fail-closed, 0.6.1) salvo OMEGA_HEALTH_ALLOW_UNSIGNED=1.
_OMEGA = os.path.expanduser(os.environ.get("OMEGA_PACKAGE_DIR", "~/omega/omega_package"))
KEYS_DIR = os.path.join(_HERE, ".audit_keys")
TRAIL_PATH = os.path.join(_HERE, "part11_health_ledger.jsonl")
SYSTEM_ID = "omega-health-companion"

MOTORE_DISPONIBILE = False
_err_import = None
try:
    if _OMEGA not in sys.path:
        sys.path.insert(0, _OMEGA)
    from compliance.part11_audit_enterprise import (   # noqa: E402
        AuditAction, Part11AuditTrail, SignatureMeaning)
    from core.crypto_core import AgentIdentity          # noqa: E402
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey    # noqa: E402
    from cryptography.hazmat.primitives import serialization as _ser                  # noqa: E402
    MOTORE_DISPONIBILE = True
except Exception as e:  # noqa: BLE001 — assenza del motore = degrado onesto, non crash
    _err_import = f"{type(e).__name__}: {e}"

_trail: Optional["Part11AuditTrail"] = None
_identita: Dict[str, "AgentIdentity"] = {}

# ── FALLBACK APERTO «firma-locale» (2026-09-06) ───────────────────────────────
# Il claim pubblico («le conferme portano una firma elettronica legata al
# record») deve essere VERO anche per chi clona questo repo senza il motore
# Part 11: se `cryptography` è installata, il ponte firma comunque — Ed25519
# per-operatore (chiavi 0600), firma su SHA-256 del record canonico, ledger
# JSONL append-only. Meno ricco del motore (niente §11.50 meanings/§11.10(e)
# semantics complete) e DICHIARATO come livello «firma-locale», mai «part11».
FALLBACK_LEDGER = os.path.join(_HERE, "audit_locale_ledger.jsonl")
try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # noqa: E402
        Ed25519PrivateKey as _EdSk, Ed25519PublicKey as _EdPk)
    from cryptography.hazmat.primitives import serialization as _ser  # noqa: E402
    FIRMA_LOCALE_DISPONIBILE = True
except Exception:  # noqa: BLE001
    FIRMA_LOCALE_DISPONIBILE = False



# ── LIVELLO «base» = NESSUNA FIRMA: fail-closed (2026-09-18) ─────────────────
# Il claim pubblico è «ogni evento clinico è firmato». Senza motore Part 11 e senza `cryptography`
# (dichiarata come dipendenza dal 0.6.1) il ponte NON registra eventi non firmati in silenzio: alza
# FirmaNonDisponibile. Chi vuole davvero un trail non firmato (banco, demo su stdlib nudo) lo dice
# esplicitamente con OMEGA_HEALTH_ALLOW_UNSIGNED=1 e ottiene il livello «base» DICHIARATO.
PERMETTI_NON_FIRMATO_ENV = "OMEGA_HEALTH_ALLOW_UNSIGNED"


class FirmaNonDisponibile(RuntimeError):
    """Nessun motore di firma disponibile e OMEGA_HEALTH_ALLOW_UNSIGNED non è '1'."""


def firma_disponibile() -> bool:
    return bool(MOTORE_DISPONIBILE or FIRMA_LOCALE_DISPONIBILE)


def esigi_firma_o_optin(chi: str = "omega-health") -> None:
    """Da chiamare all'avvio di ogni entry point (server, CLI): senza motore di firma e senza opt-in esplicito
    esce SUBITO con un messaggio nominato, invece di fallire alla prima registrazione (Opus review 18/09)."""
    if not firma_disponibile() and os.environ.get(PERMETTI_NON_FIRMATO_ENV) != "1":
        raise SystemExit(f"{chi}: nessun motore di firma (installa `cryptography`); per un trail NON firmato "
                         f"di proposito imposta {PERMETTI_NON_FIRMATO_ENV}=1")


def _livello_base(nota: str = "né motore Part 11 né cryptography: nessuna firma", **extra) -> Dict:
    if os.environ.get(PERMETTI_NON_FIRMATO_ENV) != "1":
        raise FirmaNonDisponibile(nota + f" — installa `cryptography` (dipendenza dichiarata) oppure imposta "
                                  f"{PERMETTI_NON_FIRMATO_ENV}=1 per registrare eventi NON firmati di proposito")
    return {"livello": "base", "nota": nota, **extra}


def _fb_key(operatore: str) -> "_EdSk":
    slug = _slug(operatore) or "anonimo"
    os.makedirs(KEYS_DIR, exist_ok=True)
    path = os.path.join(KEYS_DIR, f"fb-{slug}.key")
    if os.path.exists(path):
        raw = base64.b64decode(open(path).read().strip())
        sk = _EdSk.from_private_bytes(raw)
        if not os.path.exists(os.path.join(KEYS_DIR, f"fb-{slug}.pub")):
            _fb_registra_pubkey(slug, sk)          # chiave nata prima del registro (13/09)
        return sk
    sk = _EdSk.generate()
    raw = sk.private_bytes(_ser.Encoding.Raw, _ser.PrivateFormat.Raw,
                           _ser.NoEncryption())
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(base64.b64encode(raw).decode())
    _fb_registra_pubkey(slug, sk)
    return sk


def _fb_registra_pubkey(slug: str, sk: "_EdSk") -> None:
    """Registro delle chiavi PUBBLICHE per operatore (`fb-<slug>.pub`, 2026-09-13, council): il verbale
    verifica una firma SOLO contro la chiave registrata dell'operatore, mai contro la chiave scritta
    nella riga stessa (con quella, chi riscrive il ledger ri-firma con una chiave propria e passa)."""
    pk = sk.public_key().public_bytes(_ser.Encoding.Raw, _ser.PublicFormat.Raw)
    with open(os.path.join(KEYS_DIR, f"fb-{slug}.pub"), "w") as f:
        f.write(base64.b64encode(pk).decode())


def fb_pubkey_registrata(operatore: str) -> Optional[str]:
    """Chiave pubblica registrata (base64) dell'operatore, o None se mai registrata (fail-closed)."""
    slug = _slug(operatore) or "anonimo"
    path = os.path.join(KEYS_DIR, f"fb-{slug}.pub")
    if not os.path.exists(path):
        # chiave privata presente ma .pub mancante (installazioni precedenti al 13/09): derivala una volta
        kpath = os.path.join(KEYS_DIR, f"fb-{slug}.key")
        if os.path.exists(kpath) and FIRMA_LOCALE_DISPONIBILE:
            _fb_registra_pubkey(slug, _EdSk.from_private_bytes(base64.b64decode(open(kpath).read().strip())))
        else:
            return None
    with open(path) as f:
        return f.read().strip()


def ultimo_id(prefisso: str) -> int:
    """Highest N of a `<prefisso>-N` target in the signed local ledger (0 if none): an in-memory counter must
    continue from here after a restart, or a new record would reuse an old id in the signed history.
    Prefixes in use: `prealert` (board) and `incidente` (multi-patient incidents, since 0.6.1)."""
    if not os.path.exists(FALLBACK_LEDGER):
        return 0
    best = 0
    rx = __import__("re").compile(r'"target":\s*"' + __import__("re").escape(prefisso) + r'-(\d+)')
    with open(FALLBACK_LEDGER, encoding="utf-8") as f:
        for line in f:
            m = rx.search(line)
            if m:
                best = max(best, int(m.group(1)))
    return best


def ultimo_id_prealert() -> int:
    return ultimo_id("prealert")


def enrol_legacy_keys() -> Dict[str, int]:
    """EXPLICIT enrolment (never during verification): derive `fb-<slug>.pub` for every `fb-<slug>.key` that
    has no registered public key (installations older than 13/09/2026)."""
    n = 0
    if os.path.isdir(KEYS_DIR) and FIRMA_LOCALE_DISPONIBILE:
        for name in sorted(os.listdir(KEYS_DIR)):
            if name.startswith("fb-") and name.endswith(".key") and not os.path.exists(os.path.join(KEYS_DIR, name[:-4] + ".pub")):
                with open(os.path.join(KEYS_DIR, name)) as f:
                    _fb_registra_pubkey(name[3:-4], _EdSk.from_private_bytes(base64.b64decode(f.read().strip())))
                n += 1
    return {"registrate": n}


def _fb_ultimo_sha256() -> str:
    """Ultimo record_sha256 del ledger locale (o GENESIS): l'anello per la catena prev_sha256."""
    if not os.path.exists(FALLBACK_LEDGER):
        return "GENESIS"
    last = None
    with open(FALLBACK_LEDGER, encoding="utf-8") as f:
        for line in f:
            if line.strip():
                last = line
    if not last:
        return "GENESIS"
    try:
        e = json.loads(last)
    except ValueError as ex:
        # fail-closed (council 15/09, Haiku): a torn/corrupt last line used to send the next record back to
        # GENESIS — a silent fork of the chain. The operator must repair the file, not the code hide it.
        raise ValueError(f"ultima riga del ledger illeggibile ({ex.msg}): append rifiutato, riparare il file") from None
    if not isinstance(e, dict) or not isinstance(e.get("record_sha256"), str):
        raise ValueError("ultima riga del ledger senza record_sha256: append rifiutato")
    return e["record_sha256"]


_FB_LOCK = __import__("threading").Lock()


def _no_floats(obj, path="dettaglio"):
    """Signed records carry NO floats (council 15/09, five minds): Python, JS, Go and Rust do not print floats the
    same way, so a re-serialising verifier could never agree. Integers, strings, bools, null only."""
    if isinstance(obj, bool) or obj is None or isinstance(obj, (int, str)):
        return
    if isinstance(obj, float):
        raise ValueError(f"{path}: float non ammesso in un record firmato (usa interi: es. latenza_ms) — valore {obj!r}")
    if isinstance(obj, dict):
        for k, v in obj.items():
            if not isinstance(k, str):
                raise ValueError(f"{path}: chiave non stringa")
            _no_floats(v, f"{path}.{k}")
    elif isinstance(obj, (list, tuple)):
        for i, v in enumerate(obj):
            _no_floats(v, f"{path}[{i}]")
    else:
        raise ValueError(f"{path}: tipo non serializzabile {type(obj).__name__}")


def _fb_registra(target_id: str, azione: str, dettaglio: Dict, operatore: str) -> Dict:
    """prev_sha256 letto e riga scritta sotto UN lock di PROCESSO (fcntl.flock sul file .lock, come mission_case) e
    di thread: due worker (CLI + server, gunicorn) che leggevano la stessa coda forkavano la catena per sempre
    (council 15/09, quattro menti)."""
    import fcntl
    _no_floats(dettaglio)
    os.makedirs(os.path.dirname(FALLBACK_LEDGER) or ".", exist_ok=True)
    with _FB_LOCK, open(FALLBACK_LEDGER + ".lock", "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            return _fb_registra_locked(target_id, azione, dettaglio, operatore)
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)


def _fb_registra_locked(target_id: str, azione: str, dettaglio: Dict, operatore: str) -> Dict:
    import hashlib
    # prev_sha256 (2026-09-13, council): catena hash FIRMATA fra le righe. Senza, cancellare o
    # riordinare una riga (es. la ricezione con risposta alternativa) era invisibile al verbale.
    rec = {"kind": "audit_locale", "target": target_id, "azione": azione,
           "dettaglio": dettaglio, "operatore": operatore,
           "ts": __import__("datetime").datetime.now(
               __import__("datetime").timezone.utc).isoformat(timespec="seconds"),
           "prev_sha256": _fb_ultimo_sha256(),
           "alg": "ed25519"}      # crypto-agility: the signature scheme is a DECLARED, signed field (v0.5.0)
    # canonical ASCII profile (FORMAT.md): sort_keys, compact, ensure_ascii=True, no NaN — the SIGNED bytes
    canon = json.dumps(rec, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()
    digest = hashlib.sha256(canon).digest()
    sk = _fb_key(operatore)
    sig = sk.sign(digest)
    pk = sk.public_key().public_bytes(_ser.Encoding.Raw, _ser.PublicFormat.Raw)
    entry = {**rec, "record_sha256": digest.hex(),
             "firma_ed25519_b64": base64.b64encode(sig).decode(),
             "pubkey_b64": base64.b64encode(pk).decode()}
    with open(FALLBACK_LEDGER, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    if not os.path.exists(os.path.join(KEYS_DIR, f"fb-{_slug(operatore) or 'anonimo'}.pub")):
        _fb_registra_pubkey(_slug(operatore) or "anonimo", sk)      # chiavi nate prima del registro
    # verifica immediata (mai un verde non provato)
    try:
        _EdPk.from_public_bytes(pk).verify(sig, digest)
        ok = True
    except Exception:  # noqa: BLE001
        ok = False
    return {"livello": "firma-locale", "record_sha256": digest.hex(),
            "firma_verificata": ok, "firmatario": operatore,
            "riga": entry,      # la riga scritta, per chi deve costruire una ricevuta senza rileggere il ledger (0.7.0)
            "nota": ("firma Ed25519 per-operatore legata al record (fallback aperto); "
                     "il motore Part 11 completo aggiunge i significati §11.50")}


def _get_trail() -> "Part11AuditTrail":
    global _trail
    if _trail is None:
        _trail = Part11AuditTrail(TRAIL_PATH, SYSTEM_ID)
    return _trail


def _slug(operatore: str) -> str:
    return "".join(c if c.isalnum() or c in "-_" else "-" for c in operatore.strip().lower())[:40]


def _identity(operatore: str) -> "AgentIdentity":
    """Chiave per-operatore, persistita (0600): la firma è dell'OPERATORE, non
    del server — enrollment leggero da pilota, dichiarato nella docstring."""
    slug = _slug(operatore) or "anonimo"
    if slug in _identita:
        return _identita[slug]
    os.makedirs(KEYS_DIR, exist_ok=True)
    path = os.path.join(KEYS_DIR, f"{slug}.json")
    if os.path.exists(path):
        with open(path) as f:
            d = json.load(f)
        ident = AgentIdentity(
            agent_id=d["agent_id"],
            ed25519_sk=Ed25519PrivateKey.from_private_bytes(base64.b64decode(d["ed25519"])),
            x25519_sk=X25519PrivateKey.from_private_bytes(base64.b64decode(d["x25519"])))
    else:
        ident = AgentIdentity.generate(f"health-op-{slug}")
        raw = lambda sk: base64.b64encode(sk.private_bytes(          # noqa: E731
            _ser.Encoding.Raw, _ser.PrivateFormat.Raw, _ser.NoEncryption())).decode()
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump({"agent_id": ident.agent_id,
                       "ed25519": raw(ident.ed25519_sk), "x25519": raw(ident.x25519_sk)}, f)
    _identita[slug] = ident
    return ident


def registra_prealert(prealert_id: str, prealert_sha256: str, operatore: str) -> Dict:
    """Pre-alert emesso → record CREATE nell'audit trail + firma AUTHORSHIP
    dell'equipaggio. Nel trail va il DIGEST del pre-alert, mai i dati sanitari."""
    if not MOTORE_DISPONIBILE:
        if FIRMA_LOCALE_DISPONIBILE:
            return _fb_registra(prealert_id, "emissione",
                                {"prealert_sha256": prealert_sha256}, operatore)
        return _livello_base()
    t = _get_trail()
    rec = t.log_change(operatore, AuditAction.CREATE, prealert_id,
                       reason="emissione pre-alert ambulanza",
                       new_value={"prealert_sha256": prealert_sha256})
    ident = _identity(operatore)
    es = t.sign_record(rec, ident, printed_name=operatore, meaning=SignatureMeaning.AUTHORSHIP)
    return {"livello": "part11", "record_sha3": rec.canonical_hash(),
            "firma_verificata": t.verify_signature_for_record(es, rec),
            "firmatario": operatore, "significato": "authorship"}


def _impronta_nota(nota: str) -> Dict:
    """FIX 2026-09-11 (round 3): la nota libera del PS finiva IN CHIARO su disco (audit_locale_ledger
    e trail Part 11) — misurato: «paziente MARIO ROSSI CF RSSMRA…» ritrovato nel file, mentre PRIVACY
    prometteva «no health data at rest». Su disco va SOLO l'impronta: chi ha la nota (in bacheca,
    effimera) può provare che è quella; chi ha il disco non legge nulla."""
    import hashlib
    n = (nota or "")[:100]
    return {"nota_sha256": hashlib.sha256(n.encode("utf-8")).hexdigest(), "nota_len": len(n)}


def registra_conferma(prealert_id: str, nota: str, operatore: str) -> Dict:
    """Conferma del team PS → record CREATE (conferma) + firma RESPONSIBILITY:
    chi ha preso in carico il percorso, quando — firmato. La nota è legata per DIGEST, mai in chiaro."""
    impronta = _impronta_nota(nota)
    if not MOTORE_DISPONIBILE:
        if FIRMA_LOCALE_DISPONIBILE:
            return _fb_registra(f"{prealert_id}/conferma", "presa_in_carico", impronta, operatore)
        return _livello_base()
    t = _get_trail()
    rec = t.log_change(operatore, AuditAction.CREATE, f"{prealert_id}/conferma",
                       reason=f"presa in carico (nota legata per digest {impronta['nota_sha256'][:16]}…)",
                       new_value=impronta)
    ident = _identity(operatore)
    es = t.sign_record(rec, ident, printed_name=operatore,
                       meaning=SignatureMeaning.RESPONSIBILITY)
    return {"livello": "part11", "record_sha3": rec.canonical_hash(),
            "firma_verificata": t.verify_signature_for_record(es, rec),
            "firmatario": operatore, "significato": "responsibility"}


def registra_ricezione(prealert_id: str, dettaglio: Dict, operatore_ps: str) -> Dict:
    """Ricezione del pre-alert nel PS (linea guida RCEM/AACE 2025: «recorded line», clinico senior che
    attua la risposta, risposta alternativa discussa apertamente) → record CREATE + firma RESPONSIBILITY
    di chi ha ricevuto. `dettaglio` è già a valori chiusi + digest (verbale_probatorio.registra_ricezione):
    nel trail non entra testo libero. Separato da registra_conferma: significato diverso (ricevere e decidere
    la risposta ≠ prendere in carico il percorso)."""
    if not MOTORE_DISPONIBILE:
        if FIRMA_LOCALE_DISPONIBILE:
            return _fb_registra(f"{prealert_id}/ricezione", "ricezione_pre_alert", dettaglio, operatore_ps)
        return _livello_base()
    t = _get_trail()
    rec = t.log_change(operatore_ps, AuditAction.CREATE, f"{prealert_id}/ricezione",
                       reason=(f"ricezione pre-alert PS: richiesta {dettaglio.get('risposta_richiesta')} → "
                               f"attuata {dettaglio.get('risposta_attuata')}"),
                       new_value=dettaglio)
    ident = _identity(operatore_ps)
    es = t.sign_record(rec, ident, printed_name=operatore_ps,
                       meaning=SignatureMeaning.RESPONSIBILITY)
    return {"livello": "part11", "record_sha3": rec.canonical_hash(),
            "firma_verificata": t.verify_signature_for_record(es, rec),
            "firmatario": operatore_ps, "significato": "responsibility"}


def registra_evento_clinico(prealert_id: str, azione: str, dettaglio: Dict, operatore: str) -> Dict:
    """Eventi di coordinamento firmati (13/09/2026, coordinamento.py): aggiornamento ETA/posizione, messaggio
    (per digest), allegato (per digest), esito clinico «close the loop». `dettaglio` arriva già a valori chiusi
    o digest: nel trail non entra testo libero né byte. Significato RESPONSIBILITY (chi lo dichiara ne risponde)."""
    if not MOTORE_DISPONIBILE:
        if FIRMA_LOCALE_DISPONIBILE:
            return _fb_registra(f"{prealert_id}/{azione}", azione, dettaglio, operatore)
        return _livello_base()
    t = _get_trail()
    rec = t.log_change(operatore, AuditAction.CREATE, f"{prealert_id}/{azione}",
                       reason=f"evento di coordinamento: {azione}", new_value=dettaglio)
    ident = _identity(operatore)
    es = t.sign_record(rec, ident, printed_name=operatore, meaning=SignatureMeaning.RESPONSIBILITY)
    return {"livello": "part11", "record_sha3": rec.canonical_hash(),
            "firma_verificata": t.verify_signature_for_record(es, rec),
            "firmatario": operatore, "significato": "responsibility"}


def registra_evento_sistema(target_id: str, azione: str, motivo: str, operatore: str,
                            nota_rimossa: Optional[str] = None) -> Dict:
    """Evento AMMINISTRATIVO (rimozione di una nota dalla bacheca, rotazione del token): il MOTIVO
    resta in chiaro (è la giustificazione dell'operatore, richiesta dalla disciplina Part 11 — «mai
    silenziosa»), mentre l'eventuale NOTA CLINICA rimossa è legata per digest, mai in chiaro.
    Separato da registra_conferma (round 3, 11/09): riusarla per questi eventi li marcava «presa in
    carico» con firma RESPONSIBILITY — significato falso — e, dopo il fix privacy, hashava anche il motivo."""
    dettaglio: Dict = {"azione": azione, "motivo": (motivo or "")[:120]}
    if nota_rimossa is not None:
        dettaglio["nota_rimossa"] = _impronta_nota(nota_rimossa)
    if not MOTORE_DISPONIBILE:
        if FIRMA_LOCALE_DISPONIBILE:
            return _fb_registra(target_id, azione, dettaglio, operatore)
        return _livello_base()
    t = _get_trail()
    act = AuditAction.DELETE if azione.startswith("rimozione") else AuditAction.MODIFY
    # §11.10(e): su modifica/cancellazione il valore precedente NON si oscura. Qui il "precedente" è
    # legato per digest quando è una nota clinica (mai in chiaro su disco) o descritto quando è un segreto
    # (il token non viene MAI registrato, né vecchio né nuovo).
    precedente = ({"nota": dettaglio["nota_rimossa"]} if "nota_rimossa" in dettaglio
                  else {"token": "revocato — i token non vengono registrati nel trail"})
    rec = t.log_change(operatore, act, target_id, reason=f"{azione}: {dettaglio['motivo']}",
                       old_value=precedente, new_value=dettaglio)
    ident = _identity(operatore)
    es = t.sign_record(rec, ident, printed_name=operatore, meaning=SignatureMeaning.AUTHORSHIP)
    return {"livello": "part11", "record_sha3": rec.canonical_hash(),
            "firma_verificata": t.verify_signature_for_record(es, rec),
            "firmatario": operatore, "significato": "authorship", "azione": azione}


def verifica_trail() -> Dict:
    """Riverifica l'intero audit trail (catena + content-binding dei record e
    delle firme) col verificatore del motore. Onesto se il motore manca."""
    if not MOTORE_DISPONIBILE:
        return {"livello": "base", "motore": False, "import_error": _err_import}
    return {"livello": "part11", "motore": True, **_get_trail().verify()}


# ── banco che SA FALLIRE ──────────────────────────────────────────────────────
def banco_controllo() -> Dict:
    if not MOTORE_DISPONIBILE:
        return {"motore": False, "degrado_onesto": True, "banco_sa_fallire": True,
                "nota": "senza motore il ponte dichiara 'base', mai un finto part11"}
    import tempfile
    global _trail, KEYS_DIR
    orig_trail, orig_keys, orig_ids = _trail, KEYS_DIR, dict(_identita)
    tmp = tempfile.mkdtemp(prefix="p11_health_")
    try:
        KEYS_DIR = os.path.join(tmp, "keys")     # sandbox: mai chiavi demo in produzione
        _identita.clear()
        _trail = Part11AuditTrail(os.path.join(tmp, "trail.jsonl"), SYSTEM_ID)
        r1 = registra_prealert("PA-1", "ab" * 32, "equipaggio-118-demo")
        r2 = registra_conferma("PA-1", "stroke team pronto", "dr-demo-ps")
        v = _get_trail().verify()
        # chiavi VERE del verdetto del motore: record_digests_bound + records_checked
        positivo = (r1["livello"] == "part11" and r1["firma_verificata"]
                    and r2["firma_verificata"]
                    and v.get("record_digests_bound") is True
                    and v.get("records_checked", 0) >= 4)   # 2 audit + 2 firme
        # null: una firma manomessa DEVE fallire la verifica
        rec = _get_trail().log_change("x", AuditAction.CREATE, "PA-2", "t",
                                      new_value={"d": 1})
        es = _get_trail().sign_record(rec, _identity("x"), "x", SignatureMeaning.REVIEW)
        import dataclasses
        es_falso = dataclasses.replace(es, signer_printed_name="impostore")
        nullo = not _get_trail().verify_signature(es_falso)
        # niente dati sanitari nel trail: solo digest
        blob = open(os.path.join(tmp, "trail.jsonl")).read()
        no_phi = "prealert_sha256" in blob and '"vitali"' not in blob
        return {"motore": True, "positivo_firme_verificate": positivo,
                "nullo_firma_manomessa_respinta": nullo, "solo_digest_nel_trail": no_phi,
                "banco_sa_fallire": positivo and nullo and no_phi}
    finally:
        _trail = orig_trail
        KEYS_DIR = orig_keys
        _identita.clear()
        _identita.update(orig_ids)


if __name__ == "__main__" and "--enrol-legacy" in __import__("sys").argv:
    print(json.dumps(enrol_legacy_keys()))
elif __name__ == "__main__":
    print(json.dumps(banco_controllo(), ensure_ascii=False, indent=1))
