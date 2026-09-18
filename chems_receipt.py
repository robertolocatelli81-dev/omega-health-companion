#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""OMEGA health — RICEVUTA verificabile offline per un documento CH EMS (0.7.0, «modulo per gli incumbent»).

Il caso d'uso eCH-0207 chiede che il protocollo finale firmato dall'equipaggio sia «rechtsverbindlich archiviert».
La guida CH EMS ha Composition.attester ma non profila una firma che leghi i byte del documento. Questo modulo
è quella prova, offerta a QUALSIASI ePCR (NIDA, corpuls, …) senza adottare il resto di OMEGA:

  ricevuta = { doc_sha256, target, record firmato del ledger locale (Ed25519 per operatore, catena prev_sha256),
               chiave pubblica dell'operatore, riga del verificatore }

`verifica_ricevuta(ricevuta, doc_bytes)` ricalcola il digest DAI BYTE (mai fidarsi del digest dichiarato: audit
content-binding 01/09), ricostruisce i byte canonici firmati dal record, verifica la firma con la chiave incorporata
nella ricevuta e poi controlla che quella chiave coincida con la chiave registrata per l'operatore. Esiti a tre stati: OK / NON VERIFICATA / INCONCLUSIVA
(chiave non registrata: la firma è valida ma la chiave non è ancorata a un operatore noto).
"""
from __future__ import annotations
import base64
import hashlib
import json
import os
import re
from typing import Any, Dict, Optional

import audit_bridge as AB
import chems_ingest as I

CAMPI_FIRMATI = ("kind", "target", "azione", "dettaglio", "operatore", "ts", "prev_sha256", "alg")
OPERATORE_RE = re.compile(r"^[A-Za-z0-9 ._@-]{1,60}$")     # stesso charset all'emissione (server) e alla verifica


def _canon(rec: Dict[str, Any]) -> bytes:
    return json.dumps({k: rec[k] for k in CAMPI_FIRMATI}, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode()


def emettibile() -> Optional[str]:
    """None se la ricevuta autosufficiente è emettibile (ledger locale firmato), altrimenti il motivo. Va controllato
    PRIMA di ancorare: con il motore Part 11 il record ha un'altra forma e prima si scriveva l'ancora e poi si rifiutava
    (review Opus 18/09: due righe di trail per ogni tentativo)."""
    if AB.MOTORE_DISPONIBILE:
        return "ricevuta autosufficiente non disponibile col motore Part 11 (record in altra forma): usare il verbale del motore"
    if not AB.FIRMA_LOCALE_DISPONIBILE:
        return "ricevuta non emettibile senza firma locale (cryptography assente)"
    return None


def emetti_ricevuta(doc_bytes: bytes, operatore: str, validazione: Optional[Dict] = None, identita: str = "dichiarata") -> Dict[str, Any]:
    """Ancora il documento (audit firmato) e restituisce la ricevuta autosufficiente, costruita dalla riga appena
    scritta (nessuna rilettura del ledger: niente O(N), niente gara fra ingest concorrenti)."""
    motivo = emettibile()
    if motivo:
        return {"ok": False, "motivo": motivo}
    res = I.ancora_documento(doc_bytes, operatore, validazione, identita=identita)
    audit = res["audit"]
    riga = audit.get("riga") if audit.get("livello") == "firma-locale" else None
    if not isinstance(riga, dict) or riga.get("record_sha256") != audit.get("record_sha256"):
        return {"ok": False, "motivo": "riga firmata non restituita dal bridge", "doc_sha256": res["doc_sha256"]}
    return {"ok": True, "formato": "omega-health-chems-receipt/1", "doc_sha256": res["doc_sha256"], "digest_di": res["digest_di"],
            "target": riga["target"], "record": riga,          # il target come scritto nel ledger (chems/<missione>/ingest_chems)
            "verifica": "chems_receipt.verifica_ricevuta(ricevuta, doc_bytes) — offline; la riga è inoltre verificabile con health_verify.py --audit"}


def verifica_ricevuta(ricevuta: Dict[str, Any], doc_bytes: bytes, keys_dir: Optional[str] = None) -> Dict[str, Any]:
    """Tre stati: OK (digest dai byte = dichiarato, firma valida, chiave registrata per l'operatore),
    INCONCLUSIVA (firma valida ma chiave non nel registro), NON_VERIFICATA (qualsiasi altra cosa, con il motivo)."""
    problemi = []
    digest = hashlib.sha256(doc_bytes).hexdigest()          # 1) il digest si RICALCOLA dai byte, prima di tutto
    if not isinstance(ricevuta, dict) or ricevuta.get("formato") != "omega-health-chems-receipt/1":
        return {"stato": "NON_VERIFICATA", "problemi": ["formato di ricevuta sconosciuto"], "doc_sha256": digest}
    rec = ricevuta.get("record")
    # tipi ostili (review Opus/Sonnet 18/09): la ricevuta arriva da terzi, ogni campo va controllato prima di usarlo
    if not isinstance(rec, dict) or not isinstance(rec.get("dettaglio"), dict) or not isinstance(rec.get("operatore"), str) \
            or not isinstance(rec.get("target"), str) or not all(isinstance(rec.get(k), str) for k in ("record_sha256", "firma_ed25519_b64", "pubkey_b64")):
        return {"stato": "NON_VERIFICATA", "problemi": ["record malformato: attesi record/dettaglio oggetti, operatore/target/hash/firma/chiave stringhe"], "doc_sha256": digest}
    if rec.get("azione") != "ingest_chems" or rec.get("kind") != "audit_locale":
        problemi.append("il record non è un'ancora di documento CH EMS (azione/kind)")
    if ricevuta.get("target") != rec.get("target"):
        problemi.append("target della ricevuta ≠ target del record")
    if not OPERATORE_RE.match(rec["operatore"]):
        problemi.append("operatore con caratteri non ammessi")
    if rec["dettaglio"].get("digest_di") != "bytes":          # il campo FIRMATO, non quello libero della ricevuta (review Opus r3)
        problemi.append(f"il record lega {rec['dettaglio'].get('digest_di')!r}, non i byte esatti: verificabile solo dai byte")
    if digest != ricevuta.get("doc_sha256"):
        problemi.append("doc_sha256 dichiarato ≠ sha256 dei byte forniti")
    if rec["dettaglio"].get("doc_sha256") != digest:
        problemi.append("il record firmato non porta il digest di questi byte")
    # 2) il record: hash canonico e firma
    try:
        canon = _canon(rec)
    except (KeyError, ValueError, TypeError) as e:          # campo mancante, NaN, tipo non serializzabile
        return {"stato": "NON_VERIFICATA", "problemi": problemi + [f"record non canonicalizzabile: {type(e).__name__} {e}"], "doc_sha256": digest}
    rsha = hashlib.sha256(canon).hexdigest()
    if rsha != rec.get("record_sha256"):
        problemi.append("record_sha256 ≠ sha256 dei campi firmati (record alterato)")
    if rec.get("alg") != "ed25519":
        problemi.append(f"alg {rec.get('alg')!r} non supportato (atteso 'ed25519')" if rec.get("alg") is not None else "alg assente (atteso 'ed25519')")
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        pk = Ed25519PublicKey.from_public_bytes(base64.b64decode(rec["pubkey_b64"]))
        pk.verify(base64.b64decode(rec["firma_ed25519_b64"]), bytes.fromhex(rsha))
    except Exception as e:  # noqa: BLE001
        problemi.append(f"firma Ed25519 non valida ({type(e).__name__})")
    if problemi:
        return {"stato": "NON_VERIFICATA", "problemi": problemi, "doc_sha256": digest}
    # 3) la chiave è di un operatore registrato?
    kd = keys_dir or AB.KEYS_DIR
    slug = AB._slug(rec["operatore"])                      # _slug tiene solo [alnum - _]: nessun separatore di percorso
    if not slug or not re.match(r"^[A-Za-z0-9_-]+$", slug):   # mai un ripiego su «anonimo» condiviso (review Haiku r2); mai assert
        return {"stato": "NON_VERIFICATA", "problemi": ["operatore non riducibile a uno slug di chiave"], "doc_sha256": digest}
    reg = os.path.join(kd, f"fb-{slug}.pub")
    if os.path.exists(reg):
        if os.stat(reg).st_mode & 0o022:                   # chiave pubblica scrivibile da altri: sostituibile, non affidabile
            return {"stato": "NON_VERIFICATA", "problemi": [f"registro chiavi {os.path.basename(reg)} scrivibile da altri"], "doc_sha256": digest}
        with open(reg, encoding="utf-8") as f:
            registrata = f.read().strip()
        if registrata == rec["pubkey_b64"]:
            return {"stato": "OK", "doc_sha256": digest, "operatore": rec["operatore"], "ts": rec["ts"], "record_sha256": rsha,
                    "chiave": "registrata", "identita": rec["dettaglio"].get("identita", "non dichiarata (record precedente a 0.7.0)")}
        return {"stato": "NON_VERIFICATA", "problemi": ["la chiave nella ricevuta non è quella registrata per l'operatore"], "doc_sha256": digest}
    return {"stato": "INCONCLUSIVA", "doc_sha256": digest, "operatore": rec["operatore"], "ts": rec["ts"], "record_sha256": rsha,
            "chiave": "non registrata: firma valida, operatore non ancorato a una chiave nota",
            "identita": rec["dettaglio"].get("identita", "non dichiarata (record precedente a 0.7.0)")}
