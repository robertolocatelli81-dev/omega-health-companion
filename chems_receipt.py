#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""OMEGA health — RICEVUTA verificabile offline per un documento CH EMS (0.7.0, «modulo per gli incumbent»).

Il caso d'uso eCH-0207 chiede che il protocollo finale firmato dall'equipaggio sia «rechtsverbindlich archiviert».
La guida CH EMS ha Composition.attester ma non profila una firma che leghi i byte del documento. Questo modulo
è quella prova, offerta a QUALSIASI ePCR (NIDA, corpuls, …) senza adottare il resto di OMEGA:

  ricevuta = { doc_sha256, target, record firmato del ledger locale (Ed25519 per operatore, catena prev_sha256),
               chiave pubblica dell'operatore, riga del verificatore }

`verifica_ricevuta(ricevuta, doc_bytes)` ricalcola il digest DAI BYTE (mai fidarsi del digest dichiarato: audit
content-binding 01/09), ricostruisce i byte canonici firmati dal record e verifica la firma con la chiave della
ricevuta E, se disponibile, con quella del registro locale. Esiti a tre stati: OK / NON VERIFICATA / INCONCLUSIVA
(chiave non registrata: la firma è valida ma la chiave non è ancorata a un operatore noto).
"""
from __future__ import annotations
import base64
import hashlib
import json
import os
from typing import Any, Dict, Optional

import audit_bridge as AB
import chems_ingest as I

CAMPI_FIRMATI = ("kind", "target", "azione", "dettaglio", "operatore", "ts", "prev_sha256", "alg")


def _canon(rec: Dict[str, Any]) -> bytes:
    return json.dumps({k: rec[k] for k in CAMPI_FIRMATI}, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode()


def _ultima_riga_per_digest(digest: str) -> Optional[Dict[str, Any]]:
    """La riga del ledger locale il cui dettaglio porta questo doc_sha256 (l'ultima, se più d'una)."""
    if not os.path.exists(AB.FALLBACK_LEDGER):
        return None
    found = None
    with open(AB.FALLBACK_LEDGER, encoding="utf-8") as f:
        for line in f:
            try:
                e = json.loads(line)
            except ValueError:
                continue
            if e.get("azione") == "ingest_chems" and (e.get("dettaglio") or {}).get("doc_sha256") == digest:
                found = e
    return found


def emetti_ricevuta(doc_bytes: bytes, operatore: str, validazione: Optional[Dict] = None) -> Dict[str, Any]:
    """Ancora il documento (audit firmato) e restituisce la ricevuta autosufficiente."""
    res = I.ancora_documento(doc_bytes, operatore, validazione)
    audit = res["audit"]
    if audit.get("livello") != "firma-locale":
        # motore Part 11 o livello base: la ricevuta autosufficiente esiste solo col ledger locale firmato
        return {"ok": False, "motivo": f"ricevuta non emettibile al livello {audit.get('livello')!r}: serve il ledger locale firmato",
                "doc_sha256": res["doc_sha256"], "audit": audit}
    riga = _ultima_riga_per_digest(res["doc_sha256"])
    if not riga or riga.get("record_sha256") != audit.get("record_sha256"):
        return {"ok": False, "motivo": "riga firmata non ritrovata nel ledger dopo l'ancoraggio", "doc_sha256": res["doc_sha256"]}
    return {"ok": True, "formato": "omega-health-chems-receipt/1", "doc_sha256": res["doc_sha256"], "digest_di": res["digest_di"],
            "target": res["target"], "record": riga,
            "verifica": "chems_receipt.verifica_ricevuta(ricevuta, doc_bytes) — offline; o health_verify.py --audit sul ledger"}


def verifica_ricevuta(ricevuta: Dict[str, Any], doc_bytes: bytes, keys_dir: Optional[str] = None) -> Dict[str, Any]:
    """Tre stati: OK (digest dai byte = dichiarato, firma valida, chiave registrata per l'operatore),
    INCONCLUSIVA (firma valida ma chiave non nel registro), NON_VERIFICATA (qualsiasi altra cosa, con il motivo)."""
    problemi = []
    if not isinstance(ricevuta, dict) or ricevuta.get("formato") != "omega-health-chems-receipt/1":
        return {"stato": "NON_VERIFICATA", "problemi": ["formato di ricevuta sconosciuto"]}
    rec = ricevuta.get("record") or {}
    # 1) il digest si RICALCOLA dai byte
    digest = hashlib.sha256(doc_bytes).hexdigest()
    if ricevuta.get("digest_di") != "bytes":
        problemi.append(f"la ricevuta lega {ricevuta.get('digest_di')!r}, non i byte esatti: verificabile solo dai byte")
    if digest != ricevuta.get("doc_sha256"):
        problemi.append("doc_sha256 dichiarato ≠ sha256 dei byte forniti")
    if (rec.get("dettaglio") or {}).get("doc_sha256") != digest:
        problemi.append("il record firmato non porta il digest di questi byte")
    # 2) il record: hash canonico e firma
    try:
        canon = _canon(rec)
    except KeyError as e:
        return {"stato": "NON_VERIFICATA", "problemi": problemi + [f"record incompleto: manca {e}"]}
    rsha = hashlib.sha256(canon).hexdigest()
    if rsha != rec.get("record_sha256"):
        problemi.append("record_sha256 ≠ sha256 dei campi firmati (record alterato)")
    if rec.get("alg") != "ed25519":
        problemi.append(f"alg {rec.get('alg')!r} non supportato")
    firma_ok = False
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        pk = Ed25519PublicKey.from_public_bytes(base64.b64decode(rec["pubkey_b64"]))
        pk.verify(base64.b64decode(rec["firma_ed25519_b64"]), bytes.fromhex(rsha))
        firma_ok = True
    except Exception as e:  # noqa: BLE001
        problemi.append(f"firma Ed25519 non valida ({type(e).__name__})")
    if problemi:
        return {"stato": "NON_VERIFICATA", "problemi": problemi, "doc_sha256": digest}
    # 3) la chiave è di un operatore registrato?
    kd = keys_dir or AB.KEYS_DIR
    slug = AB._slug(rec.get("operatore", "")) or "anonimo"
    reg = os.path.join(kd, f"fb-{slug}.pub")
    if os.path.exists(reg):
        with open(reg, encoding="utf-8") as f:
            registrata = f.read().strip()
        if registrata == rec["pubkey_b64"]:
            return {"stato": "OK", "doc_sha256": digest, "operatore": rec["operatore"], "ts": rec["ts"], "record_sha256": rsha,
                    "chiave": "registrata"}
        return {"stato": "NON_VERIFICATA", "problemi": ["la chiave nella ricevuta non è quella registrata per l'operatore"], "doc_sha256": digest}
    return {"stato": "INCONCLUSIVA", "doc_sha256": digest, "operatore": rec["operatore"], "ts": rec["ts"], "record_sha256": rsha,
            "chiave": "non registrata: firma valida, operatore non ancorato a una chiave nota"}
