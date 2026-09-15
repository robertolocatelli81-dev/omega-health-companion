#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""verbale_probatorio — la «linea registrata» del pre-alert, con valore di prova.

La linea guida RCEM/AACE 2025 chiede che «pre-alert calls should be made on a recorded line» e che
la chiamata sia ricevuta da un clinico senior che possa attuare la risposta; dice anche che una
risposta ALTERNATIVA a quella richiesta «does not constitute a failure» e va discussa apertamente.
Questo modulo trasforma quelle tre frasi in EVIDENZA verificabile da un terzo:

  1. `registra_ricezione`  — chi ha ricevuto il pre-alert nel PS (operatore, ruolo), quando, quale
     risposta era richiesta e quale è stata attuata; se diversa, il motivo (legato per digest: mai
     testo libero in chiaro su disco). Firmato con la stessa disciplina delle conferme
     (`audit_bridge`: Part 11 se c'è il motore, altrimenti firma-locale Ed25519 per operatore).
  2. `verbale`             — per un pre-alert: tutti gli eventi firmati (emissione, ricezione,
     prese in carico, eventi di sistema), ciascuno RI-VERIFICATO ricalcolando il digest dal record
     canonico e verificando la firma; la cronologia (latenza emissione→ricezione); il digest del
     verbale stesso. Solo digest e metadati: nessun dato sanitario.
  3. `marca_temporale_rfc3161` / `verifica_marca` — marca temporale RFC 3161 OPZIONALE sul digest del
     verbale (openssl + una TSA raggiungibile) e sua verifica crittografica (status Granted E message
     imprint == digest). Onestà: una TSA di test (es. freeTSA) dà tempo indipendente ma NON è una marca
     «qualificata» eIDAS; per il valore legale pieno serve un QTSP dell'EU Trusted List — il livello
     è dichiarato nell'output (`livello_marca`), mai millantato.

Cosa NON è: non è conservazione a norma (AgID) né una cartella clinica; è il verbale probatorio
dello scambio pre-ospedaliero, esportabile e verificabile offline.

Identità degli operatori (dichiarato): l'enrollment è leggero, da pilota — la chiave nasce al primo uso
del NOME operatore, normalizzato a slug (minuscole, separatori → «-», 40 caratteri): «dr-rossi» e «DR
ROSSI» sono la stessa identità. La firma attesta «chi possiede quella chiave», non un documento
d'identità; in produzione l'enrollment è formale (badge/IAM, QES) — vedi roadmap.
"""
from __future__ import annotations
import base64
import hashlib
import json
import os
import re
import shutil
import sys
from datetime import datetime, timezone
from typing import Dict, List, Optional

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
import audit_bridge as AB  # noqa: E402

RUOLI = ("clinico_senior", "medico", "infermiere_triage", "coordinatore", "altro")
RISPOSTE = ("resus", "trauma_team", "stroke_team", "cath_lab", "revisione_senior_immediata",
            "percorso_sepsi", "percorso_pediatrico", "percorso_ostetrico", "nessuna_risposta_specifica", "altra")
QTSP_NOTE = ("marca RFC 3161 da TSA non qualificata: tempo indipendente, NON marca qualificata eIDAS "
             "(serve un QTSP della EU Trusted List per il valore legale pieno)")


def _utc() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _impronta(testo: Optional[str]) -> Optional[Dict]:
    if testo is None:
        return None
    t = str(testo)
    return {"sha256": hashlib.sha256(t.encode()).hexdigest(), "lunghezza": len(t)}


def registra_ricezione(prealert_id: str, operatore_ps: str, ruolo: str, risposta_richiesta: str,
                       risposta_attuata: str, motivo_alternativa: Optional[str] = None,
                       ts_emissione: Optional[str] = None) -> Dict:
    """Ricezione firmata del pre-alert nel PS. Validazione a valori chiusi (mai testo libero in
    chiaro nel ledger); il motivo di una risposta alternativa è legato per digest."""
    problemi = []
    if not isinstance(operatore_ps, str) or not operatore_ps.strip() or len(operatore_ps) > 60:
        problemi.append("operatore_ps: stringa 1-60 caratteri richiesta")
    if ruolo not in RUOLI:
        problemi.append(f"ruolo non ammesso: {ruolo!r} (ammessi: {', '.join(RUOLI)})")
    for nome, v in (("risposta_richiesta", risposta_richiesta), ("risposta_attuata", risposta_attuata)):
        if v not in RISPOSTE:
            problemi.append(f"{nome} non ammessa: {v!r} (ammesse: {', '.join(RISPOSTE)})")
    if motivo_alternativa is not None and (not isinstance(motivo_alternativa, str) or len(motivo_alternativa) > 500):
        problemi.append("motivo_alternativa: stringa ≤500 caratteri")
    if not problemi and risposta_attuata != risposta_richiesta and not (motivo_alternativa or "").strip():
        problemi.append("risposta attuata diversa da quella richiesta: serve motivo_alternativa (la linea guida "
                        "chiede che la decisione sia discussa apertamente)")
    if problemi:
        return {"ok": False, "problemi": problemi}
    ts = _utc()
    latenza_ms = None
    if ts_emissione:
        # the DECLARED latency: what the caller says the emission instant was. A naive instant is refused (a local
        # time read as UTC moved the legal clock); a negative latency is refused. The MEASURED latency is computed
        # by verbale() from the crew-signed emission event and this ED-signed receipt (council 15/09, Fable).
        try:
            t0 = datetime.fromisoformat(str(ts_emissione).replace("Z", "+00:00"))
        except (ValueError, TypeError):
            return {"ok": False, "problemi": ["ts_emissione: ISO-8601 non valido"]}
        if t0.tzinfo is None:
            return {"ok": False, "problemi": ["ts_emissione: fuso orario obbligatorio (Z o ±hh:mm)"]}
        # both instants at second granularity (the receipt ts has no fraction): an emission at hh:mm:ss.7 and a
        # receipt in the same second is 0, not a negative latency
        delta = (datetime.fromisoformat(ts) - t0.replace(microsecond=0)).total_seconds()
        if delta < 0:
            return {"ok": False, "problemi": ["ts_emissione: nel futuro rispetto alla ricezione"]}
        latenza_ms = int(round(delta * 1000))
    dettaglio: Dict = {"ruolo": ruolo, "risposta_richiesta": risposta_richiesta,
                       "risposta_attuata": risposta_attuata,
                       "risposta_alternativa": risposta_attuata != risposta_richiesta,
                       "motivo_alternativa": _impronta(motivo_alternativa) if motivo_alternativa else None,
                       "ts_emissione": ts_emissione, "latenza_dichiarata_ms": latenza_ms}
    audit = AB.registra_ricezione(prealert_id, dettaglio, operatore_ps)
    latenza = (latenza_ms / 1000.0) if latenza_ms is not None else None
    return {"ok": True, "prealert_id": prealert_id, "ts": ts, "latenza_s": latenza,
            "risposta_alternativa": dettaglio["risposta_alternativa"], "audit": audit,
            "nota": "ricezione firmata: chi, quando, risposta richiesta vs attuata; motivo per digest"}


def _verifica_entry_locale(e: Dict, registro: Dict[str, str]) -> Dict:
    """Ri-verifica INDIPENDENTE di una riga del ledger firma-locale: ricanonizza (prev_sha256 incluso),
    ricalcola il digest, verifica la firma Ed25519 contro la chiave REGISTRATA dell'operatore
    (`registro`: operatore → pubkey base64). La chiave scritta nella riga NON fa fede (council 13/09:
    chi riscrive il ledger ri-firma con una chiave propria). Ritorna {ok, motivo}."""
    try:
        chiavi = ("kind", "target", "azione", "dettaglio", "operatore", "ts") + (("prev_sha256",) if "prev_sha256" in e else ()) \
                 + (("alg",) if "alg" in e else ())
        # the key set is EXACT (council 15/09, Sonnet): a line enriched with an extra field (e.g. clear text) used to
        # verify as if untouched, because only the known keys were re-hashed
        attese = set(chiavi) | {"record_sha256", "firma_ed25519_b64", "pubkey_b64"}
        if set(e) != attese:
            return {"ok": False, "motivo": f"insieme di chiavi inatteso: {sorted(set(e) ^ attese)}"}
        if e.get("alg", "ed25519") != "ed25519":
            return {"ok": False, "motivo": f"algoritmo non supportato: {e.get('alg')!r}"}
        rec = {k: e[k] for k in chiavi}
        canon = json.dumps(rec, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()
        digest = hashlib.sha256(canon).digest()
        if digest.hex() != e.get("record_sha256"):
            return {"ok": False, "motivo": "digest non corrisponde al record canonico"}
        pk_reg = registro.get(str(e.get("operatore")))
        if not pk_reg:
            return {"ok": False, "motivo": "operatore senza chiave registrata (fail-closed)"}
        if pk_reg != e.get("pubkey_b64"):
            return {"ok": False, "motivo": "chiave nella riga diversa da quella registrata per l'operatore"}
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        Ed25519PublicKey.from_public_bytes(base64.b64decode(pk_reg)).verify(
            base64.b64decode(e["firma_ed25519_b64"]), digest)
        return {"ok": True, "motivo": "firma verificata contro la chiave registrata"}
    except Exception as ex:  # noqa: BLE001 — qualunque difetto è «non verificata», mai un'eccezione
        return {"ok": False, "motivo": f"{type(ex).__name__}"}


def registro_chiavi() -> Dict[str, str]:
    """operatore(slug) → chiave pubblica registrata: legge KEYS_DIR/fb-*.pub. Esportato nel verbale
    così un terzo verifica offline contro un registro che custodisce lui."""
    reg: Dict[str, str] = {}
    if os.path.isdir(AB.KEYS_DIR):
        # READ-ONLY (council 15/09, Opus): verification must never enrol keys; a .pub is written only when a
        # record is SIGNED (audit_bridge._fb_registra_locked). Only well-formed names are read.
        for n in sorted(os.listdir(AB.KEYS_DIR)):
            if n.startswith("fb-") and n.endswith(".pub") and "/" not in n and "\\" not in n and 4 <= len(n) <= 48:
                with open(os.path.join(AB.KEYS_DIR, n)) as f:
                    reg[n[3:-4]] = f.read().strip()
    return reg


def _rottura_digest(e: Dict, n: int, rotture: List[Dict]) -> None:
    """Every line's digest is recomputed (council 15/09, Fable): before, a line outside this pre-alert could be
    edited (keeping its record_sha256) and the chain still read «integra»."""
    try:
        chiavi = ("kind", "target", "azione", "dettaglio", "operatore", "ts") + (("prev_sha256",) if "prev_sha256" in e else ()) + (("alg",) if "alg" in e else ())
        canon = json.dumps({k: e[k] for k in chiavi}, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()
        if hashlib.sha256(canon).hexdigest() != e.get("record_sha256"):
            rotture.append({"riga": n, "motivo": "record_sha256 non corrisponde al record canonico (riga modificata?)"})
    except (KeyError, TypeError, ValueError):
        rotture.append({"riga": n, "motivo": "riga non canonicalizzabile"})


def _catena_locale() -> Dict:
    """Continuità della catena prev_sha256 su TUTTO il ledger locale (non solo sul pre-alert): una riga
    cancellata o riordinata rompe l'anello successivo. Righe precedenti al 13/09 (senza prev_sha256)
    sono dichiarate «fuori catena», mai contate come verificate."""
    if not os.path.exists(AB.FALLBACK_LEDGER):
        return {"catena_ok": None, "righe": 0, "nota": "ledger assente"}
    prev, righe, fuori, rotture, incatenato = "GENESIS", 0, 0, [], False
    with open(AB.FALLBACK_LEDGER, encoding="utf-8") as f:
        for n, line in enumerate(f, 1):
            if not line.strip():
                continue
            righe += 1
            try:
                e = json.loads(line)
            except ValueError:
                rotture.append({"riga": n, "motivo": "illeggibile"})
                continue
            if not isinstance(e, dict):
                rotture.append({"riga": n, "motivo": "non è un oggetto"})
                continue
            if "prev_sha256" not in e:
                # Righe legacy (pre-13/09) ammesse SOLO in testa al ledger. Dopo la prima riga incatenata,
                # una riga senza prev_sha256 è una ROTTURA (council round 3: sostituire una riga con una
                # finta «legacy» che porta lo stesso record_sha256 lasciava catena_ok True).
                if incatenato:
                    rotture.append({"riga": n, "motivo": "riga senza prev_sha256 dopo l'inizio della catena (inserimento/sostituzione?)"})
                    continue
                fuori += 1
                prev = e.get("record_sha256") or prev
                _rottura_digest(e, n, rotture)
                continue
            if e["prev_sha256"] == "GENESIS" and incatenato:
                rotture.append({"riga": n, "motivo": "prev_sha256 GENESIS dopo l'inizio della catena (inserimento in testa?)"})
            incatenato = True
            if e["prev_sha256"] != prev:
                rotture.append({"riga": n, "motivo": "prev_sha256 non corrisponde alla riga precedente (cancellazione/riordino?)"})
            prev = e.get("record_sha256") or prev
            _rottura_digest(e, n, rotture)
    return {"catena_ok": not rotture and righe > 0, "righe": righe, "righe_fuori_catena": fuori, "rotture": rotture,
            "limite": ("rileva cancellazioni/riordini IN MEZZO al ledger; il troncamento della CODA con nuove righe "
                       "appese resta coerente: lo copre il verbale persistito con marca temporale")}


def _eventi_locali(prealert_id: str) -> List[Dict]:
    out = []
    if not os.path.exists(AB.FALLBACK_LEDGER):
        return out
    registro = {}
    for slug, pk in registro_chiavi().items():
        registro[slug] = pk
    def _pk(operatore):        # il registro è per slug; la riga porta il nome dell'operatore
        return registro.get(AB._slug(str(operatore)) or "anonimo")
    with open(AB.FALLBACK_LEDGER, encoding="utf-8") as f:
        for n, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                e = json.loads(line)
            except ValueError:
                out.append({"riga": n, "azione": "RIGA_ILLEGGIBILE", "firma_ok": False})
                continue
            if e.get("kind") != "audit_locale":
                continue
            tgt = str(e.get("target", ""))
            if tgt == prealert_id or tgt.startswith(prealert_id + "/"):
                ver = _verifica_entry_locale(e, {str(e.get("operatore")): _pk(e.get("operatore"))})
                out.append({"riga": n, "target": tgt, "azione": e.get("azione"), "operatore": e.get("operatore"),
                            "ts": e.get("ts"), "record_sha256": e.get("record_sha256"),
                            "prev_sha256": e.get("prev_sha256"),
                            "dettaglio": e.get("dettaglio"), "firma_ok": ver["ok"], "verifica": ver["motivo"]})
    return out


def _eventi_part11(prealert_id: str) -> List[Dict]:
    """Con il motore Part 11 (deploy privato) gli eventi stanno nel trail: elencati per target e
    accompagnati dalla verifica INTERA del trail (catena + firme) fatta dal motore stesso."""
    out = []
    if not os.path.exists(AB.TRAIL_PATH):
        return out
    with open(AB.TRAIL_PATH, encoding="utf-8") as f:
        for n, line in enumerate(f, 1):
            try:
                e = json.loads(line)
            except ValueError:
                continue
            e = e.get("data") if isinstance(e.get("data"), dict) else e     # PersistentLedger: {data, idx, prev_hash, self_hash}
            if e.get("kind") != "part11_audit":
                continue
            tgt = str(e.get("target_record_id", ""))
            if tgt == prealert_id or tgt.startswith(prealert_id + "/"):
                out.append({"riga": n, "target": tgt, "azione": e.get("action"), "operatore": e.get("operator_id"),
                            "ts": e.get("timestamp_utc"), "record_sha3": e.get("record_sha3"),
                            "dettaglio": e.get("new_value"), "motivo": e.get("reason")})
    return out


def verbale(prealert_id: str) -> Dict:
    """Verbale probatorio digest-only di un pre-alert: eventi firmati ri-verificati, cronologia, digest."""
    livello = "part11" if AB.MOTORE_DISPONIBILE else ("firma-locale" if AB.FIRMA_LOCALE_DISPONIBILE else "base")
    eventi: List[Dict] = []
    catena: Dict = {"catena_ok": None}
    eventi_motore = None
    if AB.MOTORE_DISPONIBILE:
        try:
            ver = AB.verifica_trail()
        except Exception as ex:  # noqa: BLE001 — trail corrotto: il motore rifiuta di caricarlo (fail-closed), il verbale lo DICE
            ver = {"chain_ok": False, "record_digests_bound": False, "errore": f"{type(ex).__name__}: {str(ex)[:120]}"}
        eventi = _eventi_part11(prealert_id)
        eventi_motore = {"verifica_trail": {k: v for k, v in ver.items() if k != "records"}}
        # il motore verifica catena e firme dell'INTERO trail: ogni evento eredita quel verdetto
        ok_trail = bool(ver.get("chain_ok")) and bool(ver.get("record_digests_bound", False))   # fail-closed default
        for e in eventi:
            e["firma_ok"] = ok_trail
            e["verifica"] = "trail Part 11 verificato dal motore" if ok_trail else "trail Part 11 NON verificato"
        catena = {"catena_ok": ok_trail, "fonte": "motore Part 11"}
    elif AB.FIRMA_LOCALE_DISPONIBILE:
        eventi = _eventi_locali(prealert_id)
        catena = _catena_locale()
    emissione = next((e for e in eventi if e.get("azione") in ("emissione", "create")), None)
    ricezioni = [e for e in eventi if e.get("azione") == "ricezione_pre_alert" or str(e.get("target", "")).endswith("/ricezione")]
    # MEASURED latency: crew-signed emission ts → ED-signed receipt ts (never the receiver's own declaration)
    latenze, anomalie_temporali = [], []
    if emissione and emissione.get("ts"):
        try:
            t_em = datetime.fromisoformat(str(emissione["ts"]).replace("Z", "+00:00"))
            for e in ricezioni:
                if e.get("firma_ok") and e.get("ts"):
                    d = (datetime.fromisoformat(str(e["ts"]).replace("Z", "+00:00")) - t_em).total_seconds()
                    if d >= 0:
                        latenze.append(int(round(d * 1000)))
                    else:   # a signed receipt dated BEFORE the signed emission is an anomaly to show, not to drop (council r2)
                        anomalie_temporali.append({"riga": e.get("riga"), "ricezione_ts": e.get("ts"), "emissione_ts": emissione["ts"],
                                                   "delta_s": round(d, 3), "nota": "ricezione firmata anteriore all'emissione firmata: orologi da verificare"})
        except (ValueError, TypeError):
            latenze = []
    dichiarate = [e["dettaglio"].get("latenza_dichiarata_ms", e["dettaglio"].get("latenza_s")) for e in ricezioni
                  if isinstance(e.get("dettaglio"), dict)]
    tutte_ok = bool(eventi) and all(e.get("firma_ok") for e in eventi) and bool(catena.get("catena_ok"))
    corpo = {"kind": "verbale_probatorio_prealert", "prealert_id": prealert_id, "generato_il": _utc(),
             "livello": livello, "eventi": eventi, "n_eventi": len(eventi),
             "firme_tutte_verificate": tutte_ok, "catena": catena,
             "registro_chiavi": registro_chiavi() if livello == "firma-locale" else None,
             "emissione_ts": emissione.get("ts") if emissione else None,
             "ricezioni": len(ricezioni), "latenza_emissione_ricezione_ms": (min(latenze) if latenze else None),
             "latenza_misurata_da": "ts firmato dell'emissione (equipaggio) → ts firmato della ricezione (PS)",
             "anomalie_temporali": anomalie_temporali,
             "latenze_dichiarate_dal_ricevente": [x for x in dichiarate if x is not None],
             "risposte_alternative": sum(1 for e in ricezioni if isinstance(e.get("dettaglio"), dict)
                                         and e["dettaglio"].get("risposta_alternativa")),
             "motore_part11": eventi_motore,
             "confine": ("solo digest, firme e metadati: nessun dato sanitario; le firme sono ri-verificate "
                         "ricalcolando il digest dal record canonico contro la chiave REGISTRATA dell'operatore; "
                         "firme_tutte_verificate richiede anche la catena prev_sha256 integra su tutto il ledger. "
                         "LIMITE: il registro chiavi vive sullo stesso host del ledger — un terzo deve riceverlo "
                         "fuori banda (o fidarsi del verbale marcato nel tempo); il troncamento della coda del "
                         "ledger è coperto solo dal verbale persistito con marca")}
    canon = json.dumps(corpo, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()   # UTF-8 profile (FORMAT.md)
    corpo["digest_verbale_sha256"] = hashlib.sha256(canon).hexdigest()
    return corpo


def persisti_verbale(v: Dict, directory: str) -> Dict:
    """Scrive i BYTE esatti del verbale (con l'eventuale marca) in `directory`: la marca RFC 3161 prova un
    digest, e il digest prova solo bytes che qualcuno custodisce. Solo digest/metadati nel file."""
    os.makedirs(directory, exist_ok=True)
    nome = f"{v.get('prealert_id')}-{v.get('digest_verbale_sha256', '')[:16]}.json"
    path = os.path.join(directory, nome)
    raw = json.dumps(v, ensure_ascii=False, sort_keys=True, indent=1).encode()
    with open(path, "wb") as f:
        f.write(raw)
    return {"path": path, "bytes": len(raw), "sha256_file": hashlib.sha256(raw).hexdigest()}


def marca_temporale_rfc3161(digest_hex: str, tsa_url: str, timeout: int = 20) -> Dict:
    """Marca RFC 3161 sul digest (openssl ts -query + POST alla TSA). Opzionale e onesta: se manca
    openssl o la rete, `anchored=False` con nota — mai un finto ancoraggio."""
    from urllib.parse import urlparse
    import subprocess  # nosec B404 - argomenti fissi, no shell
    import tempfile
    import urllib.request
    if urlparse(tsa_url).scheme not in ("http", "https"):
        return {"anchored": False, "note": "TSA URL: solo http/https"}
    if not isinstance(digest_hex, str) or len(digest_hex) != 64 or any(c not in "0123456789abcdef" for c in digest_hex):
        return {"anchored": False, "note": "digest non è SHA-256 esadecimale"}
    exe = shutil.which("openssl")
    if not exe:
        return {"anchored": False, "note": "openssl assente (RFC 3161 opzionale)"}
    d = tempfile.mkdtemp()
    try:
        tsq = os.path.join(d, "q.tsq")
        r = subprocess.run([exe, "ts", "-query", "-digest", digest_hex, "-sha256", "-cert", "-out", tsq],  # nosec B603
                           capture_output=True, timeout=timeout)
        if r.returncode != 0 or not os.path.exists(tsq):
            return {"anchored": False, "note": "openssl ts -query fallito"}
        with open(tsq, "rb") as f:
            req = f.read()
        http = urllib.request.Request(tsa_url, data=req, method="POST",
                                      headers={"Content-Type": "application/timestamp-query"})
        resp = urllib.request.urlopen(http, timeout=timeout).read()  # nosec B310 - schema validato sopra
        return {"anchored": True, "tsa": tsa_url, "tsr_b64": base64.b64encode(resp).decode(),
                "livello_marca": "rfc3161-non-qualificata", "note": QTSP_NOTE}
    except Exception as e:  # noqa: BLE001
        return {"anchored": False, "note": f"{type(e).__name__}: {str(e)[:80]}"}
    finally:
        shutil.rmtree(d, ignore_errors=True)


def verifica_marca(tsr_b64: str, digest_atteso_hex: str, timeout: int = 15, cafile: Optional[str] = None) -> Dict:
    """Verifica CRITTOGRAFICA del token RFC 3161, in tre strati dichiarati separatamente:
      1. status Granted e message imprint == digest atteso (openssl ts -reply -text);
      2. firma CMS del token valida con il certificato incluso nel token (openssl cms -verify -noverify):
         un TSR MODIFICATO o senza firma CMS qui cade; un token INVENTATO da una TSA self-signed no;
      3. catena di fiducia della TSA (openssl ts -verify -CAfile `cafile`) → `catena_tsa_ok`.
    `verified` è True SOLO con 1 E 2 E 3; con 1 E 2 ma senza CA: None («coerente, TSA non fidata»).
    Il livello resta «non qualificata» senza QTSP eIDAS. Senza openssl: None."""
    import subprocess  # nosec B404
    import tempfile
    exe = shutil.which("openssl")
    if not exe:
        return {"verified": None, "note": "openssl assente: token registrato ma NON verificato"}
    d = tempfile.mkdtemp()
    try:
        tsr = os.path.join(d, "t.tsr")
        with open(tsr, "wb") as f:
            f.write(base64.b64decode(tsr_b64))
        # strato 2: token CMS estratto dalla reply e firma verificata col certificato incluso
        tk = os.path.join(d, "t.tk")
        r2 = subprocess.run([exe, "ts", "-reply", "-in", tsr, "-token_out", "-out", tk], capture_output=True, timeout=timeout)  # nosec B603
        firma_cms = False
        if r2.returncode == 0 and os.path.exists(tk):
            r3 = subprocess.run([exe, "cms", "-verify", "-noverify", "-inform", "DER", "-in", tk, "-out", os.devnull],  # nosec B603
                                capture_output=True, timeout=timeout)
            firma_cms = r3.returncode == 0
        catena_ok, errore_cfg = None, None
        if cafile and not os.path.exists(cafile):
            catena_ok, errore_cfg = False, f"HEALTH_TSA_CAFILE non trovato: {cafile}"     # errore di configurazione NOMINATO, fail-closed
        elif cafile:
            r4 = subprocess.run([exe, "ts", "-verify", "-digest", digest_atteso_hex, "-sha256", "-in", tsr, "-CAfile", cafile],  # nosec B603
                                capture_output=True, timeout=timeout)
            catena_ok = r4.returncode == 0
        r = subprocess.run([exe, "ts", "-reply", "-in", tsr, "-text"], capture_output=True, text=True, timeout=timeout)  # nosec B603
        text = r.stdout or ""
        granted = "Status: Granted" in text or "Granted." in text
        grab, hexbytes = False, []
        for ln in text.splitlines():
            if "Message data:" in ln:
                grab = True
                continue
            if grab:
                if ln.strip() and ln[0] not in " \t":
                    break
                if " - " not in ln:
                    continue
                hexpart = ln.split(" - ", 1)[1].split("   ")[0]
                hexbytes += [h for h in hexpart.replace("-", " ").split() if len(h) == 2]
        imprint = "".join(hexbytes).lower()
        imprint_ok = imprint == digest_atteso_hex.lower()
        coerente = granted and imprint_ok and firma_cms          # token integro e coerente con SE STESSO
        # `verified` (council round 2): True SOLO se anche la CATENA verso una CA fidata regge. Senza
        # cafile un token firmato da una TSA self-signed «CN=TSA-FALSA» sarebbe coerente ma non fidato:
        # verified=None e livello «coerente-non-fidata», mai True.
        if not coerente:
            verified, livello = False, None
        elif catena_ok is True:
            verified, livello = True, "rfc3161-catena-verificata"
        elif catena_ok is False:
            verified, livello = False, None
        else:
            verified, livello = None, "rfc3161-coerente-tsa-non-fidata"
        return {"verified": verified, "granted": granted, "imprint_ok": imprint_ok, "firma_cms_ok": firma_cms,
                "catena_tsa_ok": catena_ok, "livello_marca": livello, **({"errore": errore_cfg} if errore_cfg else {}),
                "nota": ("verified=True solo con firma CMS valida E catena verso la CA data (HEALTH_TSA_CAFILE); "
                         "senza CA: coerente ma TSA non fidata (None); marca QUALIFICATA solo con un QTSP eIDAS")}
    except Exception as e:  # noqa: BLE001
        return {"verified": False, "note": f"{type(e).__name__}: {str(e)[:80]}"}
    finally:
        shutil.rmtree(d, ignore_errors=True)


# ── banco che SA FALLIRE ────────────────────────────────────────────────────────────────────
def banco_controllo() -> Dict:
    """Usa un ledger in sandbox (mai produzione). Positivo: ricezione firmata e ri-verificata;
    negativo: riga manomessa → firma_ok False; validazione: valori fuori lista rifiutati."""
    import tempfile
    if not AB.FIRMA_LOCALE_DISPONIBILE:
        return {"banco_sa_fallire": True, "degrado_onesto": True, "nota": "cryptography assente: livello base dichiarato"}
    orig = (AB.MOTORE_DISPONIBILE, AB.FALLBACK_LEDGER, AB.KEYS_DIR)
    tmp = tempfile.mkdtemp(prefix="verbale_")
    try:
        AB.MOTORE_DISPONIBILE = False
        AB.FALLBACK_LEDGER = os.path.join(tmp, "fb.jsonl")
        AB.KEYS_DIR = os.path.join(tmp, "keys")
        AB.registra_prealert("prealert-7", "ab" * 32, "equipaggio-12")
        r_bad = registra_ricezione("prealert-7", "dr-rossi", "capo", "resus", "resus")
        r_alt = registra_ricezione("prealert-7", "dr-rossi", "clinico_senior", "trauma_team", "revisione_senior_immediata")
        r_ok = registra_ricezione("prealert-7", "dr-rossi", "clinico_senior", "trauma_team",
                                  "revisione_senior_immediata", motivo_alternativa="trauma team già impegnato in sala 2",
                                  ts_emissione=_utc())
        v1 = verbale("prealert-7")
        # manomissione: cambio la risposta attuata nella riga di ricezione → la firma NON deve reggere
        lines = open(AB.FALLBACK_LEDGER, encoding="utf-8").read().splitlines()
        lines[-1] = lines[-1].replace("revisione_senior_immediata", "resus")
        open(AB.FALLBACK_LEDGER, "w", encoding="utf-8").write("\n".join(lines) + "\n")
        v2 = verbale("prealert-7")
        # cancellazione di una riga IN MEZZO (la ricezione, prima invisibile): la catena la rileva.
        # Limite dichiarato: troncare la CODA e ri-appendere resta coerente con prev_sha256; quel caso lo
        # copre solo il verbale persistito con marca temporale (fissa l'ultimo digest nel tempo).
        AB.registra_prealert("prealert-8", "ef" * 32, "equipaggio-12")   # terza riga, dopo la ricezione
        with open(AB.FALLBACK_LEDGER, encoding="utf-8") as f:
            l3 = f.read().splitlines()
        with open(AB.FALLBACK_LEDGER, "w", encoding="utf-8") as f:
            f.write(l3[0] + "\n" + l3[2] + "\n")
        v3 = verbale("prealert-8")
        ok = (r_bad["ok"] is False and r_alt["ok"] is False and r_ok["ok"] is True
              and v3["catena"]["catena_ok"] is False and v3["firme_tutte_verificate"] is False
              and r_ok["audit"]["livello"] == "firma-locale" and r_ok["risposta_alternativa"] is True
              and v1["n_eventi"] == 2 and v1["firme_tutte_verificate"] is True and v1["risposte_alternative"] == 1
              and v2["firme_tutte_verificate"] is False and v1["digest_verbale_sha256"] != v2["digest_verbale_sha256"])
        return {"banco_sa_fallire": ok, "ricezione_firmata": r_ok["ok"], "valori_chiusi_rifiutati": not r_bad["ok"],
                "motivo_obbligatorio_se_alternativa": not r_alt["ok"], "verbale_verificato": v1["firme_tutte_verificate"],
                "manomissione_rilevata": not v2["firme_tutte_verificate"],
                "cancellazione_rilevata": v3["catena"]["catena_ok"] is False}
    finally:
        AB.MOTORE_DISPONIBILE, AB.FALLBACK_LEDGER, AB.KEYS_DIR = orig
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    print(json.dumps(banco_controllo(), ensure_ascii=False, indent=1))
