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
"""
from __future__ import annotations
import base64
import hashlib
import json
import os
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
    latenza = None
    if ts_emissione:
        try:
            t0 = datetime.fromisoformat(ts_emissione.replace("Z", "+00:00"))
            latenza = round((datetime.fromisoformat(ts) - t0).total_seconds(), 1)
        except ValueError:
            latenza = None
    dettaglio: Dict = {"ruolo": ruolo, "risposta_richiesta": risposta_richiesta,
                       "risposta_attuata": risposta_attuata,
                       "risposta_alternativa": risposta_attuata != risposta_richiesta,
                       "motivo_alternativa": _impronta(motivo_alternativa) if motivo_alternativa else None,
                       "ts_emissione": ts_emissione, "latenza_s": latenza}
    audit = AB.registra_ricezione(prealert_id, dettaglio, operatore_ps)
    return {"ok": True, "prealert_id": prealert_id, "ts": ts, "latenza_s": latenza,
            "risposta_alternativa": dettaglio["risposta_alternativa"], "audit": audit,
            "nota": "ricezione firmata: chi, quando, risposta richiesta vs attuata; motivo per digest"}


def _verifica_entry_locale(e: Dict) -> bool:
    """Ri-verifica INDIPENDENTE di una riga del ledger firma-locale: ricanonizza, ricalcola il
    digest, verifica la firma Ed25519 con la chiave pubblica contenuta nella riga."""
    try:
        rec = {k: e[k] for k in ("kind", "target", "azione", "dettaglio", "operatore", "ts")}
        canon = json.dumps(rec, sort_keys=True, separators=(",", ":")).encode()
        digest = hashlib.sha256(canon).digest()
        if digest.hex() != e.get("record_sha256"):
            return False
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        Ed25519PublicKey.from_public_bytes(base64.b64decode(e["pubkey_b64"])).verify(
            base64.b64decode(e["firma_ed25519_b64"]), digest)
        return True
    except Exception:  # noqa: BLE001 — qualunque difetto è «non verificata», mai un'eccezione
        return False


def _eventi_locali(prealert_id: str) -> List[Dict]:
    out = []
    if not os.path.exists(AB.FALLBACK_LEDGER):
        return out
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
                out.append({"riga": n, "target": tgt, "azione": e.get("azione"), "operatore": e.get("operatore"),
                            "ts": e.get("ts"), "record_sha256": e.get("record_sha256"),
                            "dettaglio": e.get("dettaglio"), "firma_ok": _verifica_entry_locale(e)})
    return out


def verbale(prealert_id: str) -> Dict:
    """Verbale probatorio digest-only di un pre-alert: eventi firmati ri-verificati, cronologia, digest."""
    livello = "part11" if AB.MOTORE_DISPONIBILE else ("firma-locale" if AB.FIRMA_LOCALE_DISPONIBILE else "base")
    eventi: List[Dict] = []
    if AB.MOTORE_DISPONIBILE:
        ver = AB.verifica_trail()
        eventi_motore = {"verifica_trail": {k: v for k, v in ver.items() if k != "records"}}
    else:
        eventi_motore = None
    if AB.FIRMA_LOCALE_DISPONIBILE:
        eventi = _eventi_locali(prealert_id)
    emissione = next((e for e in eventi if e.get("azione") == "emissione"), None)
    ricezioni = [e for e in eventi if e.get("azione") == "ricezione_pre_alert"]
    latenze = [e["dettaglio"].get("latenza_s") for e in ricezioni
               if isinstance(e.get("dettaglio"), dict) and e["dettaglio"].get("latenza_s") is not None]
    tutte_ok = bool(eventi) and all(e.get("firma_ok") for e in eventi)
    corpo = {"kind": "verbale_probatorio_prealert", "prealert_id": prealert_id, "generato_il": _utc(),
             "livello": livello, "eventi": eventi, "n_eventi": len(eventi),
             "firme_tutte_verificate": tutte_ok,
             "emissione_ts": emissione.get("ts") if emissione else None,
             "ricezioni": len(ricezioni), "latenza_emissione_ricezione_s": (min(latenze) if latenze else None),
             "risposte_alternative": sum(1 for e in ricezioni if isinstance(e.get("dettaglio"), dict)
                                         and e["dettaglio"].get("risposta_alternativa")),
             "motore_part11": eventi_motore,
             "confine": ("solo digest, firme e metadati: nessun dato sanitario; le firme sono ri-verificate "
                         "ricalcolando il digest dal record canonico (mai fidandosi del digest dichiarato)")}
    canon = json.dumps(corpo, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    corpo["digest_verbale_sha256"] = hashlib.sha256(canon).hexdigest()
    return corpo


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


def verifica_marca(tsr_b64: str, digest_atteso_hex: str, timeout: int = 15) -> Dict:
    """Verifica crittografica del token: status Granted E message imprint == digest atteso
    (openssl ts -reply -text). Senza openssl: verified=None (registrato, NON verificato)."""
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
        ok = granted and imprint == digest_atteso_hex.lower()
        return {"verified": ok, "granted": granted, "imprint_ok": imprint == digest_atteso_hex.lower(),
                "livello_marca": "rfc3161-non-qualificata" if ok else None}
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
        ok = (r_bad["ok"] is False and r_alt["ok"] is False and r_ok["ok"] is True
              and r_ok["audit"]["livello"] == "firma-locale" and r_ok["risposta_alternativa"] is True
              and v1["n_eventi"] == 2 and v1["firme_tutte_verificate"] is True and v1["risposte_alternative"] == 1
              and v2["firme_tutte_verificate"] is False and v1["digest_verbale_sha256"] != v2["digest_verbale_sha256"])
        return {"banco_sa_fallire": ok, "ricezione_firmata": r_ok["ok"], "valori_chiusi_rifiutati": not r_bad["ok"],
                "motivo_obbligatorio_se_alternativa": not r_alt["ok"], "verbale_verificato": v1["firme_tutte_verificate"],
                "manomissione_rilevata": not v2["firme_tutte_verificate"]}
    finally:
        AB.MOTORE_DISPONIBILE, AB.FALLBACK_LEDGER, AB.KEYS_DIR = orig
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    print(json.dumps(banco_controllo(), ensure_ascii=False, indent=1))
