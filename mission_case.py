#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""OMEGA — fascicolo di missione (ponte OPZIONALE verso il motore case-management).

PERCHÉ: il flusso health produce atti sparsi — valutazione, pre-alert, ATMIST,
bundle FHIR — ma nessun FASCICOLO che li tenga insieme: chi ha aperto la
missione, in che stato è, quali atti la compongono, quando è stata consegnata
al DEA. È lo stesso buco che il case management colma nell'AML: da eventi
isolati a narrazione investigabile e rigiocabile.

Ciclo di vita della missione (FSM dichiarata, esaustiva):

    ALLERTA ──► VALUTAZIONE ──► TRASPORTO ──► CONSEGNATA ──► CHIUSA
       │             │
       └─────────────┴────► ANNULLATA        (falso allarme / revoca centrale)

CONFINE (stesso pattern di audit_bridge): il motore `compliance.case_management`
è PRIVATO e NON entra nel deliverable open. Se c'è sul sistema, la transizione è
validata ANCHE dal motore (livello «case-engine», doppio replay indipendente);
se non c'è, degrado ONESTO a «fascicolo-locale»: la STESSA tabella FSM validata
qui, con catena hash SHA-256 append-only nel JSONL — il claim pubblico
(«fascicolo rigiocabile e a prova di manomissione») resta VERO per chi clona
questo repo. Mai un finto «case-engine».

PRIVACY (stessa regola del resto del repo): nel fascicolo entrano SOLO digest
degli atti (sha256), mai dati sanitari.
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

_HERE = os.path.dirname(os.path.abspath(__file__))
_OMEGA = os.path.expanduser("~/omega/omega_package")
FASCICOLI_LEDGER = os.path.join(_HERE, "fascicoli_ledger.jsonl")
GENESIS = "0" * 64

# FSM della missione — la tabella è la fonte di verità per ENTRAMBI i livelli
STATI = ("ALLERTA", "VALUTAZIONE", "TRASPORTO", "CONSEGNATA", "CHIUSA", "ANNULLATA")
TRANSIZIONI: Dict[str, set] = {
    "ALLERTA": {"VALUTAZIONE", "ANNULLATA"},
    "VALUTAZIONE": {"TRASPORTO", "ANNULLATA"},
    "TRASPORTO": {"CONSEGNATA"},
    "CONSEGNATA": {"CHIUSA"},
    "CHIUSA": set(),
    "ANNULLATA": set(),
}
# stati in cui si possono ancora agganciare atti (digest)
STATI_APERTI_AGLI_ATTI = {"ALLERTA", "VALUTAZIONE", "TRASPORTO"}

MOTORE_DISPONIBILE = False
_err_import = None
try:
    if _OMEGA not in sys.path:
        sys.path.insert(0, _OMEGA)
    from enum import Enum as _Enum

    from compliance.case_management import CaseManager as _CM  # noqa: E402

    class _StatoM(str, _Enum):
        ALLERTA = "ALLERTA"
        VALUTAZIONE = "VALUTAZIONE"
        TRASPORTO = "TRASPORTO"
        CONSEGNATA = "CONSEGNATA"
        CHIUSA = "CHIUSA"
        ANNULLATA = "ANNULLATA"

    _TABELLA_M = {_StatoM(k): {_StatoM(x) for x in v} for k, v in TRANSIZIONI.items()}
    MOTORE_DISPONIBILE = True
except Exception as e:  # noqa: BLE001 — assenza del motore = degrado onesto
    _err_import = f"{type(e).__name__}: {e}"


def _utc() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _digest_valido(d: str) -> bool:
    return (isinstance(d, str) and len(d) == 64
            and all(c in "0123456789abcdef" for c in d.lower()))


class FascicoloMissione:
    """Fascicolo append-only hash-chained. Un'istanza = un ledger (file JSONL);
    lo stato di ogni missione si ricostruisce per replay (multi-processo safe
    per il pilota CLI: si rilegge il file a ogni operazione)."""

    def __init__(self, ledger_path: str = FASCICOLI_LEDGER):
        self.ledger_path = ledger_path
        self._mgr = None
        if MOTORE_DISPONIBILE:
            self._mgr = _CM(transitions_table=_TABELLA_M,
                            initial_state=_StatoM.ALLERTA)
            self._case_ids: Dict[str, str] = {}   # missione_id -> case_id motore

    # ── catena del ledger (identica nei due livelli) ─────────────────────
    def _righe(self) -> List[dict]:
        if not os.path.exists(self.ledger_path):
            return []
        return [json.loads(l) for l in open(self.ledger_path, encoding="utf-8")
                if l.strip()]

    def _append(self, body: Dict[str, Any]) -> dict:
        """Append sotto LOCK ESCLUSIVO (colpo Gemini Pro: due processi che
        leggono lo stesso prev_hash creerebbero un fork che rompe la catena
        per sempre). Il lock copre lettura del prev_hash E scrittura."""
        import fcntl
        lock_path = self.ledger_path + ".lock"
        with open(lock_path, "w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            try:
                righe = self._righe()
                body = dict(body)
                body["ts"] = _utc()
                if righe and body["ts"] < righe[-1]["ts"]:
                    # colpo Gemini Pro: la catena prova l'ORDINE, non il tempo —
                    # ma un orologio che va all'indietro è un'anomalia medico-legale
                    # da fermare, non da mettere in catena
                    raise ValueError(
                        f"orologio all'indietro ({body['ts']} < {righe[-1]['ts']}): "
                        f"evento rifiutato — sistemare l'ora di sistema (NTP) "
                        f"prima di proseguire")
                body["prev_hash"] = righe[-1]["self_hash"] if righe else GENESIS
                canon = json.dumps(body, sort_keys=True, separators=(",", ":"),
                                   ensure_ascii=False).encode()
                body["self_hash"] = hashlib.sha256(canon).hexdigest()
                with open(self.ledger_path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(body, ensure_ascii=False) + "\n")
                return body
            finally:
                fcntl.flock(lock, fcntl.LOCK_UN)

    def verifica_ledger(self) -> Dict[str, Any]:
        """Rigioca la catena intera. Verdetto esplicito, mai bool nudo."""
        prev = GENESIS
        for i, r in enumerate(self._righe()):
            body = {k: v for k, v in r.items() if k != "self_hash"}
            canon = json.dumps(body, sort_keys=True, separators=(",", ":"),
                               ensure_ascii=False).encode()
            if r.get("self_hash") != hashlib.sha256(canon).hexdigest():
                return {"ok": False, "errore": f"hash rotto alla riga {i}"}
            if r.get("prev_hash") != prev:
                return {"ok": False, "errore": f"collegamento rotto alla riga {i}"}
            prev = r["self_hash"]
        return {"ok": True, "righe": len(self._righe())}

    # ── stato per replay ─────────────────────────────────────────────────
    def _stato(self, missione_id: str) -> Optional[Dict[str, Any]]:
        st: Optional[Dict[str, Any]] = None
        for r in self._righe():
            if r.get("missione") != missione_id:
                continue
            ev = r.get("evento")
            if ev == "apertura":
                st = {"stato": "ALLERTA", "atti": [], "eventi": 1,
                      "aperta_da": r.get("operatore"), "aperta_ts": r.get("ts")}
            elif st is not None and ev == "atto":
                st["atti"].append({"tipo": r.get("tipo"),
                                   "sha256": r.get("sha256"), "ts": r.get("ts")})
                st["eventi"] += 1
            elif st is not None and ev == "transizione":
                st["stato"] = r.get("a")
                st["eventi"] += 1
        return st

    # ── API di dominio ───────────────────────────────────────────────────
    def apri(self, missione_id: str, operatore: str, motivo: str) -> Dict[str, Any]:
        if not missione_id.strip() or not operatore.strip():
            raise ValueError("missione_id e operatore obbligatori")
        if self._stato(missione_id) is not None:
            raise ValueError(f"missione {missione_id!r} gia' aperta")
        if self._mgr is not None:
            case = self._mgr.open_case(customer_ref=None,
                                       title=f"missione {missione_id}",
                                       description=motivo, actor=operatore)
            self._case_ids[missione_id] = case.case_id
        r = self._append({"evento": "apertura", "missione": missione_id,
                          "operatore": operatore, "motivo": motivo[:200]})
        return {"livello": self.livello(), "stato": "ALLERTA",
                "self_hash": r["self_hash"]}

    def aggancia_atto(self, missione_id: str, tipo: str, sha256: str,
                      operatore: str) -> Dict[str, Any]:
        """Aggancia il DIGEST di un atto (valutazione/pre-alert/atmist/fhir).
        Mai contenuto sanitario nel fascicolo."""
        if not _digest_valido(sha256):
            raise ValueError("sha256 dell'atto obbligatorio (64 hex): senza "
                             "digest l'atto e' sostituibile senza traccia")
        st = self._stato(missione_id)
        if st is None:
            raise KeyError(f"missione sconosciuta: {missione_id}")
        if st["stato"] not in STATI_APERTI_AGLI_ATTI:
            raise ValueError(f"missione {st['stato']}: atti non piu' agganciabili "
                             f"(fail-closed)")
        r = self._append({"evento": "atto", "missione": missione_id,
                          "tipo": tipo[:40], "sha256": sha256.lower(),
                          "operatore": operatore})
        return {"livello": self.livello(), "self_hash": r["self_hash"]}

    def transita(self, missione_id: str, a: str, operatore: str,
                 nota: str) -> Dict[str, Any]:
        st = self._stato(missione_id)
        if st is None:
            raise KeyError(f"missione sconosciuta: {missione_id}")
        if a not in STATI:
            raise ValueError(f"stato sconosciuto: {a!r}")
        if a not in TRANSIZIONI[st["stato"]]:
            raise ValueError(f"transizione {st['stato']} -> {a} non ammessa; "
                             f"ammesse: {sorted(TRANSIZIONI[st['stato']])}")
        # colpo Gemini Pro (truncation exploit): si valida la nota GIA' TAGLIATA
        # — 200 spazi + testo passerebbero il controllo ma salverebbero il vuoto
        nota = nota[:200]
        if a == "CONSEGNATA" and not nota.strip():
            raise ValueError("la consegna richiede la nota col destinatario "
                             "(a chi e' stato consegnato il paziente)")
        if self._mgr is not None:
            # doppio replay: il motore valida la STESSA transizione (livello
            # case-engine). Se il caso non e' in memoria (altro processo), viene
            # RICOSTRUITO dal ledger — mai un doppio replay saltato in silenzio.
            # NOTA (obiezione Pro respinta con motivo): il CaseManager qui e' un
            # VALIDATORE in-memory per processo, non persiste nulla — la fonte
            # di verita' e' il JSONL; nessun audit centrale viene frammentato.
            if missione_id not in self._case_ids:
                case = self._mgr.open_case(customer_ref=None,
                                           title=f"missione {missione_id}",
                                           description="replay dal ledger",
                                           actor="replay")
                self._case_ids[missione_id] = case.case_id
                for r in self._righe():
                    if r.get("missione") == missione_id and r.get("evento") == "transizione":
                        self._mgr.transition(case.case_id, _StatoM(r["a"]),
                                             actor=r.get("operatore", "replay"),
                                             reason=r.get("nota", "")[:200])
            self._mgr.transition(self._case_ids[missione_id], _StatoM(a),
                                 actor=operatore, reason=nota[:200])
        try:
            r = self._append({"evento": "transizione", "missione": missione_id,
                              "da": st["stato"], "a": a, "operatore": operatore,
                              "nota": nota[:200]})
        except Exception:
            # il ledger e' la fonte di verita': se l'append fallisce, lo stato
            # gia' avanzato nel validatore in-memory va INVALIDATO (al prossimo
            # uso si ricostruisce dal ledger) — mai due mondi divergenti
            if self._mgr is not None:
                self._case_ids.pop(missione_id, None)
            raise
        return {"livello": self.livello(), "stato": a, "self_hash": r["self_hash"]}

    def fascicolo_pack(self, missione_id: str) -> Dict[str, Any]:
        """Esporta il fascicolo (per il DEA / audit). Solo da CONSEGNATA in poi,
        e solo a catena verificata — mai una fotografia di un perimetro aperto."""
        st = self._stato(missione_id)
        if st is None:
            raise KeyError(f"missione sconosciuta: {missione_id}")
        if st["stato"] in STATI_APERTI_AGLI_ATTI:
            raise ValueError(f"missione {st['stato']}: il pack si esporta da "
                             f"CONSEGNATA in poi (perimetro chiuso)")
        v = self.verifica_ledger()
        if not v["ok"]:
            raise ValueError(f"catena NON verificata: pack rifiutato ({v['errore']})")
        eventi = [{k: r[k] for k in ("evento", "ts", "self_hash") if k in r}
                  | {k: r[k] for k in ("tipo", "sha256", "da", "a", "nota", "operatore")
                     if k in r}
                  for r in self._righe() if r.get("missione") == missione_id]
        corpo = {"formato": "omega-fascicolo-missione/1",
                 "missione": missione_id, "stato": st["stato"],
                 "atti": st["atti"], "eventi": eventi,
                 "livello": self.livello(),
                 "honest_scope": ("narrazione rigiocabile della missione, solo "
                                  "digest degli atti; i contenuti clinici vivono "
                                  "nei loro canali (FHIR/ATMIST), non qui")}
        blob = json.dumps(corpo, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False)
        pack = dict(corpo)
        pack["pack_sha256_contenuto"] = hashlib.sha256(blob.encode()).hexdigest()
        pack["emesso_utc"] = _utc()
        return pack

    def livello(self) -> str:
        return "case-engine" if self._mgr is not None else "fascicolo-locale"


if __name__ == "__main__":
    fm = FascicoloMissione()
    print(json.dumps({"livello": fm.livello(),
                      "motore": MOTORE_DISPONIBILE,
                      "import_error": _err_import,
                      "ledger": fm.verifica_ledger()},
                     ensure_ascii=False, indent=1))
