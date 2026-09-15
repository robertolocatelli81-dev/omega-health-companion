#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-or-later
// health-verify — independent JavaScript verifier of omega-health-companion evidence (Node ≥ 18, no dependencies).
// Same layers and verdict as health_verify.py. JSON is parsed by a strict hand-written parser that KEEPS the text of
// every number (what Python wrote is its repr, so re-emitting it verbatim reproduces the canonical bytes);
// duplicate keys and NaN/Infinity are refused. Two canonical profiles: ASCII (audit ledger: Python ensure_ascii=True)
// and UTF-8 (chains and verbale: ensure_ascii=False). Signatures: Ed25519 over the 32 raw digest bytes, checked
// against the REGISTERED key (fb-<slug>.pub), never the key the line carries.
import { createHash, verify as edVerify, createPublicKey } from "node:crypto";
import { readFileSync, readdirSync, existsSync } from "node:fs";
import { basename, join } from "node:path";

const GENESIS64 = "0".repeat(64), SPKI = Buffer.from("302a300506032b6570032100", "hex");
const AUDIT_KEYS = ["kind", "target", "azione", "dettaglio", "operatore", "ts", "prev_sha256", "alg"];
const AUDIT_UNSIGNED = ["record_sha256", "firma_ed25519_b64", "pubkey_b64"];
const AUDIT_MANDATORY = ["kind", "target", "azione", "dettaglio", "operatore", "ts", "record_sha256", "firma_ed25519_b64", "pubkey_b64"];
class Num { constructor(t) { this.text = t; } }

// ---- strict JSON parser keeping number text ----
function parse(text) {
  let i = 0, depth = 0;
  const ws = () => { while (i < text.length && " \t\n\r".includes(text[i])) i++; };
  const err = (m) => { throw new Error(m + " at " + i); };
  function value() {
    ws(); const c = text[i];
    if (c === "{") { if (++depth > 512) err("too deep"); i++; const o = {}; ws(); if (text[i] === "}") { i++; depth--; return o; }
      for (;;) { ws(); if (text[i] !== '"') err("key"); const k = str(); ws(); if (text[i] !== ":") err("colon"); i++; if (Object.prototype.hasOwnProperty.call(o, k)) err("duplicate key " + k); o[k] = value(); ws(); if (text[i] === ",") { i++; continue; } if (text[i] === "}") { i++; depth--; return o; } err("object"); } }
    if (c === "[") { if (++depth > 512) err("too deep"); i++; const a = []; ws(); if (text[i] === "]") { i++; depth--; return a; }
      for (;;) { a.push(value()); ws(); if (text[i] === ",") { i++; continue; } if (text[i] === "]") { i++; depth--; return a; } err("array"); } }
    if (c === '"') return str();
    if (text.startsWith("true", i)) { i += 4; return true; } if (text.startsWith("false", i)) { i += 5; return false; } if (text.startsWith("null", i)) { i += 4; return null; }
    const m = /^-?(0|[1-9]\d*)(\.\d+)?([eE][+-]?\d+)?/.exec(text.slice(i)); if (!m) err("value");
    i += m[0].length; return new Num(m[0]);
  }
  function str() {
    i++; let out = "";
    for (;;) { if (i >= text.length) err("eof in string"); const c = text[i++];
      if (c === '"') return out;
      if (c === "\\") { const e = text[i++];
        if (e === "u") { const h = text.slice(i, i + 4); if (!/^[0-9a-fA-F]{4}$/.test(h)) err("bad \\u"); i += 4; let cp = parseInt(h, 16);
          if (cp >= 0xd800 && cp <= 0xdbff) { if (text[i] === "\\" && text[i + 1] === "u") { const lo = parseInt(text.slice(i + 2, i + 6), 16); if (lo >= 0xdc00 && lo <= 0xdfff) { i += 6; cp = 0x10000 + ((cp - 0xd800) << 10) + (lo - 0xdc00); } else err("lone surrogate"); } else err("lone surrogate"); }
          else if (cp >= 0xdc00 && cp <= 0xdfff) err("lone surrogate");
          out += String.fromCodePoint(cp); }
        else { const map = { '"': '"', "\\": "\\", "/": "/", b: "\b", f: "\f", n: "\n", r: "\r", t: "\t" }; if (!(e in map)) err("bad escape"); out += map[e]; } }
      else { if (c.charCodeAt(0) < 0x20) err("control char in string"); out += c; } }
  }
  const v = value(); ws(); if (i !== text.length) err("trailing data"); return v;
}
// ---- canonical (Python json.dumps sort_keys, separators (",",":"), ensure_ascii = asciiOnly) ----
function esc(s, asciiOnly) {
  let out = '"';
  for (const ch of s) { const c = ch.codePointAt(0);
    if (ch === '"') out += '\\"'; else if (ch === "\\") out += "\\\\"; else if (ch === "\n") out += "\\n"; else if (ch === "\r") out += "\\r"; else if (ch === "\t") out += "\\t"; else if (ch === "\b") out += "\\b"; else if (ch === "\f") out += "\\f";
    else if (c < 0x20) out += "\\u" + c.toString(16).padStart(4, "0");
    else if (asciiOnly && c > 0x7e) { if (c > 0xffff) { const v = c - 0x10000; out += "\\u" + (0xd800 + (v >> 10)).toString(16).padStart(4, "0") + "\\u" + (0xdc00 + (v & 0x3ff)).toString(16).padStart(4, "0"); } else out += "\\u" + c.toString(16).padStart(4, "0"); }
    else out += ch; }
  return out + '"';
}
const cmp = (a, b) => { const A = [...a], B = [...b]; for (let i = 0; i < Math.min(A.length, B.length); i++) { const d = A[i].codePointAt(0) - B[i].codePointAt(0); if (d) return d; } return A.length - B.length; };
function canon(v, asciiOnly) {
  if (v === null) return "null"; if (v === true) return "true"; if (v === false) return "false";
  if (v instanceof Num) return v.text; if (typeof v === "string") return esc(v, asciiOnly);
  if (Array.isArray(v)) return "[" + v.map((x) => canon(x, asciiOnly)).join(",") + "]";
  if (typeof v === "object") return "{" + Object.keys(v).sort(cmp).map((k) => esc(k, asciiOnly) + ":" + canon(v[k], asciiOnly)).join(",") + "}";
  throw new Error("unserialisable");
}
const sha256 = (b) => createHash("sha256").update(b).digest();
const slug = (op) => [...String(op).trim().toLowerCase()].map((c) => (/[\p{L}\p{N}]/u.test(c) || c === "-" || c === "_") ? c : "-").join("").slice(0, 40);
function edOk(pubB64, sigB64, msg) { try { return edVerify(null, msg, createPublicKey({ key: Buffer.concat([SPKI, Buffer.from(pubB64, "base64")]), format: "der", type: "spki" }), Buffer.from(sigB64, "base64")); } catch { return false; } }
const L = (layer, status, detail = "") => ({ layer, status, detail });
function readLines(path) { const out = []; readFileSync(path, "utf-8").split("\n").forEach((line, idx) => { if (line.trim()) out.push([idx + 1, parse(line)]); }); return out; }
function loadRegistry(dir) { const reg = {}; if (dir && existsSync(dir)) for (const n of readdirSync(dir).sort()) if (n.startsWith("fb-") && n.endsWith(".pub")) reg[n.slice(3, -4)] = readFileSync(join(dir, n), "utf-8").trim(); return reg; }

function verifyAudit(path, registry, source) {
  const records = {}; let lines;
  try { lines = readLines(path); } catch (e) { return [L("audit-ledger", "FAIL", "unreadable: " + e.message.slice(0, 100)), records]; }
  let prev = "GENESIS", sigOk = 0, untrusted = 0, started = false; const failures = [];
  for (const [n, e] of lines) {
    if (e === null || typeof e !== "object" || Array.isArray(e) || e.kind !== "audit_locale") { failures.push(`line ${n}: not an audit_locale object`); break; }
    if (!("prev_sha256" in e)) { if (started) failures.push(`line ${n}: no prev_sha256 after the chain started (insertion/replacement?)`); prev = e.record_sha256 || prev; }
    else { started = true; if (e.prev_sha256 !== prev) failures.push(`line ${n}: prev_sha256 does not link (deletion/reorder?)`); prev = e.record_sha256 || prev; }
    const extra = Object.keys(e).filter((k) => !AUDIT_KEYS.includes(k) && !AUDIT_UNSIGNED.includes(k));
    if (extra.length) failures.push(`line ${n}: unexpected keys ${JSON.stringify(extra.sort())}`);
    if ((e.alg ?? "ed25519") !== "ed25519") failures.push(`line ${n}: unsupported alg ${JSON.stringify(e.alg)}`);
    const missingKeys = AUDIT_MANDATORY.filter((k) => !(k in e));
    if (missingKeys.length) failures.push(`line ${n}: mandatory keys missing ${JSON.stringify(missingKeys)}`);
    const rec = {}; for (const k of AUDIT_KEYS) if (k in e) rec[k] = e[k];
    let digest; try { digest = sha256(Buffer.from(canon(rec, true), "utf-8")); } catch (ex) { failures.push(`line ${n}: not canonicalisable`); continue; }
    const okDigest = digest.toString("hex") === e.record_sha256; if (!okDigest) failures.push(`line ${n}: record_sha256 does not match the canonical record`);
    const pub = registry[slug(e.operatore ?? "") || "anonimo"]; let s = null;
    if (pub) { s = edOk(pub, String(e.firma_ed25519_b64 ?? ""), digest); if (s) sigOk++; else failures.push(`line ${n}: signature invalid for the REGISTERED key of ${e.operatore}`); } else untrusted++;
    records[String(e.record_sha256)] = { ok: okDigest && Boolean(s), digestOk: okDigest, sigOk: s, registered: Boolean(pub) };
  }
  if (!lines.length) failures.push("empty ledger");
  if (failures.length) return [L("audit-ledger", "FAIL", failures.slice(0, 3).join("; ")), records];
  if (untrusted && !sigOk) return [L("audit-ledger", "SKIP", `${lines.length} records, digests and chain PASS, signatures present but NOT trusted (no registered key; registry: ${source})`), records];
  return [L("audit-ledger", "PASS", `${lines.length} records, chain from GENESIS, ${sigOk} signatures verified against registered keys (${source}), ${untrusted} operators without registered key`), records];
}
function verifyChain(path) {
  let lines; try { lines = readLines(path); } catch (e) { return L("chain-ledger", "FAIL", `${basename(path)}: unreadable: ${e.message.slice(0, 60)}`); }
  let prev = GENESIS64; const failures = [];
  for (const [n, r] of lines) {
    if (r === null || typeof r !== "object" || Array.isArray(r)) { failures.push(`line ${n}: not an object`); break; }
    if (r.prev_hash !== prev) failures.push(`line ${n}: prev_hash does not link`);
    const body = {}; for (const k of Object.keys(r)) if (k !== "self_hash") body[k] = r[k];
    let h; try { h = sha256(Buffer.from(canon(body, false), "utf-8")).toString("hex"); } catch { failures.push(`line ${n}: not canonicalisable`); continue; }
    if (h !== r.self_hash) failures.push(`line ${n}: self_hash mismatch`);
    if (typeof r.self_hash === "string") prev = r.self_hash;
  }
  if (!lines.length) failures.push("empty ledger");
  return L("chain-ledger", failures.length ? "FAIL" : "PASS", `${basename(path)}: ` + (failures.length ? failures.slice(0, 3).join("; ") : `${lines.length} entries, chain from genesis, every self_hash recomputed`));
}
function verifyVerbale(path, auditRecords, registryPresent) {
  const layers = []; let v;
  try { v = parse(readFileSync(path, "utf-8")); } catch (e) { return [L("verbale-json", "FAIL", e.message.slice(0, 100))]; }
  if (v === null || typeof v !== "object" || Array.isArray(v) || v.kind !== "verbale_probatorio_prealert") return [L("verbale-json", "FAIL", "not a verbale_probatorio_prealert object")];
  layers.push(L("verbale-json", "PASS"));
  const body = {}; for (const k of Object.keys(v)) if (k !== "digest_verbale_sha256") body[k] = v[k];
  try { const d = sha256(Buffer.from(canon(body, false), "utf-8")).toString("hex"); layers.push(L("verbale-digest", d === v.digest_verbale_sha256 ? "PASS" : "FAIL", `declared ${String(v.digest_verbale_sha256).slice(0, 16)}… computed ${d.slice(0, 16)}…`)); }
  catch { layers.push(L("verbale-digest", "FAIL", "not canonicalisable")); }
  const events = Array.isArray(v.eventi) ? v.eventi : [];
  if (auditRecords === null) layers.push(L("verbale-events", "SKIP", `${events.length} events listed; give --audit to check them against the signed ledger`));
  else {
    const isObj = (e) => e !== null && typeof e === "object" && !Array.isArray(e);
    const missing = events.filter((e) => isObj(e) && !(e.record_sha256 in auditRecords)).length;
    const present = events.filter((e) => isObj(e) && e.record_sha256 in auditRecords).map((e) => auditRecords[e.record_sha256]);
    const bad = present.filter((r) => !r.digestOk || (r.registered && r.sigOk === false)).length;
    const unverified = present.filter((r) => r.digestOk && !r.registered).length;
    const claimed = v.firme_tutte_verificate === true;
    if (missing) layers.push(L("verbale-events", "FAIL", `${missing} event(s) of the verbale are NOT in the audit ledger`));
    else if (bad) layers.push(L("verbale-events", "FAIL", `${bad} event(s) do not verify in the ledger against the registered keys`));
    else if (!events.length) layers.push(L("verbale-events", "FAIL", "no events"));
    else if (unverified) layers.push(L("verbale-events", "SKIP", `${events.length} events present in the ledger, ${unverified} with signatures NOT verified (no registered key)` + (claimed ? "; the verbale CLAIMS firme_tutte_verificate: that claim is not verified here" : "")));
    else layers.push(L("verbale-events", "PASS", `${events.length} events present in the ledger and verified there`));
  }
  return layers;
}
export function run({ audit = null, chains = [], verbale = null, keys = null, trustVerbaleRegistry = false }) {
  const layers = []; let registry = loadRegistry(keys), source = keys ? `keys dir ${keys}` : "none";
  if (!Object.keys(registry).length && verbale && trustVerbaleRegistry) { try { const vv = parse(readFileSync(verbale, "utf-8")); if (vv && typeof vv.registro_chiavi === "object" && vv.registro_chiavi !== null) { registry = {}; for (const k of Object.keys(vv.registro_chiavi)) registry[k] = String(vv.registro_chiavi[k]); source = "the verbale's own registro_chiavi (NOT out-of-band: declared)"; } } catch { /* declared below */ } }
  let auditRecords = null;
  if (audit) { const [lay, recs] = verifyAudit(audit, registry, source); layers.push(lay); auditRecords = recs; }
  for (const c of chains) layers.push(verifyChain(c));
  if (verbale) layers.push(...verifyVerbale(verbale, auditRecords, Object.keys(registry).length > 0));
  if (!layers.length) layers.push(L("input", "FAIL", "nothing to verify"));
  const ok = layers.every((l) => l.status === "PASS");
  return { ok, verdict: ok ? "PASS" : (layers.some((l) => l.status === "FAIL") ? "FAIL" : "NOT-TRUSTED"), registry: source, layers };
}
function main(argv) {
  const a = argv.slice(2); const o = { chains: [] };
  for (let i = 0; i < a.length; i++) { const nx = () => { if (i + 1 >= a.length) { console.error("usage: health-verify.mjs [--audit f] [--chain f]... [--verbale f] [--keys dir] [--trust-verbale-registry]"); process.exit(2); } return a[++i]; };
    if (a[i] === "--audit") o.audit = nx(); else if (a[i] === "--chain") o.chains.push(nx()); else if (a[i] === "--verbale") o.verbale = nx(); else if (a[i] === "--keys") o.keys = nx(); else if (a[i] === "--trust-verbale-registry") o.trustVerbaleRegistry = true; else { console.error("unknown argument " + a[i]); return 2; } }
  const r = run(o); console.log(JSON.stringify(r, null, 1)); return r.ok ? 0 : 1;
}
if (process.argv[1] && /health-verify\.mjs$/.test(process.argv[1])) process.exit(main(process.argv));
