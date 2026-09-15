// SPDX-License-Identifier: AGPL-3.0-or-later
//! health-verify — independent Rust verifier of omega-health-companion evidence. Same layers and verdict as
//! health_verify.py. Numbers keep the exact text found in the file; duplicate keys, NaN, lone surrogates and depth
//! > 512 are refused; ASCII profile for the audit ledger, UTF-8 profile for chains and the verbale.
mod sha256;

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use std::collections::BTreeMap;
use std::path::Path;

const GENESIS64: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const AUDIT_KEYS: [&str; 8] = ["kind", "target", "azione", "dettaglio", "operatore", "ts", "prev_sha256", "alg"];
const AUDIT_UNSIGNED: [&str; 3] = ["record_sha256", "firma_ed25519_b64", "pubkey_b64"];

#[derive(Clone, Debug)]
enum J { Null, Bool(bool), Num(String), Str(String), Arr(Vec<J>), Obj(BTreeMap<String, J>) }

struct P<'a> { s: &'a [u8], i: usize, depth: usize }
impl<'a> P<'a> {
    fn parse(text: &'a str) -> Result<J, String> {
        let mut p = P { s: text.as_bytes(), i: 0, depth: 0 };
        let v = p.value()?; p.ws();
        if p.i != p.s.len() { return Err("trailing data".into()); }
        Ok(v)
    }
    fn ws(&mut self) { while self.i < self.s.len() && matches!(self.s[self.i], b' ' | b'\t' | b'\n' | b'\r') { self.i += 1; } }
    fn value(&mut self) -> Result<J, String> {
        self.ws();
        let c = *self.s.get(self.i).ok_or("unexpected end")?;
        match c {
            b'{' => { self.depth += 1; if self.depth > 512 { return Err("too deep".into()); } self.i += 1; let mut m = BTreeMap::new(); self.ws();
                if self.s.get(self.i) == Some(&b'}') { self.i += 1; self.depth -= 1; return Ok(J::Obj(m)); }
                loop { self.ws(); if self.s.get(self.i) != Some(&b'"') { return Err("key expected".into()); } let k = self.string()?; self.ws();
                    if self.s.get(self.i) != Some(&b':') { return Err("colon expected".into()); } self.i += 1; let v = self.value()?;
                    if m.insert(k.clone(), v).is_some() { return Err(format!("duplicate key {k:?}")); } self.ws();
                    match self.s.get(self.i) { Some(b',') => { self.i += 1; } Some(b'}') => { self.i += 1; self.depth -= 1; return Ok(J::Obj(m)); } _ => return Err("object".into()) } } }
            b'[' => { self.depth += 1; if self.depth > 512 { return Err("too deep".into()); } self.i += 1; let mut a = vec![]; self.ws();
                if self.s.get(self.i) == Some(&b']') { self.i += 1; self.depth -= 1; return Ok(J::Arr(a)); }
                loop { a.push(self.value()?); self.ws(); match self.s.get(self.i) { Some(b',') => { self.i += 1; } Some(b']') => { self.i += 1; self.depth -= 1; return Ok(J::Arr(a)); } _ => return Err("array".into()) } } }
            b'"' => Ok(J::Str(self.string()?)),
            b't' if self.s[self.i..].starts_with(b"true") => { self.i += 4; Ok(J::Bool(true)) }
            b'f' if self.s[self.i..].starts_with(b"false") => { self.i += 5; Ok(J::Bool(false)) }
            b'n' if self.s[self.i..].starts_with(b"null") => { self.i += 4; Ok(J::Null) }
            b'-' | b'0'..=b'9' => { let st = self.i; if self.s[self.i] == b'-' { self.i += 1; }
                let d0 = self.i; while self.i < self.s.len() && self.s[self.i].is_ascii_digit() { self.i += 1; }
                if self.i == d0 { return Err("number".into()); } if self.s[d0] == b'0' && self.i - d0 > 1 { return Err("leading zero".into()); }
                if self.s.get(self.i) == Some(&b'.') { self.i += 1; let f0 = self.i; while self.i < self.s.len() && self.s[self.i].is_ascii_digit() { self.i += 1; } if self.i == f0 { return Err("fraction".into()); } }
                if matches!(self.s.get(self.i), Some(b'e' | b'E')) { self.i += 1; if matches!(self.s.get(self.i), Some(b'+' | b'-')) { self.i += 1; } let e0 = self.i; while self.i < self.s.len() && self.s[self.i].is_ascii_digit() { self.i += 1; } if self.i == e0 { return Err("exponent".into()); } }
                Ok(J::Num(std::str::from_utf8(&self.s[st..self.i]).unwrap().to_string())) }
            _ => Err("value".into()),
        }
    }
    fn string(&mut self) -> Result<String, String> {
        self.i += 1; let mut out = String::new();
        loop {
            let c = *self.s.get(self.i).ok_or("eof in string")?; self.i += 1;
            match c {
                b'"' => return Ok(out),
                b'\\' => { let e = *self.s.get(self.i).ok_or("eof")?; self.i += 1;
                    match e { b'"' => out.push('"'), b'\\' => out.push('\\'), b'/' => out.push('/'), b'b' => out.push('\u{8}'), b'f' => out.push('\u{c}'), b'n' => out.push('\n'), b'r' => out.push('\r'), b't' => out.push('\t'),
                        b'u' => { let mut cp = self.hex4()?; if (0xd800..=0xdbff).contains(&cp) { if self.s.get(self.i) == Some(&b'\\') && self.s.get(self.i + 1) == Some(&b'u') { self.i += 2; let lo = self.hex4()?; if (0xdc00..=0xdfff).contains(&lo) { cp = 0x10000 + ((cp - 0xd800) << 10) + (lo - 0xdc00); } else { return Err("lone surrogate".into()); } } else { return Err("lone surrogate".into()); } } else if (0xdc00..=0xdfff).contains(&cp) { return Err("lone surrogate".into()); }
                            out.push(char::from_u32(cp).ok_or("bad code point")?); }
                        _ => return Err("bad escape".into()) } }
                c if c < 0x20 => return Err("control char in string".into()),
                _ => { // copy one UTF-8 scalar
                    let st = self.i - 1; let len = if c < 0x80 { 1 } else if c >> 5 == 0b110 { 2 } else if c >> 4 == 0b1110 { 3 } else { 4 };
                    let sl = self.s.get(st..st + len).ok_or("bad utf-8")?; out.push_str(std::str::from_utf8(sl).map_err(|_| "bad utf-8")?); self.i = st + len; }
            }
        }
    }
    fn hex4(&mut self) -> Result<u32, String> { let h = self.s.get(self.i..self.i + 4).ok_or("bad \\u")?; self.i += 4; u32::from_str_radix(std::str::from_utf8(h).map_err(|_| "bad \\u")?, 16).map_err(|_| "bad \\u".into()) }
}

fn esc(s: &str, ascii_only: bool, out: &mut String) {
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""), '\\' => out.push_str("\\\\"), '\n' => out.push_str("\\n"), '\r' => out.push_str("\\r"), '\t' => out.push_str("\\t"), '\u{8}' => out.push_str("\\b"), '\u{c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 || (ascii_only && (c as u32) > 0x7e) => {
                let cp = c as u32;
                if cp > 0xffff { let v = cp - 0x10000; out.push_str(&format!("\\u{:04x}\\u{:04x}", 0xd800 + (v >> 10), 0xdc00 + (v & 0x3ff))); } else { out.push_str(&format!("\\u{cp:04x}")); }
            }
            c => out.push(c),
        }
    }
    out.push('"');
}
fn canon(v: &J, ascii_only: bool, out: &mut String) {
    match v {
        J::Null => out.push_str("null"), J::Bool(b) => out.push_str(if *b { "true" } else { "false" }), J::Num(t) => out.push_str(t), J::Str(s) => esc(s, ascii_only, out),
        J::Arr(a) => { out.push('['); for (i, x) in a.iter().enumerate() { if i > 0 { out.push(','); } canon(x, ascii_only, out); } out.push(']'); }
        J::Obj(m) => { out.push('{'); for (i, (k, x)) in m.iter().enumerate() { if i > 0 { out.push(','); } esc(k, ascii_only, out); out.push(':'); canon(x, ascii_only, out); } out.push('}'); }
    }
}
fn canon_bytes(v: &J, ascii_only: bool) -> Vec<u8> { let mut s = String::new(); canon(v, ascii_only, &mut s); s.into_bytes() }
fn sha_hex(b: &[u8]) -> String { sha256::hex(b) }
fn unhex(s: &str) -> Option<Vec<u8>> { if s.len() % 2 != 0 { return None; } (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok()).collect() }
fn b64(s: &str) -> Option<Vec<u8>> {
    let t: Vec<u8> = s.bytes().filter(|c| !c.is_ascii_whitespace()).collect(); let mut out = vec![]; let mut buf = 0u32; let mut n = 0;
    for &c in &t { if c == b'=' { break; } let v = match c { b'A'..=b'Z' => c - b'A', b'a'..=b'z' => c - b'a' + 26, b'0'..=b'9' => c - b'0' + 52, b'+' => 62, b'/' => 63, _ => return None } as u32;
        buf = (buf << 6) | v; n += 6; if n >= 8 { n -= 8; out.push((buf >> n) as u8); buf &= (1 << n) - 1; } }
    Some(out)
}
fn ed_ok(pub_b64: &str, sig_b64: &str, msg: &[u8]) -> bool {
    let (Some(p), Some(s)) = (b64(pub_b64), b64(sig_b64)) else { return false };
    let (Ok(pb), Ok(sb)) = (<[u8; 32]>::try_from(p.as_slice()), <[u8; 64]>::try_from(s.as_slice())) else { return false };
    let Ok(vk) = VerifyingKey::from_bytes(&pb) else { return false };
    vk.verify(msg, &Signature::from_bytes(&sb)).is_ok()
}
fn slug(op: &str) -> String { op.trim().to_lowercase().chars().map(|c| if c.is_alphanumeric() || c == '-' || c == '_' { c } else { '-' }).take(40).collect() }
fn gs<'a>(o: &'a BTreeMap<String, J>, k: &str) -> Option<&'a str> { match o.get(k) { Some(J::Str(s)) => Some(s), _ => None } }
struct Layer(String, String, String);
fn layer(a: &str, b: &str, c: String) -> Layer { Layer(a.into(), b.into(), c) }
fn read_lines(path: &str) -> Result<Vec<(usize, J)>, String> {
    let t = std::fs::read_to_string(path).map_err(|e| e.to_string())?; let mut out = vec![];
    for (i, line) in t.split('\n').enumerate() { if line.trim().is_empty() { continue; } out.push((i + 1, P::parse(line).map_err(|e| format!("line {}: {e}", i + 1))?)); }
    Ok(out)
}
fn load_registry(dir: Option<&str>) -> BTreeMap<String, String> {
    let mut reg = BTreeMap::new();
    if let Some(d) = dir { if let Ok(rd) = std::fs::read_dir(d) { let mut names: Vec<String> = rd.flatten().map(|e| e.file_name().to_string_lossy().to_string()).collect(); names.sort();
        for n in names { if n.starts_with("fb-") && n.ends_with(".pub") { if let Ok(t) = std::fs::read_to_string(Path::new(d).join(&n)) { reg.insert(n[3..n.len() - 4].to_string(), t.trim().to_string()); } } } } }
    reg
}
fn join3(f: &[String]) -> String { f.iter().take(3).cloned().collect::<Vec<_>>().join("; ") }
struct Rec { ok: bool }

fn verify_audit(path: &str, registry: &BTreeMap<String, String>, source: &str) -> (Layer, BTreeMap<String, Rec>) {
    let mut records = BTreeMap::new();
    let lines = match read_lines(path) { Ok(l) => l, Err(e) => return (layer("audit-ledger", "FAIL", format!("unreadable: {e}")), records) };
    let (mut prev, mut sig_ok, mut untrusted, mut started) = ("GENESIS".to_string(), 0, 0, false); let mut failures = vec![];
    for (n, e) in &lines {
        let J::Obj(e) = e else { failures.push(format!("line {n}: not an audit_locale object")); break };
        if gs(e, "kind") != Some("audit_locale") { failures.push(format!("line {n}: not an audit_locale object")); break; }
        let rs = gs(e, "record_sha256").unwrap_or("").to_string();
        match e.get("prev_sha256") {
            None => { if started { failures.push(format!("line {n}: no prev_sha256 after the chain started (insertion/replacement?)")); } }
            Some(ps) => { started = true; if !matches!(ps, J::Str(s) if *s == prev) { failures.push(format!("line {n}: prev_sha256 does not link (deletion/reorder?)")); } }
        }
        if !rs.is_empty() { prev = rs.clone(); }
        let extra: Vec<&String> = e.keys().filter(|k| !AUDIT_KEYS.contains(&k.as_str()) && !AUDIT_UNSIGNED.contains(&k.as_str())).collect();
        if !extra.is_empty() { failures.push(format!("line {n}: unexpected keys {extra:?}")); }
        if let Some(a) = gs(e, "alg") { if a != "ed25519" { failures.push(format!("line {n}: unsupported alg {a:?}")); } }
        let mut r = BTreeMap::new(); for k in AUDIT_KEYS { if let Some(v) = e.get(k) { r.insert(k.to_string(), v.clone()); } }
        let digest_hex = sha_hex(&canon_bytes(&J::Obj(r), true)); let ok_digest = digest_hex == rs;
        if !ok_digest { failures.push(format!("line {n}: record_sha256 does not match the canonical record")); }
        let op = gs(e, "operatore").unwrap_or(""); let mut sl = slug(op); if sl.is_empty() { sl = "anonimo".into(); }
        let mut s_ok = false;
        match registry.get(&sl) {
            Some(pubk) if !pubk.is_empty() => { s_ok = ed_ok(pubk, gs(e, "firma_ed25519_b64").unwrap_or(""), &unhex(&digest_hex).unwrap_or_default()); if s_ok { sig_ok += 1; } else { failures.push(format!("line {n}: signature invalid for the REGISTERED key of {op}")); } }
            _ => { untrusted += 1; }
        }
        records.insert(rs, Rec { ok: ok_digest && s_ok });
    }
    if lines.is_empty() { failures.push("empty ledger".into()); }
    if !failures.is_empty() { return (layer("audit-ledger", "FAIL", join3(&failures)), records); }
    if untrusted > 0 && sig_ok == 0 { return (layer("audit-ledger", "SKIP", format!("{} records, digests and chain PASS, signatures present but NOT trusted (no registered key; registry: {source})", lines.len())), records); }
    (layer("audit-ledger", "PASS", format!("{} records, chain from GENESIS, {sig_ok} signatures verified against registered keys ({source}), {untrusted} operators without registered key", lines.len())), records)
}
fn verify_chain(path: &str) -> Layer {
    let name = Path::new(path).file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
    let lines = match read_lines(path) { Ok(l) => l, Err(e) => return layer("chain-ledger", "FAIL", format!("{name}: unreadable: {e}")) };
    let mut prev = GENESIS64.to_string(); let mut failures = vec![];
    for (n, r) in &lines {
        let J::Obj(r) = r else { failures.push(format!("line {n}: not an object")); break };
        if gs(r, "prev_hash") != Some(prev.as_str()) { failures.push(format!("line {n}: prev_hash does not link")); }
        let mut body = r.clone(); body.remove("self_hash");
        let h = sha_hex(&canon_bytes(&J::Obj(body), false)); let sh = gs(r, "self_hash").unwrap_or("");
        if h != sh { failures.push(format!("line {n}: self_hash mismatch")); }
        if !sh.is_empty() { prev = sh.to_string(); }
    }
    if lines.is_empty() { failures.push("empty ledger".into()); }
    if !failures.is_empty() { layer("chain-ledger", "FAIL", format!("{name}: {}", join3(&failures))) } else { layer("chain-ledger", "PASS", format!("{name}: {} entries, chain from genesis, every self_hash recomputed", lines.len())) }
}
fn verify_verbale(path: &str, audit: Option<&BTreeMap<String, Rec>>, registry_present: bool) -> Vec<Layer> {
    let t = match std::fs::read_to_string(path) { Ok(t) => t, Err(e) => return vec![layer("verbale-json", "FAIL", e.to_string())] };
    let v = match P::parse(&t) { Ok(J::Obj(o)) => o, Ok(_) => return vec![layer("verbale-json", "FAIL", "not a verbale_probatorio_prealert object".into())], Err(e) => return vec![layer("verbale-json", "FAIL", e)] };
    if gs(&v, "kind") != Some("verbale_probatorio_prealert") { return vec![layer("verbale-json", "FAIL", "not a verbale_probatorio_prealert object".into())]; }
    let mut layers = vec![layer("verbale-json", "PASS", String::new())];
    let mut body = v.clone(); body.remove("digest_verbale_sha256");
    let d = sha_hex(&canon_bytes(&J::Obj(body), false)); let declared = gs(&v, "digest_verbale_sha256").unwrap_or("");
    layers.push(layer("verbale-digest", if d == declared { "PASS" } else { "FAIL" }, format!("declared {}… computed {}…", declared.chars().take(16).collect::<String>(), &d[..16])));
    let events: Vec<&J> = match v.get("eventi") { Some(J::Arr(a)) => a.iter().collect(), _ => vec![] };
    match audit {
        None => layers.push(layer("verbale-events", "SKIP", format!("{} events listed; give --audit to check them against the signed ledger", events.len()))),
        Some(recs) => {
            let (mut missing, mut bad) = (0, 0);
            for e in &events { if let J::Obj(eo) = e { match recs.get(gs(eo, "record_sha256").unwrap_or("")) { None => missing += 1, Some(r) if !r.ok => bad += 1, _ => {} } } }
            let claimed = matches!(v.get("firme_tutte_verificate"), Some(J::Bool(true)));
            if missing > 0 { layers.push(layer("verbale-events", "FAIL", format!("{missing} event(s) of the verbale are NOT in the audit ledger"))); }
            else if bad > 0 { layers.push(layer("verbale-events", "FAIL", format!("{bad} event(s) do not verify in the ledger against the registered keys"))); }
            else if claimed && !registry_present { layers.push(layer("verbale-events", "FAIL", "the verbale claims firme_tutte_verificate but no registry was given to re-verify them (a claim is not a verification)".into())); }
            else if events.is_empty() { layers.push(layer("verbale-events", "FAIL", "no events".into())); }
            else if registry_present { layers.push(layer("verbale-events", "PASS", format!("{} events present in the ledger and verified there", events.len()))); }
            else { layers.push(layer("verbale-events", "PASS", format!("{} events present in the ledger (signatures not trusted: no registry)", events.len()))); }
        }
    }
    layers
}
fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (mut audit, mut verbale, mut keys, mut trust_vr): (Option<String>, Option<String>, Option<String>, bool) = (None, None, None, false); let mut chains = vec![];
    let usage = || { eprintln!("usage: health-verify [--audit f] [--chain f]... [--verbale f] [--keys dir] [--trust-verbale-registry]"); std::process::exit(2) };
    let mut i = 0;
    while i < args.len() { let nx = |i: usize| args.get(i + 1).cloned().unwrap_or_else(|| usage());
        match args[i].as_str() { "--audit" => { audit = Some(nx(i)); i += 1; } "--chain" => { chains.push(nx(i)); i += 1; } "--verbale" => { verbale = Some(nx(i)); i += 1; } "--keys" => { keys = Some(nx(i)); i += 1; } "--trust-verbale-registry" => trust_vr = true, _ => { usage(); } }
        i += 1; }
    let mut registry = load_registry(keys.as_deref()); let mut source = keys.as_ref().map(|k| format!("keys dir {k}")).unwrap_or_else(|| "none".into());
    if registry.is_empty() && trust_vr { if let Some(vp) = &verbale { if let Ok(t) = std::fs::read_to_string(vp) { if let Ok(J::Obj(vo)) = P::parse(&t) { if let Some(J::Obj(rc)) = vo.get("registro_chiavi") { registry = rc.iter().map(|(k, v)| (k.clone(), match v { J::Str(s) => s.clone(), _ => String::new() })).collect(); source = "the verbale's own registro_chiavi (NOT out-of-band: declared)".into(); } } } } }
    let mut layers = vec![]; let mut records = None;
    if let Some(a) = &audit { let (l, r) = verify_audit(a, &registry, &source); layers.push(l); records = Some(r); }
    for c in &chains { layers.push(verify_chain(c)); }
    if let Some(vp) = &verbale { layers.extend(verify_verbale(vp, records.as_ref(), !registry.is_empty())); }
    if layers.is_empty() { layers.push(layer("input", "FAIL", "nothing to verify".into())); }
    let ok = layers.iter().all(|l| l.1 == "PASS"); let any_fail = layers.iter().any(|l| l.1 == "FAIL");
    let verdict = if ok { "PASS" } else if any_fail { "FAIL" } else { "NOT-TRUSTED" };
    let mut out = String::new(); esc("", false, &mut out); out.clear();
    out.push_str(&format!("{{\"ok\":{ok},\"verdict\":\"{verdict}\",\"registry\":")); esc(&source, false, &mut out); out.push_str(",\"layers\":[");
    for (i, l) in layers.iter().enumerate() { if i > 0 { out.push(','); } out.push_str("{\"layer\":"); esc(&l.0, false, &mut out); out.push_str(",\"status\":"); esc(&l.1, false, &mut out); out.push_str(",\"detail\":"); esc(&l.2, false, &mut out); out.push('}'); }
    out.push_str("]}"); println!("{out}");
    std::process::exit(if ok { 0 } else { 1 });
}
