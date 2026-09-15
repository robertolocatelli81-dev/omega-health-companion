// SPDX-License-Identifier: AGPL-3.0-or-later
// health-verify — independent Go verifier of omega-health-companion evidence (standard library only).
// Same layers and verdict as health_verify.py. Strict JSON (duplicate keys / NaN / lone surrogates / depth > 512
// refused — prescan.go is cryptovalid's), numbers kept as their text (json.Number), two canonical profiles
// (ASCII for the audit ledger, UTF-8 for chains and the verbale), Ed25519 over the raw digest against the
// REGISTERED key. Usage: health-verify [--audit f] [--chain f]... [--verbale f] [--keys dir] [--trust-verbale-registry]
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

const genesis64 = "0000000000000000000000000000000000000000000000000000000000000000"

var auditKeys = []string{"kind", "target", "azione", "dettaglio", "operatore", "ts", "prev_sha256", "alg"}
var auditUnsigned = map[string]bool{"record_sha256": true, "firma_ed25519_b64": true, "pubkey_b64": true}
var auditMandatory = []string{"kind", "target", "azione", "dettaglio", "operatore", "ts", "record_sha256", "firma_ed25519_b64", "pubkey_b64"}

type Object struct {
	Keys []string
	Vals map[string]any
}

// Parse decodes one JSON text strictly; numbers stay json.Number (their exact text).
func Parse(text []byte) (any, error) {
	if !utf8.Valid(text) {
		return nil, errors.New("non-UTF-8 input")
	}
	if err := prescan(text); err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(text))
	dec.UseNumber()
	v, err := parseValue(dec, 0)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("trailing data after JSON value")
	}
	return v, nil
}

func parseValue(dec *json.Decoder, depth int) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch t := tok.(type) {
	case json.Delim:
		if depth > MaxJSONDepth {
			return nil, errors.New("too deep")
		}
		if t == '{' {
			o := &Object{Vals: map[string]any{}}
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return nil, err
				}
				k, ok := kt.(string)
				if !ok {
					return nil, errors.New("object key not a string")
				}
				if _, dup := o.Vals[k]; dup {
					return nil, fmt.Errorf("duplicate key %q", k)
				}
				v, err := parseValue(dec, depth+1)
				if err != nil {
					return nil, err
				}
				o.Keys = append(o.Keys, k)
				o.Vals[k] = v
			}
			if _, err := dec.Token(); err != nil {
				return nil, err
			}
			return o, nil
		}
		if t == '[' {
			arr := []any{}
			for dec.More() {
				v, err := parseValue(dec, depth+1)
				if err != nil {
					return nil, err
				}
				arr = append(arr, v)
			}
			if _, err := dec.Token(); err != nil {
				return nil, err
			}
			return arr, nil
		}
		return nil, errors.New("unexpected delimiter")
	default:
		return tok, nil
	}
}

func canonical(b *bytes.Buffer, v any, asciiOnly bool) error {
	switch t := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		if t {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case json.Number:
		b.WriteString(string(t))
	case string:
		writeString(b, t, asciiOnly)
	case []any:
		b.WriteByte('[')
		for i, x := range t {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := canonical(b, x, asciiOnly); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case *Object:
		keys := append([]string(nil), t.Keys...)
		sort.Slice(keys, func(i, j int) bool { return lessByCodePoint(keys[i], keys[j]) })
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			writeString(b, k, asciiOnly)
			b.WriteByte(':')
			if err := canonical(b, t.Vals[k], asciiOnly); err != nil {
				return err
			}
		}
		b.WriteByte('}')
	default:
		return fmt.Errorf("unserialisable %T", v)
	}
	return nil
}

func lessByCodePoint(a, b string) bool { // Python sorts str by code point, not by UTF-16 unit
	ra, rb := []rune(a), []rune(b)
	for i := 0; i < len(ra) && i < len(rb); i++ {
		if ra[i] != rb[i] {
			return ra[i] < rb[i]
		}
	}
	return len(ra) < len(rb)
}

func writeString(b *bytes.Buffer, s string, asciiOnly bool) {
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		default:
			if r < 0x20 || (asciiOnly && r > 0x7e) {
				if r > 0xffff {
					v := r - 0x10000
					fmt.Fprintf(b, `\u%04x\u%04x`, 0xd800+(v>>10), 0xdc00+(v&0x3ff))
				} else {
					fmt.Fprintf(b, `\u%04x`, r)
				}
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
}

func canonBytes(v any, asciiOnly bool) ([]byte, error) {
	var b bytes.Buffer
	if err := canonical(&b, v, asciiOnly); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

type layer struct{ Layer, Status, Detail string }

func (l layer) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]string{"layer": l.Layer, "status": l.Status, "detail": l.Detail})
}

type result struct {
	Ok       bool    `json:"ok"`
	Verdict  string  `json:"verdict"`
	Registry string  `json:"registry"`
	Layers   []layer `json:"layers"`
}

type rec struct{ Ok, DigestOk, Registered, SigOk bool }

func getS(o *Object, k string) (string, bool) { v, ok := o.Vals[k].(string); return v, ok }

func slug(op string) string {
	var sb strings.Builder
	for _, r := range strings.ToLower(strings.TrimSpace(op)) {
		if unicode.IsLetter(r) || unicode.IsNumber(r) || r == '-' || r == '_' {
			sb.WriteRune(r)
		} else {
			sb.WriteRune('-')
		}
	}
	rs := []rune(sb.String())
	if len(rs) > 40 {
		rs = rs[:40]
	}
	return string(rs)
}

func edOK(pubB64, sigB64 string, msg []byte) bool {
	pub, e1 := base64.StdEncoding.DecodeString(pubB64)
	sig, e2 := base64.StdEncoding.DecodeString(sigB64)
	if e1 != nil || e2 != nil || len(pub) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pub), msg, sig)
}

func readLines(path string) ([][2]any, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out [][2]any
	for i, line := range bytes.Split(raw, []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		v, err := Parse(line)
		if err != nil {
			return nil, fmt.Errorf("line %d: %v", i+1, err)
		}
		out = append(out, [2]any{i + 1, v})
	}
	return out, nil
}

func loadRegistry(dir string) map[string]string {
	reg := map[string]string{}
	if dir == "" {
		return reg
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		return reg
	}
	for _, e := range ents {
		n := e.Name()
		if strings.HasPrefix(n, "fb-") && strings.HasSuffix(n, ".pub") {
			if b, err := os.ReadFile(filepath.Join(dir, n)); err == nil {
				reg[n[3:len(n)-4]] = strings.TrimSpace(string(b))
			}
		}
	}
	return reg
}

func join3(f []string) string {
	if len(f) > 3 {
		f = f[:3]
	}
	return strings.Join(f, "; ")
}

func verifyAudit(path string, registry map[string]string, source string) (layer, map[string]rec) {
	records := map[string]rec{}
	lines, err := readLines(path)
	if err != nil {
		return layer{"audit-ledger", "FAIL", "unreadable: " + err.Error()}, records
	}
	prev, sigOk, untrusted, started := "GENESIS", 0, 0, false
	var failures []string
	for _, ln := range lines {
		n := ln[0].(int)
		e, ok := ln[1].(*Object)
		if k, _ := getS(e, "kind"); !ok || k != "audit_locale" {
			failures = append(failures, fmt.Sprintf("line %d: not an audit_locale object", n))
			break
		}
		rs, _ := getS(e, "record_sha256")
		if ps, has := e.Vals["prev_sha256"]; !has {
			if started {
				failures = append(failures, fmt.Sprintf("line %d: no prev_sha256 after the chain started (insertion/replacement?)", n))
			}
		} else {
			started = true
			if s, _ := ps.(string); s != prev {
				failures = append(failures, fmt.Sprintf("line %d: prev_sha256 does not link (deletion/reorder?)", n))
			}
		}
		if rs != "" {
			prev = rs
		}
		known := map[string]bool{}
		for _, k := range auditKeys {
			known[k] = true
		}
		var extra []string
		for _, k := range e.Keys {
			if !known[k] && !auditUnsigned[k] {
				extra = append(extra, k)
			}
		}
		if len(extra) > 0 {
			sort.Strings(extra)
			failures = append(failures, fmt.Sprintf("line %d: unexpected keys %v", n, extra))
		}
		if alg, has := getS(e, "alg"); has && alg != "ed25519" {
			failures = append(failures, fmt.Sprintf("line %d: unsupported alg %q", n, alg))
		}
		var missingKeys []string
		for _, k := range auditMandatory {
			if _, has := e.Vals[k]; !has {
				missingKeys = append(missingKeys, k)
			}
		}
		if len(missingKeys) > 0 {
			failures = append(failures, fmt.Sprintf("line %d: mandatory keys missing %v", n, missingKeys))
		}
		r := &Object{Vals: map[string]any{}}
		for _, k := range auditKeys {
			if v, has := e.Vals[k]; has {
				r.Keys = append(r.Keys, k)
				r.Vals[k] = v
			}
		}
		cb, err := canonBytes(r, true)
		if err != nil {
			failures = append(failures, fmt.Sprintf("line %d: not canonicalisable", n))
			continue
		}
		digest := sha256.Sum256(cb)
		okDigest := hex.EncodeToString(digest[:]) == rs
		if !okDigest {
			failures = append(failures, fmt.Sprintf("line %d: record_sha256 does not match the canonical record", n))
		}
		op, _ := getS(e, "operatore")
		sl := slug(op)
		if sl == "" {
			sl = "anonimo"
		}
		pub, registered := registry[sl]
		sOk := false
		if registered && pub != "" {
			sig, _ := getS(e, "firma_ed25519_b64")
			sOk = edOK(pub, sig, digest[:])
			if sOk {
				sigOk++
			} else {
				failures = append(failures, fmt.Sprintf("line %d: signature invalid for the REGISTERED key of %s", n, op))
			}
		} else {
			registered = false
			untrusted++
		}
		records[rs] = rec{Ok: okDigest && sOk, DigestOk: okDigest, Registered: registered, SigOk: sOk}
	}
	if len(lines) == 0 {
		failures = append(failures, "empty ledger")
	}
	if len(failures) > 0 {
		return layer{"audit-ledger", "FAIL", join3(failures)}, records
	}
	if untrusted > 0 && sigOk == 0 {
		return layer{"audit-ledger", "SKIP", fmt.Sprintf("%d records, digests and chain PASS, signatures present but NOT trusted (no registered key; registry: %s)", len(lines), source)}, records
	}
	return layer{"audit-ledger", "PASS", fmt.Sprintf("%d records, chain from GENESIS, %d signatures verified against registered keys (%s), %d operators without registered key", len(lines), sigOk, source, untrusted)}, records
}

func verifyChain(path string) layer {
	name := filepath.Base(path)
	lines, err := readLines(path)
	if err != nil {
		return layer{"chain-ledger", "FAIL", name + ": unreadable: " + err.Error()}
	}
	prev := genesis64
	var failures []string
	for _, ln := range lines {
		n := ln[0].(int)
		r, ok := ln[1].(*Object)
		if !ok {
			failures = append(failures, fmt.Sprintf("line %d: not an object", n))
			break
		}
		if ph, _ := getS(r, "prev_hash"); ph != prev {
			failures = append(failures, fmt.Sprintf("line %d: prev_hash does not link", n))
		}
		body := &Object{Vals: map[string]any{}}
		for _, k := range r.Keys {
			if k != "self_hash" {
				body.Keys = append(body.Keys, k)
				body.Vals[k] = r.Vals[k]
			}
		}
		cb, err := canonBytes(body, false)
		if err != nil {
			failures = append(failures, fmt.Sprintf("line %d: not canonicalisable", n))
			continue
		}
		h := sha256.Sum256(cb)
		sh, _ := getS(r, "self_hash")
		if hex.EncodeToString(h[:]) != sh {
			failures = append(failures, fmt.Sprintf("line %d: self_hash mismatch", n))
		}
		if sh != "" {
			prev = sh
		}
	}
	if len(lines) == 0 {
		failures = append(failures, "empty ledger")
	}
	if len(failures) > 0 {
		return layer{"chain-ledger", "FAIL", name + ": " + join3(failures)}
	}
	return layer{"chain-ledger", "PASS", fmt.Sprintf("%s: %d entries, chain from genesis, every self_hash recomputed", name, len(lines))}
}

func verifyVerbale(path string, audit map[string]rec, haveAudit, _registryPresent bool) []layer {
	raw, err := os.ReadFile(path)
	if err != nil {
		return []layer{{"verbale-json", "FAIL", err.Error()}}
	}
	vv, err := Parse(raw)
	if err != nil {
		return []layer{{"verbale-json", "FAIL", err.Error()}}
	}
	v, ok := vv.(*Object)
	if k, _ := getS(v, "kind"); !ok || k != "verbale_probatorio_prealert" {
		return []layer{{"verbale-json", "FAIL", "not a verbale_probatorio_prealert object"}}
	}
	layers := []layer{{"verbale-json", "PASS", ""}}
	body := &Object{Vals: map[string]any{}}
	for _, k := range v.Keys {
		if k != "digest_verbale_sha256" {
			body.Keys = append(body.Keys, k)
			body.Vals[k] = v.Vals[k]
		}
	}
	declared, _ := getS(v, "digest_verbale_sha256")
	if cb, err := canonBytes(body, false); err != nil {
		layers = append(layers, layer{"verbale-digest", "FAIL", "not canonicalisable"})
	} else {
		h := sha256.Sum256(cb)
		d := hex.EncodeToString(h[:])
		st := "FAIL"
		if d == declared {
			st = "PASS"
		}
		layers = append(layers, layer{"verbale-digest", st, fmt.Sprintf("declared %.16s… computed %.16s…", declared, d)})
	}
	events, _ := v.Vals["eventi"].([]any)
	if !haveAudit {
		layers = append(layers, layer{"verbale-events", "SKIP", fmt.Sprintf("%d events listed; give --audit to check them against the signed ledger", len(events))})
		return layers
	}
	missing, bad, unverified := 0, 0, 0
	for _, ev := range events {
		eo, ok := ev.(*Object)
		if !ok {
			continue
		}
		rs, _ := getS(eo, "record_sha256")
		r, found := audit[rs]
		if !found {
			missing++
		} else if !r.DigestOk || (r.Registered && !r.SigOk) {
			bad++
		} else if !r.Registered {
			unverified++
		}
	}
	claimed, _ := v.Vals["firme_tutte_verificate"].(bool)
	switch {
	case missing > 0:
		layers = append(layers, layer{"verbale-events", "FAIL", fmt.Sprintf("%d event(s) of the verbale are NOT in the audit ledger", missing)})
	case bad > 0:
		layers = append(layers, layer{"verbale-events", "FAIL", fmt.Sprintf("%d event(s) do not verify in the ledger against the registered keys", bad)})
	case len(events) == 0:
		layers = append(layers, layer{"verbale-events", "FAIL", "no events"})
	case unverified > 0:
		note := ""
		if claimed {
			note = "; the verbale CLAIMS firme_tutte_verificate: that claim is not verified here"
		}
		layers = append(layers, layer{"verbale-events", "SKIP", fmt.Sprintf("%d events present in the ledger, %d with signatures NOT verified (no registered key)%s", len(events), unverified, note)})
	default:
		layers = append(layers, layer{"verbale-events", "PASS", fmt.Sprintf("%d events present in the ledger and verified there", len(events))})
	}
	return layers
}

func main() {
	var audit, verbale, keys string
	var chains []string
	trustVR := false
	args := os.Args[1:]
	next := func(i int) string {
		if i+1 >= len(args) {
			fmt.Fprintln(os.Stderr, "usage: health-verify [--audit f] [--chain f]... [--verbale f] [--keys dir] [--trust-verbale-registry]")
			os.Exit(2)
		}
		return args[i+1]
	}
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--audit":
			audit = next(i)
			i++
		case "--chain":
			chains = append(chains, next(i))
			i++
		case "--verbale":
			verbale = next(i)
			i++
		case "--keys":
			keys = next(i)
			i++
		case "--trust-verbale-registry":
			trustVR = true
		default:
			fmt.Fprintln(os.Stderr, "unknown argument", args[i])
			os.Exit(2)
		}
	}
	registry, source := loadRegistry(keys), "none"
	if keys != "" {
		source = "keys dir " + keys
	}
	if len(registry) == 0 && verbale != "" && trustVR {
		if raw, err := os.ReadFile(verbale); err == nil {
			if vv, err := Parse(raw); err == nil {
				if vo, ok := vv.(*Object); ok {
					if rc, ok := vo.Vals["registro_chiavi"].(*Object); ok {
						registry = map[string]string{}
						for _, k := range rc.Keys {
							registry[k] = fmt.Sprint(rc.Vals[k])
						}
						source = "the verbale's own registro_chiavi (NOT out-of-band: declared)"
					}
				}
			}
		}
	}
	var layers []layer
	var records map[string]rec
	haveAudit := audit != ""
	if haveAudit {
		var l layer
		l, records = verifyAudit(audit, registry, source)
		layers = append(layers, l)
	}
	for _, c := range chains {
		layers = append(layers, verifyChain(c))
	}
	if verbale != "" {
		layers = append(layers, verifyVerbale(verbale, records, haveAudit, len(registry) > 0)...)
	}
	if len(layers) == 0 {
		layers = append(layers, layer{"input", "FAIL", "nothing to verify"})
	}
	ok, anyFail := true, false
	for _, l := range layers {
		if l.Status != "PASS" {
			ok = false
		}
		if l.Status == "FAIL" {
			anyFail = true
		}
	}
	verdict := "PASS"
	if !ok {
		verdict = "NOT-TRUSTED"
		if anyFail {
			verdict = "FAIL"
		}
	}
	out, _ := json.MarshalIndent(result{Ok: ok, Verdict: verdict, Registry: source, Layers: layers}, "", " ")
	fmt.Println(string(out))
	if !ok {
		os.Exit(1)
	}
}
