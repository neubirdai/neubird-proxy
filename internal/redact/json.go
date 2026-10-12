package redact

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

// JSON masks string values inside one or more concatenated JSON documents
// (Splunk export streams newline-delimited objects). Key order, structure
// and number precision are preserved; whitespace is not.
//
// Object keys get value rules too, since maps keyed by user or email are
// common (Splunk "chart ... by user"). Key rules match the original key.
// Two keys masked to the same label collide; parsers then keep one.
//
// A string that itself holds JSON (MCP tool text, Splunk _raw) is walked as
// JSON, so key rules apply inside it; its inner whitespace is compacted.
//
// Under a blocked key every string and number leaf is masked. Elsewhere
// numbers are left alone: a 13-19 digit ID or timestamp would pass Luhn
// one time in ten, and masking would change its JSON type.
//
// An error means the body was not valid JSON; the caller decides whether
// to fall back to Text.
func (e *Engine) JSON(body []byte, st Stats) ([]byte, error) {
	return e.JSONFields(body, st, nil)
}

// JSONFields is JSON with a field allowlist; nil means no allowlist.
func (e *Engine) JSONFields(body []byte, st Stats, fields *Fields) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	w := &jsonWriter{e: e, st: st, fields: fields}
	w.out.Grow(len(body))
	w.enc = json.NewEncoder(&w.scratch)
	w.enc.SetEscapeHTML(false)

	// Local counts are committed only on success, so a fallback to Text
	// does not double count.
	local := Stats{}
	w.st = local
	docs := 0
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if docs > 0 {
			w.out.WriteByte('\n')
		}
		if err := w.value(dec, tok, nil); err != nil {
			return nil, err
		}
		docs++
	}
	if docs == 0 {
		return nil, fmt.Errorf("empty JSON body")
	}
	for k, v := range local {
		st[k] += v
	}
	return w.out.Bytes(), nil
}

type jsonWriter struct {
	e       *Engine
	st      Stats
	fields  *Fields
	path    []string
	out     bytes.Buffer
	scratch bytes.Buffer
	enc     *json.Encoder
}

func (w *jsonWriter) value(dec *json.Decoder, tok json.Token, blocked *keyRule) error {
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			w.out.WriteByte('{')
			for i := 0; dec.More(); i++ {
				kt, err := dec.Token()
				if err != nil {
					return err
				}
				key, ok := kt.(string)
				if !ok {
					return fmt.Errorf("expected object key, got %v", kt)
				}
				if i > 0 {
					w.out.WriteByte(',')
				}
				w.path = append(w.path, key)
				if w.fields != nil && !w.fields.allowsKey(w.path) {
					w.fieldMask(key)
				} else {
					w.str(w.e.String(key, w.st))
				}
				w.path = w.path[:len(w.path)-1]
				w.out.WriteByte(':')
				child := blocked
				if child == nil {
					child = w.e.blockedKey(key)
				}
				vt, err := dec.Token()
				if err != nil {
					return err
				}
				w.path = append(w.path, key)
				err = w.value(dec, vt, child)
				w.path = w.path[:len(w.path)-1]
				if err != nil {
					return err
				}
			}
			if _, err := dec.Token(); err != nil { // '}'
				return err
			}
			w.out.WriteByte('}')
		case '[':
			w.out.WriteByte('[')
			for i := 0; dec.More(); i++ {
				if i > 0 {
					w.out.WriteByte(',')
				}
				vt, err := dec.Token()
				if err != nil {
					return err
				}
				if err := w.value(dec, vt, blocked); err != nil {
					return err
				}
			}
			if _, err := dec.Token(); err != nil { // ']'
				return err
			}
			w.out.WriteByte(']')
		default:
			return fmt.Errorf("unexpected delimiter %v", t)
		}
	case string:
		switch {
		case t != "" && w.fields != nil && !w.fields.allows(w.path):
			w.fieldMask(t)
		case blocked != nil:
			w.blocked(blocked, t)
		case looksLikeJSON(t):
			if inner, err := w.e.JSON([]byte(t), w.st); err == nil {
				w.str(string(inner))
				break
			}
			w.str(w.e.String(t, w.st))
		default:
			w.str(w.e.String(t, w.st))
		}
	case json.Number:
		if w.fields != nil && !w.fields.allows(w.path) {
			w.fieldMask(t.String())
		} else if blocked != nil {
			w.blocked(blocked, t.String())
		} else {
			w.out.WriteString(t.String())
		}
	case bool:
		if t {
			w.out.WriteString("true")
		} else {
			w.out.WriteString("false")
		}
	case nil:
		w.out.WriteString("null")
	default:
		return fmt.Errorf("unexpected JSON token %T", tok)
	}
	return nil
}

func (w *jsonWriter) blocked(k *keyRule, v string) {
	if v == "" {
		w.str(v)
		return
	}
	w.st[k.name]++
	w.str(w.e.mask(k.label, v))
}

func (w *jsonWriter) fieldMask(v string) {
	w.st["field_not_allowed"]++
	w.str(w.e.mask("FIELD", v))
}

func (w *jsonWriter) str(s string) {
	w.scratch.Reset()
	_ = w.enc.Encode(s) // cannot fail for a string
	b := w.scratch.Bytes()
	w.out.Write(b[:len(b)-1]) // drop Encode's trailing newline
}

func looksLikeJSON(s string) bool {
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case ' ', '\t', '\r', '\n':
			continue
		case '{', '[':
			return true
		}
		return false
	}
	return false
}
