package redact

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

// JSON masks string values inside one or more concatenated JSON documents
// (Splunk export streams newline-delimited objects). Keys, key order,
// structure and number precision are preserved; whitespace is not.
//
// Under a blocked key every scalar leaf is masked, whatever its shape.
// Numbers are checked against value rules too, and become a masked string
// only if a rule matches. An error means the body was not valid JSON; the
// caller decides whether to fall back to Text.
func (e *Engine) JSON(body []byte, st Stats) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	w := &jsonWriter{e: e, st: st}
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
				w.str(key)
				w.out.WriteByte(':')
				child := blocked
				if child == nil {
					child = w.e.blockedKey(key)
				}
				vt, err := dec.Token()
				if err != nil {
					return err
				}
				if err := w.value(dec, vt, child); err != nil {
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
		if blocked != nil {
			w.blocked(blocked, t)
		} else {
			w.str(w.e.String(t, w.st))
		}
	case json.Number:
		s := t.String()
		switch {
		case blocked != nil:
			w.blocked(blocked, s)
		default:
			if r := w.e.String(s, w.st); r != s {
				w.str(r)
			} else {
				w.out.WriteString(s)
			}
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

func (w *jsonWriter) str(s string) {
	w.scratch.Reset()
	_ = w.enc.Encode(s) // cannot fail for a string
	b := w.scratch.Bytes()
	w.out.Write(b[:len(b)-1]) // drop Encode's trailing newline
}
