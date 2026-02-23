package models

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strings"
)

// CanonicalizeJSON returns a RFC 8785-compatible canonical form for a restricted JSON subset.
// Numbers must be integers (floats are rejected by ValidateNoJSONNumbers).
func CanonicalizeJSON(raw json.RawMessage) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v interface{}
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := canonicalizeValue(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// ValidateNoJSONNumbers enforces that no floating-point numeric tokens appear in JSON.
// Non-integers must be represented as decimal strings in JSON.
func ValidateNoJSONNumbers(raw json.RawMessage) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v interface{}
	if err := dec.Decode(&v); err != nil {
		return err
	}
	if hasInvalidNumberToken(v) {
		return errors.New("floating-point JSON tokens are not allowed; use decimal strings")
	}
	return nil
}

func hasInvalidNumberToken(v interface{}) bool {
	switch t := v.(type) {
	case json.Number:
		s := t.String()
		if strings.ContainsAny(s, ".eE") {
			return true
		}
		return false
	case map[string]interface{}:
		for _, vv := range t {
			if hasInvalidNumberToken(vv) {
				return true
			}
		}
	case []interface{}:
		for _, vv := range t {
			if hasInvalidNumberToken(vv) {
				return true
			}
		}
	}
	return false
}

func canonicalizeValue(buf *bytes.Buffer, v interface{}) error {
	switch t := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if t {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case string:
		b, _ := json.Marshal(t)
		buf.Write(b)
	case json.Number:
		s := t.String()
		if strings.ContainsAny(s, ".eE") {
			return errors.New("float numbers not supported in canonical form")
		}
		i := new(big.Int)
		if _, ok := i.SetString(s, 10); !ok {
			return errors.New("invalid number")
		}
		buf.WriteString(i.String())
	case []interface{}:
		buf.WriteString("[")
		for i, vv := range t {
			if i > 0 {
				buf.WriteString(",")
			}
			if err := canonicalizeValue(buf, vv); err != nil {
				return err
			}
		}
		buf.WriteString("]")
	case map[string]interface{}:
		buf.WriteString("{")
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for i, k := range keys {
			if i > 0 {
				buf.WriteString(",")
			}
			ks, _ := json.Marshal(k)
			buf.Write(ks)
			buf.WriteString(":")
			if err := canonicalizeValue(buf, t[k]); err != nil {
				return err
			}
		}
		buf.WriteString("}")
	default:
		return errors.New("unsupported json type")
	}
	return nil
}

// CanonicalizeJSONAllowFloat returns a canonical JSON form that preserves floating-point numbers.
// This is intended for signature payloads that must remain stable while allowing decimals.
func CanonicalizeJSONAllowFloat(raw json.RawMessage) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v interface{}
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := canonicalizeValueAllowFloat(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func canonicalizeValueAllowFloat(buf *bytes.Buffer, v interface{}) error {
	switch t := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if t {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case string:
		b, _ := json.Marshal(t)
		buf.Write(b)
	case json.Number:
		buf.WriteString(t.String())
	case []interface{}:
		buf.WriteString("[")
		for i, vv := range t {
			if i > 0 {
				buf.WriteString(",")
			}
			if err := canonicalizeValueAllowFloat(buf, vv); err != nil {
				return err
			}
		}
		buf.WriteString("]")
	case map[string]interface{}:
		buf.WriteString("{")
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for i, k := range keys {
			if i > 0 {
				buf.WriteString(",")
			}
			ks, _ := json.Marshal(k)
			buf.Write(ks)
			buf.WriteString(":")
			if err := canonicalizeValueAllowFloat(buf, t[k]); err != nil {
				return err
			}
		}
		buf.WriteString("}")
	default:
		return errors.New("unsupported json type")
	}
	return nil
}

// IntentHash computes sha256( Canonical(ActionIntent) + "|" + policyVersion + "|" + nonce )
func IntentHash(intentCanonical []byte, policyVersion string, nonce string) string {
	payload := fmt.Sprintf("%s|%s|%s", string(intentCanonical), policyVersion, nonce)
	h := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(h[:])
}
