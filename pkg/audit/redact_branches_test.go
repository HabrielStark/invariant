package audit

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
)

type invalidJSONMarshaler struct{}

func (invalidJSONMarshaler) MarshalJSON() ([]byte, error) {
	return []byte("{"), nil
}

func TestRedactRecordAndInvalidPayloads(t *testing.T) {
	t.Parallel()

	rec := Record{
		IntentRaw: json.RawMessage(`{"intent_id":"i1","operation":{"name":"x","params":{"s":"secret"}}}`),
		CertRaw:   json.RawMessage(`{"cert_id":"c1","signature":{"sig":"raw"}}`),
	}
	redacted := redactRecord(rec, []byte("salt"))
	if strings.Contains(string(redacted.IntentRaw), "secret") {
		t.Fatalf("intent not redacted: %s", string(redacted.IntentRaw))
	}
	if strings.Contains(string(redacted.CertRaw), "raw") {
		t.Fatalf("cert not redacted: %s", string(redacted.CertRaw))
	}

	intentInvalid := redactIntent(json.RawMessage(`{"intent_id":`), []byte("salt"))
	if !strings.Contains(string(intentInvalid), "redaction_error") {
		t.Fatalf("expected invalid intent redaction payload, got %s", string(intentInvalid))
	}

	certInvalid := redactCert(json.RawMessage(`{"cert_id":`), []byte("salt"))
	if !strings.Contains(string(certInvalid), "redaction_error") {
		t.Fatalf("expected invalid cert redaction payload, got %s", string(certInvalid))
	}
}

func TestHashHelpersBranches(t *testing.T) {
	t.Parallel()

	if got := hashJSONRaw(nil, nil); got != "" {
		t.Fatalf("expected empty hash for empty raw, got %q", got)
	}
	if got := hashJSONRaw(json.RawMessage(`{"bad":`), []byte("salt")); got == "" {
		t.Fatal("expected fallback hash for invalid raw json")
	}
	if got := hashJSON(map[string]any{"v": math.NaN()}, []byte("salt")); got != "" {
		t.Fatalf("expected marshal failure hashJSON to return empty string, got %q", got)
	}
	if got := hashJSON(invalidJSONMarshaler{}, []byte("salt")); got != "" {
		t.Fatalf("expected marshal failure to return empty hash, got %q", got)
	}
	if got := hashStrings(nil, nil); got != nil {
		t.Fatalf("expected nil hashes for nil input, got %#v", got)
	}
	if got := hashStrings([]string{"a", "b"}, []byte("salt")); len(got) != 2 || got[0] == got[1] {
		t.Fatalf("expected two distinct hashes, got %#v", got)
	}
}
