package models

import (
	"encoding/json"
	"testing"
)

func TestCanonicalHashDeterminism(t *testing.T) {
	intent := json.RawMessage(`{"intent_id":"1","idempotency_key":"k","actor":{"id":"a","roles":["r"],"tenant":"t"},"action_type":"TOOL_CALL","target":{"domain":"finance","object_types":[],"object_ids":[],"scope":"single"},"operation":{"name":"pay","params":{"amount":"10.00"}},"time":{"event_time":"2026-02-03T11:00:00Z","request_time":"2026-02-03T11:00:02Z"},"data_requirements":{"max_staleness_sec":30,"required_sources":["bank"],"uncertainty_budget":{}},"safety_mode":"NORMAL"}`)
	canon1, err := CanonicalizeJSON(intent)
	if err != nil {
		t.Fatal(err)
	}
	canon2, err := CanonicalizeJSON(intent)
	if err != nil {
		t.Fatal(err)
	}
	if string(canon1) != string(canon2) {
		t.Fatalf("canonical forms differ")
	}
	h1 := IntentHash(canon1, "v1", "n1")
	h2 := IntentHash(canon2, "v1", "n1")
	if h1 != h2 {
		t.Fatalf("hash mismatch")
	}
}

func TestValidateNoJSONNumbers(t *testing.T) {
	bad := json.RawMessage(`{"x": 1.1}`)
	if err := ValidateNoJSONNumbers(bad); err == nil {
		t.Fatalf("expected error for numeric token")
	}
	good := json.RawMessage(`{"x": "1"}`)
	if err := ValidateNoJSONNumbers(good); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	goodInt := json.RawMessage(`{"x": 1}`)
	if err := ValidateNoJSONNumbers(goodInt); err != nil {
		t.Fatalf("unexpected error for int: %v", err)
	}
}

func TestCanonicalizeJSONAllowFloatAndErrors(t *testing.T) {
	raw := json.RawMessage(`{"z":1.5,"a":[2.25,{"k":3.75}]}`)
	canon, err := CanonicalizeJSONAllowFloat(raw)
	if err != nil {
		t.Fatalf("allow float canonicalization failed: %v", err)
	}
	if string(canon) != `{"a":[2.25,{"k":3.75}],"z":1.5}` {
		t.Fatalf("unexpected canonicalized output: %s", string(canon))
	}

	if _, err := CanonicalizeJSON(json.RawMessage(`{"x":1.1}`)); err == nil {
		t.Fatal("expected canonicalize error for float token")
	}

	if _, err := CanonicalizeJSON(json.RawMessage(`{"x":bad}`)); err == nil {
		t.Fatal("expected canonicalize parse error for invalid json")
	}

	if err := ValidateNoJSONNumbers(json.RawMessage(`{"x":"1.1","arr":[1,2,3]}`)); err != nil {
		t.Fatalf("expected strings and integer tokens to pass validation, got %v", err)
	}
}
