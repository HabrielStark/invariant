package models

import (
	"encoding/json"
	"os"
	"testing"
)

func TestCanonicalSharedVectors(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/canonical-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors []struct {
		Name          string          `json:"name"`
		Input         json.RawMessage `json:"input"`
		Canonical     string          `json:"canonical"`
		PolicyVersion string          `json:"policy_version"`
		Nonce         string          `json:"nonce"`
		Hash          string          `json:"hash"`
	}
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	for _, v := range vectors {
		t.Run(v.Name, func(t *testing.T) {
			canonical, err := CanonicalizeJSON(v.Input)
			if err != nil {
				t.Fatal(err)
			}
			if string(canonical) != v.Canonical {
				t.Fatalf("got %s want %s", canonical, v.Canonical)
			}
			if hash := IntentHash(canonical, v.PolicyVersion, v.Nonce); hash != v.Hash {
				t.Fatalf("got hash %s want %s", hash, v.Hash)
			}
		})
	}
}

func TestCanonicalRejectsTrailingData(t *testing.T) {
	for _, raw := range []string{`{} {}`, `{} garbage`, `1 2`, `null true`} {
		if _, err := CanonicalizeJSON([]byte(raw)); err == nil {
			t.Fatalf("canonicalizer accepted %q", raw)
		}
		if _, err := CanonicalizeJSONAllowFloat([]byte(raw)); err == nil {
			t.Fatalf("float canonicalizer accepted %q", raw)
		}
		if err := ValidateNoJSONNumbers([]byte(raw)); err == nil {
			t.Fatalf("validator accepted %q", raw)
		}
	}
}
