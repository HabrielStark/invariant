package models

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestCanonicalizeValueBranches(t *testing.T) {
	t.Run("invalid_number_and_unsupported", func(t *testing.T) {
		var buf bytes.Buffer
		if err := canonicalizeValue(&buf, json.Number("12x")); err == nil {
			t.Fatal("expected invalid number error")
		}
		if err := canonicalizeValue(&buf, struct{}{}); err == nil {
			t.Fatal("expected unsupported type error")
		}
	})

	t.Run("composite_types", func(t *testing.T) {
		var buf bytes.Buffer
		val := map[string]any{
			"z": json.Number("2"),
			"a": []any{true, nil, "x"},
		}
		if err := canonicalizeValue(&buf, val); err != nil {
			t.Fatalf("unexpected canonicalize error: %v", err)
		}
		got := buf.String()
		if got != `{"a":[true,null,"x"],"z":2}` {
			t.Fatalf("unexpected canonical form: %s", got)
		}
	})
}

func TestCanonicalizeValueAllowFloatBranches(t *testing.T) {
	t.Run("unsupported_type", func(t *testing.T) {
		var buf bytes.Buffer
		if err := canonicalizeValueAllowFloat(&buf, make(chan int)); err == nil {
			t.Fatal("expected unsupported type error")
		}
	})

	t.Run("composite_float_types", func(t *testing.T) {
		var buf bytes.Buffer
		val := map[string]any{
			"b": json.Number("1.5"),
			"a": []any{json.Number("2.25"), false},
		}
		if err := canonicalizeValueAllowFloat(&buf, val); err != nil {
			t.Fatalf("unexpected canonicalize allow-float error: %v", err)
		}
		got := buf.String()
		if got != `{"a":[2.25,false],"b":1.5}` {
			t.Fatalf("unexpected allow-float canonical form: %s", got)
		}
	})
}

func TestHasInvalidNumberTokenBranches(t *testing.T) {
	if hasInvalidNumberToken(json.Number("10")) {
		t.Fatal("integer token must be valid")
	}
	if !hasInvalidNumberToken(json.Number("10.1")) {
		t.Fatal("float token must be invalid")
	}
	if !hasInvalidNumberToken(map[string]any{"x": []any{json.Number("1e2")}}) {
		t.Fatal("scientific notation token must be invalid")
	}
	if hasInvalidNumberToken(map[string]any{"x": []any{json.Number("102")}}) {
		t.Fatal("nested integer token must be valid")
	}
}

func TestValidateNoJSONNumbersParseError(t *testing.T) {
	err := ValidateNoJSONNumbers(json.RawMessage(`{"x":`))
	if err == nil {
		t.Fatal("expected decode error")
	}
	if !strings.Contains(err.Error(), "unexpected EOF") && !strings.Contains(err.Error(), "invalid") {
		t.Fatalf("unexpected error: %v", err)
	}
}
