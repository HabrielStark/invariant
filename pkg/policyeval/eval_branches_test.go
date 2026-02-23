package policyeval

import (
	"testing"

	"axiom/pkg/models"
	"axiom/pkg/policyir"
)

func TestShieldFromAxiomBranches(t *testing.T) {
	if ShieldFromAxiom(policyir.Axiom{ElseShield: ""}) != nil {
		t.Fatal("expected nil for empty else shield")
	}
	if ShieldFromAxiom(policyir.Axiom{ElseShield: "dryrun"}) != nil {
		t.Fatal("expected nil for non-shield expression")
	}
	if ShieldFromAxiom(policyir.Axiom{ElseShield: "shield()"}) != nil {
		t.Fatal("expected nil for empty shield args")
	}

	s := ShieldFromAxiom(policyir.Axiom{ElseShield: `shield("SMALL_BATCH", max=10, preview=true, note="safe", ratio=1.25, tag='x')`})
	if s == nil {
		t.Fatal("expected parsed shield")
	}
	if s.Type != "SMALL_BATCH" {
		t.Fatalf("unexpected shield type: %s", s.Type)
	}
	if s.Params["max"] != int64(10) || s.Params["preview"] != true || s.Params["note"] != "safe" || s.Params["ratio"] != 1.25 || s.Params["tag"] != "x" {
		t.Fatalf("unexpected shield params: %#v", s.Params)
	}
}

func TestParseShieldArgsBranches(t *testing.T) {
	typ, params := parseShieldArgs("")
	if typ != "" || params != nil {
		t.Fatalf("expected empty result, got type=%q params=%#v", typ, params)
	}

	typ, params = parseShieldArgs(`"REQUIRE_APPROVAL", badtoken, x=, =y, k=42`)
	if typ != "REQUIRE_APPROVAL" {
		t.Fatalf("unexpected shield type: %s", typ)
	}
	if len(params) != 1 || params["k"] != int64(42) {
		t.Fatalf("unexpected params parsing: %#v", params)
	}
}

func TestSplitShieldArgsQuotedCommas(t *testing.T) {
	out := splitShieldArgs(`"SMALL_BATCH",note="a,b,c",tag='x,y',max=10`)
	if len(out) != 4 {
		t.Fatalf("expected 4 shield args, got %d (%#v)", len(out), out)
	}
	if out[1] != `note="a,b,c"` || out[2] != "tag='x,y'" {
		t.Fatalf("expected quoted commas preserved, got %#v", out)
	}
}

func TestEvaluateWithOptionsZ3Unavailable(t *testing.T) {
	dsl := `policyset finance v1:
axiom A:
  when action.name == "x"
  require 5 <= 10`
	intent := models.ActionIntent{
		Operation: models.Operation{Name: "x"},
		Target:    models.Target{Domain: "finance"},
	}
	res, err := EvaluateWithOptions(dsl, intent, models.BeliefState{}, Options{
		Backend: "z3exec",
		Z3Path:  "bad binary",
	})
	if err != nil {
		t.Fatalf("expected graceful defer on z3exec unavailability, got err=%v", err)
	}
	if res.Verdict != "DEFER" || res.ReasonCode != "SMT_UNAVAILABLE" {
		t.Fatalf("unexpected z3exec fallback result: %#v", res)
	}
}
