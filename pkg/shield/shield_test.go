package shield

import "testing"

func TestDefaultParams(t *testing.T) {
	t.Parallel()

	tests := []struct {
		shieldType string
		key        string
		want       interface{}
	}{
		{shieldType: ShieldSmallBatch, key: "max", want: 100},
		{shieldType: ShieldDryRun, key: "report", want: true},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.shieldType, func(t *testing.T) {
			t.Parallel()
			params := DefaultParams(tt.shieldType)
			got, ok := params[tt.key]
			if !ok {
				t.Fatalf("expected key %q in params", tt.key)
			}
			if got != tt.want {
				t.Fatalf("expected %v, got %v", tt.want, got)
			}
		})
	}
}

func TestDefaultParamsUnknownReturnsEmptyMap(t *testing.T) {
	t.Parallel()

	params := DefaultParams("UNKNOWN")
	if len(params) != 0 {
		t.Fatalf("expected empty params for unknown shield, got %v", params)
	}
}

func TestSuggested(t *testing.T) {
	t.Parallel()

	params := map[string]interface{}{"max": 50}
	sh := Suggested(ShieldSmallBatch, params)
	if sh == nil {
		t.Fatal("expected suggested shield")
	}
	if sh.Type != ShieldSmallBatch {
		t.Fatalf("expected shield type %q, got %q", ShieldSmallBatch, sh.Type)
	}
	if sh.Params["max"] != 50 {
		t.Fatalf("expected max=50, got %v", sh.Params["max"])
	}
}
