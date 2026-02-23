package escrowfsm

import "testing"

func TestCanTransitionAndNextFullEventMatrix(t *testing.T) {
	cases := []struct {
		from   string
		to     string
		event  Event
		wantOK bool
		wantTo string
		label  string
	}{
		{from: Pending, to: Expired, event: EventExpire, wantOK: true, wantTo: Expired, label: "pending-expire"},
		{from: Pending, to: Cancelled, event: EventCancel, wantOK: true, wantTo: Cancelled, label: "pending-cancel"},
		{from: Pending, to: Failed, event: EventFail, wantOK: true, wantTo: Failed, label: "pending-fail"},
		{from: Approved, to: Failed, event: EventFail, wantOK: true, wantTo: Failed, label: "approved-fail"},
		{from: Executed, to: Closed, event: EventClose, wantOK: true, wantTo: Closed, label: "executed-close"},
		{from: Executed, to: Failed, event: EventFail, wantOK: true, wantTo: Failed, label: "executed-fail"},
		{from: Failed, to: RolledBack, event: EventRollback, wantOK: true, wantTo: RolledBack, label: "failed-rollback"},
		{from: Closed, to: Approved, event: EventApprove, wantOK: false, wantTo: Closed, label: "closed-invalid"},
		{from: "UNKNOWN", to: Approved, event: EventApprove, wantOK: false, wantTo: "UNKNOWN", label: "unknown-invalid"},
	}

	for _, tc := range cases {
		if got := CanTransition(tc.from, tc.to); got != tc.wantOK {
			t.Fatalf("%s: CanTransition=%v want %v", tc.label, got, tc.wantOK)
		}
		next, err := Next(tc.from, tc.event)
		if tc.wantOK && err != nil {
			t.Fatalf("%s: Next returned error: %v", tc.label, err)
		}
		if !tc.wantOK && err == nil {
			t.Fatalf("%s: Next expected error", tc.label)
		}
		if next != tc.wantTo {
			t.Fatalf("%s: Next=%q want %q", tc.label, next, tc.wantTo)
		}
	}
}
