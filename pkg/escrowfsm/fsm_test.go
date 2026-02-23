package escrowfsm

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestApproverAllowed(t *testing.T) {
	policy := ApprovalPolicy{Required: 2, EnforceSoD: true, Roles: []string{"manager"}}
	if err := ApproverAllowed("u1", "u1", []string{"manager"}, policy); !errors.Is(err, ErrSoDViolation) {
		t.Fatalf("expected SoD violation, got %v", err)
	}
	if err := ApproverAllowed("u2", "u1", []string{"employee"}, policy); !errors.Is(err, ErrApproverRole) {
		t.Fatalf("expected role violation, got %v", err)
	}
	if err := ApproverAllowed("u2", "u1", []string{"manager"}, policy); err != nil {
		t.Fatalf("expected allowed, got %v", err)
	}
}

func TestExecuteTwoPhase(t *testing.T) {
	called := []string{}
	tp := TwoPhase{
		Prepare: func(ctx context.Context) error {
			called = append(called, "prepare")
			return nil
		},
		Commit: func(ctx context.Context) error {
			called = append(called, "commit")
			return nil
		},
		Rollback: func(ctx context.Context) error {
			called = append(called, "rollback")
			return nil
		},
	}
	if err := ExecuteTwoPhase(context.Background(), tp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(called) != 2 || called[0] != "prepare" || called[1] != "commit" {
		t.Fatalf("unexpected call order: %v", called)
	}

	called = []string{}
	tp.Commit = func(ctx context.Context) error {
		called = append(called, "commit")
		return errors.New("fail")
	}
	if err := ExecuteTwoPhase(context.Background(), tp); err == nil {
		t.Fatalf("expected error")
	}
	if len(called) != 3 || called[0] != "prepare" || called[1] != "commit" || called[2] != "rollback" {
		t.Fatalf("unexpected call order on failure: %v", called)
	}
}

func TestConcurrentApprovalsUnique(t *testing.T) {
	policy := ApprovalPolicy{Required: 2, EnforceSoD: true, Roles: []string{"manager"}}
	approvers := []string{"u1", "u2", "u2", "u3", "u3", "u3"}
	set := map[string]struct{}{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, approver := range approvers {
		wg.Add(1)
		go func(a string) {
			defer wg.Done()
			if err := ApproverAllowed(a, "initiator", []string{"manager"}, policy); err != nil {
				return
			}
			mu.Lock()
			set[a] = struct{}{}
			mu.Unlock()
		}(approver)
	}
	wg.Wait()
	if len(set) != 3 {
		t.Fatalf("expected 3 unique approvers, got %d", len(set))
	}
	if !QuorumReached(len(set), policy.Required) {
		t.Fatal("expected quorum reached with unique approvals")
	}
}

func TestTransitionHelpers(t *testing.T) {
	if !CanTransition(Pending, Approved) {
		t.Fatal("expected PENDING->APPROVED transition to be allowed")
	}
	if CanTransition(Pending, Closed) {
		t.Fatal("expected PENDING->CLOSED transition to be denied")
	}
	if CanTransition(Closed, Approved) {
		t.Fatal("expected terminal state transition to be denied")
	}

	to, err := Transition(Pending, Approved)
	if err != nil {
		t.Fatalf("unexpected transition error: %v", err)
	}
	if to != Approved {
		t.Fatalf("expected APPROVED, got %s", to)
	}

	to, err = Transition(Pending, Closed)
	if !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("expected ErrInvalidTransition, got %v", err)
	}
	if to != Pending {
		t.Fatalf("expected state to remain PENDING on error, got %s", to)
	}
}

func TestNextAndTerminalAndExpiry(t *testing.T) {
	state, err := Next(Pending, EventApprove)
	if err != nil {
		t.Fatalf("unexpected next error: %v", err)
	}
	if state != Approved {
		t.Fatalf("expected APPROVED, got %s", state)
	}

	state, err = Next(state, EventExecute)
	if err != nil {
		t.Fatalf("unexpected execute error: %v", err)
	}
	if state != Executed {
		t.Fatalf("expected EXECUTED, got %s", state)
	}

	if _, err := Next(state, EventExpire); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("expected invalid transition error, got %v", err)
	}
	if _, err := Next(state, Event("UNKNOWN")); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("expected invalid event error, got %v", err)
	}

	if !IsTerminal(Closed) || !IsTerminal(Cancelled) || !IsTerminal(Expired) || !IsTerminal(RolledBack) {
		t.Fatal("expected all terminal statuses to be terminal")
	}
	if IsTerminal(Pending) {
		t.Fatal("pending must not be terminal")
	}

	now := time.Date(2026, 2, 6, 12, 0, 0, 0, time.UTC)
	if IsExpired(now, time.Time{}) {
		t.Fatal("zero expiry must not be expired")
	}
	if !IsExpired(now, now.Add(-time.Second)) {
		t.Fatal("past expiry must be expired")
	}
	if IsExpired(now, now.Add(time.Second)) {
		t.Fatal("future expiry must not be expired")
	}
}

func TestQuorumAndCompensationPaths(t *testing.T) {
	if !QuorumReached(1, 0) {
		t.Fatal("required<=0 should normalize to 1")
	}
	if QuorumReached(0, 2) {
		t.Fatal("insufficient approvals must fail quorum")
	}

	if err := ExecuteTwoPhase(context.Background(), TwoPhase{}); err == nil {
		t.Fatal("expected commit missing error")
	}

	rolledBack := false
	err := ExecuteWithCompensation(context.Background(), func(context.Context) error {
		return errors.New("boom")
	}, func(context.Context) error {
		rolledBack = true
		return nil
	})
	if err == nil {
		t.Fatal("expected execution error")
	}
	if !rolledBack {
		t.Fatal("expected compensation to be invoked")
	}

	if err := ExecuteWithCompensation(context.Background(), nil, nil); err == nil {
		t.Fatal("expected execute missing error")
	}

	if err := ExecuteWithCompensation(context.Background(), func(context.Context) error { return nil }, nil); err != nil {
		t.Fatalf("unexpected success path error: %v", err)
	}
}
