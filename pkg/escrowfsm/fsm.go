package escrowfsm

import (
	"context"
	"errors"
	"strings"
	"time"
)

const (
	Pending    = "PENDING"
	Approved   = "APPROVED"
	Executed   = "EXECUTED"
	Closed     = "CLOSED"
	Expired    = "EXPIRED"
	Cancelled  = "CANCELLED"
	RolledBack = "ROLLED_BACK"
	Failed     = "FAILED"
)

var (
	ErrInvalidTransition = errors.New("invalid escrow transition")
	ErrSoDViolation      = errors.New("approver violates separation of duties")
	ErrApproverRole      = errors.New("approver role not permitted")
)

type Event string

const (
	EventApprove  Event = "APPROVE"
	EventExecute  Event = "EXECUTE"
	EventClose    Event = "CLOSE"
	EventExpire   Event = "EXPIRE"
	EventCancel   Event = "CANCEL"
	EventFail     Event = "FAIL"
	EventRollback Event = "ROLLBACK"
)

func CanTransition(from, to string) bool {
	switch from {
	case Pending:
		return to == Approved || to == Expired || to == Cancelled || to == Failed
	case Approved:
		return to == Executed || to == Failed
	case Executed:
		return to == Closed || to == RolledBack || to == Failed
	case Failed:
		return to == RolledBack
	default:
		return false
	}
}

func Transition(from, to string) (string, error) {
	if !CanTransition(from, to) {
		return from, ErrInvalidTransition
	}
	return to, nil
}

func Next(from string, event Event) (string, error) {
	switch event {
	case EventApprove:
		return Transition(from, Approved)
	case EventExecute:
		return Transition(from, Executed)
	case EventClose:
		return Transition(from, Closed)
	case EventExpire:
		return Transition(from, Expired)
	case EventCancel:
		return Transition(from, Cancelled)
	case EventFail:
		return Transition(from, Failed)
	case EventRollback:
		return Transition(from, RolledBack)
	default:
		return from, ErrInvalidTransition
	}
}

func IsTerminal(status string) bool {
	switch status {
	case Closed, Cancelled, Expired, RolledBack:
		return true
	default:
		return false
	}
}

type ApprovalPolicy struct {
	Required   int
	Roles      []string
	EnforceSoD bool
	ExpiresIn  time.Duration
}

func QuorumReached(received, required int) bool {
	if required <= 0 {
		required = 1
	}
	return received >= required
}

func ApproverAllowed(approver, initiator string, approverRoles []string, policy ApprovalPolicy) error {
	if policy.EnforceSoD && approver != "" && initiator != "" && strings.EqualFold(approver, initiator) {
		return ErrSoDViolation
	}
	if len(policy.Roles) == 0 {
		return nil
	}
	roleSet := map[string]struct{}{}
	for _, r := range policy.Roles {
		r = strings.ToLower(strings.TrimSpace(r))
		if r != "" {
			roleSet[r] = struct{}{}
		}
	}
	for _, r := range approverRoles {
		r = strings.ToLower(strings.TrimSpace(r))
		if _, ok := roleSet[r]; ok {
			return nil
		}
	}
	return ErrApproverRole
}

func IsExpired(now, expiresAt time.Time) bool {
	if expiresAt.IsZero() {
		return false
	}
	return now.UTC().After(expiresAt.UTC())
}

type TwoPhase struct {
	Prepare  func(ctx context.Context) error
	Commit   func(ctx context.Context) error
	Rollback func(ctx context.Context) error
}

// ExecuteTwoPhase runs prepare/commit with rollback on commit failure.
func ExecuteTwoPhase(ctx context.Context, t TwoPhase) error {
	if t.Prepare != nil {
		if err := t.Prepare(ctx); err != nil {
			return err
		}
	}
	if t.Commit == nil {
		return errors.New("commit missing")
	}
	if err := t.Commit(ctx); err != nil {
		if t.Rollback != nil {
			_ = t.Rollback(ctx)
		}
		return err
	}
	return nil
}

// ExecuteWithCompensation executes and calls compensation on failure.
func ExecuteWithCompensation(ctx context.Context, execute func(context.Context) error, compensate func(context.Context) error) error {
	if execute == nil {
		return errors.New("execute missing")
	}
	if err := execute(ctx); err != nil {
		if compensate != nil {
			_ = compensate(ctx)
		}
		return err
	}
	return nil
}
