package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type fakeAuditDB struct {
	execErr   error
	rowErr    error
	rowValues []any
	execArgs  []any
	queryArgs []any
}

func (f *fakeAuditDB) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	_ = ctx
	_ = sql
	f.execArgs = append([]any(nil), args...)
	return pgconn.NewCommandTag("INSERT 0 1"), f.execErr
}

func (f *fakeAuditDB) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	_ = ctx
	_ = sql
	f.queryArgs = append([]any(nil), args...)
	return &fakeAuditRow{values: f.rowValues, err: f.rowErr}
}

type fakeAuditRow struct {
	values []any
	err    error
}

func (r *fakeAuditRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	if len(dest) != len(r.values) {
		return fmt.Errorf("scan arity mismatch: got=%d want=%d", len(dest), len(r.values))
	}
	for i := range dest {
		if err := assignAuditScan(dest[i], r.values[i]); err != nil {
			return err
		}
	}
	return nil
}

func assignAuditScan(dest any, val any) error {
	switch d := dest.(type) {
	case *string:
		v, ok := val.(string)
		if !ok {
			return fmt.Errorf("expected string, got %T", val)
		}
		*d = v
		return nil
	case *json.RawMessage:
		switch v := val.(type) {
		case json.RawMessage:
			*d = append((*d)[:0], v...)
		case []byte:
			*d = append((*d)[:0], v...)
		case string:
			*d = json.RawMessage(v)
		default:
			return fmt.Errorf("expected json raw, got %T", val)
		}
		return nil
	case *time.Time:
		v, ok := val.(time.Time)
		if !ok {
			return fmt.Errorf("expected time.Time, got %T", val)
		}
		*d = v
		return nil
	default:
		return fmt.Errorf("unsupported scan dest %T", dest)
	}
}

func rawArgString(v any) string {
	switch t := v.(type) {
	case json.RawMessage:
		return string(t)
	case []byte:
		return string(t)
	case string:
		return t
	default:
		return fmt.Sprint(v)
	}
}

func TestWriterAppendAndGet(t *testing.T) {
	now := time.Date(2026, 2, 6, 12, 0, 0, 0, time.UTC)
	intent := json.RawMessage(`{"operation":{"name":"pay","params":{"amount":"10.00"}}}`)
	cert := json.RawMessage(`{"signature":{"sig":"abc"}}`)
	counter := json.RawMessage(`{"failed_axioms":["Fresh_bank_feed"]}`)
	db := &fakeAuditDB{
		rowValues: []any{"d-1", "tenant-a", "actor-hash-1", intent, cert, "v17", "ALLOW", "OK", counter, now},
	}
	w := &Writer{DB: db}

	rec := Record{
		DecisionID:     "d-1",
		IntentRaw:      intent,
		CertRaw:        cert,
		PolicyVersion:  "v17",
		Tenant:         "tenant-a",
		Verdict:        "ALLOW",
		ReasonCode:     "OK",
		Counterexample: counter,
		CreatedAt:      now,
	}
	if err := w.Append(context.Background(), rec); err != nil {
		t.Fatalf("append: %v", err)
	}
	if len(db.execArgs) != 10 {
		t.Fatalf("expected 10 exec args, got %d", len(db.execArgs))
	}
	if got := rawArgString(db.execArgs[3]); got != string(intent) {
		t.Fatalf("unexpected intent arg: %s", got)
	}

	got, err := w.Get(context.Background(), "d-1", "tenant-a")
	if err != nil {
		t.Fatalf("get with tenant: %v", err)
	}
	if got.DecisionID != "d-1" || got.Tenant != "tenant-a" || got.Verdict != "ALLOW" {
		t.Fatalf("unexpected get record: %+v", got)
	}
	if len(db.queryArgs) != 2 {
		t.Fatalf("expected tenant-scoped query args, got %d", len(db.queryArgs))
	}

	got, err = w.Get(context.Background(), "d-1", "")
	if err != nil {
		t.Fatalf("get global: %v", err)
	}
	if got.DecisionID != "d-1" {
		t.Fatalf("unexpected decision id from global get: %s", got.DecisionID)
	}
	if len(db.queryArgs) != 1 {
		t.Fatalf("expected global query args, got %d", len(db.queryArgs))
	}
}

func TestWriterRedactionAndErrors(t *testing.T) {
	db := &fakeAuditDB{}
	w := &Writer{
		DB:       db,
		HashSalt: []byte("salt-1"),
		Redact:   true,
	}
	intent := json.RawMessage(`{"intent_id":"i1","idempotency_key":"k1","actor":{"id":"u1","roles":["r"],"tenant":"t1"},"action_type":"TOOL_CALL","target":{"domain":"finance","object_types":["Invoice"],"object_ids":["inv-1"],"scope":"single"},"operation":{"name":"pay","params":{"ssn":"111-22-3333"}},"time":{"event_time":"2026-02-01T00:00:00Z","request_time":"2026-02-01T00:00:01Z"},"data_requirements":{"max_staleness_sec":30,"required_sources":["bank"],"uncertainty_budget":{"amount_abs":"1.00"}},"safety_mode":"NORMAL"}`)
	cert := json.RawMessage(`{"cert_id":"c1","intent_hash":"h1","policy_set_id":"p1","policy_version":"v1","claims":[],"assumptions":{"open_system_terms":[],"uncertainty_budget":{},"allowed_time_skew_sec":10},"evidence":{"state_snapshot_refs":[],"attestations":[]},"rollback_plan":{"type":"ESCROW","steps":["hold"]},"expires_at":"2026-02-01T00:01:00Z","nonce":"n1","signature":{"signer":"s1","alg":"ed25519","sig":"rawsig","kid":"kid-1"}}`)
	rec := Record{
		DecisionID: "d-1",
		IntentRaw:  intent,
		CertRaw:    cert,
		CreatedAt:  time.Now().UTC(),
	}
	if err := w.Append(context.Background(), rec); err != nil {
		t.Fatalf("append redacted: %v", err)
	}

	intentStored := rawArgString(db.execArgs[3])
	if strings.Contains(intentStored, "111-22-3333") || strings.Contains(intentStored, "\"ssn\"") {
		t.Fatalf("intent PII leaked into audit record: %s", intentStored)
	}
	if !strings.Contains(intentStored, "intent_id_hash") {
		t.Fatalf("expected redacted intent hash payload: %s", intentStored)
	}

	certStored := rawArgString(db.execArgs[4])
	if strings.Contains(certStored, "rawsig") {
		t.Fatalf("raw signature leaked into audit record: %s", certStored)
	}
	if !strings.Contains(certStored, "sig_hash") {
		t.Fatalf("expected signature hash in redacted cert: %s", certStored)
	}

	db.execErr = errors.New("exec failed")
	if err := w.Append(context.Background(), rec); err == nil {
		t.Fatal("expected append error")
	}

	db.rowErr = errors.New("not found")
	if _, err := w.Get(context.Background(), "d-1", "tenant-a"); err == nil {
		t.Fatal("expected get error")
	}
}
