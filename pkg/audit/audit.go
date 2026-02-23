package audit

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type auditDB interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

type Writer struct {
	DB       auditDB
	HashSalt []byte
	Redact   bool
}

type Record struct {
	DecisionID     string
	IntentRaw      json.RawMessage
	CertRaw        json.RawMessage
	PolicyVersion  string
	Tenant         string
	ActorIDHash    string
	Verdict        string
	ReasonCode     string
	Counterexample json.RawMessage
	CreatedAt      time.Time
}

func (w *Writer) Append(ctx context.Context, rec Record) error {
	if w.Redact {
		rec = redactRecord(rec, w.HashSalt)
	}
	_, err := w.DB.Exec(ctx, `
		INSERT INTO audit_records
		(decision_id, tenant, actor_id_hash, intent_raw, cert_raw, policy_version, verdict, reason_code, counterexample, created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
	`, rec.DecisionID, rec.Tenant, rec.ActorIDHash, rec.IntentRaw, rec.CertRaw, rec.PolicyVersion, rec.Verdict, rec.ReasonCode, rec.Counterexample, rec.CreatedAt)
	return err
}

func (w *Writer) Get(ctx context.Context, decisionID, tenant string) (Record, error) {
	var rec Record
	if tenant != "" {
		row := w.DB.QueryRow(ctx, `
			SELECT decision_id, tenant, actor_id_hash, intent_raw, cert_raw, policy_version, verdict, reason_code, counterexample, created_at
			FROM audit_records WHERE tenant=$1 AND decision_id=$2
		`, tenant, decisionID)
		var counterexample json.RawMessage
		if err := row.Scan(&rec.DecisionID, &rec.Tenant, &rec.ActorIDHash, &rec.IntentRaw, &rec.CertRaw, &rec.PolicyVersion, &rec.Verdict, &rec.ReasonCode, &counterexample, &rec.CreatedAt); err != nil {
			return rec, err
		}
		rec.Counterexample = counterexample
		return rec, nil
	}
	row := w.DB.QueryRow(ctx, `
		SELECT decision_id, tenant, actor_id_hash, intent_raw, cert_raw, policy_version, verdict, reason_code, counterexample, created_at
		FROM audit_records WHERE decision_id=$1
	`, decisionID)
	var counterexample json.RawMessage
	if err := row.Scan(&rec.DecisionID, &rec.Tenant, &rec.ActorIDHash, &rec.IntentRaw, &rec.CertRaw, &rec.PolicyVersion, &rec.Verdict, &rec.ReasonCode, &counterexample, &rec.CreatedAt); err != nil {
		return rec, err
	}
	rec.Counterexample = counterexample
	return rec, nil
}
