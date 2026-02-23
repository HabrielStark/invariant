package main

import (
	"testing"
	"time"
)

func TestApplyEventStoresRecord(t *testing.T) {
	s := &Server{states: map[string]map[string]map[string]sourceRecord{}}
	err := s.applyEvent(eventInput{
		Tenant:      "tenant-a",
		Domain:      "finance",
		Source:      "bank",
		EventTime:   time.Now().UTC().Add(-3 * time.Second),
		Ingestion:   time.Now().UTC(),
		HealthScore: 0.95,
		LagSec:      3,
		JitterSec:   1,
	})
	if err != nil {
		t.Fatalf("applyEvent failed: %v", err)
	}
	bs, ok := s.buildBeliefState("tenant-a", "finance")
	if !ok {
		t.Fatal("expected belief state")
	}
	if len(bs.Sources) != 1 {
		t.Fatalf("expected 1 source, got %d", len(bs.Sources))
	}
	if bs.Sources[0].Source != "bank" {
		t.Fatalf("unexpected source: %+v", bs.Sources[0])
	}
}

func TestApplyEventValidation(t *testing.T) {
	s := &Server{states: map[string]map[string]map[string]sourceRecord{}}
	if err := s.applyEvent(eventInput{Domain: "", Source: "bank"}); err == nil {
		t.Fatal("expected validation error for empty domain")
	}
	if err := s.applyEvent(eventInput{Domain: "finance", Source: ""}); err == nil {
		t.Fatal("expected validation error for empty source")
	}
}
