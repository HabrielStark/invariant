package palantir

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"axiom/pkg/httpx"
)

type FoundryOntologyExecutor struct {
	Client       *http.Client
	BaseURL      string
	Token        string
	OntologyID   string
	Headers      map[string]string
	Retries      int
	RetryDelay   time.Duration
	AllowBatch   bool
	AllowDryRun  bool
	AllowPreview bool
}

type foundryPayload struct {
	Ontology    string                   `json:"ontology"`
	OntologyID  string                   `json:"ontology_id"`
	Action      string                   `json:"action"`
	ActionName  string                   `json:"action_name"`
	Parameters  map[string]interface{}   `json:"parameters"`
	Args        map[string]interface{}   `json:"args"`
	Batch       []map[string]interface{} `json:"batch"`
	Mode        string                   `json:"mode"`
	DryRun      *bool                    `json:"dry_run"`
	PreviewOnly *bool                    `json:"preview_only"`
}

func (f FoundryOntologyExecutor) Execute(ctx context.Context, payload json.RawMessage) (json.RawMessage, error) {
	if strings.TrimSpace(f.BaseURL) == "" {
		return nil, errors.New("foundry base url is empty")
	}
	var req foundryPayload
	if err := json.Unmarshal(payload, &req); err != nil {
		return nil, err
	}
	ontology := strings.TrimSpace(req.OntologyID)
	if ontology == "" {
		ontology = strings.TrimSpace(req.Ontology)
	}
	if ontology == "" {
		ontology = strings.TrimSpace(f.OntologyID)
	}
	if ontology == "" {
		return nil, errors.New("ontology is required")
	}
	action := strings.TrimSpace(req.Action)
	if action == "" {
		action = strings.TrimSpace(req.ActionName)
	}
	if action == "" {
		return nil, errors.New("action is required")
	}
	params := req.Parameters
	if params == nil {
		params = req.Args
	}
	if params == nil {
		params = map[string]interface{}{}
	}
	mode := strings.ToUpper(strings.TrimSpace(req.Mode))
	dryRun := mode == "DRY_RUN" || mode == "READ_ONLY"
	previewOnly := mode == "READ_ONLY"
	if req.DryRun != nil {
		dryRun = *req.DryRun
	}
	if req.PreviewOnly != nil {
		previewOnly = *req.PreviewOnly
	}
	if (dryRun || previewOnly) && !f.AllowDryRun {
		return nil, errors.New("dry-run disabled for foundry adapter")
	}
	client := f.Client
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	headers := map[string]string{"Content-Type": "application/json"}
	for k, v := range f.Headers {
		headers[k] = v
	}
	if f.Token != "" {
		headers["Authorization"] = "Bearer " + f.Token
	}
	base := strings.TrimSuffix(f.BaseURL, "/")
	var endpoint string
	var body map[string]interface{}
	if len(req.Batch) > 0 {
		if !f.AllowBatch {
			return nil, errors.New("batch disabled for foundry adapter")
		}
		endpoint = base + "/api/v2/ontologies/" + ontology + "/actions/" + action + "/applyBatch"
		requests := make([]map[string]interface{}, 0, len(req.Batch))
		for _, b := range req.Batch {
			requests = append(requests, map[string]interface{}{"parameters": b})
		}
		body = map[string]interface{}{
			"requests": requests,
		}
		if dryRun {
			body["dryRun"] = true
		}
		if previewOnly {
			body["previewOnly"] = true
		}
	} else {
		endpoint = base + "/api/v2/ontologies/" + ontology + "/actions/" + action + "/apply"
		body = map[string]interface{}{
			"parameters": params,
		}
		if dryRun {
			body["dryRun"] = true
		}
		if previewOnly {
			body["previewOnly"] = true
		}
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	status, resp, err := httpx.RequestJSON(ctx, client, http.MethodPost, endpoint, raw, headers, f.Retries, f.RetryDelay)
	if err != nil {
		return nil, err
	}
	if status >= 300 {
		return nil, errors.New("foundry upstream error")
	}
	return resp, nil
}
