package openclaw

import (
	"bytes"
	"encoding/json"
	"strings"

	"axiom/pkg/models"
)

var sensitiveParamSubstrings = []string{
	"password",
	"secret",
	"token",
	"apikey",
	"api_key",
	"authorization",
	"cookie",
}

func sanitizeAndCanonicalizeParams(raw json.RawMessage) (json.RawMessage, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return json.RawMessage(`{}`), nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var value interface{}
	if err := dec.Decode(&value); err != nil {
		return nil, err
	}
	sanitized := sanitizeJSONValue("", value)
	marshaled, err := json.Marshal(sanitized)
	if err != nil {
		return nil, err
	}
	canonical, err := canonicalizeJSONAllowFloat(marshaled)
	if err != nil {
		return nil, err
	}
	return canonical, nil
}

func sanitizeJSONValue(key string, v interface{}) interface{} {
	switch t := v.(type) {
	case map[string]interface{}:
		out := make(map[string]interface{}, len(t))
		for k, vv := range t {
			if isSensitiveKey(k) {
				out[k] = "<redacted>"
				continue
			}
			out[k] = sanitizeJSONValue(k, vv)
		}
		return out
	case []interface{}:
		out := make([]interface{}, 0, len(t))
		for _, vv := range t {
			out = append(out, sanitizeJSONValue(key, vv))
		}
		return out
	case json.Number:
		s := t.String()
		if strings.ContainsAny(s, ".eE") {
			return s
		}
		return t
	default:
		return t
	}
}

func isSensitiveKey(key string) bool {
	lower := strings.ToLower(strings.TrimSpace(key))
	for _, part := range sensitiveParamSubstrings {
		if strings.Contains(lower, part) {
			return true
		}
	}
	return false
}

func canonicalizeJSONAllowFloat(raw json.RawMessage) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v interface{}
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := canonicalizeValueAllowFloat(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func canonicalizeValueAllowFloat(buf *bytes.Buffer, v interface{}) error {
	switch t := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if t {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case string:
		b, _ := json.Marshal(t)
		buf.Write(b)
	case json.Number:
		buf.WriteString(t.String())
	case []interface{}:
		buf.WriteString("[")
		for i, vv := range t {
			if i > 0 {
				buf.WriteString(",")
			}
			if err := canonicalizeValueAllowFloat(buf, vv); err != nil {
				return err
			}
		}
		buf.WriteString("]")
	case map[string]interface{}:
		buf.WriteString("{")
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sortStrings(keys)
		for i, k := range keys {
			if i > 0 {
				buf.WriteString(",")
			}
			ks, _ := json.Marshal(k)
			buf.Write(ks)
			buf.WriteString(":")
			if err := canonicalizeValueAllowFloat(buf, t[k]); err != nil {
				return err
			}
		}
		buf.WriteString("}")
	default:
		b, err := json.Marshal(t)
		if err != nil {
			return err
		}
		buf.Write(b)
	}
	return nil
}

func sortStrings(values []string) {
	if len(values) < 2 {
		return
	}
	for i := 1; i < len(values); i++ {
		j := i
		for j > 0 && values[j-1] > values[j] {
			values[j-1], values[j] = values[j], values[j-1]
			j--
		}
	}
}

func pickFirstNonEmpty(values ...string) string {
	for _, v := range values {
		trimmed := strings.TrimSpace(v)
		if trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func ParseInvokeRequest(raw []byte) (InvokeRequest, error) {
	var generic map[string]json.RawMessage
	if err := json.Unmarshal(raw, &generic); err != nil {
		return InvokeRequest{}, err
	}
	var req InvokeRequest
	_ = json.Unmarshal(raw, &req)
	if req.Tool == "" {
		_ = json.Unmarshal(generic["toolName"], &req.Tool)
	}
	if req.Command == "" {
		_ = json.Unmarshal(generic["operation"], &req.Command)
	}
	if len(req.Args) == 0 {
		if v, ok := generic["arguments"]; ok {
			req.Args = v
		}
	}
	if len(req.Params) == 0 {
		if v, ok := generic["args"]; ok {
			req.Params = v
		}
		if len(req.Params) == 0 {
			if v, ok := generic["parameters"]; ok {
				req.Params = v
			}
		}
	}
	if req.IdempotencyKey == "" {
		_ = json.Unmarshal(generic["idempotencyKey"], &req.IdempotencyKey)
	}
	if req.ActorID == "" {
		_ = json.Unmarshal(generic["actorId"], &req.ActorID)
		if req.ActorID == "" {
			_ = json.Unmarshal(generic["agentId"], &req.ActorID)
		}
	}
	if req.Tenant == "" {
		_ = json.Unmarshal(generic["workspace"], &req.Tenant)
	}
	if req.Workspace == "" {
		_ = json.Unmarshal(generic["workspace"], &req.Workspace)
	}
	if req.RequestTime == "" {
		_ = json.Unmarshal(generic["requestTime"], &req.RequestTime)
	}
	if req.EventTime == "" {
		_ = json.Unmarshal(generic["eventTime"], &req.EventTime)
	}
	if req.SafetyMode == "" {
		_ = json.Unmarshal(generic["safetyMode"], &req.SafetyMode)
	}
	if req.ActionType == "" {
		_ = json.Unmarshal(generic["actionType"], &req.ActionType)
	}
	if req.Nonce == "" {
		_ = json.Unmarshal(generic["nonce"], &req.Nonce)
	}
	if req.ExpiresAt == "" {
		_ = json.Unmarshal(generic["expiresAt"], &req.ExpiresAt)
	}
	if req.RollbackPlan == nil {
		var rollback models.Rollback
		if rawRollback, ok := generic["rollback_plan"]; ok {
			if err := json.Unmarshal(rawRollback, &rollback); err == nil {
				req.RollbackPlan = &rollback
			}
		}
		if req.RollbackPlan == nil {
			if rawRollback, ok := generic["rollbackPlan"]; ok {
				if err := json.Unmarshal(rawRollback, &rollback); err == nil {
					req.RollbackPlan = &rollback
				}
			}
		}
	}
	if req.MaxStalenessSec == nil {
		var maxStaleness int
		if rawStaleness, ok := generic["maxStalenessSec"]; ok {
			if err := json.Unmarshal(rawStaleness, &maxStaleness); err == nil {
				req.MaxStalenessSec = &maxStaleness
			}
		}
	}
	if req.SideEffecting == nil {
		var sideEffecting bool
		if rawSideEffecting, ok := generic["sideEffecting"]; ok {
			if err := json.Unmarshal(rawSideEffecting, &sideEffecting); err == nil {
				req.SideEffecting = &sideEffecting
			}
		}
	}
	if len(req.Payload) == 0 {
		if rawPayload, ok := generic["tool_payload"]; ok {
			req.Payload = rawPayload
		}
	}
	return req, nil
}
