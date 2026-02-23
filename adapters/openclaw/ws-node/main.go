package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"axiom/adapters/openclaw"

	"github.com/coder/websocket"
	"github.com/google/uuid"
)

type wsNodeConfig struct {
	WSURL        string
	GatewayToken string
	Protocol     int
	ReconnectSec int
	CommandSet   map[string]struct{}
	ClientID     string
	DisplayName  string
	Version      string
	IdentityPath string
}

type wsIdentity struct {
	DeviceID      string `json:"device_id"`
	PublicKeyB64  string `json:"public_key_b64url"`
	PrivateKeyB64 string `json:"private_key_b64"`
}

type eventFrame struct {
	Type    string          `json:"type"`
	Event   string          `json:"event"`
	Payload json.RawMessage `json:"payload"`
}

type responseFrame struct {
	Type  string `json:"type"`
	ID    string `json:"id"`
	OK    bool   `json:"ok"`
	Error *struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

type nodeInvokeRequest struct {
	ID             string `json:"id"`
	NodeID         string `json:"nodeId"`
	Command        string `json:"command"`
	ParamsJSON     string `json:"paramsJSON,omitempty"`
	TimeoutMS      int    `json:"timeoutMs,omitempty"`
	IdempotencyKey string `json:"idempotencyKey,omitempty"`
}

func main() {
	cfg := loadWSConfig()
	adapterCfg := openclaw.LoadConfigFromEnv()
	signer, err := openclaw.LoadSigner(adapterCfg)
	if err != nil {
		log.Fatalf("openclaw-ws-node signer: %v", err)
	}
	adapter := openclaw.NewAdapter(adapterCfg, openclaw.NewHTTPGatewayClient(adapterCfg), signer, nil)
	identity, err := loadOrCreateIdentity(cfg.IdentityPath)
	if err != nil {
		log.Fatalf("openclaw-ws-node identity: %v", err)
	}

	for {
		if err := runWSNode(cfg, identity, adapter); err != nil {
			log.Printf("openclaw-ws-node disconnected: %v", err)
		}
		time.Sleep(time.Duration(cfg.ReconnectSec) * time.Second)
	}
}

func runWSNode(cfg wsNodeConfig, identity wsIdentity, adapter *openclaw.Adapter) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	conn, _, err := websocket.Dial(ctx, cfg.WSURL, &websocket.DialOptions{HTTPClient: &http.Client{Timeout: 8 * time.Second}})
	if err != nil {
		return err
	}
	defer conn.Close(websocket.StatusNormalClosure, "closed")
	conn.SetReadLimit(10 << 20)

	nonce, err := readConnectChallenge(ctx, conn)
	if err != nil {
		return err
	}
	connectReqID := uuid.New().String()
	if err := sendConnectRequest(ctx, conn, cfg, identity, nonce, connectReqID); err != nil {
		return err
	}
	if err := awaitConnectResponse(ctx, conn, connectReqID); err != nil {
		return err
	}
	log.Printf("openclaw-ws-node connected: node_id=%s", identity.DeviceID)

	for {
		_, msg, err := conn.Read(ctx)
		if err != nil {
			return err
		}
		var base struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal(msg, &base); err != nil {
			continue
		}
		if base.Type != "event" {
			continue
		}
		var event eventFrame
		if err := json.Unmarshal(msg, &event); err != nil {
			continue
		}
		if event.Event != "node.invoke.request" {
			continue
		}
		var invoke nodeInvokeRequest
		if err := json.Unmarshal(event.Payload, &invoke); err != nil {
			continue
		}
		if _, ok := cfg.CommandSet[invoke.Command]; !ok {
			_ = sendInvokeResult(ctx, conn, invoke, false, nil, map[string]string{"code": "INVALID_REQUEST", "message": "command not allowed"})
			continue
		}
		paramsRaw := json.RawMessage(`{}`)
		if strings.TrimSpace(invoke.ParamsJSON) != "" {
			paramsRaw = json.RawMessage(invoke.ParamsJSON)
		}
		idem := strings.TrimSpace(invoke.IdempotencyKey)
		if idem == "" {
			idem = invoke.ID
		}
		request := openclaw.InvokeRequest{
			Command:        invoke.Command,
			Params:         paramsRaw,
			Payload:        paramsRaw,
			IdempotencyKey: idem,
			ActorID:        "openclaw-node:" + identity.DeviceID,
			ActionType:     "TOOL_CALL",
			Source:         "openclaw.ws-node",
		}
		invokeCtx := ctx
		cancelInvoke := func() {}
		if invoke.TimeoutMS > 0 {
			invokeCtx, cancelInvoke = context.WithTimeout(ctx, time.Duration(invoke.TimeoutMS)*time.Millisecond)
		}
		resp, err := adapter.HandleInvocation(invokeCtx, request)
		cancelInvoke()
		if err != nil {
			_ = sendInvokeResult(ctx, conn, invoke, false, nil, map[string]string{"code": "INVARIANT_ERROR", "message": err.Error()})
			continue
		}
		encoded, _ := json.Marshal(resp)
		if resp.OK {
			payload := map[string]interface{}{}
			_ = json.Unmarshal(encoded, &payload)
			_ = sendInvokeResult(ctx, conn, invoke, true, payload, nil)
		} else {
			errPayload := map[string]string{"code": normalizeErrorCode(resp.ReasonCode), "message": pickMessage(resp)}
			_ = sendInvokeResult(ctx, conn, invoke, false, nil, errPayload)
		}
	}
}

func sendInvokeResult(ctx context.Context, conn *websocket.Conn, invoke nodeInvokeRequest, ok bool, payload map[string]interface{}, errPayload map[string]string) error {
	params := map[string]interface{}{
		"id":     invoke.ID,
		"nodeId": invoke.NodeID,
		"ok":     ok,
	}
	if payload != nil {
		params["payload"] = payload
		if payloadJSON, err := json.Marshal(payload); err == nil {
			params["payloadJSON"] = string(payloadJSON)
		}
	}
	if errPayload != nil {
		params["error"] = map[string]string{"code": errPayload["code"], "message": errPayload["message"]}
	}
	frame := map[string]interface{}{
		"type":   "req",
		"id":     uuid.New().String(),
		"method": "node.invoke.result",
		"params": params,
	}
	raw, _ := json.Marshal(frame)
	return conn.Write(ctx, websocket.MessageText, raw)
}

func readConnectChallenge(ctx context.Context, conn *websocket.Conn) (string, error) {
	for {
		_, msg, err := conn.Read(ctx)
		if err != nil {
			return "", err
		}
		var evt eventFrame
		if err := json.Unmarshal(msg, &evt); err != nil {
			continue
		}
		if evt.Type != "event" || evt.Event != "connect.challenge" {
			continue
		}
		var payload struct {
			Nonce string `json:"nonce"`
		}
		if err := json.Unmarshal(evt.Payload, &payload); err != nil {
			return "", err
		}
		if strings.TrimSpace(payload.Nonce) == "" {
			return "", errors.New("connect challenge missing nonce")
		}
		return strings.TrimSpace(payload.Nonce), nil
	}
}

func sendConnectRequest(ctx context.Context, conn *websocket.Conn, cfg wsNodeConfig, identity wsIdentity, nonce, reqID string) error {
	publicKeyRaw, err := base64.RawURLEncoding.DecodeString(identity.PublicKeyB64)
	if err != nil {
		return fmt.Errorf("decode public key: %w", err)
	}
	privateRaw, err := base64.StdEncoding.DecodeString(identity.PrivateKeyB64)
	if err != nil {
		return fmt.Errorf("decode private key: %w", err)
	}
	if len(privateRaw) != ed25519.PrivateKeySize {
		return fmt.Errorf("invalid private key length %d", len(privateRaw))
	}
	scopes := []string{}
	token := strings.TrimSpace(cfg.GatewayToken)
	signedAt := time.Now().UTC().UnixMilli()
	payloadToSign := strings.Join([]string{
		"v2",
		identity.DeviceID,
		cfg.ClientID,
		"node",
		"node",
		strings.Join(scopes, ","),
		fmt.Sprintf("%d", signedAt),
		token,
		nonce,
	}, "|")
	sig := ed25519.Sign(ed25519.PrivateKey(privateRaw), []byte(payloadToSign))
	sigB64URL := base64.RawURLEncoding.EncodeToString(sig)
	publicB64URL := base64.RawURLEncoding.EncodeToString(publicKeyRaw)

	frame := map[string]interface{}{
		"type":   "req",
		"id":     reqID,
		"method": "connect",
		"params": map[string]interface{}{
			"minProtocol": cfg.Protocol,
			"maxProtocol": cfg.Protocol,
			"client": map[string]interface{}{
				"id":          cfg.ClientID,
				"displayName": cfg.DisplayName,
				"version":     cfg.Version,
				"platform":    runtime.GOOS,
				"mode":        "node",
			},
			"caps":     []string{"invariant", "invariant-runtime"},
			"commands": setToSlice(cfg.CommandSet),
			"role":     "node",
			"scopes":   scopes,
			"auth": map[string]interface{}{
				"token": token,
			},
			"device": map[string]interface{}{
				"id":        identity.DeviceID,
				"publicKey": publicB64URL,
				"signature": sigB64URL,
				"signedAt":  signedAt,
				"nonce":     nonce,
			},
		},
	}
	raw, _ := json.Marshal(frame)
	return conn.Write(ctx, websocket.MessageText, raw)
}

func awaitConnectResponse(ctx context.Context, conn *websocket.Conn, reqID string) error {
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		_, msg, err := conn.Read(ctx)
		if err != nil {
			return err
		}
		var resp responseFrame
		if err := json.Unmarshal(msg, &resp); err != nil {
			continue
		}
		if resp.Type != "res" || resp.ID != reqID {
			continue
		}
		if resp.OK {
			return nil
		}
		if resp.Error != nil {
			return fmt.Errorf("connect rejected: %s", resp.Error.Message)
		}
		return errors.New("connect rejected")
	}
	return errors.New("connect response timeout")
}

func loadWSConfig() wsNodeConfig {
	commands := env("OPENCLAW_WS_NODE_COMMANDS", "invariant.tool.execute,invariant.agent.send")
	commandSet := map[string]struct{}{}
	for _, c := range strings.Split(commands, ",") {
		trimmed := strings.TrimSpace(c)
		if trimmed != "" {
			commandSet[trimmed] = struct{}{}
		}
	}
	if len(commandSet) == 0 {
		commandSet["invariant.tool.execute"] = struct{}{}
	}
	return wsNodeConfig{
		WSURL:        env("OPENCLAW_WS_URL", "ws://localhost:18789"),
		GatewayToken: strings.TrimSpace(os.Getenv("OPENCLAW_GATEWAY_TOKEN")),
		Protocol:     envInt("OPENCLAW_WS_PROTOCOL", 3),
		ReconnectSec: envInt("OPENCLAW_WS_RECONNECT_SEC", 2),
		CommandSet:   commandSet,
		ClientID:     env("OPENCLAW_WS_NODE_CLIENT_ID", "node-host"),
		DisplayName:  env("OPENCLAW_WS_NODE_DISPLAY_NAME", "Invariant WS Node"),
		Version:      env("OPENCLAW_WS_NODE_VERSION", "0.1.0"),
		IdentityPath: env("OPENCLAW_WS_NODE_IDENTITY_PATH", ".invariant/openclaw/ws-node-identity.json"),
	}
}

func loadOrCreateIdentity(path string) (wsIdentity, error) {
	if raw, err := os.ReadFile(path); err == nil {
		var identity wsIdentity
		if err := json.Unmarshal(raw, &identity); err == nil && identity.DeviceID != "" && identity.PublicKeyB64 != "" && identity.PrivateKeyB64 != "" {
			return identity, nil
		}
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return wsIdentity{}, err
	}
	pubRaw := make([]byte, len(pub))
	copy(pubRaw, pub)
	deviceHash := sha256.Sum256(pubRaw)
	identity := wsIdentity{
		DeviceID:      hex.EncodeToString(deviceHash[:]),
		PublicKeyB64:  base64.RawURLEncoding.EncodeToString(pubRaw),
		PrivateKeyB64: base64.StdEncoding.EncodeToString(priv),
	}
	dir := "."
	if idx := strings.LastIndex(path, "/"); idx > 0 {
		dir = path[:idx]
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return wsIdentity{}, err
	}
	encoded, _ := json.MarshalIndent(identity, "", "  ")
	if err := os.WriteFile(path, append(encoded, '\n'), 0o600); err != nil {
		return wsIdentity{}, err
	}
	return identity, nil
}

func setToSlice(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	for i := 1; i < len(out); i++ {
		j := i
		for j > 0 && out[j-1] > out[j] {
			out[j-1], out[j] = out[j], out[j-1]
			j--
		}
	}
	return out
}

func normalizeErrorCode(reason string) string {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return "INVARIANT_DENY"
	}
	upper := strings.ToUpper(reason)
	if strings.Contains(upper, " ") {
		upper = strings.ReplaceAll(upper, " ", "_")
	}
	return upper
}

func pickMessage(resp openclaw.InvokeResponse) string {
	if resp.Error != nil && strings.TrimSpace(resp.Error.Message) != "" {
		return resp.Error.Message
	}
	if strings.TrimSpace(resp.ReasonCode) != "" {
		return resp.ReasonCode
	}
	return "invariant rejected"
}

func env(name, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(name)); v != "" {
		return v
	}
	return fallback
}

func envInt(name string, fallback int) int {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback
	}
	v, err := strconv.Atoi(raw)
	if err != nil {
		return fallback
	}
	return v
}
