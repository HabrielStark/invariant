package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestParseErrorLine(t *testing.T) {
	cases := []struct {
		msg  string
		want int
	}{
		{"invalid policyset header at line 4", 4},
		{"line 12: unknown statement", 12},
		{"no line info", 0},
	}
	for _, tt := range cases {
		if got := parseErrorLine(tt.msg); got != tt.want {
			t.Fatalf("parseErrorLine(%q)=%d want=%d", tt.msg, got, tt.want)
		}
	}
}

func TestWordAt(t *testing.T) {
	text := "policyset finance v1:\n  domain finance\naxiom Fresh:\n  when action.name == \"pay_invoice\"\n  require source(\"bank\").age_sec <= 30\n"
	if got := wordAt(text, 0, 5); got != "policyset" {
		t.Fatalf("expected policyset, got %q", got)
	}
	if got := wordAt(text, 3, 8); got != "action.name" {
		t.Fatalf("expected action.name, got %q", got)
	}
	if got := wordAt(text, 1, 2); got != "domain" {
		t.Fatalf("expected domain, got %q", got)
	}
}

func TestServerDocStore(t *testing.T) {
	s := NewServer()
	s.setDoc("file://a.ax", "policyset finance v1:")
	if got := s.getDoc("file://a.ax"); got != "policyset finance v1:" {
		t.Fatalf("unexpected doc text: %q", got)
	}
}

func TestHandleInitializeAndShutdown(t *testing.T) {
	s := NewServer()
	initResp, notes := s.handle(Request{JSONRPC: "2.0", ID: json.RawMessage(`1`), Method: "initialize"})
	if len(notes) != 0 || len(initResp) != 1 {
		t.Fatalf("unexpected initialize output: responses=%d notifications=%d", len(initResp), len(notes))
	}
	if initResp[0].Error != nil {
		t.Fatalf("unexpected initialize error: %#v", initResp[0].Error)
	}
	shutdownResp, _ := s.handle(Request{JSONRPC: "2.0", ID: json.RawMessage(`2`), Method: "shutdown"})
	if len(shutdownResp) != 1 || shutdownResp[0].Error != nil {
		t.Fatalf("unexpected shutdown output: %#v", shutdownResp)
	}
}

func TestHandleDidOpenDidChangeAndHover(t *testing.T) {
	s := NewServer()
	openReq := Request{
		Method: "textDocument/didOpen",
		Params: json.RawMessage(`{"textDocument":{"uri":"file://dsl.ax","text":"policyset finance v1:\n"}}`),
	}
	resp, notes := s.handle(openReq)
	if len(resp) != 0 || len(notes) != 1 {
		t.Fatalf("unexpected didOpen output: responses=%d notifications=%d", len(resp), len(notes))
	}
	changeReq := Request{
		Method: "textDocument/didChange",
		Params: json.RawMessage(`{"textDocument":{"uri":"file://dsl.ax"},"contentChanges":[{"text":"policyset finance v1:\naxiom A:\n  when action.name == \"pay\"\n  require source(\"bank\").age_sec <= 30\n"}]}`),
	}
	resp, notes = s.handle(changeReq)
	if len(resp) != 0 || len(notes) != 1 {
		t.Fatalf("unexpected didChange output: responses=%d notifications=%d", len(resp), len(notes))
	}
	hoverReq := Request{
		JSONRPC: "2.0",
		ID:      json.RawMessage(`3`),
		Method:  "textDocument/hover",
		Params:  json.RawMessage(`{"textDocument":{"uri":"file://dsl.ax"},"position":{"line":0,"character":2}}`),
	}
	hoverResp, _ := s.handle(hoverReq)
	if len(hoverResp) != 1 || hoverResp[0].Error != nil || hoverResp[0].Result == nil {
		t.Fatalf("unexpected hover response: %#v", hoverResp)
	}
}

func TestHandleCompletionAndUnknownMethod(t *testing.T) {
	s := NewServer()
	compResp, notes := s.handle(Request{JSONRPC: "2.0", ID: json.RawMessage(`4`), Method: "textDocument/completion"})
	if len(notes) != 0 || len(compResp) != 1 || compResp[0].Error != nil {
		t.Fatalf("unexpected completion output: responses=%#v notifications=%#v", compResp, notes)
	}
	var list completionList
	raw, _ := json.Marshal(compResp[0].Result)
	if err := json.Unmarshal(raw, &list); err != nil {
		t.Fatalf("completion result decode failed: %v", err)
	}
	if len(list.Items) != len(keywordOrder) {
		t.Fatalf("unexpected completion count: %d", len(list.Items))
	}

	unknownResp, _ := s.handle(Request{JSONRPC: "2.0", ID: json.RawMessage(`5`), Method: "unknown/method"})
	if len(unknownResp) != 1 || unknownResp[0].Error == nil || unknownResp[0].Error.Code != -32601 {
		t.Fatalf("expected method-not-found error, got %#v", unknownResp)
	}
}

func TestPublishDiagnosticsAndHelpers(t *testing.T) {
	s := NewServer()
	notes := s.publishDiagnostics("file://valid.ax", "policyset finance v1:\n")
	if len(notes) != 1 {
		t.Fatalf("expected one diagnostics notification, got %d", len(notes))
	}
	raw, _ := json.Marshal(notes[0])
	var msg map[string]interface{}
	_ = json.Unmarshal(raw, &msg)
	params := msg["params"].(map[string]interface{})
	if diagnostics, ok := params["diagnostics"].([]interface{}); ok && len(diagnostics) != 0 {
		t.Fatalf("expected no diagnostics for valid text, got %#v", diagnostics)
	}

	notes = s.publishDiagnostics("file://bad.ax", "policyset")
	raw, _ = json.Marshal(notes[0])
	_ = json.Unmarshal(raw, &msg)
	params = msg["params"].(map[string]interface{})
	diagnostics, _ := params["diagnostics"].([]interface{})
	if len(diagnostics) == 0 {
		t.Fatal("expected diagnostics for invalid policy")
	}

	if got := lineAt("a\nb\nc", -1); got != "" {
		t.Fatalf("expected empty line for negative index, got %q", got)
	}
	if got := lineAt("a\nb\nc", 10); got != "" {
		t.Fatalf("expected empty line for out-of-range index, got %q", got)
	}
	if got := lineAt("a\nb\nc", 1); got != "b" {
		t.Fatalf("expected line 'b', got %q", got)
	}
	if isWordChar('!') {
		t.Fatal("expected '!' to be non-word char")
	}
	if !isWordChar('_') || !isWordChar('-') || !isWordChar('.') {
		t.Fatal("expected '_', '-' and '.' to be word chars")
	}
}

func TestReadWriteMessage(t *testing.T) {
	payload := []byte(`{"jsonrpc":"2.0","method":"initialize"}`)
	var out bytes.Buffer
	if err := writeMessage(&out, payload); err != nil {
		t.Fatalf("writeMessage failed: %v", err)
	}
	wire := out.String()
	if !strings.Contains(wire, "Content-Length: ") {
		t.Fatalf("missing content-length header: %q", wire)
	}
	reader := bufio.NewReader(strings.NewReader(wire))
	got, err := readMessage(reader)
	if err != nil {
		t.Fatalf("readMessage failed: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("unexpected payload: %q", string(got))
	}
	missingHeader := bufio.NewReader(strings.NewReader("\r\n{}"))
	if _, err := readMessage(missingHeader); err == nil {
		t.Fatal("expected missing content-length error")
	}
	badHeader := bufio.NewReader(strings.NewReader("Content-Length: abc\r\n\r\n{}"))
	if _, err := readMessage(badHeader); err == nil {
		t.Fatal("expected invalid content-length error")
	}
}

type failWriter struct {
}

func (w *failWriter) Write(p []byte) (int, error) {
	return 0, errors.New("write failed")
}

func TestRunServer(t *testing.T) {
	buildWire := func(msgs ...[]byte) string {
		var buf bytes.Buffer
		for _, m := range msgs {
			_ = writeMessage(&buf, m)
		}
		return buf.String()
	}

	t.Run("processes_responses_and_notifications", func(t *testing.T) {
		initialize := []byte(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)
		didOpen := []byte(`{"jsonrpc":"2.0","method":"textDocument/didOpen","params":{"textDocument":{"uri":"file://bad.ax","text":"policyset"}}}`)
		var out bytes.Buffer
		if err := runServer(strings.NewReader(buildWire(initialize, didOpen)), &out); err != nil {
			t.Fatalf("runServer failed: %v", err)
		}

		reader := bufio.NewReader(strings.NewReader(out.String()))
		msg1, err := readMessage(reader)
		if err != nil {
			t.Fatalf("read first lsp message: %v", err)
		}
		msg2, err := readMessage(reader)
		if err != nil {
			t.Fatalf("read second lsp message: %v", err)
		}
		var resp Response
		if err := json.Unmarshal(msg1, &resp); err != nil {
			t.Fatalf("decode response: %v", err)
		}
		if resp.ID == nil || resp.Result == nil {
			t.Fatalf("expected initialize response with id/result, got %#v", resp)
		}
		var note map[string]interface{}
		if err := json.Unmarshal(msg2, &note); err != nil {
			t.Fatalf("decode diagnostics notification: %v", err)
		}
		if note["method"] != "textDocument/publishDiagnostics" {
			t.Fatalf("expected diagnostics notification, got %#v", note)
		}
	})

	t.Run("invalid_request_is_skipped", func(t *testing.T) {
		invalid := []byte(`{bad`)
		shutdown := []byte(`{"jsonrpc":"2.0","id":2,"method":"shutdown","params":{}}`)
		var out bytes.Buffer
		if err := runServer(strings.NewReader(buildWire(invalid, shutdown)), &out); err != nil {
			t.Fatalf("runServer should continue after invalid request, err=%v", err)
		}
		reader := bufio.NewReader(strings.NewReader(out.String()))
		msg, err := readMessage(reader)
		if err != nil {
			t.Fatalf("expected shutdown response after invalid request, got %v", err)
		}
		var resp Response
		if err := json.Unmarshal(msg, &resp); err != nil {
			t.Fatalf("decode shutdown response: %v", err)
		}
		if string(resp.ID) != "2" {
			t.Fatalf("expected shutdown response id=2, got %#v", resp.ID)
		}
	})

	t.Run("write_error_propagates", func(t *testing.T) {
		initialize := []byte(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)
		w := &failWriter{}
		err := runServer(strings.NewReader(buildWire(initialize)), w)
		if err == nil || !strings.Contains(err.Error(), "write failed") {
			t.Fatalf("expected write failure propagation, got %v", err)
		}
	})

	t.Run("read_error_propagates", func(t *testing.T) {
		err := runServer(strings.NewReader("Content-Length: abc\r\n\r\n{}"), io.Discard)
		if err == nil {
			t.Fatal("expected malformed content-length read error")
		}
	})
}
