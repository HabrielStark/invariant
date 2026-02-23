package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"
)

// Tests for uncovered branches in axiomdsl-lsp

func TestWordAtEdgeCases(t *testing.T) {
	// Test empty text
	if got := wordAt("", 0, 0); got != "" {
		t.Fatalf("expected empty for empty text, got %q", got)
	}

	// Test line out of bounds
	if got := wordAt("firstline\nsecondline", 5, 0); got != "" {
		t.Fatalf("expected empty for line out of bounds, got %q", got)
	}

	// Test negative character position
	if got := wordAt("hello world", 0, -5); got == "" || got != "hello" {
		t.Fatalf("expected word at start for negative ch, got %q", got)
	}

	// Test character position beyond line length
	if got := wordAt("hello", 0, 100); got != "hello" {
		t.Fatalf("expected word for ch beyond line length, got %q", got)
	}

	// Test getting word in middle
	if got := wordAt("hello_world test", 0, 7); got != "hello_world" {
		t.Fatalf("expected 'hello_world' for middle position, got %q", got)
	}

	// Test start >= end (no word found)
	if got := wordAt("   ", 0, 1); got != "" {
		t.Fatalf("expected empty for whitespace-only content, got %q", got)
	}
}

func TestIsWordCharAllTypes(t *testing.T) {
	// Lowercase
	if !isWordChar('a') || !isWordChar('z') {
		t.Fatal("expected lowercase to be word char")
	}

	// Uppercase
	if !isWordChar('A') || !isWordChar('Z') {
		t.Fatal("expected uppercase to be word char")
	}

	// Digits
	if !isWordChar('0') || !isWordChar('9') {
		t.Fatal("expected digits to be word char")
	}

	// Special chars
	if !isWordChar('_') || !isWordChar('-') || !isWordChar('.') {
		t.Fatal("expected underscore, dash, dot to be word char")
	}

	// Non-word chars
	if isWordChar(' ') || isWordChar('@') || isWordChar('#') || isWordChar('!') || isWordChar('(') {
		t.Fatal("expected special characters to not be word char")
	}
}

func TestParseErrorLineEdgeCases(t *testing.T) {
	// No "line " found
	if got := parseErrorLine("some error"); got != 0 {
		t.Fatalf("expected 0 for no line info, got %d", got)
	}

	// "line " but no number
	if got := parseErrorLine("at line abc"); got != 0 {
		t.Fatalf("expected 0 for non-numeric line, got %d", got)
	}

	// Valid line number
	if got := parseErrorLine("error at line 42: syntax"); got != 42 {
		t.Fatalf("expected 42, got %d", got)
	}

	// Line at end of string
	if got := parseErrorLine("line 7"); got != 7 {
		t.Fatalf("expected 7, got %d", got)
	}
}

func TestLineAtBoundaries(t *testing.T) {
	// Negative line
	if got := lineAt("hello", -1); got != "" {
		t.Fatalf("expected empty for negative line, got %q", got)
	}

	// Line beyond range
	if got := lineAt("one\ntwo", 5); got != "" {
		t.Fatalf("expected empty for line beyond range, got %q", got)
	}

	// Valid line
	if got := lineAt("first\nsecond\nthird", 1); got != "second" {
		t.Fatalf("expected 'second', got %q", got)
	}
}

func TestServerHandleUnknownMethodWithID(t *testing.T) {
	s := NewServer()
	req := Request{
		Method: "unknownMethod",
		ID:     json.RawMessage(`1`),
	}
	responses, _ := s.handle(req)
	if len(responses) != 1 {
		t.Fatalf("expected 1 response, got %d", len(responses))
	}
	if responses[0].Error == nil || responses[0].Error.Code != -32601 {
		t.Fatalf("expected method not found error, got %+v", responses[0])
	}
}

func TestServerHandleUnknownMethodWithoutID(t *testing.T) {
	s := NewServer()
	req := Request{
		Method: "notification/unknown",
	}
	responses, notifications := s.handle(req)
	if len(responses) != 0 || len(notifications) != 0 {
		t.Fatalf("expected empty responses for notification-style unknown method")
	}
}

func TestWriteMessageError(t *testing.T) {
	// Test write error by using a failing writer
	failWriter := &failingWriter{}
	err := writeMessage(failWriter, []byte("test payload"))
	if err == nil {
		t.Fatal("expected write error")
	}
}

func TestReadMessageMissingContentLength(t *testing.T) {
	input := "X-Header: value\r\n\r\n"
	reader := bufio.NewReader(strings.NewReader(input))
	_, err := readMessage(reader)
	if err == nil || !strings.Contains(err.Error(), "content length") {
		t.Fatalf("expected missing content length error, got %v", err)
	}
}

func TestReadMessageInvalidContentLength(t *testing.T) {
	input := "Content-Length: abc\r\n\r\n"
	reader := bufio.NewReader(strings.NewReader(input))
	_, err := readMessage(reader)
	if err == nil {
		t.Fatal("expected parse error for invalid content length")
	}
}

func TestRunServerInvalidJSON(t *testing.T) {
	// Valid content-length but invalid JSON body
	input := "Content-Length: 10\r\n\r\n{invalid!!"
	var output bytes.Buffer
	err := runServer(strings.NewReader(input), &output)
	// Should continue and not error for invalid JSON (just log and skip)
	if err != nil {
		t.Fatalf("expected nil error for invalid JSON (logged only), got %v", err)
	}
}

func TestServerHoverNoWord(t *testing.T) {
	s := NewServer()
	s.setDoc("test.axiom", "   ") // whitespace only
	req := Request{
		Method: "textDocument/hover",
		ID:     json.RawMessage(`2`),
		Params: json.RawMessage(`{"textDocument":{"uri":"test.axiom"},"position":{"line":0,"character":1}}`),
	}
	responses, _ := s.handle(req)
	if len(responses) != 1 || responses[0].Result != nil {
		t.Fatalf("expected nil result for hover on whitespace, got %+v", responses[0])
	}
}

func TestServerHoverUnknownWord(t *testing.T) {
	s := NewServer()
	s.setDoc("test.axiom", "unknownword")
	req := Request{
		Method: "textDocument/hover",
		ID:     json.RawMessage(`3`),
		Params: json.RawMessage(`{"textDocument":{"uri":"test.axiom"},"position":{"line":0,"character":3}}`),
	}
	responses, _ := s.handle(req)
	if len(responses) != 1 || responses[0].Result != nil {
		t.Fatalf("expected nil result for unknown word, got %+v", responses[0])
	}
}

func TestServerDidChangeNoContentChanges(t *testing.T) {
	s := NewServer()
	s.setDoc("test.axiom", "original")
	req := Request{
		Method: "textDocument/didChange",
		Params: json.RawMessage(`{"textDocument":{"uri":"test.axiom"},"contentChanges":[]}`),
	}
	_, notifications := s.handle(req)
	// Should publish diagnostics even with empty content changes
	if len(notifications) != 1 {
		t.Fatalf("expected 1 notification, got %d", len(notifications))
	}
	// Doc should be set to empty
	if s.getDoc("test.axiom") != "" {
		t.Fatalf("expected doc to be empty after no content changes")
	}
}

func TestReadMessageEOF(t *testing.T) {
	// Test EOF handling
	reader := bufio.NewReader(strings.NewReader(""))
	_, err := readMessage(reader)
	if err == nil || err != io.EOF {
		t.Fatalf("expected EOF, got %v", err)
	}
}

func TestRunServerEOF(t *testing.T) {
	// Test clean EOF handling
	var output bytes.Buffer
	err := runServer(strings.NewReader(""), &output)
	if err != nil {
		t.Fatalf("expected nil for clean EOF, got %v", err)
	}
}

// Helper types
type failingWriter struct{}

func (f *failingWriter) Write(p []byte) (n int, err error) {
	return 0, bytes.ErrTooLarge
}

// failingReader returns non-EOF error
type failingReader struct{}

func (f *failingReader) Read(p []byte) (n int, err error) {
	return 0, bytes.ErrTooLarge
}

func TestRunServerReadError(t *testing.T) {
	// Test non-EOF read error
	err := runServer(&failingReader{}, &bytes.Buffer{})
	if err == nil {
		t.Fatal("expected read error")
	}
}

// partialReader returns valid header then errors
type partialReader struct {
	data     []byte
	idx      int
	errAfter int
}

func (r *partialReader) Read(p []byte) (n int, err error) {
	if r.errAfter > 0 && r.idx >= r.errAfter {
		return 0, bytes.ErrTooLarge
	}
	if r.idx >= len(r.data) {
		return 0, io.EOF
	}
	n = copy(p, r.data[r.idx:])
	r.idx += n
	return n, nil
}

func TestRunServerInitializeAndExit(t *testing.T) {
	// Build a valid initialize + exit request sequence
	initReq := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"capabilities":{}}}`
	exitReq := `{"jsonrpc":"2.0","method":"exit"}`

	input := lspMsg(initReq) + lspMsg(exitReq)
	var output bytes.Buffer

	err := runServer(strings.NewReader(input), &output)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func lspMsg(content string) string {
	return "Content-Length: " + strconvItoa(len(content)) + "\r\n\r\n" + content
}

func strconvItoa(n int) string {
	var buf [20]byte
	idx := len(buf) - 1
	for n >= 10 {
		buf[idx] = byte('0' + n%10)
		n /= 10
		idx--
	}
	buf[idx] = byte('0' + n)
	return string(buf[idx:])
}

// Use strconv.Itoa instead
func TestRunServerWithValidFlow(t *testing.T) {
	didOpenReq := `{"jsonrpc":"2.0","method":"textDocument/didOpen","params":{"textDocument":{"uri":"file:///test.axiom","languageId":"axiom","version":1,"text":"policyset test v1:\n  axiom TestAxiom\n"}}}`
	hoverReq := `{"jsonrpc":"2.0","id":2,"method":"textDocument/hover","params":{"textDocument":{"uri":"file:///test.axiom"},"position":{"line":1,"character":8}}}`

	input := lspMsg(didOpenReq) + lspMsg(hoverReq)
	var output bytes.Buffer

	err := runServer(strings.NewReader(input), &output)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
