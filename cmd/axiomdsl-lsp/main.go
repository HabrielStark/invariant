package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"

	"axiom/pkg/axiomdsl"
)

type Request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type Response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  interface{}     `json:"result,omitempty"`
	Error   *RespError      `json:"error,omitempty"`
}

type RespError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type Server struct {
	mu   sync.RWMutex
	docs map[string]string
}

func NewServer() *Server {
	return &Server{docs: map[string]string{}}
}

func (s *Server) setDoc(uri, text string) {
	s.mu.Lock()
	s.docs[uri] = text
	s.mu.Unlock()
}

func (s *Server) getDoc(uri string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.docs[uri]
}

func (s *Server) handle(req Request) ([]Response, []interface{}) {
	switch req.Method {
	case "initialize":
		capabilities := map[string]interface{}{
			"capabilities": map[string]interface{}{
				"textDocumentSync": map[string]interface{}{
					"openClose": true,
					"change":    1,
				},
				"completionProvider": map[string]interface{}{
					"triggerCharacters": []string{" ", "\"", "."},
				},
				"hoverProvider": true,
			},
		}
		return []Response{{JSONRPC: "2.0", ID: req.ID, Result: capabilities}}, nil
	case "shutdown":
		return []Response{{JSONRPC: "2.0", ID: req.ID, Result: nil}}, nil
	case "textDocument/didOpen":
		var params didOpenParams
		_ = json.Unmarshal(req.Params, &params)
		s.setDoc(params.TextDocument.URI, params.TextDocument.Text)
		return nil, s.publishDiagnostics(params.TextDocument.URI, params.TextDocument.Text)
	case "textDocument/didChange":
		var params didChangeParams
		_ = json.Unmarshal(req.Params, &params)
		text := ""
		if len(params.ContentChanges) > 0 {
			text = params.ContentChanges[0].Text
		}
		s.setDoc(params.TextDocument.URI, text)
		return nil, s.publishDiagnostics(params.TextDocument.URI, text)
	case "textDocument/completion":
		return []Response{{JSONRPC: "2.0", ID: req.ID, Result: buildCompletionList()}}, nil
	case "textDocument/hover":
		var params hoverParams
		_ = json.Unmarshal(req.Params, &params)
		text := s.getDoc(params.TextDocument.URI)
		word := wordAt(text, params.Position.Line, params.Position.Character)
		if word == "" {
			return []Response{{JSONRPC: "2.0", ID: req.ID, Result: nil}}, nil
		}
		if desc, ok := keywordDocs[word]; ok {
			result := map[string]interface{}{
				"contents": map[string]string{
					"kind":  "markdown",
					"value": fmt.Sprintf("**%s**\n\n%s", word, desc),
				},
			}
			return []Response{{JSONRPC: "2.0", ID: req.ID, Result: result}}, nil
		}
		return []Response{{JSONRPC: "2.0", ID: req.ID, Result: nil}}, nil
	default:
		if req.ID != nil {
			return []Response{{JSONRPC: "2.0", ID: req.ID, Error: &RespError{Code: -32601, Message: "method not found"}}}, nil
		}
		return nil, nil
	}
}

func (s *Server) publishDiagnostics(uri, text string) []interface{} {
	var diagnostics []diagnostic
	if text != "" {
		if _, err := axiomdsl.ParseDSL(text); err != nil {
			line := parseErrorLine(err.Error())
			startLine := 0
			if line > 0 {
				startLine = line - 1
			}
			lineText := lineAt(text, startLine)
			diagnostics = append(diagnostics, diagnostic{
				Range: diagnosticRange{
					Start: position{Line: startLine, Character: 0},
					End:   position{Line: startLine, Character: len(lineText)},
				},
				Severity: 1,
				Source:   "axiomdsl",
				Message:  err.Error(),
			})
		}
	}
	msg := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "textDocument/publishDiagnostics",
		"params": map[string]interface{}{
			"uri":         uri,
			"diagnostics": diagnostics,
		},
	}
	return []interface{}{msg}
}

type didOpenParams struct {
	TextDocument textDocumentItem `json:"textDocument"`
}

type didChangeParams struct {
	TextDocument   textDocumentIdentifier      `json:"textDocument"`
	ContentChanges []textDocumentContentChange `json:"contentChanges"`
}

type textDocumentItem struct {
	URI  string `json:"uri"`
	Text string `json:"text"`
}

type textDocumentIdentifier struct {
	URI string `json:"uri"`
}

type textDocumentContentChange struct {
	Text string `json:"text"`
}

type hoverParams struct {
	TextDocument textDocumentIdentifier `json:"textDocument"`
	Position     position               `json:"position"`
}

type position struct {
	Line      int `json:"line"`
	Character int `json:"character"`
}

type diagnostic struct {
	Range    diagnosticRange `json:"range"`
	Severity int             `json:"severity"`
	Source   string          `json:"source"`
	Message  string          `json:"message"`
}

type diagnosticRange struct {
	Start position `json:"start"`
	End   position `json:"end"`
}

type completionItem struct {
	Label  string `json:"label"`
	Kind   int    `json:"kind"`
	Detail string `json:"detail,omitempty"`
}

type completionList struct {
	IsIncomplete bool             `json:"isIncomplete"`
	Items        []completionItem `json:"items"`
}

func buildCompletionList() completionList {
	items := []completionItem{}
	for _, kw := range keywordOrder {
		items = append(items, completionItem{Label: kw, Kind: 14, Detail: "axiomdsl keyword"})
	}
	return completionList{IsIncomplete: false, Items: items}
}

var keywordDocs = map[string]string{
	"policyset": "Declare a policy set header: policyset <name> <version>:",
	"domain":    "Declare policy domain (applies to all axioms).",
	"axiom":     "Begin a new axiom block: axiom <Name>:",
	"when":      "Guard clause for an axiom; only evaluated when true.",
	"require":   "Constraint that must be satisfied when axiom is applicable.",
	"else":      "Fallback shield to suggest when an axiom fails.",
	"shield":    "Shield helper, e.g. shield(\"READ_ONLY\").",
	"rate":      "Rate limit configuration for decisions.",
	"limit":     "Rate limit clause keyword.",
	"approvals": "Approval policy (quorum, roles, SoD).",
	"invariant": "Domain invariant applied to all decisions.",
	"abac":      "Attribute-based access control rule.",
	"allow":     "Allow effect for ABAC rules.",
	"deny":      "Deny effect for ABAC rules.",
	"scope":     "Rate limit scope (actor, tenant, global).",
}

var keywordOrder = []string{
	"policyset",
	"domain",
	"axiom",
	"when",
	"require",
	"else",
	"shield",
	"rate",
	"limit",
	"approvals",
	"invariant",
	"abac",
	"allow",
	"deny",
	"scope",
}

func parseErrorLine(msg string) int {
	msg = strings.ToLower(msg)
	idx := strings.Index(msg, "line ")
	if idx == -1 {
		return 0
	}
	start := idx + len("line ")
	end := start
	for end < len(msg) && msg[end] >= '0' && msg[end] <= '9' {
		end++
	}
	if end == start {
		return 0
	}
	n, err := strconv.Atoi(msg[start:end])
	if err != nil {
		return 0
	}
	return n
}

func lineAt(text string, line int) string {
	if line < 0 {
		return ""
	}
	lines := strings.Split(text, "\n")
	if line >= len(lines) {
		return ""
	}
	return lines[line]
}

func wordAt(text string, line, ch int) string {
	lineText := lineAt(text, line)
	if lineText == "" {
		return ""
	}
	if ch < 0 {
		ch = 0
	}
	if ch > len(lineText) {
		ch = len(lineText)
	}
	start := ch
	for start > 0 && isWordChar(lineText[start-1]) {
		start--
	}
	end := ch
	for end < len(lineText) && isWordChar(lineText[end]) {
		end++
	}
	if start >= end {
		return ""
	}
	return lineText[start:end]
}

func isWordChar(b byte) bool {
	if b >= 'a' && b <= 'z' {
		return true
	}
	if b >= 'A' && b <= 'Z' {
		return true
	}
	if b >= '0' && b <= '9' {
		return true
	}
	switch b {
	case '_', '-', '.':
		return true
	default:
		return false
	}
}

func readMessage(r *bufio.Reader) ([]byte, error) {
	length := 0
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return nil, err
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "content-length:") {
			v := strings.TrimSpace(line[len("content-length:"):])
			n, err := strconv.Atoi(v)
			if err != nil {
				return nil, err
			}
			length = n
		}
	}
	if length <= 0 {
		return nil, errors.New("missing content length")
	}
	buf := make([]byte, length)
	_, err := io.ReadFull(r, buf)
	return buf, err
}

func writeMessage(w io.Writer, payload []byte) error {
	_, err := fmt.Fprintf(w, "Content-Length: %d\r\n\r\n", len(payload))
	if err != nil {
		return err
	}
	_, err = w.Write(payload)
	return err
}

func runServer(input io.Reader, output io.Writer) error {
	server := NewServer()
	reader := bufio.NewReader(input)
	writer := bufio.NewWriter(output)
	defer writer.Flush()

	for {
		msg, err := readMessage(reader)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			log.Printf("read error: %v", err)
			return err
		}
		var req Request
		if err := json.Unmarshal(msg, &req); err != nil {
			log.Printf("invalid request: %v", err)
			continue
		}
		responses, notifications := server.handle(req)
		for _, resp := range responses {
			b, _ := json.Marshal(resp)
			if err := writeMessage(writer, b); err != nil {
				return err
			}
			if err := writer.Flush(); err != nil {
				return err
			}
		}
		for _, note := range notifications {
			b, _ := json.Marshal(note)
			if err := writeMessage(writer, b); err != nil {
				return err
			}
			if err := writer.Flush(); err != nil {
				return err
			}
		}
	}
}

// Testable variables for main()
var (
	logSetOutput           = log.SetOutput
	serverStdin  io.Reader = os.Stdin
	serverStdout io.Writer = os.Stdout
	logStderr    io.Writer = os.Stderr
)

func main() {
	logSetOutput(logStderr)
	if err := runServer(serverStdin, serverStdout); err != nil {
		log.Printf("server stopped: %v", err)
	}
}
