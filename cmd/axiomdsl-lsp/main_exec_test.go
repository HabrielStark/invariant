package main

import (
	"bufio"
	"bytes"
	"io"
	"strings"
	"testing"
)

// TestMainDirectLSP tests the actual main() function by overriding global vars
func TestMainDirectLSP(t *testing.T) {
	origLogSetOutput := logSetOutput
	origStdin := serverStdin
	origStdout := serverStdout
	origStderr := logStderr
	defer func() {
		logSetOutput = origLogSetOutput
		serverStdin = origStdin
		serverStdout = origStdout
		logStderr = origStderr
	}()

	t.Run("main initializes and processes LSP messages", func(t *testing.T) {
		initReq := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`
		shutdownReq := `{"jsonrpc":"2.0","id":2,"method":"shutdown"}`

		var input bytes.Buffer
		input.WriteString("Content-Length: ")
		input.WriteString(itoa(len(initReq)))
		input.WriteString("\r\n\r\n")
		input.WriteString(initReq)
		input.WriteString("Content-Length: ")
		input.WriteString(itoa(len(shutdownReq)))
		input.WriteString("\r\n\r\n")
		input.WriteString(shutdownReq)

		var output bytes.Buffer
		var logOutput bytes.Buffer

		logSetOutput = func(w io.Writer) {}
		serverStdin = &input
		serverStdout = &output
		logStderr = &logOutput

		main()

		if output.Len() > 0 {
			t.Log("main produced output")
		}
	})

	t.Run("main handles empty input", func(t *testing.T) {
		var input bytes.Buffer
		var output bytes.Buffer
		var logOutput bytes.Buffer

		logSetOutput = func(w io.Writer) {}
		serverStdin = &input
		serverStdout = &output
		logStderr = &logOutput

		main() // Should not panic
	})
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

// TestRunServerEdges tests edge cases in runServer
func TestRunServerEdges(t *testing.T) {
	t.Run("handles malformed LSP header", func(t *testing.T) {
		input := strings.NewReader("Bad-Header: value\r\n\r\n")
		var output bytes.Buffer
		_ = runServer(input, &output)
	})

	t.Run("handles empty JSON body", func(t *testing.T) {
		input := strings.NewReader("Content-Length: 2\r\n\r\n{}")
		var output bytes.Buffer
		_ = runServer(input, &output)
	})

	t.Run("handles textDocument/hover", func(t *testing.T) {
		initReq := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`
		hoverReq := `{"jsonrpc":"2.0","id":2,"method":"textDocument/hover","params":{"textDocument":{"uri":"test.axiom"},"position":{"line":0,"character":0}}}`

		var input bytes.Buffer
		input.WriteString("Content-Length: ")
		input.WriteString(itoa(len(initReq)))
		input.WriteString("\r\n\r\n")
		input.WriteString(initReq)
		input.WriteString("Content-Length: ")
		input.WriteString(itoa(len(hoverReq)))
		input.WriteString("\r\n\r\n")
		input.WriteString(hoverReq)

		var output bytes.Buffer
		_ = runServer(&input, &output)

		if strings.Contains(output.String(), "result") {
			t.Log("hover responded with result")
		}
	})

	t.Run("handles textDocument/definition", func(t *testing.T) {
		initReq := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`
		defReq := `{"jsonrpc":"2.0","id":2,"method":"textDocument/definition","params":{"textDocument":{"uri":"test.axiom"},"position":{"line":0,"character":0}}}`

		var input bytes.Buffer
		input.WriteString("Content-Length: ")
		input.WriteString(itoa(len(initReq)))
		input.WriteString("\r\n\r\n")
		input.WriteString(initReq)
		input.WriteString("Content-Length: ")
		input.WriteString(itoa(len(defReq)))
		input.WriteString("\r\n\r\n")
		input.WriteString(defReq)

		var output bytes.Buffer
		_ = runServer(&input, &output)
	})

	t.Run("handles textDocument/references", func(t *testing.T) {
		initReq := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`
		refReq := `{"jsonrpc":"2.0","id":2,"method":"textDocument/references","params":{"textDocument":{"uri":"test.axiom"},"position":{"line":0,"character":0}}}`

		var input bytes.Buffer
		input.WriteString("Content-Length: ")
		input.WriteString(itoa(len(initReq)))
		input.WriteString("\r\n\r\n")
		input.WriteString(initReq)
		input.WriteString("Content-Length: ")
		input.WriteString(itoa(len(refReq)))
		input.WriteString("\r\n\r\n")
		input.WriteString(refReq)

		var output bytes.Buffer
		_ = runServer(&input, &output)
	})

	t.Run("handles textDocument/formatting", func(t *testing.T) {
		initReq := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`
		fmtReq := `{"jsonrpc":"2.0","id":2,"method":"textDocument/formatting","params":{"textDocument":{"uri":"test.axiom"},"options":{"tabSize":4}}}`

		var input bytes.Buffer
		input.WriteString("Content-Length: ")
		input.WriteString(itoa(len(initReq)))
		input.WriteString("\r\n\r\n")
		input.WriteString(initReq)
		input.WriteString("Content-Length: ")
		input.WriteString(itoa(len(fmtReq)))
		input.WriteString("\r\n\r\n")
		input.WriteString(fmtReq)

		var output bytes.Buffer
		_ = runServer(&input, &output)
	})

	t.Run("handles exit notification", func(t *testing.T) {
		initReq := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`
		exitReq := `{"jsonrpc":"2.0","method":"exit"}`

		var input bytes.Buffer
		input.WriteString("Content-Length: ")
		input.WriteString(itoa(len(initReq)))
		input.WriteString("\r\n\r\n")
		input.WriteString(initReq)
		input.WriteString("Content-Length: ")
		input.WriteString(itoa(len(exitReq)))
		input.WriteString("\r\n\r\n")
		input.WriteString(exitReq)

		var output bytes.Buffer
		_ = runServer(&input, &output)
	})
}

// Ensure bufio import is used
var _ = bufio.NewReader
