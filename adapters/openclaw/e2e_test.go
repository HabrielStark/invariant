package openclaw

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestE2EDemoScript(t *testing.T) {
	if testing.Short() {
		t.Skip("short mode")
	}
	if os.Getenv("RUN_OPENCLAW_E2E") != "1" {
		t.Skip("set RUN_OPENCLAW_E2E=1 to run docker compose e2e")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not available")
	}
	cmd := exec.Command("bash", "scripts/demo_openclaw_invariant.sh")
	cmd.Env = append(os.Environ(), "KEEP_STACK_UP=0")
	cmd.Dir = "../.."
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("demo script failed: %v\n%s", err, string(output))
	}
	if !strings.Contains(string(output), "DEMO_SUCCESS") {
		t.Fatalf("demo did not complete successfully\n%s", string(output))
	}
}
