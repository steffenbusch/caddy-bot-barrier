package botbarrier

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2/caddytest"
)

func TestCaddyfileBotBarrier(t *testing.T) {
	const complexity = 20

	config := fmt.Sprintf(`
	{
		skip_install_trust
		admin localhost:2999
		http_port 8080
	}

	localhost:8080

	bot_barrier {
		# Verify that the secret is optional
		# secret
		complexity %d
		valid_for 5m
	}

	respond 200
	`, complexity)

	tester := caddytest.NewTester(t)
	tester.InitServer(config, "caddyfile")

	// Create a new GET request
	req, err := http.NewRequest("GET", "http://localhost:8080", nil)
	if err != nil {
		t.Fatalf("Failed to create GET request: %v", err)
	}

	// Assert the response code is 200
	resp := tester.AssertResponseCode(req, 200)

	// Check for the presence of the "X-Bot-Barrier" header
	expectedHeader := "X-Bot-Barrier"
	expectedValue := "challenge"
	if resp.Header.Get(expectedHeader) != expectedValue {
		t.Errorf("Expected header %s to have value %s, but got %s", expectedHeader, expectedValue, resp.Header.Get(expectedHeader))
	}

	// Verify the response contains the complexity value
	if !containsComplexity(resp, complexity) {
		t.Errorf("Response does not contain the expected complexity value: %d", complexity)
	}

	fmt.Println("BotBarrier Caddyfile test completed")
}

func containsComplexity(resp *http.Response, complexity int) bool {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	// Check if the body contains the exact string "const complexity = <value>;"
	expectedString := fmt.Sprintf("const complexity = %d;", complexity)
	return strings.Contains(string(body), expectedString)
}
