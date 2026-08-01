package botbarrier

import (
	"context"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap/zaptest"
)

func TestNewSeed(t *testing.T) {
	bb := BotBarrier{}
	seed, err := bb.newSeed()
	if err != nil {
		t.Fatalf("Seed generation returned an error: %v", err)
	}
	if len(seed) != 16 {
		t.Fatalf("Expected seed length of 16, got %d", len(seed))
	}
}

func TestCreateMAC(t *testing.T) {
	bb := BotBarrier{Secret: "testsecret"}
	seed := []byte("testseed")
	mac := bb.createMAC(seed)

	expectedMAC := hmac.New(sha512.New, []byte("testsecret"))
	expectedMAC.Write(seed)
	if !hmac.Equal(expectedMAC.Sum(nil), mac) {
		t.Fatalf("MAC does not match the expected value")
	}
}

func TestIsSeedValid(t *testing.T) {
	bb := BotBarrier{
		ValidFor:   caddy.Duration(10 * time.Minute),
		Complexity: "16",
		logger:     zaptest.NewLogger(t),
	}
	now := uint64(time.Now().Unix())
	seed := make([]byte, 16)
	binary.BigEndian.PutUint64(seed[0:8], now)

	age, valid := bb.isSeedValid(seed)
	if !valid {
		t.Fatalf("Expected seed to be valid")
	}
	if age > time.Duration(bb.ValidFor) {
		t.Fatalf("Expected seed age to be within valid duration, got %v", age)
	}
}

func TestCheckSolution(t *testing.T) {
	bb := BotBarrier{
		Secret:             "testsecret",
		ValidFor:           caddy.Duration(10 * time.Minute),
		SeedCookieName:     "__challenge_seed",
		SolutionCookieName: "__challenge_solution",
		MacCookieName:      "__challenge_mac",
		logger:             zaptest.NewLogger(t),
	}

	seed := make([]byte, 16)
	now := uint64(time.Now().Unix())
	binary.BigEndian.PutUint64(seed[0:8], now)
	mac := bb.createMAC(seed)

	// Find a nonce that meets the complexity requirement
	var nonce []byte
	var hash [64]byte
	for i := uint64(0); ; i++ {
		nonce = make([]byte, 8)
		binary.BigEndian.PutUint64(nonce, i)
		combined := append(seed, nonce...)
		hash = sha512.Sum512(combined)
		if countLeadingZeroBits(hash[:]) >= 16 {
			break
		}
	}

	// Create a mock HTTP request with cookies
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: bb.SeedCookieName, Value: hex.EncodeToString(seed)})
	req.AddCookie(&http.Cookie{Name: bb.SolutionCookieName, Value: hex.EncodeToString(nonce)})
	req.AddCookie(&http.Cookie{Name: bb.MacCookieName, Value: hex.EncodeToString(mac)})

	valid := bb.checkSolution(req, 16, bb.logger)
	if !valid {
		t.Fatalf("Expected solution to be valid")
	}
}

func TestRenderChallengePageSetsNoStoreHeaders(t *testing.T) {
	bb := BotBarrier{
		TemplatePath: defaultHTML,
	}

	rec := httptest.NewRecorder()
	data := map[string]any{
		"Seed":           "00112233445566778899aabbccddeeff",
		"MAC":            "00",
		"Complexity":     16,
		"SeedCookie":     "__challenge_seed",
		"SolutionCookie": "__challenge_solution",
		"MacCookie":      "__challenge_mac",
		"MaxAge":         600,
	}

	if err := bb.renderChallengePage(rec, data); err != nil {
		t.Fatalf("renderChallengePage returned an error: %v", err)
	}

	if got := rec.Header().Get("Cache-Control"); got != "no-store, private" {
		t.Fatalf("expected Cache-Control header %q, got %q", "no-store, private", got)
	}
	if got := rec.Header().Get("Pragma"); got != "no-cache" {
		t.Fatalf("expected Pragma header %q, got %q", "no-cache", got)
	}
	if got := rec.Header().Get("Expires"); got != "0" {
		t.Fatalf("expected Expires header %q, got %q", "0", got)
	}
	if got := rec.Header().Get("Vary"); got != "Cookie" {
		t.Fatalf("expected Vary header %q, got %q", "Cookie", got)
	}
}

func TestValidateRejectsStaticComplexityAboveMax(t *testing.T) {
	bb := BotBarrier{
		Secret:     "testsecret",
		Complexity: "33",
	}

	if err := bb.Validate(); err == nil {
		t.Fatal("expected Validate to reject complexity above 32")
	}
}

func TestServeHTTPClampsResolvedComplexityToMax(t *testing.T) {
	rec := httptest.NewRecorder()
	req := newRequestWithReplacer(http.MethodGet, "https://example.com/", "700")

	bb := BotBarrier{
		Secret:             "testsecret",
		Complexity:         "{vars.bot_barrier_complexity}",
		ValidFor:           caddy.Duration(10 * time.Minute),
		SeedCookieName:     "__challenge_seed",
		SolutionCookieName: "__challenge_solution",
		MacCookieName:      "__challenge_mac",
		TemplatePath:       defaultHTML,
		logger:             zaptest.NewLogger(t),
	}

	err := bb.ServeHTTP(rec, req, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		t.Fatal("next handler should not be called for an unsolved challenge")
		return nil
	}))
	if err != nil {
		t.Fatalf("ServeHTTP returned an error: %v", err)
	}

	if !strings.Contains(rec.Body.String(), "const complexity = 32;") {
		t.Fatalf("expected rendered challenge to clamp complexity to 32, body was: %s", rec.Body.String())
	}
}

func TestServeHTTPDefaultsInvalidResolvedComplexityToDefault(t *testing.T) {
	rec := httptest.NewRecorder()
	req := newRequestWithReplacer(http.MethodGet, "https://example.com/", "invalid")

	bb := BotBarrier{
		Secret:             "testsecret",
		Complexity:         "{vars.bot_barrier_complexity}",
		ValidFor:           caddy.Duration(10 * time.Minute),
		SeedCookieName:     "__challenge_seed",
		SolutionCookieName: "__challenge_solution",
		MacCookieName:      "__challenge_mac",
		TemplatePath:       defaultHTML,
		logger:             zaptest.NewLogger(t),
	}

	err := bb.ServeHTTP(rec, req, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		t.Fatal("next handler should not be called for an unsolved challenge")
		return nil
	}))
	if err != nil {
		t.Fatalf("ServeHTTP returned an error: %v", err)
	}

	if !strings.Contains(rec.Body.String(), "const complexity = 16;") {
		t.Fatalf("expected rendered challenge to default complexity to 16, body was: %s", rec.Body.String())
	}
}

func newRequestWithReplacer(method, target, complexity string) *http.Request {
	req := httptest.NewRequest(method, target, nil)
	repl := caddy.NewReplacer()
	repl.Set("vars.bot_barrier_complexity", complexity)
	ctx := context.WithValue(req.Context(), caddy.ReplacerCtxKey, repl)
	ctx = context.WithValue(ctx, caddyhttp.VarsCtxKey, map[string]any{})
	return req.WithContext(ctx)
}
