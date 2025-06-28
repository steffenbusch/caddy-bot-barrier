package botbarrier

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
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
