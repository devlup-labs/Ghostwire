package general

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRegisterHandlerMethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/register", nil)
	rec := httptest.NewRecorder()

	RegisterHandler(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected status %d, got %d", http.StatusMethodNotAllowed, rec.Code)
	}
}

func TestRegisterHandlerInvalidJSON(t *testing.T) {
	req := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/register",
		strings.NewReader(`{"deviceId":`),
	)
	rec := httptest.NewRecorder()

	RegisterHandler(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d", http.StatusBadRequest, rec.Code)
	}
}

func TestRegisterHandlerMissingIDToken(t *testing.T) {
	body := `{"publicKey":"cHVia2V5","isHealthy":true}`

	req := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/register",
		strings.NewReader(body),
	)
	rec := httptest.NewRecorder()

	RegisterHandler(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d", http.StatusBadRequest, rec.Code)
	}
}

func TestRegisterHandlerMissingPublicKey(t *testing.T) {
	body := `{"idToken":"test-token","isHealthy":true}`

	req := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/register",
		strings.NewReader(body),
	)
	rec := httptest.NewRecorder()

	RegisterHandler(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d", http.StatusBadRequest, rec.Code)
	}
}

func TestRegisterHandlerUnhealthyDevice(t *testing.T) {
	body := `{"idToken":"test-token","publicKey":"cHVia2V5","isHealthy":false}`

	req := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/register",
		strings.NewReader(body),
	)
	rec := httptest.NewRecorder()

	RegisterHandler(rec, req)

	if rec.Code != http.StatusNotAcceptable {
		t.Fatalf("expected status %d, got %d", http.StatusNotAcceptable, rec.Code)
	}
}

func TestBuildAllowList(t *testing.T) {
	allowList := BuildAllowList("test@example.com")

	if len(allowList) != 2 {
		t.Fatalf("expected 2 allowed addresses, got %d", len(allowList))
	}

	if allowList[0] != "10.0.0.6" || allowList[1] != "10.0.0.7" {
		t.Fatalf("unexpected allow list: %#v", allowList)
	}
}
