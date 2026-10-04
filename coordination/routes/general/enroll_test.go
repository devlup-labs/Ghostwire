package general

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestEnrollHandlerMethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/enroll", nil)
	rec := httptest.NewRecorder()

	EnrollHandler(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected status %d, got %d", http.StatusMethodNotAllowed, rec.Code)
	}
}

func TestEnrollHandlerOIDCNotInitialized(t *testing.T) {
	originalConfig := oauthConfig
	oauthConfig = nil
	defer func() {
		oauthConfig = originalConfig
	}()

	req := httptest.NewRequest(http.MethodPost, "/enroll", nil)
	rec := httptest.NewRecorder()

	EnrollHandler(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected status %d, got %d", http.StatusInternalServerError, rec.Code)
	}
}

func TestEnrollmentStatusMissingSessionID(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/enroll/status", nil)
	rec := httptest.NewRecorder()

	EnrollmentStatusHandler(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d", http.StatusBadRequest, rec.Code)
	}
}

func TestEnrollmentStatusMethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/enroll/status", nil)
	rec := httptest.NewRecorder()

	EnrollmentStatusHandler(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected status %d, got %d", http.StatusMethodNotAllowed, rec.Code)
	}
}

func TestEnrollmentStatusPending(t *testing.T) {
	sessionID := "test-session-pending"

	enrollmentMu.Lock()
	enrollments[sessionID] = &EnrollmentSession{
		State:     sessionID,
		Status:    "PENDING",
		Email:     "test@example.com",
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}
	enrollmentMu.Unlock()

	defer func() {
		enrollmentMu.Lock()
		delete(enrollments, sessionID)
		enrollmentMu.Unlock()
	}()

	req := httptest.NewRequest(
		http.MethodGet,
		"/enroll/status?sessionId="+sessionID,
		nil,
	)
	rec := httptest.NewRecorder()

	EnrollmentStatusHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rec.Code)
	}

	var response map[string]interface{}
	if err := json.NewDecoder(rec.Body).Decode(&response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if response["status"] != "PENDING" {
		t.Fatalf("expected status PENDING, got %v", response["status"])
	}

	if response["email"] != "test@example.com" {
		t.Fatalf("expected test email, got %v", response["email"])
	}
}

func TestEnrollmentStatusExpiredSession(t *testing.T) {
	sessionID := "test-session-expired"

	enrollmentMu.Lock()
	enrollments[sessionID] = &EnrollmentSession{
		State:     sessionID,
		Status:    "PENDING",
		ExpiresAt: time.Now().Add(-time.Minute),
	}
	enrollmentMu.Unlock()

	req := httptest.NewRequest(
		http.MethodGet,
		"/enroll/status?sessionId="+sessionID,
		nil,
	)
	rec := httptest.NewRecorder()

	EnrollmentStatusHandler(rec, req)

	if rec.Code != http.StatusGone {
		t.Fatalf("expected status %d, got %d", http.StatusGone, rec.Code)
	}

	enrollmentMu.Lock()
	_, exists := enrollments[sessionID]
	enrollmentMu.Unlock()

	if exists {
		t.Fatal("expected expired enrollment session to be deleted")
	}
}

func TestRandomString(t *testing.T) {
	value, err := randomString(32)
	if err != nil {
		t.Fatalf("randomString returned error: %v", err)
	}

	if len(value) == 0 {
		t.Fatal("expected randomString to return a non-empty string")
	}

	other, err := randomString(32)
	if err != nil {
		t.Fatalf("second randomString returned error: %v", err)
	}

	if value == other {
		t.Fatal("expected two generated values to differ")
	}
}

func TestCreateCodeChallenge(t *testing.T) {
	verifier := "test-code-verifier"

	challenge := createCodeChallenge(verifier)

	if challenge == "" {
		t.Fatal("expected a non-empty code challenge")
	}

	if strings.ContainsAny(challenge, "+/=") {
		t.Fatalf("expected URL-safe base64 without padding, got %q", challenge)
	}

	if challenge != createCodeChallenge(verifier) {
		t.Fatal("expected code challenge generation to be deterministic")
	}
}
