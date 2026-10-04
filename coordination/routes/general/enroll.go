package general

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/devlup-labs/Ghostwire/coordination-server/database"
	"golang.org/x/oauth2"
)

type EnrollmentSession struct {
	State        string
	CodeVerifier string

	// Filled when Google authentication succeeds.
	OAuthID string
	Email   string
	IDToken string

	Status    string
	ExpiresAt time.Time
}

var (
	enrollmentMu sync.Mutex

	enrollments = make(map[string]*EnrollmentSession)

	oauthConfig *oauth2.Config
)

// InitializeOAuth creates the Google OAuth configuration used by
// the enrollment flow.
//
// InitializeOIDC in register.go calls this after creating the
// Google OIDC provider.
func InitializeOAuth(provider *oidc.Provider, clientID string) {
	redirectURL := os.Getenv("GOOGLE_REDIRECT_URI")

	if redirectURL == "" {
		redirectURL = "http://127.0.0.1:8000/enroll/callback"
	}

	oauthConfig = &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
		Endpoint:     provider.Endpoint(),
		RedirectURL:  redirectURL,
		Scopes: []string{
			"openid",
			"email",
			"profile",
		},
	}
}

// EnrollHandler starts a new enrollment session.
//
// The client calls:
//
//	POST /enroll
//
// The server creates a random state + PKCE verifier and returns
// the Google authorization URL.
func EnrollHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if oauthConfig == nil {
		http.Error(
			w,
			"OIDC is not initialized",
			http.StatusInternalServerError,
		)
		return
	}

	state, err := randomString(32)
	if err != nil {
		http.Error(
			w,
			"failed to create enrollment state",
			http.StatusInternalServerError,
		)
		return
	}

	codeVerifier, err := randomString(32)
	if err != nil {
		http.Error(
			w,
			"failed to create PKCE verifier",
			http.StatusInternalServerError,
		)
		return
	}

	session := &EnrollmentSession{
		State:        state,
		CodeVerifier: codeVerifier,
		Status:       "PENDING",
		ExpiresAt:    time.Now().Add(10 * time.Minute),
	}

	enrollmentMu.Lock()
	enrollments[state] = session
	enrollmentMu.Unlock()

	codeChallenge := createCodeChallenge(codeVerifier)

	authURL := oauthConfig.AuthCodeURL(
		state,
		oauth2.SetAuthURLParam(
			"code_challenge",
			codeChallenge,
		),
		oauth2.SetAuthURLParam(
			"code_challenge_method",
			"S256",
		),
	)

	response := map[string]string{
		"sessionId": state,
		"authUrl":   authURL,
		"expiresAt": session.ExpiresAt.UTC().Format(time.RFC3339),
	}

	w.WriteHeader(http.StatusCreated)

	if err := json.NewEncoder(w).Encode(response); err != nil {
		return
	}
}

// EnrollCallback receives Google's authorization response.
//
// Google redirects:
//
//	/enroll/callback?code=...&state=...
//
// We verify state, exchange the authorization code using PKCE,
// verify the returned ID token, and associate the authenticated
// Google identity with the enrollment session.
func EnrollCallback(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if oauthConfig == nil {
		http.Error(
			w,
			"OIDC is not initialized",
			http.StatusInternalServerError,
		)
		return
	}

	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")

	if state == "" || code == "" {
		http.Error(
			w,
			"missing authorization response",
			http.StatusBadRequest,
		)
		return
	}

	enrollmentMu.Lock()
	session, exists := enrollments[state]
	enrollmentMu.Unlock()

	if !exists {
		http.Error(
			w,
			"invalid enrollment session",
			http.StatusBadRequest,
		)
		return
	}

	if time.Now().After(session.ExpiresAt) {
		enrollmentMu.Lock()
		delete(enrollments, state)
		enrollmentMu.Unlock()

		http.Error(
			w,
			"enrollment session expired",
			http.StatusBadRequest,
		)
		return
	}

	// Exchange the authorization code.
	token, err := oauthConfig.Exchange(
		context.Background(),
		code,
		oauth2.SetAuthURLParam(
			"code_verifier",
			session.CodeVerifier,
		),
	)

	if err != nil {
		http.Error(
			w,
			"failed to exchange authorization code",
			http.StatusUnauthorized,
		)
		return
	}

	// Google should return an ID token because "openid" is included
	// in the requested scopes.
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		http.Error(
			w,
			"Google did not return an ID token",
			http.StatusUnauthorized,
		)
		return
	}

	// Verify the ID token using the same OIDC verifier that
	// /register uses.
	if oidcVerifier == nil {
		http.Error(
			w,
			"OIDC verifier is not initialized",
			http.StatusInternalServerError,
		)
		return
	}

	idToken, err := oidcVerifier.Verify(
		context.Background(),
		rawIDToken,
	)

	if err != nil {
		http.Error(
			w,
			"invalid ID token",
			http.StatusUnauthorized,
		)
		return
	}

	var claims struct {
		Subject       string `json:"sub"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
	}

	if err := idToken.Claims(&claims); err != nil {
		http.Error(
			w,
			"invalid ID token claims",
			http.StatusUnauthorized,
		)
		return
	}

	if claims.Subject == "" {
		http.Error(
			w,
			"missing subject in ID token",
			http.StatusUnauthorized,
		)
		return
	}

	if !claims.EmailVerified {
		http.Error(
			w,
			"email is not verified",
			http.StatusUnauthorized,
		)
		return
	}

	// Authentication succeeded.
	//
	// Now we check Ghostwire authorization.
	//
	// If the Google identity already exists in the users table,
	// the user has been approved.
	//
	// If it doesn't exist yet, the session remains PENDING and
	// an administrator can approve the user through the admin flow.
	_, userErr := database.GetUserByOAuth(
		"google",
		claims.Subject,
	)

	status := "PENDING"

	if userErr == nil {
		status = "APPROVED"
	} else if !errors.Is(userErr, sql.ErrNoRows) {
		// We cannot safely distinguish database failure from
		// a missing user without exposing sql.ErrNoRows here.
		//
		// The helper allows database-specific errors to remain
		// inside the database package.
		http.Error(
			w,
			"failed to check user approval",
			http.StatusInternalServerError,
		)
		return
	}

	enrollmentMu.Lock()

	session.OAuthID = claims.Subject
	session.Email = claims.Email
	session.IDToken = rawIDToken
	session.Status = status

	enrollmentMu.Unlock()

	// Do not return the ID token from the OAuth callback.
	//
	// The client learns the result by polling /enroll/status.
	w.WriteHeader(http.StatusOK)

	json.NewEncoder(w).Encode(map[string]string{
		"message": "enrollment authentication completed",
		"status":  status,
	})
}

// EnrollmentStatusHandler allows the client to poll an enrollment
// session until the administrator approves the authenticated user.
//
//	GET /enroll/status?sessionId=<id>
func EnrollmentStatusHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")

	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	sessionID := r.URL.Query().Get("sessionId")

	if sessionID == "" {
		http.Error(
			w,
			"missing sessionId",
			http.StatusBadRequest,
		)
		return
	}

	enrollmentMu.Lock()
	session, exists := enrollments[sessionID]

	if !exists {
		enrollmentMu.Unlock()

		http.Error(
			w,
			"enrollment session not found",
			http.StatusNotFound,
		)
		return
	}

	if time.Now().After(session.ExpiresAt) {
		delete(enrollments, sessionID)
		enrollmentMu.Unlock()

		http.Error(
			w,
			"enrollment session expired",
			http.StatusGone,
		)
		return
	}

	status := session.Status
	email := session.Email
	idToken := session.IDToken
	enrollmentMu.Unlock()

	// The OAuth callback may have authenticated the user while
	// they were still pending approval.
	//
	// Therefore, every poll re-checks the database.
	if status == "PENDING" && session.OAuthID != "" {
		user, err := database.GetUserByOAuth(
			"google",
			session.OAuthID,
		)

		if err == nil {
			status = "APPROVED"

			enrollmentMu.Lock()
			session.Status = "APPROVED"
			idToken = session.IDToken
			enrollmentMu.Unlock()

			_ = user
		} else if !errors.Is(err, sql.ErrNoRows) {
			http.Error(
				w,
				"failed to check approval status",
				http.StatusInternalServerError,
			)
			return
		}
	}

	response := map[string]interface{}{
		"status": status,
	}

	if email != "" {
		response["email"] = email
	}

	// Only release the ID token after Ghostwire authorization
	// has reached APPROVED.
	if status == "APPROVED" && idToken != "" {
		response["idToken"] = idToken
	}

	w.WriteHeader(http.StatusOK)

	if err := json.NewEncoder(w).Encode(response); err != nil {
		return
	}
}

// randomString creates cryptographically random URL-safe data.
func randomString(n int) (string, error) {
	b := make([]byte, n)

	if _, err := rand.Read(b); err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(b), nil
}

// createCodeChallenge creates the PKCE S256 challenge:
//
//	base64url(SHA256(code_verifier))
func createCodeChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))

	return base64.RawURLEncoding.EncodeToString(sum[:])
}
