// Package general implements the login/reconnect endpoint and other
// non-admin, non-audit HTTP handlers for the coordination server.
package general

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"time"
)

// loginRequest is the body the agent sends to prove it still holds a valid
// refresh token and to report its current health.
type loginRequest struct {
	DeviceID     string `json:"deviceId"`
	RefreshToken string `json:"refreshToken"`
	IsHealthy    *bool  `json:"isHealthy"` // pointer so a missing field is distinguishable from an explicit false
}

// loginResponse is returned when the refresh token checks out.
type loginResponse struct {
	AccessToken          string   `json:"accessToken"`
	AccessTokenExpiresAt string   `json:"accessTokenExpiresAt"`
	RefreshToken         string   `json:"refreshToken"`
	Allowlist            []string `json:"allowlist"`
	Blocklist            []string `json:"blocklist"`
}

// errorResponse is returned for every failure case. ReauthURL is only
// populated when the client should open a browser to redo SSO.
type errorResponse struct {
	Error     string `json:"error"`
	ReauthURL string `json:"reauthUrl,omitempty"`
}

// DeviceRecord is what the store layer hands back for a given device ID.
type DeviceRecord struct {
	DeviceID         string
	RefreshTokenHash string
	RefreshExpiresAt time.Time
	Revoked          bool
	Allowlist        []string
	Blocklist        []string
}

// Store is the seam between this handler and the database. Implement it
// against the real sqlc-generated queries; a fake implementing this same
// interface is what unit tests for this handler should use.
//
// RotateRefreshToken performs a compare-and-swap: it only writes the new
// hash if the row's current hash still matches oldHash. The returned bool
// is false when that comparison fails — i.e. something else already
// rotated this token since it was read, most likely a duplicate/retried
// request. A single failed swap is not, on its own, evidence of theft;
// callers should fail that request safely and let the client retry login
// rather than escalating straight to revocation.
type Store interface {
	GetDeviceByID(ctx context.Context, deviceID string) (*DeviceRecord, error)
	RotateRefreshToken(ctx context.Context, deviceID, oldHash, newHash string, newExpiry time.Time) (ok bool, err error)
}

// Sessions creates enrollment sessions — the same mechanism used for
// first-time enrollment — so an expired refresh token can be recovered
// without inventing a second reauth flow.
type Sessions interface {
	CreateForDevice(ctx context.Context, deviceID string) (sessionID string, err error)
}

// LoginHandler handles POST /api/v1/login.
//
// ReauthBaseURL is set once at server startup, from this deployment's own
// config (e.g. GHOSTWIRE_REAUTH_URL) — every self-hosted instance points
// at its own company's enrollment page, so this must never be hardcoded.
type LoginHandler struct {
	Store           Store
	Sessions        Sessions
	AccessTokenTTL  time.Duration // e.g. 15 * time.Minute
	RefreshTokenTTL time.Duration // e.g. 30 * 24 * time.Hour
	ReauthBaseURL   string
}

func (h *LoginHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer r.Body.Close()

	// This response can carry an access token, a refresh token, or a
	// reauth URL — never let a cache or intermediary proxy hold a copy.
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")

	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	var req loginRequest
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "malformed_request", "")
		return
	}
	if req.DeviceID == "" || req.RefreshToken == "" {
		writeError(w, http.StatusBadRequest, "malformed_request", "")
		return
	}
	if req.IsHealthy == nil {
		writeError(w, http.StatusBadRequest, "malformed_request", "")
		return
	}

	device, err := h.Store.GetDeviceByID(ctx, req.DeviceID)
	if err != nil || device == nil {
		writeError(w, http.StatusUnauthorized, "token_invalid", "")
		return
	}

	providedHash := hashToken(req.RefreshToken)
	if subtle.ConstantTimeCompare([]byte(providedHash), []byte(device.RefreshTokenHash)) != 1 {
		writeError(w, http.StatusUnauthorized, "token_invalid", "")
		return
	}

	if time.Now().After(device.RefreshExpiresAt) {
		sessionID, err := h.Sessions.CreateForDevice(ctx, req.DeviceID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal_error", "")
			return
		}
		writeError(w, http.StatusUnauthorized, "token_expired", h.ReauthBaseURL+"?s="+sessionID)
		return
	}

	if device.Revoked {
		writeError(w, http.StatusForbidden, "device_revoked", "")
		return
	}

	if !*req.IsHealthy {
		writeError(w, http.StatusNotAcceptable, "unhealthy", "")
		return
	}

	newAccessToken := generateToken()
	newRefreshToken := generateToken()
	newRefreshExpiry := time.Now().Add(h.RefreshTokenTTL)

	ok, err := h.Store.RotateRefreshToken(ctx, req.DeviceID, device.RefreshTokenHash, hashToken(newRefreshToken), newRefreshExpiry)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "")
		return
	}
	if !ok {
		// Someone else rotated this token between our read and our write —
		// almost always a duplicate/retried request, not an attack. Fail
		// this one request cleanly; the client just logs in again.
		writeError(w, http.StatusConflict, "token_conflict", "")
		return
	}

	writeJSON(w, http.StatusOK, loginResponse{
		AccessToken:          newAccessToken,
		AccessTokenExpiresAt: time.Now().Add(h.AccessTokenTTL).Format(time.RFC3339),
		RefreshToken:         newRefreshToken,
		Allowlist:            nonNilStrings(device.Allowlist),
		Blocklist:            nonNilStrings(device.Blocklist),
	})
}

// nonNilStrings guarantees a non-nil slice, so JSON encoding produces []
// instead of null when a device has no allow/blocklist entries yet.
func nonNilStrings(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// generateToken returns a cryptographically random, URL-safe token with
// 256 bits of entropy — enough that guessing it is not a realistic attack.
func generateToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand failing means the OS's entropy source is broken —
		// there is no safe way to continue, so this should be caught by
		// a top-level recover-and-500 middleware, not handled locally.
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// hashToken returns a hex-encoded SHA-256 digest of a token, for storage.
// SHA-256 (fast) is correct here — unlike passwords, these tokens already
// have 256 bits of entropy, so there's nothing for a slow, adaptive hash
// like bcrypt to protect against.
func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// writeJSON writes a JSON response with the given status code.
func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(body)
}

// writeError writes a structured JSON error. reauthURL is left empty for
// every case except token_expired.
func writeError(w http.ResponseWriter, status int, code, reauthURL string) {
	writeJSON(w, status, errorResponse{Error: code, ReauthURL: reauthURL})
}
