package general

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"sync"
	"time"
)

type LoginRequest struct {
	DeviceID     string `json:"deviceId"`
	RefreshToken string `json:"refreshToken"`
	IsHealthy    *bool  `json:"isHealthy"` // pointer so a missing field is distinguishable from an explicit false, matching checkin.go
}

type LoginResponse struct {
	AccessToken  string   `json:"accessToken"`
	RefreshToken string   `json:"refreshToken"`
	AllowList    []string `json:"allowList"`
	BlockList    []string `json:"blockList"`
}

// authRecord is login's own mock device-auth store — kept separate from connect.go's mockDevices, since none of the existing stub files share state with each other either. A real devices table would likely hold these fields alongside the ones connect.go reads.
type authRecord struct {
	RefreshTokenHash string
	RefreshExpiresAt time.Time
	Revoked          bool
	AllowList        []string
	BlockList        []string
}

var (
	// mockAuthMu guards mockAuth. Login is the first handler in this package that writes to shared state (rotating the refresh token on every successful login) — Go maps aren't safe for concurrent read/write, and net/http serves each request on its own goroutine.
	mockAuthMu sync.Mutex

	mockAuth = map[string]authRecord{
		"device-001": {
			RefreshTokenHash: hashToken("dev-refresh-token-001"),
			RefreshExpiresAt: time.Now().Add(30 * 24 * time.Hour),
			Revoked:          false,
			AllowList:        []string{"research-server", "db-server"},
			BlockList:        []string{"finance-server"},
		},
	}
)

// reauthBaseURL is where a client should send the user to redo SSO once its refresh token has expired.
// TODO: Change this to be based on env vars, same as router.go's server Addr.
const reauthBaseURL = "https://ghostwire.example.com/enroll"

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	// Matching checkin.go: Content-Type set once, up front, applying to every response path below — success or error — rather than being set (or forgotten) separately in each branch.
	w.Header().Set("Content-Type", "application/json")

	// This response can carry an access token, a refresh token, or a reauth URL — never let a cache or intermediary proxy hold a copy.
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")

	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]string{"message": "Method Not Allowed"})
		return
	}

	defer r.Body.Close()

	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	var req LoginRequest
	if err := dec.Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"message": "Invalid JSON"})
		return
	}

	if req.DeviceID == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"message": "Missing field deviceId"})
		return
	}
	if req.RefreshToken == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"message": "Missing field refreshToken"})
		return
	}
	if req.IsHealthy == nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"message": "Missing field isHealthy"})
		return
	}

	mockAuthMu.Lock()
	defer mockAuthMu.Unlock()

	record, exists := mockAuth[req.DeviceID]
	if !exists || hashToken(req.RefreshToken) != record.RefreshTokenHash {
		// Same response for "no such device" and "wrong token" on purpose: a distinct message for "no such device" would let someone enumerate valid device IDs by watching which error comes back — the same issue connect.go currently has via its 404.
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"message": "Invalid refresh token"})
		return
	}

	if time.Now().After(record.RefreshExpiresAt) {
		// The one deliberate extension beyond checkin.go's plain {"message": ...} shape: this path needs to hand back a URL the client can act on, not just prose. Still the same map[string]string type, just a second key, added only where it's actually needed.
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{
			"message":   "Refresh token expired",
			"reauthUrl": reauthBaseURL + "?device=" + req.DeviceID,
		})
		return
	}

	if record.Revoked {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{"message": "Device has been revoked"})
		return
	}

	if !*req.IsHealthy {
		w.WriteHeader(http.StatusNotAcceptable)
		json.NewEncoder(w).Encode(map[string]string{"message": "Device reported unhealthy"})
		return
	}

	newAccessToken := generateToken()
	newRefreshToken := generateToken()

	record.RefreshTokenHash = hashToken(newRefreshToken)
	record.RefreshExpiresAt = time.Now().Add(30 * 24 * time.Hour)
	mockAuth[req.DeviceID] = record

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(LoginResponse{
		AccessToken:  newAccessToken,
		RefreshToken: newRefreshToken,
		AllowList:    record.AllowList,
		BlockList:    record.BlockList,
	})
}

// generateToken returns a cryptographically random, URL-safe token with 256 bits of entropy.
func generateToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// hashToken returns a hex-encoded SHA-256 digest, so mockAuth (and later, a real devices table) never holds a directly usable token in plaintext.
func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
