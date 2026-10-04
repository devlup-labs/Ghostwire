package general

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/devlup-labs/Ghostwire/coordination-server/database"
)

type RegisterRequest struct {
	DeviceID  string `json:"deviceId"`
	IDToken   string `json:"idToken"`
	PublicKey []byte `json:"publicKey"`
	IsHealthy bool   `json:"isHealthy"`
}

type RegisterResponse struct {
	DeviceID  string   `json:"deviceId"`
	VirtualIP string   `json:"virtualIp"`
	AllowList []string `json:"allowList"`
}

var oidcVerifier *oidc.IDTokenVerifier

// InitializeOIDC initializes the Google OIDC provider and creates the
// verifier used by the registration endpoint.
// The OAuth authorization flow itself is handled by enroll.go.
// This function only initializes the OIDC provider/verifier and passes
// the provider to the enrollment code so it can configure OAuth.
func InitializeOIDC(clientID string) error {
	ctx := context.Background()

	provider, err := oidc.NewProvider(
		ctx,
		"https://accounts.google.com",
	)
	if err != nil {
		return err
	}

	oidcVerifier = provider.Verifier(&oidc.Config{
		ClientID: clientID,
	})

	InitializeOAuth(provider, clientID)

	return nil
}

func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	defer r.Body.Close()

	var req RegisterRequest

	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if req.IDToken == "" {
		http.Error(w, "idToken is required", http.StatusBadRequest)
		return
	}

	if len(req.PublicKey) == 0 {
		http.Error(w, "publicKey is required", http.StatusBadRequest)
		return
	}

	if !req.IsHealthy {
		http.Error(w, "device is unhealthy", http.StatusNotAcceptable)
		return
	}

	// Verify the ID token that was obtained through the enrollment flow.
	idToken, err := oidcVerifier.Verify(
		r.Context(),
		req.IDToken,
	)
	if err != nil {
		http.Error(w, "invalid ID token", http.StatusUnauthorized)
		return
	}

	// Extract identity claims from the verified token.
	var claims struct {
		Subject       string `json:"sub"`
		Email         string `json:"email"`
		Name          string `json:"name"`
		EmailVerified bool   `json:"email_verified"`
	}

	if err := idToken.Claims(&claims); err != nil {
		http.Error(w, "invalid ID token claims", http.StatusUnauthorized)
		return
	}

	if claims.Subject == "" {
		http.Error(w, "missing subject in ID token", http.StatusUnauthorized)
		return
	}

	if !claims.EmailVerified {
		http.Error(w, "email is not verified", http.StatusUnauthorized)
		return
	}

	// Check whether the authenticated Google user exists in Ghostwire.
	// Authentication by Google and authorization by Ghostwire are
	// separate things. A valid Google identity does not automatically
	// mean that the user is allowed to use Ghostwire.
	user, err := database.GetUserByOAuth("google", claims.Subject)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			http.Error(
				w,
				"user is awaiting admin approval",
				http.StatusForbidden,
			)
			return
		}

		http.Error(
			w,
			"failed to lookup user",
			http.StatusInternalServerError,
		)
		return
	}

	// A user may exist in the database but still be revoked by an admin.
	if user.IsRevoked {
		http.Error(
			w,
			"user has been revoked",
			http.StatusForbidden,
		)
		return
	}

	// If the client supplied a DeviceID, this is an existing device
	// registration/re-registration.
	var device database.Device

	if req.DeviceID != "" {
		device, err = database.GetDevice(req.DeviceID)

		if err == nil {
			// Make sure the device actually belongs to the authenticated user.
			if device.UserId != user.UserId {
				http.Error(
					w,
					"device does not belong to user",
					http.StatusForbidden,
				)
				return
			}

			// Update information supplied by the device.
			if err := device.UpdatePublicKey(req.PublicKey); err != nil {
				http.Error(
					w,
					"failed to update device public key",
					http.StatusInternalServerError,
				)
				return
			}

			if err := device.UpdateLastAccessTime(time.Now()); err != nil {
				http.Error(
					w,
					"failed to update device access time",
					http.StatusInternalServerError,
				)
				return
			}

			if err := device.UpdateUserAgent(r.UserAgent()); err != nil {
				http.Error(
					w,
					"failed to update device user agent",
					http.StatusInternalServerError,
				)
				return
			}

			allowList := BuildAllowList(claims.Email)

			response := RegisterResponse{
				DeviceID:  device.DeviceId,
				VirtualIP: device.GwIp,
				AllowList: allowList,
			}

			w.WriteHeader(http.StatusOK)

			if err := json.NewEncoder(w).Encode(response); err != nil {
				return
			}

			return
		}

		if !errors.Is(err, sql.ErrNoRows) {
			http.Error(
				w,
				"failed to lookup device",
				http.StatusInternalServerError,
			)
			return
		}

		// sql.ErrNoRows means the supplied DeviceID does not exist,
		// so registration continues as a new device.
	}

	// Allocate a Ghostwire virtual IP for the new device.
	virtualIP := AllocateVirtualIP()

	// Generate device authentication tokens.
	//
	// Only their hashes are stored in the database. The raw tokens
	// are returned to the client and can subsequently be used by
	// the login flow.
	accessToken := generateToken()
	refreshToken := generateToken()

	accessTokenHash := hashToken(accessToken)
	refreshTokenHash := hashToken(refreshToken)

	// Create the device and associate it with the authenticated user.
	device, err = user.CreateDevice(
		req.PublicKey,
		virtualIP,
		refreshTokenHash,
		accessTokenHash,
		r.UserAgent(),
	)

	if err != nil {
		http.Error(
			w,
			"failed to create device",
			http.StatusInternalServerError,
		)
		return
	}

	// Build the initial access-control list for the device.
	allowList := BuildAllowList(claims.Email)

	response := RegisterResponse{
		DeviceID:  device.DeviceId,
		VirtualIP: device.GwIp,
		AllowList: allowList,
	}

	w.WriteHeader(http.StatusCreated)

	if err := json.NewEncoder(w).Encode(response); err != nil {
		return
	}
}

// AllocateVirtualIP currently returns a placeholder IP.
//
// This will eventually be replaced by the coordination server's
// actual virtual-IP allocation mechanism.
func AllocateVirtualIP() string {
	return "10.0.0.5"
}

// BuildAllowList currently returns a placeholder ACL.
//
// The actual implementation will eventually derive this from
// Ghostwire groups/policies.
func BuildAllowList(email string) []string {
	return []string{
		"10.0.0.6",
		"10.0.0.7",
	}
}
