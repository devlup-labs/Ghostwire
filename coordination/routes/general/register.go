package general

import (
	"encoding/json"
	"errors"
	"net/http"
)

type RegisterRequest struct {
	DeviceID   string `json:"deviceId"`
	OAuthToken string `json:"oAuthToken"`
	IsHealthy  bool   `json:"isHealthy"`
}

type RegisterResponse struct {
	VirtualIP string   `json:"virtualIp"`
	AllowList []string `json:"allowList"`
}

func RegisterHandler(w http.ResponseWriter, r *http.Request) {

	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	defer r.Body.Close()


	var req RegisterRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}

	if req.DeviceID == "" || req.OAuthToken == "" {
		http.Error(w, "Missing required fields", http.StatusBadRequest)
		return
	}

	userEmail, err := VerifyOAuthToken(req.OAuthToken)
	if err != nil {
		http.Error(w, "Invalid OAuth Token", http.StatusUnauthorized)
		return
	}

	userExists := CheckExistingUser(userEmail)

	if !userExists {

		// Sending registration request for admin approval.

		http.Error(w, "User awaiting admin approval", http.StatusForbidden)
		return
	}

	deviceExists := CheckExistingDevice(req.DeviceID)

	if deviceExists {
		http.Error(w, "Device already registered", http.StatusConflict)
		return
	}

	virtualIP := AllocateVirtualIP()

	allowList := BuildAllowList(userEmail)

	resp := RegisterResponse{
		VirtualIP: virtualIP,
		AllowList: allowList,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)

	json.NewEncoder(w).Encode(resp)
}



func VerifyOAuthToken(token string) (string, error) {

	if token == "" {
		return "", errors.New("Empty token")
	}

	return "aarav@gmail.com", nil
}

func CheckExistingUser(email string) bool {

	if email == "aarav@gmail.com" {

		return true
	}

	return false
}

func CheckExistingDevice(deviceID string) bool {

	if deviceID == "device123" {

		return true
	}

	return false
}

func AllocateVirtualIP() string {

	return "10.0.0.5"
}

func BuildAllowList(email string) []string {

	return []string{
		"10.0.0.6",
		"10.0.0.7",
	}
}
