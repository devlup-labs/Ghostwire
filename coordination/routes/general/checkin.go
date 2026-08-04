package general

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
)

// NOTE: ACL stands for Access Control List, i.e. both allowlist and blocklist

type ACLEntry struct {
	UserID        string
	Name          string
	GwIp          string
	PublicKey     []byte
	PublicAddress string
}

// "DeviceID": ACLEntry object
type ACL map[string]ACLEntry

// "DeviceID": "sha256hash of the associated ACLEntry object"
type ACLHashes map[string]string

func dummyGetACL(deviceId string) (allowlist ACL, blocklist ACL) {
	// Fetches ACL from the database, computed according to network policies
	allowlist = ACL{
		"0": {
			UserID:        "laptop",
			Name:          "ABCD",
			GwIp:          "127.0.0.2",
			PublicKey:     []byte("1234"),
			PublicAddress: "56.67.78.89:42342",
		},
		"1": {
			UserID:        "server",
			Name:          "DEFG",
			GwIp:          "127.0.0.3",
			PublicKey:     []byte("7890"),
			PublicAddress: "66.77.88.99:88488",
		},
	}
	blocklist = ACL{}
	return
}

func CheckinHandler(w http.ResponseWriter, r *http.Request) {
	// TODO: Record valid and invalid checkins, and for audit log

	w.Header().Set("Content-Type", "application/json")

	var requestVars struct {
		DeviceId        string    `json:"deviceId"`
		GwIp            string    `json:"gwIp"`
		GwPort          int       `json:"gwPort"`
		IsHealthy       *bool     `json:"isHealthy"` // Pointer to detect whether field is unset or false
		AllowlistHashes ACLHashes `json:"allowlistHashes"`
		BlocklistHashes ACLHashes `json:"blocklistHashes"`
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	err := dec.Decode(&requestVars)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"message": "Invalid JSON"})
		return
	}

	if requestVars.DeviceId == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"message": "Missing field deviceId"})
		return
	}
	if requestVars.GwIp == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"message": "Missing field gwIp"})
		return
	}
	if requestVars.IsHealthy == nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"message": "Missing field isHealthy"})
		return
	}

	if !(*requestVars.IsHealthy) {
		w.WriteHeader(http.StatusNotAcceptable)
		w.Write([]byte("Disconnect"))
		return
	}

	// Handle updates in ACL
	allowlist, blocklist := dummyGetACL(requestVars.DeviceId)

	for userId, hash := range requestVars.AllowlistHashes {
		entry, ok := allowlist[userId]
		if !ok {
			// This key is in server's allowlist,
			// but not the users.
			// Keep it in `allowlist`
		} else {
			if hash == createACLEntryHash(entry) {
				// No changes required
				delete(allowlist, userId)
			}
		}
	}

	for userId, hash := range requestVars.BlocklistHashes {
		entry, ok := blocklist[userId]
		if !ok {
			// This key is in server's blocklist,
			// but not the users.
			// Keep it in `blocklist`
		} else {
			if hash == createACLEntryHash(entry) {
				// Don't send; user has exact entry
				delete(blocklist, userId)
			}
		}
	}

	res := map[string]ACL{}
	if len(allowlist) != 0 {
		res["allowlist"] = allowlist
	}
	if len(blocklist) != 0 {
		res["blocklist"] = blocklist
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(res)
}

func createACLEntryHash(entry ACLEntry) string {
	b, _ := json.Marshal(entry)
	// TODO: Error handling
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
