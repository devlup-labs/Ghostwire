package general

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/devlup-labs/Ghostwire/coordination-server/database"
)

// NOTE: ACL stands for Access Control List, i.e. allowlist

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

func getDevicesForEntity(entityId string, entityType string) ([]database.Device, error) {
	switch entityType {
	case "user":
		user, err := database.GetUser(entityId)
		if err != nil {
			return nil, err
		}
		devices, err := user.GetDevices()
		if err != nil {
			return nil, err
		}
		return devices, nil
	case "group":
		grp, err := database.GetGroup(entityId)
		if err != nil {
			return nil, err
		}
		devices, err := grp.ListDevices()
		return devices, nil
	}
	return []database.Device{}, nil
}

func GetACL(deviceId string) (allowlist ACL, err error) {
	allowlist = make(ACL)

	policies, err := database.ListPolicies()
	if err != nil {
		return nil, err
	}

	device, err := database.GetDevice(deviceId)
	if err != nil {
		return nil, err
	}
	groupList, err := device.GetGroups()
	if err != nil {
		return nil, err
	}
PolicyLoop:
	for _, policy := range policies {
		if !(policy.Active) {
			continue
		}

		// If deviceId is not found in policy's senders, skip it
	PolicySwitch:
		switch policy.SenderType {
		case "user":
			if device.UserId != policy.SenderId {
				continue PolicyLoop
			}
		case "group":
			for _, v := range groupList {
				if v.GroupId == policy.SenderId {
					// Applicable policy found, so continue
					break PolicySwitch
				}
			}
			// If no group matches, wrong policy
			continue PolicyLoop
		default:
			return nil, errors.New("Invalid policy.SenderType")
		}

		receiverDevices, err := getDevicesForEntity(policy.ReceiverId, policy.ReceiverType)
		if err != nil {
			return nil, err
		}

		for _, receiverDevice := range receiverDevices {
			allowlist[receiverDevice.DeviceId] = ACLEntry{
				UserID:        receiverDevice.UserId,
				Name:          "NAME",
				GwIp:          receiverDevice.GwIp,
				PublicKey:     receiverDevice.PublicKey,
				PublicAddress: receiverDevice.PublicIp,
			}
		}
	}

	return allowlist, nil
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
	allowlist, err := GetACL(requestVars.DeviceId)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{"message": "Not found" + err.Error()})
		} else {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"message": err.Error()})
		}
		return
	}

	for deviceId, hash := range requestVars.AllowlistHashes {
		entry, ok := allowlist[deviceId]
		if !ok {
			// This key is in server's allowlist,
			// but not the device's.
			// Keep it in `allowlist`
		} else {
			if hash == createACLEntryHash(entry) {
				// No changes required
				delete(allowlist, deviceId)
			}
		}
	}

	res := map[string]ACL{}
	if len(allowlist) != 0 {
		res["allowlist"] = allowlist
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
