package general

import (
	"encoding/json"
	"net/http"
)

type connectReq struct {
	DeviceID  string `json:"deviceId"`
	IsHealthy bool   `json:"isHealthy"`
}

type connectResponse struct {
	GWIP      string   `json:"gwIp"`
	GWPort    int      `json:"gwPort"`
	AllowList []string `json:"allowList"`
	BlockList []string `json:"blockList"`
}

type deviceData struct { // This is a temporary database. SQLite to be implemented later on.
	DeviceID  string
	GWIP      string
	GWPort    int
	AllowList []string
	BlockList []string
}

var mockDevices = map[string]deviceData{
	"device-001": {
		DeviceID:  "device-001",
		GWIP:      "100.64.0.10",
		GWPort:    51820,
		AllowList: []string{"research-server", "db-server"},
		BlockList: []string{"finance-server"},
	},
	"device-002": {
		DeviceID:  "device-002",
		GWIP:      "100.64.0.11",
		GWPort:    51820,
		AllowList: []string{"content-server"},
		BlockList: []string{},
	},
}

func ConnectHandler(w http.ResponseWriter, r *http.Request) {

	// Disable caching
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")

	// Only allow POST
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var req connectReq

	// Decode JSON request
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Validate request
	if req.DeviceID == "" {
		http.Error(w, "deviceId is required", http.StatusBadRequest)
		return
	}

	// Optional health check
	if !req.IsHealthy {
		http.Error(w, "Device reported unhealthy", http.StatusNotAcceptable)
		return
	}

	// Look up device in mock database
	device, exists := mockDevices[req.DeviceID]
	if !exists {
		http.Error(w, "Device not found", http.StatusNotFound)
		return
	}

	response := connectResponse{
		GWIP:      device.GWIP,
		GWPort:    device.GWPort,
		AllowList: device.AllowList,
		BlockList: device.BlockList,
	}

	w.Header().Set("Content-Type", "application/json")

	err = json.NewEncoder(w).Encode(response)
	if err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}
