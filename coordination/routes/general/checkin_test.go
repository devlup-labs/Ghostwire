package general

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/devlup-labs/Ghostwire/coordination-server/database"
	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	err := database.InitializeDatabase("file::memory:?_foreign_keys=on")
	if err != nil {
		log.Fatal(err)
	}
	os.Exit(m.Run())
}

func SeedDatabase(t *testing.T) {
	aliceUserId, err := database.CreateUser("alice", "regular", "", "")
	require.NoError(t, err)
	aliceUser, err := database.GetUser(aliceUserId)
	require.NoError(t, err)
	bobUserId, err := database.CreateUser("bob", "regular", "", "")
	require.NoError(t, err)
	bobUser, err := database.GetUser(bobUserId)
	require.NoError(t, err)
	charlieUserId, err := database.CreateUser("charlie", "regular", "", "")
	require.NoError(t, err)
	charlieUser, err := database.GetUser(charlieUserId)
	require.NoError(t, err)

	_, err = aliceUser.CreateDevice([]byte("alice_pub_key1"), "10.0.0.1", "e", "", "Ubuntu")
	require.NoError(t, err)
	_, err = aliceUser.CreateDevice([]byte("alice_pub_key2"), "10.0.0.2", "e", "", "Arch Linux")
	require.NoError(t, err)

	_, err = bobUser.CreateDevice([]byte("bob_pub_key"), "10.0.1.1", "e", "", "Fedora")
	require.NoError(t, err)

	_, err = charlieUser.CreateDevice([]byte("charlie_pub_key"), "10.0.2.1", "e", "", "MacOS")
	require.NoError(t, err)

	devGrp, err := database.CreateGroup("devs", "All Developers")
	require.NoError(t, err)
	devGrp.AddUser(charlieUser)

	database.CreatePolicy("Alice to Bob", "", "user", aliceUserId, "user", bobUserId, true, "admin")
	database.CreatePolicy("Alice to All Developers", "", "user", aliceUserId, "group", devGrp.GroupId, true, "admin")
}

func TestGetACL_UserSenderPolicy(t *testing.T) {
	SeedDatabase(t)

	alices, err := database.GetUsersByUserName("alice")
	require.NoError(t, err)
	aliceDev, err := alices[0].GetDevices()
	allowlist, err := GetACL(aliceDev[0].DeviceId)
	require.NoError(t, err)

	bobs, err := database.GetUsersByUserName("bob")
	require.NoError(t, err)
	bobUserId := bobs[0].UserId
	bobDev, err := bobs[0].GetDevices()
	require.NoError(t, err)

	entry, ok := allowlist[bobDev[0].DeviceId]
	require.True(t, ok, "Expected receiver device in allowlist")
	require.Equal(t, bobUserId, entry.UserID)
}

func TestGetACL_GroupSenderPolicy(t *testing.T) {
	SeedDatabase(t)

	alices, err := database.GetUsersByUserName("alice")
	require.NoError(t, err)
	aliceDev, err := alices[0].GetDevices()
	require.NoError(t, err)

	allowlist, err := GetACL(aliceDev[0].DeviceId)
	require.NoError(t, err)

	charlies, err := database.GetUsersByUserName("charlie")
	require.NoError(t, err)
	charlieUserId := charlies[0].UserId
	charlieDev, err := charlies[0].GetDevices()
	require.NoError(t, err)

	entry, ok := allowlist[charlieDev[0].DeviceId]
	t.Logf("%#v", allowlist)
	require.True(t, ok, "Expected receiver device in allowlist derived from group policy")
	require.Equal(t, charlieUserId, entry.UserID)
}

func TestCheckinHandler_ValidationErrors(t *testing.T) {
	tests := []struct {
		name           string
		payload        map[string]any
		expectedStatus int
	}{
		{
			name: "Missing DeviceId",
			payload: map[string]any{
				"gwIp":      "10.0.0.1",
				"isHealthy": true,
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "Missing GwIp",
			payload: map[string]any{
				"deviceId":  "dev123",
				"isHealthy": true,
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "Missing IsHealthy",
			payload: map[string]any{
				"deviceId": "dev123",
				"gwIp":     "10.0.0.1",
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "Unhealthy Device",
			payload: map[string]any{
				"deviceId":  "dev123",
				"gwIp":      "10.0.0.1",
				"isHealthy": false,
			},
			expectedStatus: http.StatusNotAcceptable,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, err := json.Marshal(tt.payload)
			require.NoError(t, err)

			req := httptest.NewRequest(http.MethodPost, "/checkin", bytes.NewBuffer(body))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()

			CheckinHandler(rec, req)
			require.Equal(t, tt.expectedStatus, rec.Code)
		})
	}
}

func TestCheckinHandler_WithSeededACL(t *testing.T) {
	SeedDatabase(t)

	alices, err := database.GetUsersByUserName("alice")
	require.NoError(t, err)
	aliceDev, err := alices[0].GetDevices()
	require.NoError(t, err)

	payload := map[string]any{
		"deviceId":  aliceDev[0].DeviceId,
		"gwIp":      aliceDev[0].GwIp,
		"isHealthy": true,
		"allowlistHashes": ACLHashes{
			"0": "outdated_hash_triggering_resync",
		},
	}

	body, err := json.Marshal(payload)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/checkin", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	CheckinHandler(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)

	var res map[string]ACL
	err = json.Unmarshal(rec.Body.Bytes(), &res)
	require.NoError(t, err)
	require.Contains(t, res, "allowlist", "Expected updated allowlist in sync response")
}
