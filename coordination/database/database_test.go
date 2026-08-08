// database/database_test.go
package database

import (
	"log"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestMain sets up the database for the entire package
func TestMain(m *testing.M) {
	err := InitializeDatabase("file::memory:?_foreign_keys=on")
	log.Println(err)
	os.Exit(m.Run())
}
func TestDatabaseWorkflow(t *testing.T) {
	var user User
	t.Run("Create User", func(t *testing.T) {
		userId, err := CreateUser("alice", "regular", "Whoogle", "abcd")
		require.NoError(t, err)
		user, err = GetUser(userId)
		require.NoError(t, err)
		require.NotEmpty(t, user.UserId)
	})

	var user2 User
	t.Run("Create User2", func(t *testing.T) {
		userId, err := CreateUser("bob", "admin", "Microslop", "xyzw")
		require.NoError(t, err)
		user2, err = GetUser(userId)
		require.NoError(t, err)
		require.NotEmpty(t, user2.UserId)
	})

	t.Run("Create Group", func(t *testing.T) {
		//t.Log(DbQueries)
		grp, err := CreateGroup("devs", "Consists of all devlopers")
		require.NoError(t, err)
		require.NotEmpty(t, grp.GroupId)

		err = grp.AddUser(user.UserId)
		require.NoError(t, err)

		grps, err := user.Groups()
		require.NoError(t, err)
		require.Len(t, grps, 1)
		require.Equal(t, grps[0].GroupId, grp.GroupId)
	})

	t.Run("Register Device", func(t *testing.T) {
		device, err := user.CreateDevice(
			[]byte("pubkey"),
			"127.0.0.1",
			"a2bbdb2de53523b8099b37013f251546f3d65dbe7a0774fa41af0a4176992fd4",
			"092fcfbbcfca3b5be7ae1b5e58538e92c35ab273ae13664fed0d67484c8e78a6",
			"Ubuntu (Linux) 22.04",
		)
		require.NotEmpty(t, device.DeviceId)
		require.NoError(t, err)
		devices, err := user.GetDevices()
		require.Equal(t, device.DeviceId, devices[0].DeviceId)
	})

	var device2Id string
	t.Run("Register Device2", func(t *testing.T) {
		device2, err := user2.CreateDevice(
			[]byte("bobpubkey"),
			"127.0.66.77",
			"565905928333c1a968f96b8ed5bd313ce78531a9fc84f441aacbd6c9ce4f10d6",
			"7120c0dae0f533c35606dc99a4d3c8afcb809061ce2df562d84271c1bf092c02",
			"Fedora (Linux) 44",
		)
		require.NotEmpty(t, device2.DeviceId)
		require.NoError(t, err)
		devices, err := user2.GetDevices()
		require.Equal(t, device2, devices[0])
		device2Id = device2.DeviceId
	})

	t.Run("Group Union", func(t *testing.T) {
		device2, err := GetDevice(device2Id)
		require.NoError(t, err)
		require.Equal(t, "Fedora (Linux) 44", device2.UserAgent)

		users, err := GetUsersByUserName("alice")
		require.NoError(t, err)
		require.Len(t, users, 1)

		linuxGroup, err := CreateGroup("Linux Group", "")
		require.NoError(t, err)

		require.NoError(t, linuxGroup.AddUser(users[0].UserId))
		require.NoError(t, linuxGroup.AddDevice(device2.DeviceId))

		devs, err := linuxGroup.ListDevices()
		require.NoError(t, err)
		require.Len(t, devs, 2)
	})
}
