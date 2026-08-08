package database

import (
	"database/sql"

	"github.com/devlup-labs/Ghostwire/coordination-server/database/sqlc_db"
	"github.com/google/uuid"
)

type Group struct {
	GroupId   string
	GroupName string
	GroupDesc string
}

func (g Group) ListDevices() (res []Device, err error) {
	// Union logic query
	devices, err := DbQueries.ListDevicesInGroup(ctx, g.GroupId)
	if err != nil {
		return res, err
	}
	for _, device := range devices {
		res = append(res, Device{
			DeviceId:  device.Deviceid,
			PublicKey: device.Publickey,
			GwIp:      device.Gwip,
			PublicIp:  device.Publicip.String,
		})
	}
	return res, err
}

func (g Group) UpdateGroup(groupName string, groupDesc string) (err error) {
	_, err = DbQueries.UpdateGroup(ctx, sqlc_db.UpdateGroupParams{
		Groupname: groupName,
		Groupdesc: sql.NullString{String: groupDesc, Valid: groupDesc != ""},
		Groupid:   g.GroupId,
	})
	return err
}

func (g Group) AddUser(userId string) (err error) {
	err = DbQueries.AddUserToGroup(ctx, sqlc_db.AddUserToGroupParams{
		Groupid: g.GroupId,
		Userid:  userId,
	})
	return err
}

func (g Group) RemoveUser(userId string) (err error) {
	err = DbQueries.RemoveUserFromGroup(ctx, sqlc_db.RemoveUserFromGroupParams{
		Groupid: g.GroupId,
		Userid:  userId,
	})
	return err
}

func (g Group) AddDevice(deviceId string) (err error) {
	err = DbQueries.AddDeviceToGroup(ctx, sqlc_db.AddDeviceToGroupParams{
		Groupid:  g.GroupId,
		Deviceid: deviceId,
	})
	return err
}

func (g Group) RemoveDevice(deviceId string) (err error) {
	err = DbQueries.RemoveDeviceFromGroup(ctx, sqlc_db.RemoveDeviceFromGroupParams{
		Groupid:  g.GroupId,
		Deviceid: deviceId,
	})
	return err
}

// CreateGroup returns the group struct of the created group, and an error.
// Can panic if cannot generate a valid UUID.
func CreateGroup(groupName string, groupDesc string) (grp Group, err error) {
	groupId := uuid.NewString()
	g, err := DbQueries.CreateGroup(ctx, sqlc_db.CreateGroupParams{
		Groupid:   groupId,
		Groupname: groupName,
		Groupdesc: sql.NullString{String: groupDesc, Valid: groupDesc != ""},
	})
	if err != nil {
		return grp, err
	}
	grp.GroupId = g.Groupid
	grp.GroupName = g.Groupname
	grp.GroupDesc = g.Groupdesc.String

	return grp, err
}

func GetGroup(groupId string) (g Group, err error) {
	group, err := DbQueries.GetGroup(ctx, groupId)
	if err != nil {
		return g, err
	}
	g.GroupId = group.Groupid
	g.GroupName = group.Groupname
	g.GroupDesc = group.Groupdesc.String
	return g, err
}

func DeleteGroup(groupId string) (err error) {
	err = DbQueries.DeleteGroup(ctx, groupId)
	return err
}
