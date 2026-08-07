package database

import (
	"database/sql"

	"github.com/devlup-labs/Ghostwire/coordination-server/database/sqlc_db"
)

type Group struct {
	groupId   string
	groupName string
	groupDesc string
}

func (g Group) ListDevices() (res []Device, err error) {
	// Union logic query
	devices, err := DbQueries.ListDevicesInGroup(ctx, g.groupId)
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

func CreateGroup(groupId string, groupName string, groupDesc string) (grp Group, err error) {
	g, err := DbQueries.CreateGroup(ctx, sqlc_db.CreateGroupParams{
		Groupid:   groupId,
		Groupname: groupName,
		Groupdesc: sql.NullString{String: groupDesc, Valid: groupDesc != ""},
	})

	grp.groupId = g.Groupid
	grp.groupName = g.Groupname
	grp.groupDesc = g.Groupdesc.String

	return grp, err
}

func GetGroup(groupId string) (g Group, err error) {
	group, err := DbQueries.GetGroup(ctx, groupId)
	if err != nil {
		return g, err
	}
	g.groupId = group.Groupid
	g.groupName = group.Groupname
	g.groupDesc = group.Groupdesc.String
	return g, err
}

func UpdateGroup(groupId string, groupName string, groupDesc string) (err error) {
	_, err = DbQueries.UpdateGroup(ctx, sqlc_db.UpdateGroupParams{
		Groupname: groupName,
		Groupdesc: sql.NullString{String: groupDesc, Valid: groupDesc != ""},
		Groupid:   groupId,
	})
	return err
}

func DeleteGroup(groupId string) (err error) {
	err = DbQueries.DeleteGroup(ctx, groupId)
	return err
}

func AddUserToGroup(groupId string, userId string) (err error) {
	err = DbQueries.AddUserToGroup(ctx, sqlc_db.AddUserToGroupParams{
		Groupid: groupId,
		Userid:  userId,
	})
	return err
}

func RemoveUserFromGroup(groupId string, userId string) (err error) {
	err = DbQueries.RemoveUserFromGroup(ctx, sqlc_db.RemoveUserFromGroupParams{
		Groupid: groupId,
		Userid:  userId,
	})
	return err
}

func AddDeviceToGroup(groupId string, deviceId string) (err error) {
	err = DbQueries.AddDeviceToGroup(ctx, sqlc_db.AddDeviceToGroupParams{
		Groupid:  groupId,
		Deviceid: deviceId,
	})
	return err
}

func RemoveDeviceFromGroup(groupId string, deviceId string) (err error) {
	err = DbQueries.RemoveDeviceFromGroup(ctx, sqlc_db.RemoveDeviceFromGroupParams{
		Groupid:  groupId,
		Deviceid: deviceId,
	})
	return err
}
