package database

import "github.com/devlup-labs/Ghostwire/coordination-server/database/sqlc_db"

type User struct {
	userId   string
	userName string
}

func (u User) Groups() (res []Group, err error) {
	g, err := DbQueries.ListGroupsForUser(ctx, u.userId)
	if err != nil {
		return res, err
	}
	for _, v := range g {
		res = append(res, Group{
			groupId:   v.Groupid,
			groupName: v.Groupname,
			groupDesc: v.Groupdesc.String,
		})
	}
	return res, err
}

func (u User) CreateDevice(deviceId string, publicKey []byte, gwIp string) (err error) {
	_, err = DbQueries.CreateDevice(ctx, sqlc_db.CreateDeviceParams{
		Deviceid:  deviceId,
		Userid:    u.userId,
		Publickey: publicKey,
		Gwip:      gwIp,
	})
	return err
}

func (u User) GetDevices() (res []Device, err error) {
	d, err := DbQueries.ListDevicesByUser(ctx, u.userId)
	if err != nil {
		return res, err
	}
	for _, device := range d {
		res = append(res, Device{
			DeviceId:  device.Deviceid,
			PublicKey: device.Publickey,
			GwIp:      device.Gwip,
			PublicIp:  device.Publicip.String,
		})
	}
	return res, nil
}

func CreateUser(userId string, userName string) (err error) {
	_, err = DbQueries.CreateUser(ctx, sqlc_db.CreateUserParams{
		Userid:   userId,
		Username: userName,
	})
	return err
}

func GetUser(userId string) (u User, err error) {
	user, err := DbQueries.GetUser(ctx, userId)
	if err != nil {
		return u, err
	}
	u.userId = user.Userid
	u.userName = user.Username

	return u, err
}

func ListUsers() (res []User, err error) {
	users, err := DbQueries.ListUsers(ctx)
	if err != nil {
		return res, err
	}
	for _, u := range users {
		res = append(res, User{
			userId:   u.Userid,
			userName: u.Username,
		})
	}
	return res, err
}

func DeleteUser(userId string) (err error) {
	err = DbQueries.DeleteUser(ctx, userId)
	return err
}
