package database

import (
	"database/sql"

	"github.com/devlup-labs/Ghostwire/coordination-server/database/sqlc_db"
)

type Device struct {
	DeviceId  string
	PublicKey []byte
	GwIp      string
	PublicIp  string
}

func GetDevice(deviceId string) (d Device, err error) {
	device, err := DbQueries.GetDevice(ctx, deviceId)
	if err != nil {
		return d, err
	}
	d.DeviceId = device.Deviceid
	d.PublicKey = device.Publickey
	d.GwIp = device.Gwip
	d.PublicIp = device.Publicip.String
	return d, err
}

func UpdateDevice(deviceId string, publicKey []byte, gwIp string, publicIp string) (err error) {
	_, err = DbQueries.UpdateDevice(ctx, sqlc_db.UpdateDeviceParams{
		Publickey: publicKey,
		Gwip:      gwIp,
		Publicip:  sql.NullString{String: publicIp, Valid: publicIp != ""},
		Deviceid:  deviceId,
	})
	return err
}

func DeleteDevice(deviceId string) (err error) {
	err = DbQueries.DeleteDevice(ctx, deviceId)
	return err
}
