package database

import (
	"database/sql"
	"time"

	"github.com/devlup-labs/Ghostwire/coordination-server/database/sqlc_db"
)

type Device struct {
	DeviceId         string
	PublicKey        []byte
	GwIp             string
	PublicIp         string
	RefreshTokenHash string
	AccessTokenHash  string
	FirstAccessTime  time.Time
	LastAccessTime   time.Time
	UserAgent        string
}

func (d Device) UpdatePublicKey(publicKey []byte) error {
	return d.Update(publicKey, d.GwIp, d.PublicIp, d.LastAccessTime, d.UserAgent, d.RefreshTokenHash, d.AccessTokenHash)
}

func (d Device) UpdateGwIp(gwIp string) error {
	return d.Update(d.PublicKey, gwIp, d.PublicIp, d.LastAccessTime, d.UserAgent, d.RefreshTokenHash, d.AccessTokenHash)
}

func (d Device) UpdatePublicIp(publicIp string) error {
	return d.Update(d.PublicKey, d.GwIp, publicIp, d.LastAccessTime, d.UserAgent, d.RefreshTokenHash, d.AccessTokenHash)
}

func (d Device) UpdateLastAccessTime(lastAccessTime time.Time) error {
	return d.Update(d.PublicKey, d.GwIp, d.PublicIp, lastAccessTime, d.UserAgent, d.RefreshTokenHash, d.AccessTokenHash)
}

func (d Device) UpdateUserAgent(userAgent string) error {
	return d.Update(d.PublicKey, d.GwIp, d.PublicIp, d.LastAccessTime, userAgent, d.RefreshTokenHash, d.AccessTokenHash)
}

func (d Device) UpdateRefreshTokenHash(refreshTokenHash string) error {
	return d.Update(d.PublicKey, d.GwIp, d.PublicIp, d.LastAccessTime, d.UserAgent, refreshTokenHash, d.AccessTokenHash)
}

func (d Device) UpdateAccessTokenHash(accessTokenHash string) error {
	return d.Update(d.PublicKey, d.GwIp, d.PublicIp, d.LastAccessTime, d.UserAgent, d.RefreshTokenHash, accessTokenHash)
}

func (d Device) Update(publicKey []byte, gwIp string, publicIp string, lastAccessTime time.Time, userAgent string, refreshTokenHash string, accessTokenHash string) (err error) {
	_, err = DbQueries.UpdateDevice(ctx, sqlc_db.UpdateDeviceParams{
		Publickey:        publicKey,
		Gwip:             gwIp,
		Publicip:         sql.NullString{String: publicIp, Valid: publicIp != ""},
		Lastaccesstime:   lastAccessTime,
		Useragent:        userAgent,
		Refreshtokenhash: refreshTokenHash,
		Accesstokenhash:  accessTokenHash,
		Deviceid:         d.DeviceId,
	})
	return err
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
	d.RefreshTokenHash = device.Refreshtokenhash
	d.AccessTokenHash = device.Accesstokenhash
	d.FirstAccessTime = device.Firstaccesstime
	d.LastAccessTime = device.Lastaccesstime
	d.UserAgent = device.Useragent
	return d, err
}

func DeleteDevice(deviceId string) (err error) {
	err = DbQueries.DeleteDevice(ctx, deviceId)
	return err
}
