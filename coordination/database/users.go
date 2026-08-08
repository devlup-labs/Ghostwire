package database

import (
	"errors"
	"time"

	"github.com/devlup-labs/Ghostwire/coordination-server/database/sqlc_db"
	"github.com/google/uuid"
)

type User struct {
	UserId        string
	UserName      string
	UserType      string
	OAuthProvider string
	OAuthId       string
	IsRevoked     bool
}

func (u User) Groups() (res []Group, err error) {
	g, err := DbQueries.ListGroupsForUser(ctx, u.UserId)
	if err != nil {
		return res, err
	}
	for _, v := range g {
		res = append(res, Group{
			GroupId:   v.Groupid,
			GroupName: v.Groupname,
			GroupDesc: v.Groupdesc.String,
		})
	}
	return res, err
}

func (u User) CreateDevice(publicKey []byte, gwIp string, refreshTokenHash string, accessTokenHash string, userAgent string) (dev Device, err error) {
	deviceId := uuid.NewString()
	d, err := DbQueries.CreateDevice(ctx, sqlc_db.CreateDeviceParams{
		Deviceid:         deviceId,
		Userid:           u.UserId,
		Publickey:        publicKey,
		Gwip:             gwIp,
		Refreshtokenhash: refreshTokenHash,
		Accesstokenhash:  accessTokenHash,
		Firstaccesstime:  time.Now(),
		Lastaccesstime:   time.Now(),
		Useragent:        userAgent,
	})

	dev = Device{
		DeviceId:         d.Deviceid,
		PublicKey:        d.Publickey,
		GwIp:             d.Gwip,
		PublicIp:         d.Publicip.String,
		RefreshTokenHash: d.Refreshtokenhash,
		AccessTokenHash:  d.Accesstokenhash,
		FirstAccessTime:  d.Firstaccesstime,
		LastAccessTime:   d.Lastaccesstime,
		UserAgent:        d.Useragent,
	}
	return dev, err
}

func (u User) GetDevices() (res []Device, err error) {
	d, err := DbQueries.ListDevicesByUser(ctx, u.UserId)
	if err != nil {
		return res, err
	}
	for _, device := range d {
		res = append(res, Device{
			DeviceId:         device.Deviceid,
			PublicKey:        device.Publickey,
			GwIp:             device.Gwip,
			PublicIp:         device.Publicip.String,
			RefreshTokenHash: device.Refreshtokenhash,
			AccessTokenHash:  device.Accesstokenhash,
			FirstAccessTime:  device.Firstaccesstime,
			LastAccessTime:   device.Lastaccesstime,
			UserAgent:        device.Useragent,
		})
	}
	return res, nil
}

// CreateUser returns the userId (UUID) of the created user, and an error.
// Can panic if cannot generate a valid UUID.
func CreateUser(userName string, userType string, oAuthProvider string, oAuthId string) (userId string, err error) {
	if userType != "regular" && userType != "admin" && userType != "superadmin" {
		return "", errors.New("userType must be one of 'regular', 'admin', 'superadmin'")
	}
	// TODO: Restrict so that there's only one superadmin
	userId = uuid.NewString()
	_, err = DbQueries.CreateUser(ctx, sqlc_db.CreateUserParams{
		Userid:        userId,
		Username:      userName,
		Usertype:      userType,
		Oauthprovider: oAuthProvider,
		Oauthid:       oAuthId,
		Isrevoked:     false,
	})
	return userId, err
}

func GetUser(userId string) (u User, err error) {
	user, err := DbQueries.GetUser(ctx, userId)
	if err != nil {
		return u, err
	}
	u.UserId = user.Userid
	u.UserName = user.Username
	u.UserType = user.Usertype
	u.OAuthProvider = user.Oauthprovider
	u.OAuthId = user.Oauthid
	u.IsRevoked = user.Isrevoked

	return u, nil
}

// SearchUser looks up a user by their username.
// If multiple usernames are found, they are all returned, sorted by userId
func GetUsersByUserName(userName string) (res []User, err error) {
	// Assuming ctx is a global context or passed in your actual implementation
	users, err := DbQueries.GetUsersByUsername(ctx, userName)
	if err != nil {
		return res, err
	}

	for _, u := range users {
		res = append(res, User{
			UserId:        u.Userid,
			UserName:      u.Username,
			UserType:      u.Usertype,
			OAuthProvider: u.Oauthprovider,
			OAuthId:       u.Oauthid,
			IsRevoked:     u.Isrevoked,
		})
	}

	return res, nil
}

func ListUsers() (res []User, err error) {
	users, err := DbQueries.ListUsers(ctx)
	if err != nil {
		return res, err
	}
	for _, u := range users {
		res = append(res, User{
			UserId:        u.Userid,
			UserName:      u.Username,
			UserType:      u.Usertype,
			OAuthProvider: u.Oauthprovider,
			OAuthId:       u.Oauthid,
			IsRevoked:     u.Isrevoked,
		})
	}
	return res, err
}

func DeleteUser(userId string) (err error) {
	err = DbQueries.DeleteUser(ctx, userId)
	return err
}
