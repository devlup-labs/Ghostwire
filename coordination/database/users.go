package database

import (
	"database/sql"
	"errors"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

func (u User) GetGroups() (res []Group, err error) {
	err = db.Model(&u).Association("Groups").Find(&res)
	return
}

func (u User) CreateDevice(publicKey []byte, gwIp string, refreshTokenHash string, accessTokenHash string, userAgent string) (dev Device, err error) {
	deviceId := uuid.NewString()
	err = gorm.G[Device](db).Create(ctx, &Device{
		DeviceId:         deviceId,
		UserId:           u.UserId,
		PublicKey:        publicKey,
		GwIp:             gwIp,
		RefreshTokenHash: refreshTokenHash,
		AccessTokenHash:  accessTokenHash,
		UserAgent:        userAgent,
	})
<<<<<<< HEAD

	dev = Device{
		DeviceId:         d.Deviceid,
		UserId:           d.Userid,
		PublicKey:        d.Publickey,
		GwIp:             d.Gwip,
		PublicIp:         d.Publicip.String,
		RefreshTokenHash: d.Refreshtokenhash,
		AccessTokenHash:  d.Accesstokenhash,
		FirstAccessTime:  d.Firstaccesstime,
		LastAccessTime:   d.Lastaccesstime,
		UserAgent:        d.Useragent,
	}

=======
	if err != nil {
		return Device{}, err
	}
	dev, err = GetDevice(deviceId)
>>>>>>> 84fc771 (feat: revamp database to use GORM instead of sqlc)
	return dev, err
}

func (u User) GetDevices() (res []Device, err error) {
<<<<<<< HEAD
	d, err := DbQueries.ListDevicesByUser(ctx, u.UserId)
	if err != nil {
		return res, err
	}
	for _, device := range d {
		res = append(res, Device{
			DeviceId:         device.Deviceid,
			UserId:           device.Userid,
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
=======
	err = db.Model(&u).Association("Devices").Find(&res)
	return
>>>>>>> 84fc771 (feat: revamp database to use GORM instead of sqlc)
}

// CreateUser returns the userId (UUID) of the created user, and an error.
// Can panic if cannot generate a valid UUID.
func CreateUser(userName string, userType string, oAuthProvider string, oAuthId string) (userId string, err error) {
	if userType != "regular" && userType != "admin" && userType != "superadmin" {
		return "", errors.New("userType must be one of 'regular', 'admin', 'superadmin'")
	}
	// TODO: Restrict so that there's only one superadmin
	userId = uuid.NewString()

	err = gorm.G[User](db).Create(ctx, &User{
		UserId:        userId,
		UserName:      userName,
		UserType:      userType,
		OAuthProvider: oAuthProvider,
		OAuthId:       oAuthId,
	})
	return userId, err
}

func GetUser(userId string) (u User, err error) {
	u, err = gorm.G[User](db).Where("userId = ?", userId).Take(ctx)
	return
}

func GetUserByOAuth(oAuthProvider string, oAuthId string) (u User, err error) {
	user, err := DbQueries.GetUserByOAuth(ctx, sqlc_db.GetUserByOAuthParams{
		Oauthprovider: oAuthProvider,
		Oauthid:       oAuthId,
	})
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
	res, err = gorm.G[User](db).Where("userName = ?", userName).Find(ctx)
	return
}

func ListUsers() (res []User, err error) {
	res, err = gorm.G[User](db).Find(ctx)
	return
}

func DeleteUser(userId string) (rowsAffected int, err error) {
	rowsAffected, err = gorm.G[User](db).Where("userId = ?", userId).Delete(ctx)
	return
}

func ErrUserNotFound() error {
	return sql.ErrNoRows
}
