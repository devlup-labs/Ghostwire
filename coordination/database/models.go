package database

import (
	"time"
)

type Group struct {
	GroupId   string   `gorm:"column:groupId;primaryKey"`
	GroupName string   `gorm:"column:groupName;not null"`
	GroupDesc string   `gorm:"column:groupDesc;not null"`
	Users     []User   `gorm:"many2many:group_users;joinForeignKey:groupId;joinReferences:userId"`
	Devices   []Device `gorm:"many2many:group_devices;joinForeignKey:groupId;joinReferences:deviceId"`
}

type User struct {
	UserId        string   `gorm:"column:userId;primaryKey"`
	UserName      string   `gorm:"column:userName;not null"`
	UserType      string   `gorm:"column:userType;not null"`
	OAuthProvider string   `gorm:"column:oAuthProvider;not null"`
	OAuthId       string   `gorm:"column:oAuthId;not null"`
	IsRevoked     bool     `gorm:"column:isRevoked;not null;default:false"`
	Devices       []Device `gorm:"foreignKey:userId;constraint:OnDelete:CASCADE"`
	Groups        []Group  `gorm:"many2many:group_users;joinForeignKey:userId;joinReferences:groupId"`
}

type Device struct {
	DeviceId         string    `gorm:"column:deviceId;primaryKey"`
	UserId           string    `gorm:"column:userId;not null"`
	PublicKey        []byte    `gorm:"column:publicKey;not null"`
	GwIp             string    `gorm:"column:gwIp;not null"`
	PublicIp         string    `gorm:"column:publicIp"` // Nullable
	RefreshTokenHash string    `gorm:"column:refreshTokenHash;not null"`
	AccessTokenHash  string    `gorm:"column:accessTokenHash;not null"`
	FirstAccessTime  time.Time `gorm:"column:firstAccessTime;not null;autoCreateTime"`
	LastAccessTime   time.Time `gorm:"column:lastAccessTime;not null;autoCreateTime"`
	UserAgent        string    `gorm:"column:userAgent;not null"`
	Groups           []Group   `gorm:"many2many:group_devices;joinForeignKey:deviceId;joinReferences:groupId"`
}

type Policy struct {
	PolicyId         string    `gorm:"column:policyId;primaryKey"`
	PolicyName       string    `gorm:"column:policyName;not null"`
	PolicyDesc       string    `gorm:"column:policyDesc;not null"`
	SenderType       string    `gorm:"column:senderType;not null"`
	SenderId         string    `gorm:"column:senderId;not null"`
	ReceiverType     string    `gorm:"column:receiverType;not null"`
	ReceiverId       string    `gorm:"column:receiverId;not null"`
	Active           bool      `gorm:"column:active;not null;default:true"`
	CreatedTimestamp time.Time `gorm:"column:createdTimestamp;not null"`
	CreatedBy        string    `gorm:"column:createdBy;not null"`
}
