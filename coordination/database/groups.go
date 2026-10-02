package database

import (
	"github.com/google/uuid"
	"gorm.io/gorm"
)

func deviceUnion(a, b []Device) []Device {
	seen := make(map[string]struct{}, len(a))
	result := make([]Device, 0, len(a)+len(b))
	for _, item := range a {
		seen[item.DeviceId] = struct{}{}
		result = append(result, item)
	}
	for _, item := range b {
		if _, exists := seen[item.DeviceId]; !exists {
			result = append(result, item)
		}
	}
	return result
}

func (g Group) ListDevices() (res []Device, err error) {
	// Union logic query
	var devicesOfUsersInGroup []Device
	var groupUsers []User
	var devicesDirectlyInGroup []Device

	err = db.Model(&g).Association("Users").Find(&groupUsers)
	if err != nil {
		return nil, err
	}
	err = db.Model(&g).Association("Devices").Find(&devicesDirectlyInGroup)
	if err != nil {
		return nil, err
	}

	for _, u := range groupUsers {
		userDevices, err := u.GetDevices()
		if err != nil {
			return nil, err
		}
		devicesOfUsersInGroup = append(devicesOfUsersInGroup, userDevices...)
	}
	res = deviceUnion(devicesDirectlyInGroup, devicesOfUsersInGroup)
	return res, err
}

func (g Group) UpdateGroup(groupName string, groupDesc string) (err error) {
	gorm.G[Group](db).Where(g).Updates(ctx, Group{
		GroupName: groupName,
		GroupDesc: groupDesc,
	})
	return err
}

func (g Group) AddUser(user User) (err error) {
	err = db.Model(&g).Association("Users").Append(&user)
	return
}

func (g Group) RemoveUser(user User) (err error) {
	err = db.Model(&g).Association("Users").Delete(&user)
	return
}

func (g Group) AddDevice(device Device) (err error) {
	err = db.Model(&g).Association("Devices").Append(&device)
	return
}

func (g Group) RemoveDevice(device Device) (err error) {
	err = db.Model(&g).Association("Devices").Delete(&device)
	return
}

// CreateGroup returns the group struct of the created group, and an error.
// Can panic if cannot generate a valid UUID.
func CreateGroup(groupName string, groupDesc string) (grp Group, err error) {
	groupId := uuid.NewString()
	grp = Group{
		GroupId:   groupId,
		GroupName: groupName,
		GroupDesc: groupDesc,
	}
	err = gorm.G[Group](db).Create(ctx, &grp)
	return
}

func GetGroup(groupId string) (g Group, err error) {
	g, err = gorm.G[Group](db).Where("groupId = ?", groupId).Take(ctx)
	return
}

func DeleteGroup(groupId string) (rowsAffected int, err error) {
	rowsAffected, err = gorm.G[Group](db).Where("groupId = ?", groupId).Delete(ctx)
	return
}
