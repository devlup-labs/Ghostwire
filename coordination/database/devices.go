package database

import (
	"log"

	"gorm.io/gorm"
)

func (d Device) GetGroups() (res []Group, err error) {
	err = db.Model(&d).Association("Groups").Find(&res)
	return
}

func (d Device) Update(updatedDevice Device) (err error) {
	rowsAffected, err := gorm.G[Device](db).Where(d).Updates(ctx, updatedDevice)
	log.Printf("Updated device %#v with %d rows affected\n", d, rowsAffected)
	return
}

func GetDevice(deviceId string) (d Device, err error) {
	d, err = gorm.G[Device](db).Where("deviceId = ?", deviceId).Take(ctx)
	return
}

func DeleteDevice(deviceId string) (rowsAffected int, err error) {
	rowsAffected, err = gorm.G[Device](db).Where("deviceId = ?", deviceId).Delete(ctx)
	return
}
