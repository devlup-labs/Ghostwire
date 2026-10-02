package database

import (
	"errors"
	"log"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

func CreatePolicy(policyName string, policyDesc string, senderType string, senderId string, receiverType string, receiverId string, active bool, createdBy string) (pol Policy, err error) {
	if senderType != "group" && senderType != "user" {
		return Policy{}, errors.New("senderType can only be 'group' or 'user'")
	}
	if receiverType != "group" && receiverType != "user" {
		return Policy{}, errors.New("receiverType can only be 'group' or 'user'")
	}
	pol = Policy{
		PolicyId:     uuid.NewString(),
		PolicyName:   policyName,
		PolicyDesc:   policyDesc,
		SenderType:   senderType,
		SenderId:     senderId,
		ReceiverType: receiverType,
		ReceiverId:   receiverId,
		Active:       active,
		CreatedBy:    createdBy,
	}
	err = gorm.G[Policy](db).Create(ctx, &pol)
	return pol, err
}

func GetPolicy(policyId string) (p Policy, err error) {
	p, err = gorm.G[Policy](db).Where("policyId = ?", policyId).Take(ctx)
	return
}

func ListPolicies() (res []Policy, err error) {
	res, err = gorm.G[Policy](db).Find(ctx)
	return res, err
}

func UpdatePolicy(policyId string, updatedPolicy Policy) (err error) {
	rowsAffected, err := gorm.G[Policy](db).Where("policyId = ?", policyId).Updates(ctx, updatedPolicy)
	log.Printf("Updated policy %s with %d rows affected\n", policyId, rowsAffected)
	return
}

func DeletePolicy(policyId string) (rowsAffected int, err error) {
	rowsAffected, err = gorm.G[Policy](db).Where("policyId = ?", policyId).Delete(ctx)
	return
}
