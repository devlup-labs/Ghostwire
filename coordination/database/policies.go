package database

import (
	"database/sql"
	"errors"
	"time"

	"github.com/devlup-labs/Ghostwire/coordination-server/database/sqlc_db"
)

type Policy struct {
	policyId         string
	policyType       string
	policyName       string
	policyDesc       string
	senderType       string
	senderId         string
	receiverType     string
	receiverId       string
	bidirectional    bool
	active           bool
	createdTimestamp time.Time
	createdBy        string
}

func CreatePolicy(p Policy) (err error) {
	if p.policyType != "allow" && p.policyType != "block" {
		return errors.New("policyType can only be 'allow' or 'block'")
	}
	if p.senderType != "group" && p.senderType != "user" {
		return errors.New("senderType can only be 'group' or 'user'")
	}
	if p.receiverType != "group" && p.receiverType != "user" {
		return errors.New("receiverType can only be 'group' or 'user'")
	}
	_, err = DbQueries.CreatePolicy(ctx, sqlc_db.CreatePolicyParams{
		Policytype:       p.policyType,
		Policyname:       p.policyName,
		Policydesc:       sql.NullString{String: p.policyDesc, Valid: p.policyDesc != ""},
		Sendertype:       p.senderType,
		Senderid:         p.senderId,
		Receivertype:     p.receiverType,
		Receiverid:       p.receiverId,
		Bidirectional:    p.bidirectional,
		Active:           p.active,
		Createdtimestamp: time.Now(),
		Createdby:        p.createdBy,
	})
	return err
}

func GetPolicy(policyId string) (p Policy, err error) {
	policy, err := DbQueries.GetPolicy(ctx, policyId)
	if err != nil {
		return p, err
	}
	p = Policy{
		policyId:         policy.Policyid,
		policyType:       policy.Policytype,
		policyName:       policy.Policyname,
		policyDesc:       policy.Policydesc.String,
		senderType:       policy.Sendertype,
		senderId:         policy.Senderid,
		receiverType:     policy.Receivertype,
		receiverId:       policy.Receiverid,
		bidirectional:    policy.Bidirectional,
		active:           policy.Active,
		createdTimestamp: policy.Createdtimestamp,
		createdBy:        policy.Createdby,
	}
	return p, err
}

func ListPolicies() (res []Policy, err error) {
	policies, err := DbQueries.ListPolicies(ctx)
	if err != nil {
		return res, err
	}
	for _, policy := range policies {
		res = append(res, Policy{
			policyId:         policy.Policyid,
			policyType:       policy.Policytype,
			policyName:       policy.Policyname,
			policyDesc:       policy.Policydesc.String,
			senderType:       policy.Sendertype,
			senderId:         policy.Senderid,
			receiverType:     policy.Receivertype,
			receiverId:       policy.Receiverid,
			bidirectional:    policy.Bidirectional,
			active:           policy.Active,
			createdTimestamp: policy.Createdtimestamp,
			createdBy:        policy.Createdby,
		})
	}
	return res, err
}

func UpdatePolicy(policyId string, p Policy) (err error) {
	_, err = DbQueries.UpdatePolicy(ctx, sqlc_db.UpdatePolicyParams{
		Policytype:    p.policyType,
		Policyname:    p.policyName,
		Policydesc:    sql.NullString{String: p.policyDesc, Valid: p.policyDesc != ""},
		Sendertype:    p.senderType,
		Senderid:      p.senderId,
		Receivertype:  p.receiverType,
		Receiverid:    p.receiverId,
		Bidirectional: p.bidirectional,
		Active:        p.active,
		Policyid:      policyId,
	})
	return err
}

func DeletePolicy(policyId string) (err error) {
	err = DbQueries.DeletePolicy(ctx, policyId)
	return err
}

// TODO: Calculate Allowlist and Blocklist from policies
