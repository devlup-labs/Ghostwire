-- ===========
-- |  Users  |
-- ===========

-- name: CreateUser :one
INSERT INTO users (
    userId, userName, userType, oAuthProvider, oAuthId, isRevoked
) VALUES (
    ?, ?, ?, ?, ?, ?
) RETURNING *;

-- name: ListUsers :many
SELECT * FROM users
ORDER BY userId;

-- name: UpdateUser :exec
UPDATE users
SET userName = ?, userType = ?, oAuthProvider = ?, oAuthId = ?, isRevoked = ?
WHERE userId = ?;

-- name: GetUser :one
SELECT * FROM users
WHERE userId = ? LIMIT 1;

-- name: GetUsersByUsername :many
SELECT * FROM users
WHERE userName = ?
ORDER BY userId;

-- name: DeleteUser :exec
DELETE FROM users
WHERE userId = ?;

-- =============
-- |  Devices  |
-- =============

-- name: CreateDevice :one
INSERT INTO devices (
    deviceId, userId, publicKey, gwIp, publicIp, firstAccessTime, lastAccessTime, userAgent, refreshTokenHash, accessTokenHash
) VALUES (
    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
) RETURNING *;

-- name: GetDevice :one
SELECT * FROM devices
WHERE deviceId = ? LIMIT 1;

-- name: ListDevicesByUser :many
SELECT * FROM devices
WHERE userId = ?;

-- name: UpdateDevice :one
UPDATE devices
SET publicKey = ?, gwIp = ?, publicIp = ?, firstAccessTime = ?, lastAccessTime = ?, userAgent = ?, refreshTokenHash = ?, accessTokenHash = ?
WHERE deviceId = ?
RETURNING *;

-- name: DeleteDevice :exec
DELETE FROM devices
WHERE deviceId = ?;

-- ==========
-- | Groups |
-- ==========

-- name: CreateGroup :one
INSERT INTO groups (
    groupId, groupName, groupDesc
) VALUES (
    ?, ?, ?
) RETURNING *;

-- name: GetGroup :one
SELECT * FROM groups
WHERE groupId = ? LIMIT 1;

-- name: UpdateGroup :one
UPDATE groups
SET groupName = ?, groupDesc = ?
WHERE groupId = ?
RETURNING *;

-- name: DeleteGroup :exec
DELETE FROM groups
WHERE groupId = ?;

-- ===================
-- | Group <-> Users |
-- ===================

-- name: AddUserToGroup :exec
INSERT INTO group_users (
    groupId, userId
) VALUES (
    ?, ?
);

-- name: RemoveUserFromGroup :exec
DELETE FROM group_users
WHERE groupId = ? AND userId = ?;

-- name: ListUsersInGroup :many
SELECT u.* FROM users u
JOIN group_users gu ON u.userId = gu.userId
WHERE gu.groupId = ?;

-- name: ListGroupsForUser :many
SELECT g.* FROM groups g
JOIN group_users gu ON g.groupId = gu.groupId
WHERE gu.userId = ?;

-- =====================
-- | Group <-> Devices |
-- =====================

-- name: AddDeviceToGroup :exec
INSERT INTO group_devices (
    groupId, deviceId
) VALUES (
    ?, ?
);

-- name: RemoveDeviceFromGroup :exec
DELETE FROM group_devices
WHERE groupId = ? AND deviceId = ?;

-- name: ListOnlyDevicesInGroup :many
SELECT d.* FROM devices d
JOIN group_devices gd ON d.deviceId = gd.deviceId
WHERE gd.groupId = ?;

-- For the union logic of devices and user's devices
-- name: ListDevicesInGroup :many
SELECT d.deviceId, d.userId, d.publicKey, d.gwIp, d.publicIp, d.firstAccessTime, d.lastAccessTime, d.userAgent, d.refreshTokenHash, d.accessTokenHash
FROM devices d
JOIN group_devices gd ON d.deviceId = gd.deviceId
WHERE gd.groupId = ?1
UNION
SELECT d.deviceId, d.userId, d.publicKey, d.gwIp, d.publicIp, d.firstAccessTime, d.lastAccessTime, d.userAgent, d.refreshTokenHash, d.accessTokenHash
FROM devices d
JOIN group_users gu ON d.userId = gu.userId
WHERE gu.groupId = ?1;

-- ============
-- | Policies |
-- ============

-- name: CreatePolicy :one
INSERT INTO policies (
    policyType, policyName, policyDesc, senderType, senderId,
    receiverType, receiverId, bidirectional, active, createdTimestamp, createdBy
) VALUES (
    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
) RETURNING *;

-- name: GetPolicy :one
SELECT * FROM policies
WHERE policyId = ? LIMIT 1;

-- name: ListPolicies :many
SELECT * FROM policies;

-- name: UpdatePolicy :one
UPDATE policies
SET policyType = ?, policyName = ?, policyDesc = ?, senderType = ?, senderId = ?, receiverType = ?, receiverId = ?, bidirectional = ?, active = ?
WHERE policyId = ?
RETURNING *;

-- name: DeletePolicy :exec
DELETE FROM policies
WHERE policyId = ?;
