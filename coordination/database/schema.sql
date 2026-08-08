CREATE TABLE IF NOT EXISTS groups (
    groupId TEXT PRIMARY KEY,
    groupName TEXT NOT NULL,
    groupDesc TEXT
);

CREATE TABLE IF NOT EXISTS users (
    userId TEXT PRIMARY KEY,
    userName TEXT NOT NULL,
    userType TEXT NOT NULL,
    oAuthProvider TEXT NOT NULL,
    oAuthId TEXT NOT NULL,
    isRevoked INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS devices (
    deviceId TEXT PRIMARY KEY,
    userId TEXT NOT NULL,
    publicKey BLOB NOT NULL,
    gwIp TEXT NOT NULL,
    publicIp TEXT,
    refreshTokenHash TEXT NOT NULL,
    accessTokenHash TEXT NOT NULL,
    firstAccessTime timestamp NOT NULL,
    lastAccessTime timestamp NOT NULL,
    userAgent TEXT NOT NULL,
    -- Reln between users and devices (one-many)
    FOREIGN KEY (userId) REFERENCES users(userId) ON DELETE CASCADE
);

-- Reln between groups and users (many-many)
CREATE TABLE IF NOT EXISTS group_users (
    groupId TEXT NOT NULL,
    userId TEXT NOT NULL,
    PRIMARY KEY (groupId, userId),
    FOREIGN KEY (groupId) REFERENCES groups(groupId) ON DELETE CASCADE,
    FOREIGN KEY (userId) REFERENCES users(userId) ON DELETE CASCADE
);

-- Reln between groups and devices (many-many)
CREATE TABLE IF NOT EXISTS group_devices (
    groupId TEXT NOT NULL,
    deviceId TEXT NOT NULL,
    PRIMARY KEY (groupId, deviceId),
    FOREIGN KEY (groupId) REFERENCES groups(groupId) ON DELETE CASCADE,
    FOREIGN KEY (deviceId) REFERENCES devices(deviceId) ON DELETE CASCADE
);
-- IMPORTANT NOTE: Groups can contain both devices and users
-- i.e. effective group devices = `group.devices` ∪ `group.users.devices()`

CREATE TABLE IF NOT EXISTS policies (
    policyId TEXT PRIMARY KEY,
    policyType TEXT NOT NULL,
    policyName TEXT NOT NULL,
    policyDesc TEXT,
    
    -- Sender: Request going from whom?
    senderType TEXT NOT NULL,
    senderId TEXT NOT NULL,
    
    -- Receiver: Request going to whom?
    receiverType TEXT NOT NULL,
    receiverId TEXT NOT NULL,
    
    bidirectional INTEGER NOT NULL DEFAULT 1, -- Maps to a bool
    active INTEGER NOT NULL DEFAULT 0, -- Policies are inactive by default
    
    createdTimestamp timestamp NOT NULL,
    createdBy TEXT NOT NULL  -- Name of admin
)
