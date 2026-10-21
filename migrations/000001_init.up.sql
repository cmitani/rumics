CREATE TABLE rooms (
    id TEXT PRIMARY KEY,
    salt BYTEA NOT NULL,
    key BYTEA,
    iv BYTEA,
    creation TIMESTAMPTZ NOT NULL DEFAULT now(),
    expire TIMESTAMPTZ NOT NULL
);

CREATE TABLE messages (
    id BIGSERIAL PRIMARY KEY,
    room_id TEXT NOT NULL,
    ciphertext BYTEA NOT NULL,
    iv BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT messages_room_id_fkey
        FOREIGN KEY (room_id)
        REFERENCES rooms(id)
        ON DELETE CASCADE
);

CREATE INDEX messages_room_id_id_idx
ON messages (room_id, id);