ALTER TABLE rooms
    ADD COLUMN idle_minutes INT,
    ADD COLUMN max_messages INT,
    ADD COLUMN message_count INT NOT NULL DEFAULT 0,
    ADD COLUMN last_activity TIMESTAMPTZ NOT NULL DEFAULT now();