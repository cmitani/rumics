ALTER TABLE rooms
    DROP COLUMN idle_minutes,
    DROP COLUMN max_messages,
    DROP COLUMN message_count,
    DROP COLUMN last_activity;