-- Migration SQL: add parent_id to comment table for threaded replies
-- WARNING: Review and run against your database. Backup first.
-- Example for PostgreSQL:

ALTER TABLE comment
  ADD COLUMN parent_id INTEGER REFERENCES comment(id);

-- Optionally add an index to speed up queries:
CREATE INDEX IF NOT EXISTS idx_comment_parent_id ON comment(parent_id);

-- If using SQLite, ALTER TABLE support is limited. For SQLite you may need to recreate the table.
