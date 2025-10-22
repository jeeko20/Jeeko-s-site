-- Migration SQL: add is_global and ressource_id to discussion table
-- WARNING: Review and run against your database. Backup first.

ALTER TABLE discussion
  ADD COLUMN is_global BOOLEAN DEFAULT FALSE,
  ADD COLUMN ressource_id INTEGER REFERENCES ressource(id);

CREATE INDEX IF NOT EXISTS idx_discussion_ressource_id ON discussion(ressource_id);
