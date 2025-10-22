Database migrations - manual SQL files

Files included:
- 001_add_parent_id_to_comments.sql  -> adds parent_id column to comment table (threaded replies)

Instructions:
1) Backup your database before applying any migration.
2) If you use Flask-Migrate/Alembic, prefer generating and applying migrations via `flask db migrate` / `flask db upgrade`.
3) To apply the provided SQL files manually (PostgreSQL example):

   psql "<DATABASE_URL>" -f migrations/001_add_parent_id_to_comments.sql

4) For SQLite: ALTER TABLE is limited; you may need to recreate the table. Ask me to generate a SQLite-specific migration script if needed.

Notes:
- After applying the migrations, restart the Flask app.
- Verify endpoints: GET /api/discussion/<id>/comments should now return nested children; POST /api/discussion/<id>/comment accepts parent_id.
- If you use Alembic, I can generate a migration file for you to commit.
