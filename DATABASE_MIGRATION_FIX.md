# Database Migration Fix - Adding is_active Column

## Issue
The existing database table `user` doesn't have the `is_active` column, causing:
```
sqlite3.OperationalError: no such column: user.is_active
```

## Root Cause
SQLAlchemy's `db.create_all()` only creates new tables - it doesn't modify existing tables. The database was created before we added the `is_active` column to the model.

## Solution
Added automatic database migration code that:
1. Checks if `is_active` column exists
2. If not, adds it using `ALTER TABLE`
3. Updates existing admin user to have `is_active=1`
4. Handles errors gracefully

## Migration Code
```python
# Try to query - if column doesn't exist, this will fail
try:
    db.session.execute(db_text("SELECT is_active FROM user LIMIT 1"))
except Exception:
    # Column doesn't exist, add it
    db.session.execute(db_text("ALTER TABLE user ADD COLUMN is_active BOOLEAN DEFAULT 1"))
    db.session.commit()
```

## What Happens Now

1. **On startup:**
   - Code checks if `is_active` column exists
   - If not found, automatically adds it
   - Updates existing admin user

2. **For new installations:**
   - `db.create_all()` creates table with all columns including `is_active`
   - No migration needed

## Testing

After this fix:
1. Restart webapp: `docker compose restart webapp`
2. Check logs: `docker compose logs webapp`
3. Should see: "Successfully added is_active column" (if migration ran)
4. App should start without errors
5. Login should work correctly

## Alternative: Manual Migration

If automatic migration doesn't work, you can manually add the column:

```bash
docker compose exec webapp sqlite3 /opt/security-audit/data/webapp.db "ALTER TABLE user ADD COLUMN is_active BOOLEAN DEFAULT 1;"
docker compose exec webapp sqlite3 /opt/security-audit/data/webapp.db "UPDATE user SET is_active = 1 WHERE username = 'admin';"
```

## Alternative: Reset Database

If you don't have important data:

```bash
docker compose stop webapp
docker volume rm security-audit-suite-full_app-data
docker compose up -d webapp
```

This will recreate the database with the correct schema.

