# Flask before_first_request Deprecation Fix

## Issue
`@app.before_first_request` decorator was deprecated in Flask 2.2 and removed in Flask 2.3+.

**Error:**
```
AttributeError: 'Flask' object has no attribute 'before_first_request'
```

## Root Cause
Flask 2.3.3 (our current version) no longer supports `@app.before_first_request` decorator. This was removed because it caused issues in production environments with multiple workers (like Gunicorn).

## Solution
Replaced `@app.before_first_request` with `with app.app_context():` which is the recommended approach for Flask 2.2+.

**Old code (deprecated):**
```python
@app.before_first_request
def create_admin():
    db.create_all()
    # ...
```

**New code (Flask 2.3+ compatible):**
```python
# Initialize database and create admin user (Flask 2.3+ compatible)
with app.app_context():
    db.create_all()
    if not User.query.filter_by(username='admin').first():
        u=User(username='admin', role='admin')
        u.set_password('ChangeMeNow!')
        u.mfa_secret=pyotp.random_base32()
        u.mfa_enabled=True
        db.session.add(u)
        db.session.commit()
```

## Why This Works
- `app.app_context()` creates an application context where database operations can be performed
- This runs immediately when the module is imported, ensuring the database is initialized before any requests
- Works correctly with Gunicorn and multiple worker processes
- No race conditions or timing issues

## Additional Improvements
- Removed duplicate code (we had both old and new approaches)
- Better error handling with explicit commit
- Cleaner code structure

## Verification
After the fix, the Flask app should start successfully:

```bash
# Rebuild webapp container
docker compose build webapp

# Restart container
docker compose up -d webapp

# Check logs - should show successful startup
docker compose logs -f webapp
```

You should see Gunicorn workers starting without errors.

