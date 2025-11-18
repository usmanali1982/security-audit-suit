# Flask SQLAlchemy Model Fix

## Issue
SQLAlchemy syntax error in User model definition:

```python
role=db.Column(db.String(20),"user")  # ❌ Incorrect
```

**Error:**
```
sqlalchemy.exc.ArgumentError: 'SchemaItem' object, such as a 'Column' or a 'Constraint' expected, got 'user'
```

## Root Cause
The default value `"user"` was passed as a positional argument instead of a keyword argument. SQLAlchemy expects column constraints and defaults to be passed as keyword arguments.

## Solution
Changed from:
```python
role=db.Column(db.String(20),"user")  # ❌ Wrong
```

To:
```python
role=db.Column(db.String(20), default="user")  # ✅ Correct
```

## Fix Applied
- Updated `webapp/app.py` line 19
- Changed `role=db.Column(db.String(20),"user")` to `role=db.Column(db.String(20), default="user")`

## Verification
After the fix, the Flask app should start successfully:

```bash
# Rebuild webapp container
docker compose build webapp

# Restart container
docker compose up -d webapp

# Check logs
docker compose logs -f webapp
```

## SQLAlchemy Column Syntax Reference
Correct syntax for Column with default value:
```python
# Default value (Python-level)
column_name = db.Column(db.String(20), default="value")

# Server default (database-level)
column_name = db.Column(db.String(20), server_default="value")

# With multiple parameters
column_name = db.Column(
    db.String(20),
    default="value",
    nullable=False,
    unique=True
)
```

