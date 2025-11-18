# Fix Flask-Login is_active Attribute Error

## Issue
After login, Flask-Login was checking for `user.is_active` attribute which didn't exist in the User model, causing:
```
AttributeError: 'User' object has no attribute 'is_active'
```

## Root Cause
Flask-Login by default checks `user.is_active` before allowing login. Our User model was missing this required attribute.

## Solution

### 1. Added `is_active` attribute to User model
```python
is_active=db.Column(db.Boolean, default=True)  # Required by Flask-Login
```

### 2. Added Flask-Login compatibility methods
```python
@property
def is_authenticated(self):
    return True

@property
def is_anonymous(self):
    return False
```

### 3. Updated admin user creation
- Ensures `is_active=True` is set when creating admin user
- Added migration code to update existing users

## Flask-Login User Model Requirements

Flask-Login requires User models to have:
- `get_id()` - Returns unique identifier (already had)
- `is_authenticated` - Property returning True if user is authenticated
- `is_anonymous` - Property returning False for real users
- `is_active` - Boolean indicating if account is active (was missing)

## Migration Note

The code includes automatic migration for existing admin users to ensure `is_active` is set. This handles the case where the database was created before this fix.

## Testing

After rebuild:
1. Login should work without errors
2. User should be redirected to dashboard successfully
3. No AttributeError should occur

## Next Steps

Rebuild and restart:
```bash
docker compose build webapp
docker compose up -d webapp
```

Login should now work correctly!

