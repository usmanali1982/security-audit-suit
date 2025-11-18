# Fix Unauthorized Error in Web App

## Issue
When accessing the web portal, users see:
```
Unauthorized
The server could not verify that you are authorized to access the URL requested.
```

## Root Cause
Flask-Login was not configured with a `login_view`, so when unauthenticated users tried to access protected routes, Flask-Login didn't know where to redirect them, resulting in a 401 Unauthorized error instead of redirecting to the login page.

## Solution

### 1. Configure Flask-Login
Added `login_view` and `login_message` to the LoginManager:

```python
login = LoginManager(app)
login.login_view = 'login'  # ✅ Tell Flask-Login which route to redirect to
login.login_message = 'Please log in to access this page.'
```

### 2. Improved Login Page
Enhanced the login template with:
- Better styling
- Error message display
- Form validation
- User-friendly hints

## How It Works Now

1. **Unauthenticated user visits `/`:**
   - Flask-Login detects no session
   - Automatically redirects to `/login` (status 302)
   - User sees login form

2. **User submits login:**
   - Validates credentials
   - Checks MFA if enabled
   - Creates session
   - Redirects to `/`

3. **Authenticated user:**
   - Can access all protected routes
   - Session persists

## Testing

After the fix:

```bash
# Rebuild webapp container
docker compose build webapp

# Restart container
docker compose up -d webapp

# Access the portal
# http://192.168.3.183:5005
```

**Expected behavior:**
- First visit redirects to `/login` (not "Unauthorized" error)
- Login form displays properly
- After login, redirects to dashboard
- Error messages display correctly

## Default Credentials

- Username: `admin`
- Password: `ChangeMeNow!`
- MFA Token: Generate from your authenticator app (if enabled)

⚠️ **Important**: Change the default password immediately after first login!

