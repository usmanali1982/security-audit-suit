# Python Dependency Fixes

## Issue
Flask 3.0.0 conflicts with Flask-APScheduler 1.13.0, which requires Flask<3.0.0.

## Solution
Updated `requirements-webapp.txt` to use compatible versions:

### Changes Made
- `flask==3.0.0` → `flask==2.3.3` (compatible with Flask-APScheduler)
- `Flask-APScheduler==1.13.0` → `Flask-APScheduler==1.13.1` (latest compatible version)
- `Flask-SQLAlchemy==3.1.1` → `Flask-SQLAlchemy==3.0.5` (compatible with Flask 2.3)
- `werkzeug==3.0.1` → `werkzeug==2.3.7` (compatible with Flask 2.3)

### Why These Versions?
- Flask 2.3.3 is the latest stable 2.x version
- Flask-APScheduler 1.13.1 supports Flask 2.2.5 to <3.0.0
- All other packages are compatible with Flask 2.3.3
- These versions are well-tested and stable

## Verification
After rebuilding, the webapp container should build successfully:

```bash
docker compose build webapp
docker compose up -d webapp
```

## Note
If you need Flask 3.0+ features in the future, you'll need to wait for Flask-APScheduler to support it, or use an alternative scheduling solution.

