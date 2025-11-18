# Fixes Applied for Ubuntu Jump Server Setup

## Issues Fixed

### 1. Package Availability Issues

**Problem:**
- `nikto` package not available in Debian Bookworm standard repositories
- `openjdk-11-jre-headless` replaced with OpenJDK 17 in Debian Bookworm

**Solution:**
- ✅ Updated to `openjdk-17-jre-headless` (Debian Bookworm default)
- ✅ Added fallback installation for `nikto` from source if package not available
- ✅ Added required Perl dependencies for nikto
- ✅ Removed unnecessary `docker.io` and `docker-compose` packages (using Docker CLI via socket mount)

### 2. Docker Compose Build Command

**Problem:**
- `--pull` flag not supported in older docker-compose versions
- Version warning about obsolete `version` attribute

**Solution:**
- ✅ Removed `--pull` flag from build command
- ✅ Added fallback to `docker-compose` (v1) if `docker compose` (v2) not available
- ✅ Removed `version: '3.8'` from docker-compose.yml (obsolete in newer versions)
- ✅ Added graceful error handling for build failures

### 3. Additional Improvements

- ✅ Added `lsb-release` package (needed for `lsb_release` command in Docker installation)
- ✅ Better error handling in nikto installation
- ✅ Improved comments in Dockerfile

## Files Modified

1. **Dockerfile.scanner**
   - Updated Java version to OpenJDK 17
   - Added nikto fallback installation from source
   - Removed unnecessary docker-compose package
   - Added lsb-release package

2. **setup-ubuntu-jump-server.sh**
   - Fixed docker compose build command
   - Removed --pull flag
   - Added fallback for docker-compose v1
   - Better error handling

3. **docker-compose.yml**
   - Removed obsolete version attribute

## Testing

After applying these fixes, run:

```bash
# Rebuild the images
sudo ./setup-ubuntu-jump-server.sh

# Or manually:
docker compose build
docker compose up -d
```

## Verification

To verify the fixes worked:

```bash
# Check scanner container has all tools
docker compose exec scanner nikto -Version
docker compose exec scanner java -version  # Should show OpenJDK 17
docker compose exec scanner nmap --version
docker compose exec scanner lynis --version
```

## Next Steps

1. Pull latest changes from GitHub
2. Run setup script again: `sudo ./setup-ubuntu-jump-server.sh`
3. Start services: `docker compose up -d`
4. Verify all containers are running: `docker compose ps`

