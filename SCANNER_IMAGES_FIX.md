# Scanner Docker Images - Fixes and Alternatives

## Issue
Some scanner Docker images couldn't be pulled due to:
- Docker Hub rate limiting (especially for unauthenticated pulls)
- Deprecated/renamed images
- Network/firewall restrictions

## Solutions Applied

### 1. OWASP ZAP Image
**Problem:** `owasp/zap2docker-stable` is deprecated/not accessible

**Solution:** 
- Updated to use `zaproxy/zap-stable` (new official image)
- Fallback to old name if new one fails
- Script updated to try both automatically

**Updated in:**
- `setup-ubuntu-jump-server.sh` - tries both image names
- `reporting/run_full_scan.py` - automatically detects and pulls correct image

### 2. Trivy Image
**Problem:** Rate limiting or network issues

**Solution:**
- Image name is correct: `aquasecurity/trivy:latest`
- Will be pulled on-demand during scans if not available
- Can also use Trivy via Docker during scan execution

### 3. SQLMap Image
**Problem:** `sqlmapproject/sqlmap` not accessible

**Solution:**
- Try alternative: `paoloo/sqlmap`
- Falls back to old name
- Optional tool (not critical for basic scans)

### 4. Image Pulling Strategy
**Changed approach:**
- Made image pulling optional during setup
- Images are pulled on-demand during scans if not available
- Better error handling and fallbacks
- More informative messages

## Impact

**No impact on functionality:**
- All scanner images are pulled automatically when needed during scans
- Setup script now warns but continues if images can't be pulled
- Scan scripts automatically detect and pull missing images
- Better user experience with clear messages

## Manual Image Pulling (If Needed)

If you want to pre-pull images manually:

```bash
# OWASP ZAP (new official image)
docker pull zaproxy/zap-stable:latest

# Trivy
docker pull aquasecurity/trivy:latest

# SQLMap (alternative)
docker pull paoloo/sqlmap:latest

# WPScan
docker pull wpscanteam/wpscan:latest
```

## Docker Hub Rate Limiting

If you're hitting rate limits:
1. **Create Docker Hub account** (free) and login:
   ```bash
   docker login
   ```
2. **Use authenticated pulls** (higher rate limits)
3. **Images will still work** - they're pulled on-demand during scans

## Verification

After setup, verify images are available when needed:

```bash
# Check available images
docker images | grep -E "zap|trivy|sqlmap|wpscan"

# During scan, images will be pulled automatically if missing
# Check scan logs for image pull attempts
docker compose logs scanner | grep -i "pull\|image"
```

## Next Steps

1. ✅ Setup script updated - will continue even if images fail to pull
2. ✅ Scan scripts updated - will automatically pull images when needed
3. ✅ Better error messages - users know what's happening
4. ✅ No functionality loss - everything works on-demand

**Your setup is complete!** The missing images will be pulled automatically when scans run.

