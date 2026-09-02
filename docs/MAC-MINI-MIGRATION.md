# BrandShield — Mac Mini migration runbook

Moves the `brand-shield` web service off Render (Starter instance, ~$7/month)
onto the Mac Mini as a launchd LaunchAgent. Nothing about the app changes:
same code, same env vars, same daily scan at `SCAN_HOUR_UTC`, same Resend
emails. The only functional difference is that the dashboard is no longer on
a public URL — it listens on `127.0.0.1:5050` and is reached over Tailscale.

There is no data to migrate. On Render the SQLite database lived on the
instance's ephemeral disk and was wiped on every deploy (see `docs/ICE.md`
§3), so the Mini starts from an empty DB exactly as each Render deploy did.

## On the Mac Mini (once)

```bash
# 1. Code
mkdir -p ~/code && cd ~/code
git clone https://github.com/S7SSL/brand-shield.git
cd brand-shield

# 2. Venv, data dir, .env template, launchd plists
bash scripts/install-mac.sh

# 3. Bring the env vars across. In the Render dashboard: brand-shield ->
#    Environment -> Export -> "Download .env". Then merge it over the template
#    the installer wrote, and set the Mac-specific values on top:
cat ~/Downloads/.env >> .env          # Render's values win (later lines override)
cat >> .env <<'MAC'
BS_DATA_DIR="$HOME/Library/Application Support/brand-shield"
HOST=127.0.0.1
PORT=5050
DEBUG=false
MAC
open -e .env                          # eyeball it: quote any value with spaces or < >

# 4. Start it, and the 03:30 daily DB backup
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.byerim.brand-shield.plist
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.byerim.brand-shield-backup.plist

# 5. Verify
curl -s http://127.0.0.1:5050/health
tail -20 ~/Library/Logs/brand-shield.log
```

`/health` should return JSON with `"status": "ok"` (or `"degraded"` until the
first scan has run — that is expected on a fresh DB). The log should show
`Scheduler started` with the next scan time.

## Then, on Render

1. Dashboard → `brand-shield` → Settings → **Suspend Web Service**. Suspended
   services are not billed; the config stays so it can be resumed if needed.
2. Delete the cron-job.org keep-alive job that pinged
   `https://brand-shield.onrender.com/health` every 5 minutes — it only
   existed to stop the free tier sleeping, and will now just log failures.

## Day to day

| Task | Command |
|---|---|
| Logs | `tail -f ~/Library/Logs/brand-shield.log` |
| Restart | `launchctl kickstart -k gui/$(id -u)/com.byerim.brand-shield` |
| Stop | `launchctl bootout gui/$(id -u)/com.byerim.brand-shield` |
| Start | `launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.byerim.brand-shield.plist` |
| Update code | `cd ~/code/brand-shield && git pull && .venv/bin/pip install -r requirements.txt && launchctl kickstart -k gui/$(id -u)/com.byerim.brand-shield` |
| Change env | edit `~/code/brand-shield/.env`, then restart |
| Dashboard | `http://127.0.0.1:5050` on the Mini, or `http://<mini-tailscale-name>:5050` from any device on the tailnet |
| DB | `~/Library/Application Support/brand-shield/brand_shield.db`; daily snapshots in `~/Documents/Claude/brand-shield-backups/` |

Auto-deploy on push no longer exists (that was Render). Pull and restart by
hand after merging, or add a `git pull` to a scheduled task if that becomes a
chore.

## If the Mini is off

The scan simply does not run that day; nothing queues. The deadline job that
flags overdue notices catches up at the next start. Keep the Mini set to
restart after power failure (System Settings → Energy) and the LaunchAgent
(`RunAtLoad`) brings the service back with it.
