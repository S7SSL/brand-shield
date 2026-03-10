# BrandDefend

**Automated brand protection for @erim & @byerim**

> Formerly "Brand Shield" — rebranded to BrandDefend (branddefend.ai)

Live dashboard: [https://brand-shield.onrender.com](https://brand-shield.onrender.com)
Future domain: **branddefend.ai** (in progress)

---

## What It Does

BrandDefend monitors the web for brand threats against **Erim Kaur (@erim)** and **ByErim (@byerim)**:

- 🔍 **Scans** Google/DuckDuckGo for impersonation accounts, counterfeit products, content theft
- 🚨 **Detects** and scores threats by severity (critical / high / medium / low)
- 📋 **Generates** DMCA takedown notices (Meta, Amazon, Shopify, Twitter, general)
- 📧 **Sends** notices via Resend API or SMTP
- 📊 **Dashboard** with threat management, DMCA workflow, weekly reports
- 🔄 **Scheduler** runs scans every 6 hours automatically

---

## Tech Stack

- **Backend**: Python / Flask + Gunicorn
- **Database**: SQLite (WAL mode)
- **Search**: DuckDuckGo HTML scraper (no key) + Google CSE (optional)
- **Email**: Resend API (preferred) or SMTP
- **Scheduler**: APScheduler (background)
- **Hosting**: Render.com (free tier)

---

## Setup & Environment Variables

Set these in Render dashboard under **Environment**:

| Variable | Required | Description |
|---|---|---|
| `SECRET_KEY` | ✅ | Flask session secret — set to a long random string |
| `RESEND_API_KEY` | ✅ recommended | Resend API key for email. Get free at [resend.com](https://resend.com) — 3,000 emails/month free |
| `RESEND_FROM` | optional | From address (default: `BrandDefend <legal@byerim.com>`) |
| `GOOGLE_CSE_API_KEY` | optional | Google Custom Search API key (upgrade from DDG) |
| `GOOGLE_CSE_CX` | optional | Google Custom Search Engine ID |
| `SMTP_HOST` | optional | SMTP host (alternative to Resend) |
| `SMTP_USER` | optional | SMTP username |
| `SMTP_PASS` | optional | SMTP password |
| `REPORT_RECIPIENTS` | optional | Comma-separated email list for weekly reports (default: `sat@byerim.com,erim@byerim.com`) |

---

## Keep-Alive (Prevent Render Sleep)

Render free tier spins down after 15 minutes of inactivity, killing the scheduler.

**Fix:** Set up a free cron job at [cron-job.org](https://cron-job.org) to ping `/health` every 5 minutes:

1. Go to [cron-job.org](https://cron-job.org) → Create free account
2. New cron job → URL: `https://brand-shield.onrender.com/health`
3. Schedule: every 5 minutes
4. Enable → Save

The `/health` endpoint returns scheduler status and last scan time.

---

## Email (Resend Setup)

1. Sign up at [resend.com](https://resend.com) — free tier = 3,000 emails/month
2. Add & verify your domain (`byerim.com`) under **Domains**
3. Create an API key under **API Keys**
4. Set `RESEND_API_KEY` in Render environment variables
5. Set `RESEND_FROM` to `BrandDefend <legal@byerim.com>`

---

## Search Backend

BrandDefend uses a dual-engine approach:

1. **DuckDuckGo** (default, no API key) — runs via HTML scraper, free, ~10 results/query
2. **Google Custom Search** (optional upgrade) — 100 free searches/day, more accurate

To upgrade to Google CSE:
1. Create a Custom Search Engine at [cse.google.com](https://cse.google.com)
2. Get an API key from Google Cloud Console
3. Set `GOOGLE_CSE_API_KEY` and `GOOGLE_CSE_CX` in Render

---

## Default Logins

| Username | Password | Role |
|---|---|---|
| `sat` | `BrandShield2026!` | Admin |
| `erim` | `ByErim2026!` | Brand owner |

---

## Deployment

```bash
# Auto-deployed via Render on push to main
git push origin main
```

Render config in `render.yaml`.

---

## Architecture

```
brand-shield/
├── backend/
│   ├── app.py              # Flask API server
│   ├── auth.py             # Session auth
│   ├── config.py           # Brand config (keywords, handles, etc.)
│   ├── database.py         # SQLite layer
│   ├── scrapers/
│   │   ├── duckduckgo_search.py  # DDG scraper (primary, no key needed)
│   │   └── google_search.py      # Google CSE (optional upgrade)
│   ├── services/
│   │   ├── scanner.py      # Scan orchestrator
│   │   ├── detector.py     # Threat scoring
│   │   ├── scheduler.py    # APScheduler jobs
│   │   └── reporter.py     # Weekly email reports
│   ├── templates/          # DMCA notice templates
│   └── static/             # Dashboard + login HTML
├── requirements.txt
├── render.yaml
└── Procfile
```
