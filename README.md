# BrandShield

**Automated brand protection for @erim & @byerim**

> Formerly "Brand Shield" — rebranded to BrandShield (brand-shield.onrender.com)

Live dashboard: [https://brand-shield.onrender.com](https://brand-shield.onrender.com)
Future domain: **brand-shield.onrender.com** (in progress)

---

## What It Does

BrandShield monitors the web for brand threats against **Erim Kaur (@erim)** and **ByErim (@byerim)**:

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
| `RESEND_FROM` | optional | From address (default: `BrandShield <legal@byerim.com>`) |
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
5. Set `RESEND_FROM` to `BrandShield <legal@byerim.com>`

---

## Search Backend

BrandShield uses a dual-engine approach:

1. **DuckDuckGo** (default, no API key) — runs via HTML scraper, free, ~10 results/query
2. **Google Custom Search** (optional upgrade) — 100 free searches/day, more accurate

To upgrade to Google CSE:
1. Create a Custom Search Engine at [cse.google.com](https://cse.google.com)
2. Get an API key from Google Cloud Console
3. Set `GOOGLE_CSE_API_KEY` and `GOOGLE_CSE_CX` in Render

---

## Logins

**Never commit passwords to this (public) repo.** Set `ADMIN_USER` and
`ADMIN_PASSWORD` in the Render environment. If unset, a random password is
generated on first boot and printed once to the server logs.

> ⚠️ The previously hardcoded logins are permanently in git history and must
> be considered compromised — delete `data/users.json` on the server, set the
> env vars, and redeploy.

---

## End-to-End Takedowns

The **+ New Takedown** button on the dashboard (or `POST /api/takedown`) runs
the full pipeline: paste an infringing URL → threat record → correct legal
route → recipient resolution → draft notice(s) → one-click send → automatic
deadline tracking and follow-up.

Legal routes (auto-selected by domain, overridable):

| Route | Basis | Deadline tracked |
|---|---|---|
| `ncii` | TAKE IT DOWN Act (Pub. L. 119-12) — non-consensual intimate imagery incl. deepfakes; FTC-enforced since 19 May 2026 | 48 hours |
| `dmca` | 17 U.S.C. § 512(c)(3) copyright | 72 hours |
| `both` | Sends both notices | per notice |

Recipient resolution order: built-in registry (`backend/services/takedown.py`)
→ `TAKEDOWN_CONTACTS` env JSON override → RDAP registrar-abuse lookup →
manual. Sites that hide their abuse email behind JS bot-protection (e.g.
erome) need the address confirmed once in a browser, then stored:

```
TAKEDOWN_CONTACTS={"erome.com": {"email": "<address from https://www.erome.com/s/report>"}}
```

**Fully automated by default** (`AUTO_SEND_TAKEDOWNS=true`): notices are sent
via Resend the moment they're generated — from the dashboard, the API, or the
scheduled leak-site sweep. The only hard gate: auto-send is blocked until
`DMCA_SIGNER_NAME`, `DMCA_ADDRESS`, and `DMCA_EMAIL` are set (a sworn notice
with blank identity fields is legally void — set them once, then everything
is zero-touch).

The automation loop, end to end:

1. **Discover** — 6-hourly scans now include a leak-site sweep
   (`site:erome.com` etc. + "leaked" queries, safesearch off) alongside the
   existing impersonation/counterfeit scans.
2. **Notice** — every leak-site hit auto-creates a critical threat, picks the
   route (NCII 48h / DMCA), resolves the recipient, generates and sends.
3. **Chase** — hourly deadline job auto-sends one follow-up when the 48h/72h
   clock expires.
4. **Escalate** — still no response → notice marked `overdue`, registrar
   abuse contact auto-emailed via RDAP lookup (`AUTO_ESCALATE=true`).
5. **Alert** — every auto-sent notice, follow-up, and overdue escalation
   emails `REPORT_RECIPIENTS` immediately; weekly report summarises.

What stays human (deliberately): the one-time claimant config, confirming
JS-hidden abuse emails (`TAKEDOWN_CONTACTS`), and filing FTC complaints for
overdue NCII notices — that's a legal filing the alert email walks you through.

Additional env vars:

| Variable | Purpose |
|---|---|
| `ADMIN_USER` / `ADMIN_PASSWORD` | Dashboard login (required — see above) |
| `DMCA_SIGNER_NAME` | Full legal name of the person signing notices (**required for auto-send**) |
| `DMCA_ADDRESS` / `DMCA_PHONE` / `DMCA_EMAIL` | Claimant contact block (**address+email required for auto-send**) |
| `AUTO_SEND_TAKEDOWNS` | Default `true` — auto-send notices via Resend; `false` = drafts for review |
| `AUTO_ESCALATE` | Default `true` — auto-email registrar abuse contact when a notice goes overdue |
| `TAKEDOWN_CONTACTS` | JSON map of domain → contact overrides |
| `SEED_DEMO` | `true` to load demo data (default off — demo data no longer pollutes prod) |

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
# Fix: Redeploy trigger
