# erimkaur.com — Cloudflare migration runbook

> Date: 2026-05-01.
> Reason: needed a Cloudflare zone we own to host a Cloudflare Tunnel
> hostname for `brand-shield.erimkaur.com`, since neither byerim.com nor
> the existing clearlegacy.co.uk gave us the right brand association.
> If anything breaks, follow §6 (Rollback) — should restore the prior
> state in 5–60 minutes (DNS propagation dependent).

---

## 1. Pre-migration state (before any change)

**Domain:** erimkaur.com
**Registrar:** IONOS (UI / 1&1)
**Authoritative DNS (current):** IONOS, via these four nameservers:

```
ns1022.ui-dns.biz
ns1099.ui-dns.org
ns1097.ui-dns.de
ns1094.ui-dns.com
```

**Where each thing is hosted:**

| What | Where |
|---|---|
| Apex website (erimkaur.com) | GitHub Pages — A records to 185.199.108.153, .109.153, .110.153, .111.153 |
| `www.erimkaur.com` | GitHub Pages — CNAME → `s7ssl.github.io` |
| Email (anything `@erimkaur.com`) | Google Workspace — MX records to alt1–4.aspmx.l.google.com |
| Site source | `S7SSL/brand-shield` repo, `erimkaur-site/` directory (deployed via GitHub Pages) |
| Domain ownership verification | Google site-verification TXT record |

**Full inventory of records on IONOS** (from `dig +short` 2026-05-01):

| Type | Name | Content | Notes |
|---|---|---|---|
| A | erimkaur.com | 185.199.111.153 | GitHub Pages |
| A | erimkaur.com | 185.199.110.153 | GitHub Pages |
| A | erimkaur.com | 185.199.108.153 | GitHub Pages |
| A | erimkaur.com | 185.199.109.153 | GitHub Pages |
| AAAA | erimkaur.com | (none) | — |
| CNAME | autodiscover.erimkaur.com | adsredir.ionos.in… | IONOS legacy mail autoconfig |
| CNAME | _domainconnect.erimkaur.com | _domainconnec… | IONOS Domain Connect (provisioning helper) |
| CNAME | www.erimkaur.com | s7ssl.github.io | GitHub Pages |
| MX | erimkaur.com | 5 alt1.aspmx.l.google.com | Google Workspace |
| MX | erimkaur.com | 5 alt2.aspmx.l.google.com | Google Workspace |
| MX | erimkaur.com | 10 alt3.aspmx.l.google.com | Google Workspace |
| MX | erimkaur.com | 10 alt4.aspmx.l.google.com | Google Workspace |
| TXT | erimkaur.com | google-site-verification=VOgJzwa-b1slDJQoswJLyfB5Arp4tu_61UgHqjJ8r1U | Workspace / Search Console |

**Pre-existing oddity** (not introduced by this migration): the standard
Google Workspace primary MX record `1 ASPMX.L.GOOGLE.COM` is missing —
only the four backup alts (priority 5 + 10) are present. Mail still
flows because mailservers fall back through the alt list. Worth fixing
later as a separate task.

---

## 2. Cloudflare side

**Account:** `Sat@byerim.com's Account` (account ID `f520d3a645627577b250957a7341a988`)
**Plan:** Free
**Zone:** erimkaur.com
**Records imported:** identical to the IONOS inventory above
**Proxy status set on import:** all proxiable records (A, CNAME) flipped
to **DNS only** (gray cloud) before activation, because:
- GitHub Pages SSL needs the request to arrive at GitHub's IPs directly;
  Cloudflare proxy in default "Flexible" SSL mode breaks the cert.
- IONOS legacy CNAMEs (`autodiscover`, `_domainconnect`) point at IONOS
  hosts and would 404 through Cloudflare's edge.

So Cloudflare is acting purely as authoritative DNS, no proxy. We can
flip individual records to Proxied later once we configure SSL/TLS to
Full / Full (strict) and verify each origin.

**Cloudflare-assigned nameservers (the 2 we have to set at IONOS):**

```
amy.ns.cloudflare.com
todd.ns.cloudflare.com
```

These are unique per zone — Cloudflare assigns them at activation time
and they don't change. If for any reason the IONOS form rejects them,
re-check by signing in to the Cloudflare dashboard for erimkaur.com →
Overview, the values are listed there too.

---

## 3. Cutover step (the only irreversible part)

Done once the records above are confirmed correct in Cloudflare:

1. Sign in to IONOS.
2. Open erimkaur.com → Nameservers / DNS → switch from "1&1 IONOS" /
   custom NS to "Custom nameservers".
3. Replace the four `*.ui-dns.*` entries with the **two** Cloudflare
   nameservers from §2.
4. Save.
5. Wait for propagation. Cloudflare will email
   `Sat@byerim.com` when the zone goes Active (usually < 1 hour, can take
   up to 24h in the worst case).

While propagation is in flight some resolvers will still reach IONOS
and some will reach Cloudflare. Because Cloudflare's record set was set
identical to IONOS's, both should resolve to the same answers and the
site + email keep working.

---

## 4. Post-cutover verification (must all pass)

```bash
# Should show two cloudflare.com NS values
dig +short NS erimkaur.com

# Site IPs — should still be the four 185.199.x.153 GitHub Pages IPs
dig +short A erimkaur.com

# Email — should still be the four alt[1-4].aspmx.l.google.com hosts
dig +short MX erimkaur.com

# www — should still resolve to s7ssl.github.io
dig +short CNAME www.erimkaur.com

# Open in browser — site loads, valid SSL cert
curl -I https://erimkaur.com
curl -I https://www.erimkaur.com

# Email — send a test message to whichever @erimkaur.com inbox is in use
```

If the site or email fails, see §6.

---

## 5. After verification — add the brand-shield CNAME

Once the zone is active in Cloudflare, the brand-shield Cloudflare
Tunnel route can be created:

```bash
# On the Mac Mini
cloudflared tunnel route dns brand-shield brand-shield.erimkaur.com
```

This adds a `CNAME brand-shield.erimkaur.com → <tunnel-id>.cfargotunnel.com`
record automatically. From that point on the dashboard is reachable at
`https://brand-shield.erimkaur.com` (with a Cloudflare-issued SSL cert,
proxied through Cloudflare → tunnel → 127.0.0.1:5050 on the Mac Mini).

---

## 6. Rollback — point DNS back at IONOS if the migration breaks something

This is the panic-button procedure. Total time-to-recovery: 5 min of
clicks + however long DNS propagation takes (usually ~5 min, occasionally
hours).

1. Sign in to IONOS.
2. Open erimkaur.com → Nameservers → switch back to "1&1 IONOS
   nameservers" (the default option). Or paste back these four explicitly:

   ```
   ns1022.ui-dns.biz
   ns1099.ui-dns.org
   ns1097.ui-dns.de
   ns1094.ui-dns.com
   ```

3. Save.
4. Wait for `dig NS erimkaur.com` to show `ui-dns.*` again — usually
   under 10 min on most resolvers, can take longer to clear globally.
5. Verify the site + email come back: `curl -I https://erimkaur.com`,
   send a test email.

The Cloudflare zone remains in place but inactive — Cloudflare won't be
authoritative any more. You can leave it or delete it from the
Cloudflare dashboard later. No data loss either way.

If, while rolling back, you discover that a record was missing on IONOS
that was present on Cloudflare (e.g. you'd added the brand-shield CNAME
in Cloudflare and never on IONOS), recreate it manually in IONOS's DNS
panel before relying on the rollback.

---

## 7. Why this was the right call

- byerim.com is the e-commerce domain → too critical to migrate without
  a planned maintenance window.
- erimkaur.com is a personal landing page → minimal blast radius if
  something goes wrong.
- We need a Cloudflare zone we own to use Cloudflare Tunnel.
- After this is done, brand-shield gets a clean URL on a brand-relevant
  domain (`brand-shield.erimkaur.com`) without re-doing this work.

---

## 8. Open follow-ups (non-blocking)

- Add the missing primary Google Workspace MX (`1 ASPMX.L.GOOGLE.COM`)
  in the Cloudflare DNS panel after activation — fixes a long-standing
  email config gap.
- Consider deleting `autodiscover` and `_domainconnect` CNAMEs (IONOS-
  specific, dead now that we're not on IONOS DNS).
- Once SSL/TLS mode in Cloudflare is set to "Full (strict)", you can
  flip the GitHub Pages A records and the `www` CNAME to Proxied for
  caching + DDoS protection.
