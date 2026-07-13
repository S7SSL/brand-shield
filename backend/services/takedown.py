"""
End-to-end takedown orchestration for BrandDefend.

One call does the whole chain:
    URL -> threat record -> correct legal route (DMCA / NCII / both)
        -> recipient resolution (registry -> RDAP abuse lookup -> manual)
        -> notice generation from template -> (optional) send -> deadline tracking.

Legal routes:
  * "dmca"  — copyright, 17 U.S.C. § 512(c)(3). Deadline: expeditious (we track 72h).
  * "ncii"  — non-consensual intimate imagery, TAKE IT DOWN Act (Pub. L. 119-12,
              in force 19 May 2026, FTC-enforced). Platforms must remove within
              48 HOURS of a valid request. Also covers AI/edited "deepfakes".

Notices are created as DRAFTS by default. A human clicks send (or passes
send=true). Follow-ups on already-sent notices are automated.
"""
import os
import json
import logging
from datetime import datetime, timezone, timedelta
from pathlib import Path
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "templates"

# Hours until a sent notice is considered overdue, per legal basis.
DEADLINE_HOURS = {"ncii": 48, "dmca": 72, "general": 72}

# ─── Recipient registry ────────────────────────────────────────────────
# Known hosts and their takedown channels. Extend freely.
# email=None means the contact must be confirmed once (many adult sites hide
# the address behind JS bot-protection — open form_url in a browser, read the
# address, then set it via the TAKEDOWN_CONTACTS env override or edit here).
#
# Env override (JSON), merged on top of this registry:
#   TAKEDOWN_CONTACTS='{"erome.com": {"email": "abuse@..."}}'
TAKEDOWN_REGISTRY = {
    # ── Adult / leak sites ─────────────────────────────────────────
    "erome.com": {
        "email": None,  # JS-protected — read once at form_url, then set TAKEDOWN_CONTACTS
        "form_url": "https://www.erome.com/s/report",
        "agent": "DMCA Now LLC, 100 S. Dixie Hwy., 3rd Floor, West Palm Beach, FL 33401 (fax +1 800-371-0235)",
        "default_basis": "ncii",
        "notes": "Also supports DigiRegs auto-matching (digiregs.com). Report button on album pages.",
    },
    # ── Mainstream platforms ───────────────────────────────────────
    "instagram.com": {"email": "ip@fb.com", "form_url": "https://help.instagram.com/contact/372592039493026", "default_basis": "dmca"},
    "facebook.com": {"email": "ip@fb.com", "form_url": "https://www.facebook.com/help/contact/634636770043106", "default_basis": "dmca"},
    "tiktok.com": {"email": "legal@tiktok.com", "form_url": "https://www.tiktok.com/legal/report/Copyright", "default_basis": "dmca"},
    "twitter.com": {"email": None, "form_url": "https://help.twitter.com/forms/dmca", "default_basis": "dmca"},
    "x.com": {"email": None, "form_url": "https://help.twitter.com/forms/dmca", "default_basis": "dmca"},
    "youtube.com": {"email": None, "form_url": "https://www.youtube.com/copyright_complaint_form", "default_basis": "dmca"},
    "shopify.com": {"email": "legal@shopify.com", "form_url": "https://www.shopify.com/legal/dmca", "default_basis": "dmca"},
    "amazon.com": {"email": "copyright@amazon.com", "form_url": "https://www.amazon.com/report/infringement", "default_basis": "dmca"},
    "telegram.org": {"email": "dmca@telegram.org", "form_url": None, "default_basis": "dmca"},
    "reddit.com": {"email": None, "form_url": "https://www.reddit.com/report", "default_basis": "dmca"},
}

# Domains whose content class implies the NCII route should be offered.
ADULT_SITE_HINTS = ("erome", "porn", "xvideo", "xhamster", "xnxx", "coomer",
                    "kemono", "fapello", "thothub", "leak", "nsfw", "onlyfans",
                    "redgifs", "motherless", "spankbang")


def _merged_registry():
    """Registry with TAKEDOWN_CONTACTS env JSON merged on top."""
    reg = {k: dict(v) for k, v in TAKEDOWN_REGISTRY.items()}
    raw = os.getenv("TAKEDOWN_CONTACTS", "")
    if raw:
        try:
            for domain, entry in json.loads(raw).items():
                reg.setdefault(domain.lower(), {}).update(entry)
        except Exception as e:
            logger.warning(f"Bad TAKEDOWN_CONTACTS JSON ignored: {e}")
    return reg


def registrable_domain(url_or_host: str) -> str:
    """'https://www.erome.com/a/x' -> 'erome.com' (naive eTLD+1, good enough here)."""
    host = url_or_host
    if "//" in host:
        host = urlparse(url_or_host).netloc or url_or_host
    host = host.lower().split(":")[0]
    if host.startswith("www."):
        host = host[4:]
    parts = host.split(".")
    if len(parts) >= 3 and parts[-2] in ("co", "com", "org", "net", "ac", "gov") and len(parts[-1]) == 2:
        return ".".join(parts[-3:])  # e.g. bbc.co.uk
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def rdap_abuse_lookup(domain: str, timeout: int = 10):
    """Best-effort abuse contact from RDAP (registrar abuse email). Returns str or None."""
    import requests
    try:
        resp = requests.get(f"https://rdap.org/domain/{domain}", timeout=timeout,
                            headers={"Accept": "application/rdap+json"})
        if resp.status_code != 200:
            return None
        data = resp.json()
        for ent in data.get("entities", []):
            stack = [ent] + ent.get("entities", [])
            for e in stack:
                if "abuse" in (e.get("roles") or []):
                    for v in (e.get("vcardArray") or [None, []])[1]:
                        if v and v[0] == "email":
                            return v[3]
    except Exception as e:
        logger.info(f"RDAP lookup failed for {domain}: {e}")
    return None


def resolve_recipient(url: str, use_rdap: bool = True) -> dict:
    """
    Resolve the takedown channel for a URL.
    Returns {domain, email, cc, form_url, agent, default_basis, source, notes}.
    """
    domain = registrable_domain(url)
    reg = _merged_registry()
    entry = dict(reg.get(domain, {}))
    result = {
        "domain": domain,
        "email": entry.get("email"),
        "cc": entry.get("cc"),
        "form_url": entry.get("form_url"),
        "agent": entry.get("agent"),
        "default_basis": entry.get("default_basis"),
        "notes": entry.get("notes", ""),
        "source": "registry" if entry else None,
    }
    if not result["default_basis"]:
        result["default_basis"] = (
            "ncii" if any(h in domain for h in ADULT_SITE_HINTS) else "dmca"
        )
    if not result["email"] and use_rdap:
        abuse = rdap_abuse_lookup(domain)
        if abuse:
            result["email"] = abuse
            result["source"] = result["source"] or "rdap"
            result["notes"] = (result["notes"] + " Recipient from registrar RDAP abuse "
                               "contact — registrar-level, escalation channel.").strip()
    if not result["source"]:
        result["source"] = "unresolved"
    return result


# ─── Notice generation ─────────────────────────────────────────────────

def _claimant():
    from backend.config import DMCA_CLAIMANT
    c = dict(DMCA_CLAIMANT)
    # Env overrides so real legal details never need to live in git
    c["signer"] = os.getenv("DMCA_SIGNER_NAME", c.get("signer", c.get("name", "")))
    c["address"] = os.getenv("DMCA_ADDRESS", c.get("address", ""))
    c["phone"] = os.getenv("DMCA_PHONE", c.get("phone", ""))
    c["email"] = os.getenv("DMCA_EMAIL", c.get("email", ""))
    return c


def fill_template(template_name: str, mapping: dict) -> str:
    path = TEMPLATE_DIR / template_name
    if not path.exists():
        path = TEMPLATE_DIR / "dmca_general.txt"
    body = path.read_text()
    for key, value in mapping.items():
        body = body.replace("{{ %s }}" % key, str(value if value is not None else ""))
    return body


def build_notice_bodies(url: str, basis: str, threat: dict, recipient: dict,
                        extra: dict = None) -> list:
    """Return [(notice_type, template, subject, body), ...] for the legal basis."""
    extra = extra or {}
    c = _claimant()
    now = datetime.now(timezone.utc)
    common = {
        "date": now.strftime("%d %B %Y"),
        "claimant_name": c.get("name", ""),
        "signer_name": c.get("signer", ""),
        "company": c.get("company", ""),
        "claimant_email": c.get("email", ""),
        "claimant_address": c.get("address", ""),
        "claimant_phone": c.get("phone", ""),
        "claimant_website": c.get("website", ""),
        "infringing_url": url,
        "infringer_username": threat.get("infringer_username", "") or "Unknown",
        "infringing_platform": recipient["domain"],
        "recipient_name": extra.get("recipient_name", "Abuse / Copyright Team"),
        "copyright_agent": recipient.get("agent") or "Designated Copyright Agent",
        "original_url": extra.get("original_url", c.get("website", "")),
        "original_description": extra.get(
            "original_description",
            f"Original content created and owned by {threat.get('brand', c.get('name', ''))}"),
        "evidence_description": extra.get(
            "evidence_description",
            "The material at the identified URL reproduces the claimant's original "
            "content without licence or authorisation."),
        "confidence": str(int((threat.get("confidence") or 1.0) * 100)),
        "product_title": extra.get("product_title", "N/A"),
    }
    notices = []
    if basis in ("ncii", "both"):
        subject = (f"URGENT: NCII Removal Request (48-Hour Removal Required — "
                   f"TAKE IT DOWN Act) — {url}")
        notices.append(("ncii", "ncii_removal.txt", subject,
                        fill_template("ncii_removal.txt", common)))
    if basis in ("dmca", "both"):
        subject = f"DMCA Takedown Notice — 17 U.S.C. § 512(c)(3) — {url}"
        notices.append(("dmca", "dmca_general.txt", subject,
                        fill_template("dmca_general.txt", common)))
    return notices


# ─── Orchestrator ──────────────────────────────────────────────────────

def create_takedown(url: str, brand: str = "@erim", basis: str = None,
                    send: bool = False, recipient_email: str = None,
                    severity: str = "critical", extra: dict = None) -> dict:
    """
    Full pipeline: URL -> threat -> notice draft(s) (-> send).
    basis: 'dmca' | 'ncii' | 'both' | None (auto from registry/domain).
    Returns dict with threat, notices, recipient info, warnings.
    """
    from backend.database import query, execute

    warnings = []
    recipient = resolve_recipient(url)
    basis = basis or recipient["default_basis"]
    if recipient_email:
        recipient["email"] = recipient_email
        recipient["source"] = "manual"

    domain = recipient["domain"]
    is_adult = any(h in domain for h in ADULT_SITE_HINTS)
    threat_type = "leaked_content" if is_adult else "content_theft"

    # Reuse an existing open threat for the same URL, else create one.
    existing = query(
        "SELECT * FROM threats WHERE detected_url = ? AND status NOT IN ('resolved','ignored')",
        (url,), one=True)
    if existing:
        threat_id = existing["id"]
        threat = existing
    else:
        threat_id = execute(
            """INSERT INTO threats (brand, threat_type, severity, platform, detected_url,
               infringer_username, confidence, evidence_json, status, notes)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (brand, threat_type, severity, domain, url, "", 1.0,
             json.dumps({"source": "manual_takedown", "basis": basis}),
             "new", f"Manual takedown request ({basis})"))
        threat = query("SELECT * FROM threats WHERE id = ?", (threat_id,), one=True)

    if not recipient["email"]:
        warnings.append(
            f"No email contact resolved for {domain}. "
            + (f"Submit via form: {recipient['form_url']}. " if recipient.get("form_url") else "")
            + "Notice saved as draft — set a recipient before sending "
              "(TAKEDOWN_CONTACTS env var, or pass recipient_email).")

    created = []
    for notice_type, template, subject, body in build_notice_bodies(
            url, basis, threat, recipient, extra):
        deadline_hours = DEADLINE_HOURS.get(notice_type, 72)
        nid = execute(
            """INSERT INTO dmca_notices (threat_id, notice_type, template_used,
               recipient_email, recipient_platform, subject_line, body, status,
               legal_basis, deadline_hours)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (threat_id, notice_type, template, recipient["email"] or "",
             domain, subject, body, "draft", notice_type, deadline_hours))

        sent = False
        if send and recipient["email"]:
            try:
                from backend.app import send_email
                send_email(recipient["email"], subject, body)
                now = datetime.now(timezone.utc)
                deadline = (now + timedelta(hours=deadline_hours)).isoformat()
                execute("UPDATE dmca_notices SET status='sent', sent_at=?, deadline_at=? WHERE id=?",
                        (now.isoformat(), deadline, nid))
                sent = True
            except Exception as e:
                warnings.append(f"Send failed for notice {nid}: {e}")
        elif send and not recipient["email"]:
            warnings.append(f"Notice {nid} not sent — no recipient email.")

        created.append({**query("SELECT * FROM dmca_notices WHERE id = ?", (nid,), one=True),
                        "sent_now": sent})

    execute("UPDATE threats SET status = 'reported' WHERE id = ?", (threat_id,))

    return {
        "threat": query("SELECT * FROM threats WHERE id = ?", (threat_id,), one=True),
        "recipient": recipient,
        "basis": basis,
        "notices": created,
        "warnings": warnings,
        "next_steps": ([recipient["form_url"]] if recipient.get("form_url") else [])
    }


def mark_notice_sent(nid: int):
    """Stamp sent_at + deadline when a draft is sent through any path."""
    from backend.database import query, execute
    n = query("SELECT * FROM dmca_notices WHERE id = ?", (nid,), one=True)
    if not n:
        return
    hours = n.get("deadline_hours") or DEADLINE_HOURS.get(n.get("legal_basis") or "", 72)
    now = datetime.now(timezone.utc)
    execute("UPDATE dmca_notices SET status='sent', sent_at=?, deadline_at=? WHERE id=?",
            (now.isoformat(), (now + timedelta(hours=hours)).isoformat(), nid))


def check_deadlines_and_followup() -> dict:
    """
    Scheduler job: find sent notices past their deadline with no response.
    First breach -> send ONE follow-up email and mark followup_sent_at.
    Already followed-up + another deadline period elapsed -> status 'overdue'
    (surfaces in dashboard + weekly report for human escalation: FTC complaint
    for NCII, host/registrar abuse for DMCA).
    """
    from backend.database import query, execute

    now = datetime.now(timezone.utc)
    now_iso = now.isoformat()
    followed_up, overdue = 0, 0

    breached = query(
        """SELECT * FROM dmca_notices
           WHERE status = 'sent' AND deadline_at IS NOT NULL AND deadline_at < ?
             AND response_at IS NULL""", (now_iso,))
    for n in breached:
        if not n.get("followup_sent_at"):
            body = (
                f"FOLLOW-UP — REMOVAL DEADLINE PASSED\n\n"
                f"On {n.get('sent_at', '')} we sent the notice below regarding:\n"
                f"  {n.get('recipient_platform', '')}\n\n"
                f"The removal deadline has now passed without confirmation of removal."
                + ("\n\nNon-consensual intimate imagery must be removed within 48 hours "
                   "under the TAKE IT DOWN Act (Pub. L. 119-12), enforceable by the US "
                   "Federal Trade Commission. Continued non-compliance will be reported "
                   "to the FTC." if n.get("legal_basis") == "ncii" else
                   "\n\nFailure to expeditiously remove infringing material upon valid "
                   "notification forfeits DMCA safe-harbor protection (17 U.S.C. § 512).")
                + "\n\nPlease confirm removal immediately.\n\n"
                  "--- ORIGINAL NOTICE ---\n\n" + (n.get("body") or ""))
            try:
                if n.get("recipient_email"):
                    from backend.app import send_email
                    send_email(n["recipient_email"], "FOLLOW-UP: " + (n.get("subject_line") or ""), body)
                    execute("UPDATE dmca_notices SET followup_sent_at = ? WHERE id = ?",
                            (now_iso, n["id"]))
                    followed_up += 1
                else:
                    execute("UPDATE dmca_notices SET status = 'overdue' WHERE id = ?", (n["id"],))
                    overdue += 1
            except Exception as e:
                logger.error(f"Follow-up send failed for notice {n['id']}: {e}")
        else:
            # Follow-up already sent; give one more deadline period, then escalate.
            try:
                fu = datetime.fromisoformat(n["followup_sent_at"])
                if fu.tzinfo is None:
                    fu = fu.replace(tzinfo=timezone.utc)
            except Exception:
                fu = now
            hours = n.get("deadline_hours") or 72
            if now > fu + timedelta(hours=hours):
                execute("UPDATE dmca_notices SET status = 'overdue' WHERE id = ?", (n["id"],))
                overdue += 1

    if followed_up or overdue:
        logger.info(f"[TAKEDOWN] follow-ups sent: {followed_up}, marked overdue: {overdue}")
    return {"followups_sent": followed_up, "marked_overdue": overdue}
