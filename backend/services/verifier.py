"""
Content verification for BrandShield.

Every candidate URL must pass verify_url() BEFORE any takedown notice is
generated. This exists because keyword+domain matching alone produced almost
entirely false positives — search-result pages (e.g. erome.com/search?q=italian),
unrelated content, and other people's names — which must never become sworn
NCII/DMCA notices (a false NCII claim is a perjurious misrepresentation).

A URL is only actionable when ALL of these hold:
  1. It is a specific content/profile page, not a search / listing / tag /
     category / "browse" page, and not a bare domain root.
  2. It actually resolves (HTTP 200). 404/410/errors mean nothing to action.
  3. Its page content genuinely references the brand's real identity — the
     full display name or a verified handle (>= 5 chars) — NOT a loose
     keyword. A standalone weak token like "erim" alone is not enough.

Even a verified URL is only ever QUEUED as a draft for human approval, with
the extracted evidence attached, because the final judgement of whether the
content is genuinely intimate / non-consensual / infringing is a human call.
"""
import re
import logging
from urllib.parse import urlparse, parse_qs

logger = logging.getLogger(__name__)

REQUEST_TIMEOUT = 15
_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
       "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")

# Path fragments that mark a listing / search / aggregation page — never a
# single specific piece of infringing content.
_NON_CONTENT_PATH = re.compile(
    r"/search\b|/s/|/tags?\b|/categor|/label/|/discover|/trending|/popular"
    r"|/latest|/random|/models?\b|/pornstars?\b|/channels?\b|/browse\b"
    r"|/genre|/most-|/results?\b", re.I)
_SEARCH_QUERY_KEYS = {"q", "s", "query", "search", "k", "keyword", "term"}

# Verification confidence needed to treat a page as a genuine brand match.
VERIFY_THRESHOLD = 0.7


def strong_identity_terms(brand_key, brand_config):
    """Specific identity tokens that genuinely indicate the brand: the full
    display name and verified handles ONLY. Deliberately EXCLUDES the loose
    `keywords` list (which contained 'punjabi', 'indian', 'UK sikh
    influencer', etc. and produced the false positives)."""
    terms = set()
    dn = (brand_config.get("display_name") or "").strip().lower()
    if dn:
        terms.add(dn)
    for h in (brand_config.get("platform_handles") or {}).values():
        h = (h or "").strip().lower()
        if len(h) >= 4:
            terms.add(h)
    bk = brand_key.lstrip("@").strip().lower()
    if len(bk) >= 4:
        terms.add(bk)
    for a in ("erim kaur", "erimkaur", "erim_kaur", "byerim", "by erim"):
        terms.add(a)
    return {t for t in terms if t}


def is_listing_url(url: str) -> bool:
    """True if the URL is a search / listing / aggregation page or bare root
    (never a specific actionable content page)."""
    try:
        p = urlparse(url)
    except Exception:
        return True
    path = p.path or "/"
    if _NON_CONTENT_PATH.search(path):
        return True
    q = parse_qs(p.query or "")
    if any(k.lower() in _SEARCH_QUERY_KEYS for k in q):
        return True
    segs = [s for s in path.split("/") if s]
    if not segs:                      # bare domain root, e.g. hasitleaked.com/
        return True
    return False


def _fetch(url):
    import requests
    r = requests.get(url, timeout=REQUEST_TIMEOUT,
                     headers={"User-Agent": _UA, "Accept-Language": "en"},
                     allow_redirects=True)
    return r.status_code, (r.text or "")


def _extract(html):
    """Return (title, head_text, body_text_lower). head_text = title + meta
    (the strong signal); body = bounded stripped text."""
    title = ""
    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
    if m:
        title = re.sub(r"\s+", " ", m.group(1)).strip()
    metas = " ".join(re.findall(
        r'<meta[^>]+content=["\']([^"\']+)["\']', html, re.I))
    body = re.sub(r"<script.*?</script>|<style.*?</style>", " ", html,
                  flags=re.I | re.S)
    body = re.sub(r"<[^>]+>", " ", body)
    body = re.sub(r"\s+", " ", body)[:20000]
    head = (title + " " + metas).lower()
    return title, head, body.lower()


def _match_terms(terms, text):
    out = []
    for t in sorted(terms, key=len, reverse=True):
        if re.search(r"(?<![a-z0-9])" + re.escape(t) + r"(?![a-z0-9])", text):
            out.append(t)
    return out


def verify_url(url, brand_key, brand_config, fetch=True):
    """Return a verdict dict:
       {url, verified: bool, confidence: float, reason, evidence:{...}}"""
    result = {"url": url, "verified": False, "confidence": 0.0,
              "reason": "", "evidence": {}}

    if is_listing_url(url):
        result["reason"] = "listing/search page — not specific content"
        return result

    if not fetch:
        result["reason"] = "structural check passed (fetch disabled)"
        result["confidence"] = 0.3
        return result

    try:
        status, html = _fetch(url)
    except Exception as e:
        result["reason"] = f"unreachable ({e})"
        return result

    result["evidence"]["http_status"] = status
    if status in (404, 410):
        result["reason"] = f"page gone (HTTP {status}) — nothing to action"
        return result
    if status != 200:
        result["reason"] = f"non-OK response (HTTP {status})"
        return result

    title, head, body = _extract(html)
    result["evidence"]["title"] = title[:200]

    terms = strong_identity_terms(brand_key, brand_config)
    matched = _match_terms(terms, head + " " + body)
    result["evidence"]["matched_terms"] = matched

    dn = (brand_config.get("display_name") or "").strip().lower()
    strong = [m for m in matched if len(m) >= 5]      # e.g. byerim, erimkaur
    conf = 0.0
    if dn and dn in head:
        conf = 0.9                                    # full name in title/meta
    elif strong and any(m in head for m in strong):
        conf = 0.85                                   # verified handle in title/meta
    elif dn and dn in body:
        conf = 0.75                                   # full name in body
    elif strong:
        conf = 0.7                                    # verified handle in body
    elif matched:
        conf = 0.4                                    # only weak token (e.g. "erim")

    result["confidence"] = round(conf, 2)
    result["verified"] = conf >= VERIFY_THRESHOLD
    if result["verified"]:
        result["reason"] = "brand identity confirmed on page: " + ", ".join(matched)
    else:
        result["reason"] = ("no strong brand match on page (found: "
                            + (", ".join(matched) or "nothing") + ")")
    return result
