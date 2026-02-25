"""
Basic web scraper for Brand Shield.
Fetches public profile pages and extracts relevant metadata.
"""
import re
import time
import logging
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# Common user-agent to avoid blocks
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-GB,en;q=0.9",
}


def fetch_page(url, timeout=10):
    """Fetch a web page and return parsed HTML."""
    import requests
    from bs4 import BeautifulSoup

    try:
        response = requests.get(url, headers=HEADERS, timeout=timeout, allow_redirects=True)
        response.raise_for_status()
        return BeautifulSoup(response.text, "html.parser")
    except Exception as e:
        logger.warning(f"Failed to fetch {url}: {e}")
        return None


def extract_profile_data(url):
    """
    Extract profile information from a public web page.
    Returns dict with: username, display_name, bio, follower_count, platform
    """
    domain = urlparse(url).netloc.lower()
    soup = fetch_page(url)
    if not soup:
        return None

    data = {
        "url": url,
        "platform": _detect_platform(domain),
        "username": None,
        "display_name": None,
        "bio": None,
        "follower_count": 0,
    }

    # Try platform-specific extraction
    if "twitter.com" in domain or "x.com" in domain:
        data.update(_extract_twitter(soup, url))
    elif "instagram.com" in domain:
        data.update(_extract_instagram(soup, url))
    elif "tiktok.com" in domain:
        data.update(_extract_tiktok(soup, url))
    elif "youtube.com" in domain:
        data.update(_extract_youtube(soup, url))
    else:
        data.update(_extract_generic(soup, url))

    return data


def _detect_platform(domain):
    """Map domain to platform name."""
    if "twitter.com" in domain or "x.com" in domain:
        return "twitter"
    if "instagram.com" in domain:
        return "instagram"
    if "tiktok.com" in domain:
        return "tiktok"
    if "youtube.com" in domain:
        return "youtube"
    if "facebook.com" in domain:
        return "facebook"
    if "amazon" in domain:
        return "amazon"
    if "ebay" in domain:
        return "ebay"
    if "etsy.com" in domain:
        return "etsy"
    return "web"


def _extract_twitter(soup, url):
    """Extract data from Twitter/X public pages."""
    data = {}
    path = urlparse(url).path.strip("/")
    parts = path.split("/")
    if parts:
        data["username"] = parts[0]

    # Try meta tags (work even without JS rendering)
    og_title = soup.find("meta", property="og:title")
    if og_title:
        content = og_title.get("content", "")
        # Format: "Display Name (@username) / X"
        match = re.match(r"(.+?)\s*\(@?(\w+)\)", content)
        if match:
            data["display_name"] = match.group(1).strip()
            data["username"] = match.group(2)

    og_desc = soup.find("meta", property="og:description")
    if og_desc:
        data["bio"] = og_desc.get("content", "")[:500]

    return data


def _extract_instagram(soup, url):
    """Extract data from Instagram public pages."""
    data = {}
    path = urlparse(url).path.strip("/")
    parts = path.split("/")
    if parts:
        data["username"] = parts[0]

    og_title = soup.find("meta", property="og:title")
    if og_title:
        content = og_title.get("content", "")
        match = re.match(r"(.+?)\s*\(@?(\w+)\)", content)
        if match:
            data["display_name"] = match.group(1).strip()

    og_desc = soup.find("meta", property="og:description")
    if og_desc:
        desc = og_desc.get("content", "")
        data["bio"] = desc[:500]
        follower_match = re.search(r"([\d,.]+[KMB]?)\s*Followers", desc, re.IGNORECASE)
        if follower_match:
            data["follower_count"] = _parse_count(follower_match.group(1))

    return data


def _extract_tiktok(soup, url):
    """Extract data from TikTok public pages."""
    data = {}
    path = urlparse(url).path.strip("/")
    if path.startswith("@"):
        data["username"] = path[1:].split("/")[0]

    og_desc = soup.find("meta", attrs={"name": "description"})
    if og_desc:
        desc = og_desc.get("content", "")
        data["bio"] = desc[:500]
        follower_match = re.search(r"([\d,.]+[KMB]?)\s*Followers", desc, re.IGNORECASE)
        if follower_match:
            data["follower_count"] = _parse_count(follower_match.group(1))

    title_tag = soup.find("title")
    if title_tag:
        match = re.match(r"(.+?)\s*\(@", title_tag.text)
        if match:
            data["display_name"] = match.group(1).strip()

    return data


def _extract_youtube(soup, url):
    """Extract data from YouTube public pages."""
    data = {}
    path = urlparse(url).path.strip("/")
    parts = path.split("/")
    if parts:
        handle = parts[-1]
        if handle.startswith("@"):
            data["username"] = handle[1:]
        else:
            data["username"] = handle

    og_title = soup.find("meta", property="og:title")
    if og_title:
        data["display_name"] = og_title.get("content", "")

    og_desc = soup.find("meta", property="og:description")
    if og_desc:
        data["bio"] = og_desc.get("content", "")[:500]

    return data


def _extract_generic(soup, url):
    """Extract basic data from any web page."""
    data = {}

    title_tag = soup.find("title")
    if title_tag:
        data["display_name"] = title_tag.text.strip()[:200]

    meta_desc = soup.find("meta", attrs={"name": "description"})
    if not meta_desc:
        meta_desc = soup.find("meta", property="og:description")
    if meta_desc:
        data["bio"] = meta_desc.get("content", "")[:500]

    return data


def _parse_count(count_str):
    """Parse follower counts like '1.2K', '3.5M', '100'."""
    count_str = count_str.replace(",", "").strip()
    multipliers = {"K": 1000, "M": 1000000, "B": 1000000000}
    for suffix, mult in multipliers.items():
        if count_str.upper().endswith(suffix):
            try:
                return int(float(count_str[:-1]) * mult)
            except ValueError:
                return 0
    try:
        return int(float(count_str))
    except ValueError:
        return 0

