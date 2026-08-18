"""
Web Activity Control — shared vocabulary.

New capability (GenAI / web-activity control). Defines the vocabulary ONCE
so the policy engine, the agent-facing evaluate endpoint, the event
pipeline, and the browser extension can't drift from each other — the same
lesson CyberSentinel's own commit f435920 called out ("core/web_activity.py
defines the vocabulary once ... so [they] cannot drift").

Two independent axes:

  APP_CATEGORIES -- what KIND of destination this is (classified via
  app_catalog, see server/app/models/app_catalog.py):
    webmail       -- Gmail, Outlook web, ...
    file_sharing  -- Drive, OneDrive, Dropbox, Box, S3, ...
    collaboration -- Slack, Teams, Discord, Telegram/WhatsApp web, ...
    genai         -- ChatGPT, Copilot, Gemini, Claude, ... (new -- SeceoKnight
                     had zero coverage of this category before this feature)

  ACTIVITIES -- what the user is DOING there:
    upload        -- sending a file via a file-picker/drop, request body
    download      -- receiving a file from the destination
    attach        -- attaching a file to a message/email being composed
                     (webmail/collaboration-specific nuance on top of upload)
    send          -- submitting a composed message (webmail/collaboration)
    post          -- submitting a prompt/message (genai) -- what the user
                     typed IN, as opposed to what came back
    ai_response   -- the reply streaming back FROM a genai destination --
                     what the vendor could echo back to the user, e.g. a
                     model quoting sensitive context back in its answer

A policy's matrix is a mapping of (category, activity) -> action, where
action is one of ACTIONS. Not every (category, activity) pair is
meaningful (e.g. genai x attach isn't really a thing) -- MEANINGFUL_CELLS
below is what the dashboard actually renders and what the evaluator
actually consults; an action configured for a non-meaningful cell is
simply never reachable.
"""
from typing import Dict, List, Optional, Tuple

APP_CATEGORIES: List[str] = ["webmail", "file_sharing", "collaboration", "genai"]

ACTIVITIES: List[str] = ["upload", "download", "attach", "send", "post", "ai_response"]

# allow: let it through unmodified, log only.
# alert: let it through, raise a medium-severity event.
# block: stop the request/response entirely (a true 4xx to the page, or
#        request never reaches the destination).
# redact: let it through, but strip sensitive values out first (see
#        app/core/masking.py) -- new action, ported from CyberSentinel
#        commit d3ed5e4.
ACTIONS: List[str] = ["allow", "alert", "block", "redact"]

DEFAULT_ACTION = "allow"

# (category, activity) pairs the dashboard renders and the evaluator
# consults. Everything else in the full cross-product is a non-cell -- e.g.
# "webmail x ai_response" doesn't mean anything, so it's left out rather
# than silently defaulting to some action nobody configured.
#
# SCOPE (this build): only cells the browser extension actually emits are
# listed as meaningful. "upload"/"attach"/"download" are real activities in
# the ACTIVITIES vocabulary above and the server-side evaluator handles
# them correctly if sent -- but the extension's file-upload interception
# still runs through the OLDER, separate cloud_upload_hosts/CLOUD_HOSTS
# path (native-host "classify" message, POST /policy/evaluate with
# event_type=cloud_upload) rather than this new evaluate_web_activity()
# path, to avoid double-submitting/double-logging the same upload through
# two different classifiers. Unifying those two paths is future work, not
# done in this pass -- documented here rather than silently claiming
# "upload" cells work when nothing currently reaches them. "post" (GenAI
# prompts) and "send" (webmail/collaboration composed messages) are NOT
# file-bearing, so they have no such overlap and are fully wired end to
# end, including "ai_response" -- the actual headline capability this
# feature exists for.
MEANINGFUL_CELLS: List[Tuple[str, str]] = [
    ("webmail", "send"),
    ("collaboration", "send"),
    ("genai", "post"), ("genai", "ai_response"),
]


def is_meaningful_cell(category: str, activity: str) -> bool:
    return (category, activity) in MEANINGFUL_CELLS


def cell_key(category: str, activity: str) -> str:
    """The flat string key a matrix dict is keyed by, e.g. 'genai.ai_response'."""
    return f"{category}.{activity}"


def normalize_matrix(raw: Dict[str, str]) -> Dict[str, str]:
    """Sanitize a policy's stored matrix: drop unknown/non-meaningful cells
    and invalid actions, defaulting anything left unspecified to DEFAULT_ACTION
    only at evaluation time (not here) -- an explicitly-empty matrix is a
    valid "not configured yet" state, distinct from "everything allowed"."""
    out: Dict[str, str] = {}
    for category, activity in MEANINGFUL_CELLS:
        key = cell_key(category, activity)
        action = raw.get(key)
        if action in ACTIONS:
            out[key] = action
    return out


def lookup_action(matrix: Dict[str, str], category: str, activity: str) -> str:
    if not is_meaningful_cell(category, activity):
        return DEFAULT_ACTION
    return matrix.get(cell_key(category, activity), DEFAULT_ACTION)


def classify_host(host: str, catalog: List[Tuple[str, str]]) -> Optional[str]:
    """Suffix-match ``host`` against a list of (domain, category) pairs from
    app_catalog, same matching style as cloud_upload_hosts' extra-hosts list
    and IP allowlist's CIDR containment -- an exact match or a subdomain of
    a catalog domain counts. Returns the category, or None if unclassified
    (an unrecognized host is simply not watched by web-activity policies,
    same "additive allowlist of destinations to classify" reasoning as
    cloud_upload_hosts).

    Longest-domain-wins on multiple matches (e.g. a future
    "docs.google.com" entry should take priority over a broader
    "google.com" entry if both existed) -- catalog should be pre-sorted by
    domain length descending by the caller for this to be meaningful;
    falls back to first-match order otherwise, which is still correct for
    today's seed (no two seeded domains overlap as suffixes of each other).
    """
    if not host:
        return None
    host = host.lower()
    best: Optional[str] = None
    best_len = -1
    for domain, category in catalog:
        d = (domain or "").lower()
        if not d:
            continue
        if host == d or host.endswith("." + d):
            if len(d) > best_len:
                best = category
                best_len = len(d)
    return best
