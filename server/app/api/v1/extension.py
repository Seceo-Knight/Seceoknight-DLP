"""
Browser-extension distribution -- the update feed endpoints force-install from.

New capability (gap-scan of CyberSentinel-DLP, August 18, 2026). SeceoKnight's
browser extension was previously only distributed as an unpacked dev-mode
load ("chrome://extensions -> Load unpacked") -- something an end user can
switch off in two clicks, an unacceptable property for a DLP control. Ported
in spirit from CyberSentinel-DLP's own server/app/api/v1/extension.py: pack
with scripts/pack-extension.py, serve here, force-install via the agent's
ExtensionInstallForcelist registry policy (see agent.cpp's
ApplyBrowserExtensionPolicy / HandleApplyBrowserExtensionGuard).

Chrome and Edge fetch ``update.xml`` and the ``.crx`` themselves, as the
browser process, with no credentials and no session. So these three routes
are:

  * UNAUTHENTICATED -- the browser has nothing to authenticate with. What
    they serve is a signed, publicly-distributable extension package, not
    data. No Depends() on this router for that reason.
  * EXEMPT from the portal IP allowlist -- see _is_exempt() in
    app/middleware/ip_allowlist.py, same posture as the agent endpoints an
    endpoint must keep reaching from any network.
  * served with the exact content types the browsers require -- Chrome
    refuses a CRX served as text/plain, and the failure is silent from the
    endpoint's side.

Content is produced by ``scripts/pack-extension.py`` into
``server/extension_dist``. When that directory is empty every route 404s
with a message saying so, which is the honest answer to "nothing has been
packed yet" and far easier to diagnose than an empty feed that looks like it
worked.
"""
from __future__ import annotations

import json
import pathlib

from fastapi import APIRouter, HTTPException, Request, status
from fastapi.responses import FileResponse, Response
import structlog

logger = structlog.get_logger()
router = APIRouter()

# server/app/api/v1/extension.py -> server/extension_dist
DIST_DIR = pathlib.Path(__file__).resolve().parents[3] / "extension_dist"

CRX_MEDIA_TYPE = "application/x-chrome-extension"


def _dist_file(name: str) -> pathlib.Path:
    """Resolve a file inside the dist directory, refusing anything outside it."""
    candidate = (DIST_DIR / name).resolve()
    try:
        candidate.relative_to(DIST_DIR.resolve())
    except ValueError:
        # A traversal attempt. These routes are unauthenticated, so this is
        # the one place that genuinely needs the check.
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not found")
    if not candidate.is_file():
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            f"'{name}' has not been published. Run scripts/pack-extension.py on the "
            "DLP server to build and publish the browser extension.",
        )
    return candidate


@router.get("/update.xml")
async def update_manifest(request: Request):
    """The update feed. Polled by every force-installed browser a few times a day.

    Built from the REQUEST rather than served from disk. Chrome requires an
    absolute ``codebase`` URL, so a file baked at pack time hardcodes
    whichever hostname the packaging machine was told about -- and the
    moment the same build is deployed to a second server, every endpoint
    there is pointed back at the first one. Deriving it from the host the
    endpoint actually reached means one artifact works on every deployment,
    including behind a reverse proxy or on a different port.
    """
    info = json.loads(_dist_file("extension.json").read_text())
    # url_for keeps the scheme/host/port the client used, and nginx's
    # X-Forwarded-* handling keeps that correct behind the dashboard proxy.
    crx_url = str(request.url_for("download_crx", filename=info["crx"]))
    xml = (
        "<?xml version='1.0' encoding='UTF-8'?>\n"
        "<gupdate xmlns='http://www.google.com/update2/response' protocol='2.0'>\n"
        f"  <app appid='{info['extension_id']}'>\n"
        f"    <updatecheck codebase='{crx_url}' version='{info['version']}' />\n"
        "  </app>\n"
        "</gupdate>\n"
    )
    return Response(content=xml, media_type="application/xml")


@router.get("/info")
async def extension_info():
    """Extension id, version and hash -- what agent.cpp's
    ApplyBrowserExtensionPolicy() reads to write the ExtensionInstallForcelist
    entry, and what install/manage scripts read for status reporting.

    Exists so nobody ever has to type a 32-character extension id by hand
    into a registry policy, which is the single most error-prone step in a
    force-install and fails silently when wrong.
    """
    path = _dist_file("extension.json")
    return json.loads(path.read_text())


@router.get("/{filename}")
async def download_crx(filename: str):
    """The signed package itself."""
    if not filename.endswith(".crx"):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not found")
    path = _dist_file(filename)
    return FileResponse(
        path,
        media_type=CRX_MEDIA_TYPE,
        filename=filename,
        # The CRX is immutable for a given version -- the version is what changes.
        headers={"Cache-Control": "public, max-age=300"},
    )
