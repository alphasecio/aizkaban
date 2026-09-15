"""AIzkaban -- API Key Auditor.

This tool scans a Google Cloud organization. It looks for API keys that
may expose the Gemini API. It runs as one Cloud Run service.

The tool scans through Cloud Asset Inventory. It shows the results on a
web page. It saves the last scan to Cloud Storage, if a bucket is set.
If no bucket is set, it keeps the last scan in memory only.
"""

import base64
import json
import logging
import os
import sys
import threading
import time
from datetime import datetime, timezone

from flask import Flask, Response, redirect, render_template, url_for
from google.api_core import exceptions as gexc
from google.cloud import asset_v1
from google.protobuf.json_format import MessageToDict

APP_VERSION = "0.1.0"

# The Gemini API (generativelanguage) became public in March 2023. A key
# made before this date cannot have been made for Gemini. Any Gemini
# access such a key has was added later, often without anyone meaning to.
PRE_GEMINI_CUTOFF = "2023-03-01T00:00:00Z"
GEMINI_SERVICE = "generativelanguage.googleapis.com"

SEVERITY_ORDER = {"critical": 0, "high": 1, "low": 2, "info": 3}
CARDS = (
    ("critical", "Critical", "Unrestricted key, Gemini enabled"),
    ("high", "High", "Unrestricted key, Gemini not enabled"),
    ("low", "Low", "Restricted key, Gemini enabled"),
    ("info", "Info", "Restricted key, Gemini not enabled"),
)

# ── Configuration ────────────────────────────────────────────────────────

ORG_ID = os.environ.get("ORG_ID", "").strip()
BUCKET = os.environ.get("BUCKET", "").strip().removeprefix("gs://").strip("/")
SNAPSHOT_KEY = os.environ.get("SNAPSHOT_KEY", "snapshot.json").strip().lstrip("/")
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()

if not hasattr(logging, LOG_LEVEL):
    print(
        f"LOG_LEVEL '{LOG_LEVEL}' is not a valid level. Using INFO instead.",
        file=sys.stderr,
    )
    LOG_LEVEL = "INFO"

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL),
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("aizkaban")

if not ORG_ID.isdigit():
    sys.exit(
        "ORG_ID is missing or is not a number. "
        "Set ORG_ID to your Google Cloud organization ID and restart."
    )

app = Flask(__name__)
app.jinja_env.trim_blocks = True
app.jinja_env.lstrip_blocks = True

# Read the CSS, JS, and favicon once at startup. The exported report
# inlines these so the downloaded file works offline, with no server and
# no network. A missing file here is a packaging error, so let it crash
# the app at startup rather than fail quietly the first time someone
# clicks Export.
_STATIC_DIR = os.path.join(app.root_path, "static")


def _read_static(filename):
    with open(os.path.join(_STATIC_DIR, filename), encoding="utf-8") as f:
        return f.read()


INLINE_CSS = _read_static("style.css")
INLINE_JS = _read_static("app.js")
FAVICON_DATA_URI = "data:image/svg+xml;base64," + base64.b64encode(
    _read_static("favicon.svg").encode("utf-8")
).decode("ascii")

# ── Persistence ──────────────────────────────────────────────────────────


class MemoryStore:
    """Keeps the last scan in memory. Loses it when the container restarts."""

    persistent = False

    def __init__(self):
        self._snapshot = None

    def load(self):
        return self._snapshot

    def save(self, snapshot):
        self._snapshot = snapshot


class BucketStore:
    """Keeps the last scan as one JSON object in Cloud Storage."""

    persistent = True

    def __init__(self, bucket, key):
        from google.cloud import storage

        self._blob = storage.Client().bucket(bucket).blob(key)

    def load(self):
        try:
            return json.loads(self._blob.download_as_bytes())
        except gexc.NotFound:
            return None
        except Exception:
            log.exception("Could not read the snapshot from the bucket.")
            return None

    def save(self, snapshot):
        self._blob.upload_from_string(
            json.dumps(snapshot), content_type="application/json"
        )


def build_store():
    if not BUCKET:
        log.warning(
            "BUCKET is not set. Aizkaban keeps scan results in memory only. "
            "A container restart will lose all results."
        )
        return MemoryStore()
    try:
        store_ = BucketStore(BUCKET, SNAPSHOT_KEY)
        log.info("Saving scan results to gs://%s/%s", BUCKET, SNAPSHOT_KEY)
        return store_
    except Exception:
        log.exception("Could not use the bucket. Falling back to memory.")
        return MemoryStore()


store = build_store()

# ── Scanner ──────────────────────────────────────────────────────────────

_asset_client = None


def get_asset_client():
    """Return a shared Asset Inventory client, built on first use.

    Building it lazily, on the first scan rather than at import time,
    means a credentials problem shows up as a normal error on the
    dashboard instead of a crash at container startup.
    """
    global _asset_client
    if _asset_client is None:
        _asset_client = asset_v1.AssetServiceClient()
    return _asset_client


def _data(asset):
    """Return the resource payload of a CAI asset as a plain dict.

    asset.resource.data has type google.protobuf.Struct. The client
    library wraps Struct fields as a MapComposite object. That object has
    no _pb attribute that MessageToDict can read.

    Do not call MessageToDict on resource.data. Instead, read the raw
    Struct through resource._pb.data. This works because resource is an
    ordinary message field. The library does not wrap it.
    """
    return MessageToDict(asset.resource._pb.data)


def _project_number(asset_name):
    """Return the project number from a CAI asset name.

    Example: //apikeys.googleapis.com/projects/123/... -> "123"
    """
    parts = asset_name.split("/")
    return parts[4] if len(parts) > 4 else ""


def fetch_projects(parent):
    """Return a map of project number to project ID.

    Only active projects are included.
    """
    request = asset_v1.ListAssetsRequest(
        parent=parent,
        asset_types=["cloudresourcemanager.googleapis.com/Project"],
        content_type=asset_v1.ContentType.RESOURCE,
    )
    projects = {}
    for asset in get_asset_client().list_assets(request=request):
        data = _data(asset)
        if data.get("lifecycleState") != "ACTIVE":
            continue
        number = str(data.get("projectNumber", "")).split("/")[-1]
        project_id = data.get("projectId", "")
        if number and project_id:
            projects[number] = project_id
    return projects


def fetch_gemini_projects(scope):
    """Return the set of project numbers where Gemini is enabled."""
    request = asset_v1.SearchAllResourcesRequest(
        scope=scope,
        asset_types=["serviceusage.googleapis.com/Service"],
        query=f"state:ENABLED AND name:*{GEMINI_SERVICE}*",
    )
    enabled = set()
    for result in get_asset_client().search_all_resources(request=request):
        number = (result.project or "").split("/")[-1]
        if number:
            enabled.add(number)
    return enabled


def fetch_org_domain(parent):
    """Return the organization's domain name, or None if it is not found.

    For a Google Cloud organization, the domain name is its display name.
    This uses the same permission as fetch_projects, so it needs no new
    IAM role.
    """
    request = asset_v1.ListAssetsRequest(
        parent=parent,
        asset_types=["cloudresourcemanager.googleapis.com/Organization"],
        content_type=asset_v1.ContentType.RESOURCE,
    )
    for asset in get_asset_client().list_assets(request=request):
        data = _data(asset)
        return data.get("displayName") or None
    return None


def classify(asset, projects, gemini_projects):
    """Turn one API key asset into a finding.

    Return None if the key was deleted.
    """
    data = _data(asset)
    if data.get("deleteTime"):
        return None

    number = _project_number(asset.name)
    if not number:
        return None

    gemini_on = number in gemini_projects
    restrictions = data.get("restrictions") or {}
    api_targets = restrictions.get("apiTargets")
    services = [t.get("service", "") for t in (api_targets or [])]

    if api_targets is None:
        key_type = "unrestricted"
    elif GEMINI_SERVICE in services:
        key_type = "gemini_scoped"
    else:
        key_type = "restricted"

    if key_type == "unrestricted" and gemini_on:
        severity = "critical"
    elif key_type == "unrestricted":
        severity = "high"
    elif gemini_on:
        severity = "low"
    else:
        severity = "info"

    # A restriction can be an empty object, for example {}. An empty
    # object still means the restriction type is set. Check for None,
    # not for truth.
    if restrictions.get("browserKeyRestrictions") is not None:
        app_restriction = "Browser"
    elif restrictions.get("serverKeyRestrictions") is not None:
        app_restriction = "Server/IP"
    elif restrictions.get("androidKeyRestrictions") is not None:
        app_restriction = "Android"
    elif restrictions.get("iosKeyRestrictions") is not None:
        app_restriction = "iOS"
    else:
        app_restriction = "None"

    created = data.get("createTime", "")

    return {
        "severity": severity,
        "project": projects.get(number, number),
        "key_name": data.get("displayName") or "unnamed",
        "gemini_scoped": key_type == "gemini_scoped" and gemini_on,
        "created": created,
        "expires": data.get("expireTime", ""),
        "pre_gemini": bool(created and created < PRE_GEMINI_CUTOFF),
        "app_restriction": app_restriction,
        "api_targets": services,
    }


def scan():
    """Run one full scan of the organization. Return a snapshot dict."""
    log.info("Scan started for organization %s", ORG_ID)
    parent = scope = f"organizations/{ORG_ID}"

    projects = fetch_projects(parent)
    gemini_projects = fetch_gemini_projects(scope)
    org_domain = fetch_org_domain(parent)

    request = asset_v1.ListAssetsRequest(
        parent=parent,
        asset_types=["apikeys.googleapis.com/Key"],
        content_type=asset_v1.ContentType.RESOURCE,
    )
    findings = [
        finding
        for finding in (
            classify(asset, projects, gemini_projects)
            for asset in get_asset_client().list_assets(request=request)
        )
        if finding
    ]
    findings.sort(key=lambda f: (SEVERITY_ORDER[f["severity"]], f["project"]))

    counts = {level: 0 for level in SEVERITY_ORDER}
    for finding in findings:
        counts[finding["severity"]] += 1

    flagged = {
        f["project"] for f in findings if f["severity"] in ("critical", "high", "low")
    }

    snapshot = {
        "scanned_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "org_id": ORG_ID,
        "org_domain": org_domain,
        "projects_total": len(projects),
        "projects_flagged": len(flagged),
        "projects_gemini": len(gemini_projects),
        "keys_total": len(findings),
        "counts": counts,
        "findings": findings,
    }
    log.info(
        "Scan finished. critical=%(critical)d high=%(high)d low=%(low)d info=%(info)d",
        counts,
    )
    return snapshot


_scan_lock = threading.Lock()
_last_scan_at = 0.0
_SCAN_DEBOUNCE_SECONDS = 5
_SCAN_WAIT_TIMEOUT = 120


def run_scan():
    """Run a scan and save it. Return (snapshot, error_message).

    If a scan is already running, this waits for it instead of failing.
    Without this, an automatic first-load scan and a manual click could
    race. The one that lost the race used to show a false error, even
    though the other scan finished fine.

    A short cooldown after a finished scan stops a fast double-click from
    starting a second scan.
    """
    global _last_scan_at
    if not _scan_lock.acquire(timeout=_SCAN_WAIT_TIMEOUT):
        return store.load(), "The scan is taking too long. Please try again."
    try:
        if time.monotonic() - _last_scan_at < _SCAN_DEBOUNCE_SECONDS:
            return store.load(), None
        snapshot = scan()
        store.save(snapshot)
        _last_scan_at = time.monotonic()
        return snapshot, None
    except gexc.PermissionDenied as exc:
        message = (
            f"Access denied on organizations/{ORG_ID}. Grant the service "
            "account two roles at the organization level: "
            "roles/cloudasset.viewer and "
            f"roles/resourcemanager.organizationViewer. ({exc.message})"
        )
    except gexc.GoogleAPICallError as exc:
        message = f"Cloud Asset API error: {exc.message or exc}"
    except Exception as exc:  # noqa: BLE001 -- shown to the user, not hidden
        log.exception("Scan failed.")
        message = f"Scan failed: {exc}"
    finally:
        _scan_lock.release()
    log.error(message)
    return store.load(), message


# ── Rendering ────────────────────────────────────────────────────────────


def group_findings(findings):
    """Return a dict of severity to its list of findings."""
    grouped = {sev: [] for sev, _, _ in CARDS}
    for finding in findings:
        grouped[finding["severity"]].append(finding)
    return grouped


def render_dashboard(snapshot, error=None, export=False):
    notices = []
    if error:
        notices.append({"level": "error", "text": error})
    if not export and not store.persistent:
        notices.append({
            "level": "info",
            "text": (
                "BUCKET is not set. Results are kept in memory only. "
                "A restart will lose them."
            ),
        })

    context = {
        "subtitle": "API Key Audit Report" if export else "API Key Auditor",
        "export": export,
        "version": APP_VERSION,
        "org_id": snapshot["org_id"] if snapshot else ORG_ID,
        "org_domain": snapshot.get("org_domain") if snapshot else None,
        "snapshot": snapshot,
        "grouped": group_findings(snapshot["findings"]) if snapshot else {},
        "cards": CARDS,
        "notices": notices,
    }
    if export:
        context["inline_css"] = INLINE_CSS
        context["inline_js"] = INLINE_JS
        context["favicon_data_uri"] = FAVICON_DATA_URI
    return render_template("dashboard.html", **context)


# ── Routes ───────────────────────────────────────────────────────────────


@app.after_request
def security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; base-uri 'self'; form-action 'self'; "
        "frame-ancestors 'none'; object-src 'none'",
    )
    if response.mimetype == "text/html":
        # The dashboard is built fresh on every request. Without this, a
        # cached copy can keep showing an old script after a new version
        # is deployed, with no sign that anything is stale.
        response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/")
def dashboard():
    snapshot = store.load()
    error = None
    if snapshot is None:
        # First visit after a deploy: scan now so the page is never empty.
        snapshot, error = run_scan()
    return render_dashboard(snapshot, error)


@app.post("/scan")
def rescan():
    run_scan()
    return redirect(url_for("dashboard"))


@app.get("/export")
def export_report():
    snapshot = store.load()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    body = render_dashboard(snapshot, export=True)
    return Response(
        body,
        mimetype="text/html",
        headers={
            "Content-Disposition": f'attachment; filename="aizkaban-{stamp}.html"'
        },
    )


@app.get("/healthz")
def healthz():
    return {"status": "ok", "version": APP_VERSION}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)), debug=False)
