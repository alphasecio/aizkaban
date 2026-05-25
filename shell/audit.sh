#!/bin/bash

# ==============================================================================
# aizkaban — API Key Auditor
# Scans a GCP organization for API keys that may expose the Gemini API.
#
# PREREQUISITES:
#   1. gcloud CLI authenticated with sufficient permissions
#   2. jq installed
#   3. Cloud Asset API enabled on the active gcloud project:
#        gcloud services enable cloudasset.googleapis.com
#   4. The following IAM roles bound at Organization level:
#        roles/cloudasset.viewer
#        roles/resourcemanager.organizationViewer
#        roles/serviceusage.serviceUsageViewer
#
# NOTE: The generated report contains org ID, project IDs, and key metadata.
# Treat it as sensitive and handle accordingly.
# ==============================================================================

set -euo pipefail

SCAN_TIME=$(date "+%Y-%m-%d %H:%M:%S %Z")
REPORT_FILE="aizkaban-$(date -u +%Y%m%d-%H%M%S).html"
PRE_GEMINI_CUTOFF="2023-03-01T00:00:00Z"
FAVICON_B64="PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCA2NCA2NCI+CiAgPHJlY3Qgd2lkdGg9IjY0IiBoZWlnaHQ9IjY0IiByeD0iMTIiIGZpbGw9IiMxYTFhMTgiLz4KICA8IS0tIEdlbWluaS1zdHlsZSBzdGFyIG1hcmsgaW4gd2hpdGUgLS0+CiAgPHBhdGggZD0iTTMyIDEwIEMzMiAxMCAyNiAyNiAxMCAzMiBDMjYgMzggMzIgNTQgMzIgNTQgQzMyIDU0IDM4IDM4IDU0IDMyIEMzOCAyNiAzMiAxMCAzMiAxMCBaIiBmaWxsPSJ3aGl0ZSIvPgo8L3N2Zz4K"

# ── Checks ─────────────────────────────────────────────────────────────────────

if ! command -v jq &>/dev/null; then
  echo "Error: jq is not installed." >&2; exit 1
fi

echo "AIzkaban — API Key Auditor"
echo "=========================="

CAI_CHECK=$(gcloud services list --enabled   --filter="config.name:cloudasset.googleapis.com"   --format="value(config.name)" 2>/dev/null)

if [ "$CAI_CHECK" != "cloudasset.googleapis.com" ]; then
  echo "Error: Cloud Asset API not enabled on active project." >&2
  echo "  Run: gcloud services enable cloudasset.googleapis.com" >&2
  exit 1
fi
echo "✅ Cloud Asset API enabled."

# ── Org ID ─────────────────────────────────────────────────────────────────────

ORG_ID="${ORG_ID:-}"
if [ -z "$ORG_ID" ]; then
  read -r -p "Enter GCP Organization ID: " ORG_ID
fi
if [ -z "$ORG_ID" ]; then
  echo "Error: Organization ID required." >&2; exit 1
fi
echo "Organization: $ORG_ID"
echo ""

# ── Data collection ────────────────────────────────────────────────────────────

echo "Building project map (org-scoped)..."
PROJECT_MAP=$(gcloud asset search-all-resources \
  --scope="organizations/$ORG_ID" \
  --asset-types="cloudresourcemanager.googleapis.com/Project" \
  --query="state:ACTIVE" \
  --format="json(name,displayName)" 2>/dev/null)
[ -z "$PROJECT_MAP" ] && PROJECT_MAP="[]"

echo "Querying projects with Gemini API enabled..."
GEMINI_PROJECTS=$(gcloud asset search-all-resources   --scope="organizations/$ORG_ID"   --asset-types="serviceusage.googleapis.com/Service"   --query="state:ENABLED AND name:*generativelanguage.googleapis.com*"   --format="value(project)" 2>/dev/null | sed 's/projects\///' || true)

GEMINI_SET="[]"
if [ -n "$GEMINI_PROJECTS" ]; then
  GEMINI_SET=$(echo "$GEMINI_PROJECTS" | jq -R . | jq -s .)
fi

echo "Querying all API keys org-wide..."
KEYS_JSON=$(gcloud asset list   --organization="$ORG_ID"   --asset-types="apikeys.googleapis.com/Key"   --content-type=resource   --format="json" 2>/dev/null)
[ -z "$KEYS_JSON" ] && KEYS_JSON="[]"

echo "Analyzing..."

# ── Classify findings (exclude deleted keys) ───────────────────────────────────

FINDINGS=$(echo "$KEYS_JSON" | jq -c   --argjson pmap "$PROJECT_MAP"   --argjson gemini_set "$GEMINI_SET"   --arg cutoff "$PRE_GEMINI_CUTOFF" '
  ($pmap | map({(.name | split("/")[-1]): .displayName}) | add // {}) as $dict |
  ($gemini_set | map({(.): true}) | add // {}) as $gset |
  [
    .[] |
    select(.resource.data.deleteTime == null) |
    (.name | split("/")[4]) as $pnum |
    ($dict[$pnum] // $pnum) as $pid |
    ($gset[$pnum] // false) as $gemini_on |
    .resource.data as $d |
    ($d.restrictions.apiTargets // null) as $targets |
    (
      if $targets == null then "unrestricted"
      elif ($targets | map(.service) | any(. == "generativelanguage.googleapis.com")) then "gemini_scoped"
      else "restricted"
      end
    ) as $key_type |
    (
      if   $key_type == "unrestricted" and $gemini_on  then "critical"
      elif $key_type == "unrestricted"                   then "high"
      elif $key_type != "unrestricted" and $gemini_on   then "low"
      else "info"
      end
    ) as $severity |
    {
      severity:        $severity,
      project:         $pid,
      project_num:     $pnum,
      name:            ($d.displayName // "unnamed"),
      gemini_scoped:   ($key_type == "gemini_scoped" and $gemini_on),
      created:         ($d.createTime // ""),
      expires:         ($d.expireTime // ""),
      pre_gemini:      (($d.createTime // "") < $cutoff and ($d.createTime // "") != ""),
      app_restriction: (
        if $d.restrictions.browserKeyRestrictions then "Browser"
        elif $d.restrictions.serverKeyRestrictions then "Server/IP"
        elif $d.restrictions.androidKeyRestrictions then "Android"
        elif $d.restrictions.iosKeyRestrictions then "iOS"
        else "None"
        end
      ),
      api_targets: (
        if $targets == null then []
        else [$targets[] | .service]
        end
      )
    }
  ] |
  sort_by(
    if .severity == "critical" then 0
    elif .severity == "high"   then 1
    elif .severity == "low"    then 2
    else 3 end
  )
')

# ── Projects with findings ────────────────────────────────────────────────────────
PROJECTS_WITH_FINDINGS=$(echo "$FINDINGS" | jq '
  [.[] | select(.severity == "critical" or .severity == "high" or .severity == "low") | .project] | unique | length
')

# ── Summary counts ─────────────────────────────────────────────────────────────

TOTAL_PROJECTS=$(echo "$PROJECT_MAP" | jq 'length')
GEMINI_COUNT=$(echo "$GEMINI_SET" | jq 'length')
TOTAL_KEYS=$(echo "$FINDINGS" | jq 'length')
CRITICAL_COUNT=$(echo "$FINDINGS" | jq '[.[] | select(.severity=="critical")] | length')
HIGH_COUNT=$(echo "$FINDINGS"     | jq '[.[] | select(.severity=="high")]     | length')
LOW_COUNT=$(echo "$FINDINGS"      | jq '[.[] | select(.severity=="low")]      | length')
INFO_COUNT=$(echo "$FINDINGS"     | jq '[.[] | select(.severity=="info")]     | length')

# ── Build HTML table rows ──────────────────────────────────────────────────────

GEMINI_ICON='<svg width="13" height="13" viewBox="0 0 24 24" style="vertical-align:-2px;margin-left:4px" title="Gemini-scoped"><path fill="#1a73e8" d="M12 2C12 2 9.5 9.5 2 12C9.5 14.5 12 22 12 22C12 22 14.5 14.5 22 12C14.5 9.5 12 2Z"/></svg>'

make_rows() {
  local sev="$1"
  echo "$FINDINGS" | jq -r --arg sev "$sev" --arg icon "$GEMINI_ICON" '
    .[] | select(.severity == $sev) |
    "<tr onclick=\"toggleApis(this)\">" +
    "<td class=\"col-project\">" + .project + "</td>" +
    "<td class=\"col-name\">" + .name + "</td>" +
    "<td class=\"col-created\">" + (if .pre_gemini then "<span class=\"badge-pre\">Pre-Gemini</span>" elif .created != "" then .created[0:10] else "—" end) + "</td>" +
    "<td class=\"col-expires\">" + (if .expires != "" then .expires[0:10] else "—" end) + "</td>" +
    "<td class=\"col-restriction\">" + .app_restriction + "</td>" +
    "<td class=\"col-apis\">" +
      (if .api_targets | length == 0
       then "<span class=\"apis-unrestricted\">All APIs</span>"
       else "<span class=\"apis-badge\">" + (.api_targets | length | tostring) + "</span>" + (if .gemini_scoped then $icon else "" end)
       end) +
    "</td>" +
    "</tr>" +
    "<tr class=\"apis-row\" style=\"display:none\">" +
    "<td colspan=\"6\"><div class=\"apis-list\">" +
      (if .api_targets | length == 0
       then "No API restrictions — key has access to all enabled APIs."
       else (.api_targets | map("<span class=\"api-pill\">" + . + "</span>") | join(""))
       end) +
    "</div></td>" +
    "</tr>"
  '
}

FINDINGS_COLGROUP='<colgroup>
  <col class="col-project"><col class="col-name"><col class="col-created">
  <col class="col-expires"><col class="col-restriction"><col class="col-apis">
</colgroup>'
FINDINGS_THEAD='<thead><tr>
  <th>Project</th><th>Key Name</th><th>Created</th>
  <th>Expires</th><th>App Restriction</th><th>APIs</th>
</tr></thead>'

make_table() {
  local rows="$1"
  if [ -z "$rows" ]; then
    echo '<p class="empty">No findings in this category.</p>'
    return
  fi
  echo "<div class=\"table-wrap\"><table>${FINDINGS_COLGROUP}${FINDINGS_THEAD}<tbody>${rows}</tbody></table></div>"
}

CRITICAL_TABLE=$(make_table "$(make_rows critical)")
HIGH_TABLE=$(make_table "$(make_rows high)")
LOW_TABLE=$(make_table "$(make_rows low)")
INFO_TABLE=$(make_table "$(make_rows info)")

p() { [ "$1" = "1" ] && echo "$2" || echo "$3"; }
CL=$(p "$CRITICAL_COUNT" "key" "keys")
HL=$(p "$HIGH_COUNT" "key" "keys")
LL=$(p "$LOW_COUNT" "key" "keys")
IL=$(p "$INFO_COUNT" "key" "keys")

# ── Write report ───────────────────────────────────────────────────────────────

cat > "$REPORT_FILE" << HTMLEOF
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>AIzkaban — Audit Report</title>
<link rel="icon" type="image/svg+xml" href="data:image/svg+xml;base64,${FAVICON_B64}">
<style>
@import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@300;400;500;600&display=swap');
:root {
  --bg:#f7f7f5;--surface:#fff;--border:#e4e4e0;--text:#1a1a18;--muted:#6b6b65;
  --critical:#c0392b;--high:#e67e22;--low:#27ae60;--info:#2980b9;
  --critical-bg:#fdf2f1;--high-bg:#fef9f2;--low-bg:#f2faf5;--info-bg:#f2f8fd;
  --pre-color:#8e44ad;--pre-bg:#f8f2fc;--radius:8px;
}
@media (prefers-color-scheme:dark){:root{
  --bg:#111110;--surface:#1c1c1a;--border:#2e2e2b;--text:#e8e8e4;--muted:#888882;
  --critical-bg:#2a1614;--high-bg:#2a1f10;--low-bg:#122216;--info-bg:#0f1e2a;--pre-bg:#1e1226;
}}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:"DM Sans",ui-sans-serif,system-ui,sans-serif;background:var(--bg);color:var(--text);font-size:14px;line-height:1.6;-webkit-font-smoothing:antialiased}
header{padding:20px 40px;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:16px}
.logo{font-size:20px;font-weight:600;letter-spacing:-0.4px}
.org-id{font-size:12px;color:var(--muted);margin-left:auto}
main{max-width:1200px;margin:0 auto;padding:28px 40px 60px}
.stat-bar{display:flex;gap:12px;margin-bottom:32px;flex-wrap:wrap}
.stat-group{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);display:flex;overflow:hidden;flex:1;min-width:260px}
.stat-group-label{writing-mode:vertical-rl;font-size:10px;font-weight:500;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);padding:12px 8px;border-right:1px solid var(--border);background:var(--bg);display:flex;align-items:center;justify-content:center}
.stat-cells{display:flex;flex:1}
.stat{flex:1;padding:14px 16px;border-right:1px solid var(--border);min-width:0}
.stat:last-child{border-right:none}
.stat-value{font-size:26px;font-weight:600;line-height:1;margin-bottom:3px}
.stat-label{font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);white-space:nowrap}
.stat.critical .stat-value{color:var(--critical)}
.stat.high .stat-value{color:var(--high)}
.stat.low .stat-value{color:var(--low)}
.stat.info .stat-value{color:var(--info)}
.card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);margin-bottom:16px;overflow:hidden}
.card-header{display:flex;align-items:center;gap:10px;padding:12px 18px;border-bottom:1px solid var(--border)}
.card-header.critical{background:var(--critical-bg)}
.card-header.high{background:var(--high-bg)}
.card-header.low{background:var(--low-bg)}
.card-header.info{background:var(--info-bg)}
.dot{width:8px;height:8px;border-radius:50%;flex-shrink:0}
.dot.critical{background:var(--critical)}
.dot.high{background:var(--high)}
.dot.low{background:var(--low)}
.dot.info{background:var(--info)}
.card-title{font-weight:600;font-size:13px}
.card-desc{font-size:12px;color:var(--muted)}
.card-count{margin-left:auto;font-size:12px;color:var(--muted);background:var(--bg);border:1px solid var(--border);border-radius:20px;padding:2px 10px}
.table-wrap{overflow-x:auto}
table{width:100%;border-collapse:collapse;font-size:13px;table-layout:fixed}
col.col-project{width:24%}col.col-name{width:22%}col.col-created{width:11%}
col.col-expires{width:11%}col.col-restriction{width:13%}col.col-apis{width:10%}
th{text-align:left;font-size:11px;font-weight:500;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);padding:9px 16px;border-bottom:1px solid var(--border);cursor:pointer;user-select:none;white-space:nowrap}
th:hover{color:var(--text)}
th.asc::after{content:" ↑"}th.desc::after{content:" ↓"}
td{padding:9px 16px;border-bottom:1px solid var(--border);vertical-align:middle;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
tbody tr.data-row{cursor:pointer}
tbody tr.data-row:hover td{background:var(--bg)}
tr.apis-row td{padding:0;border-bottom:1px solid var(--border);white-space:normal}
tr:last-child td{border-bottom:none}
.apis-badge{display:inline-block;font-size:11px;font-weight:500;background:var(--bg);border:1px solid var(--border);border-radius:20px;padding:1px 8px;cursor:pointer}
.apis-list{display:flex;flex-wrap:wrap;gap:6px;padding:10px 16px}
.api-pill{display:inline-block;font-size:11px;background:var(--bg);border:1px solid var(--border);border-radius:4px;padding:2px 8px;color:var(--muted)}
.apis-unrestricted{font-size:12px;color:var(--muted)}
.badge-pre{display:inline-block;font-size:10px;font-weight:500;background:var(--pre-bg);color:var(--pre-color);border:1px solid var(--pre-color);border-radius:4px;padding:1px 6px}
.empty{padding:18px;color:var(--muted);font-size:13px}
footer{text-align:center;padding:20px;font-size:11px;color:var(--muted);border-top:1px solid var(--border)}
@media print{.card{break-inside:avoid}tbody tr.data-row:hover td{background:none}}
</style>
</head>
<body>
<header>
  <div class="logo">AIzkaban</div>
  <div class="org-id">Org ID: $ORG_ID</div>
</header>
<main>
  <div class="stat-bar">
    <div class="stat-group">
      <div class="stat-group-label">Projects</div>
      <div class="stat-cells">
        <div class="stat"><div class="stat-value">$TOTAL_PROJECTS</div><div class="stat-label">Total</div></div>
        <div class="stat critical"><div class="stat-value">$PROJECTS_WITH_FINDINGS</div><div class="stat-label">Findings</div></div>
        <div class="stat"><div class="stat-value">$GEMINI_COUNT</div><div class="stat-label">Gemini Enabled</div></div>
      </div>
    </div>
    <div class="stat-group">
      <div class="stat-group-label">API Keys</div>
      <div class="stat-cells">
        <div class="stat"><div class="stat-value">$TOTAL_KEYS</div><div class="stat-label">Total</div></div>
        <div class="stat critical"><div class="stat-value">$CRITICAL_COUNT</div><div class="stat-label">Critical</div></div>
        <div class="stat high"><div class="stat-value">$HIGH_COUNT</div><div class="stat-label">High</div></div>
        <div class="stat low"><div class="stat-value">$LOW_COUNT</div><div class="stat-label">Low</div></div>
        <div class="stat info"><div class="stat-value">$INFO_COUNT</div><div class="stat-label">Info</div></div>
      </div>
    </div>
  </div>

  <div class="card">
    <div class="card-header critical">
      <span class="dot critical"></span><span class="card-title">Critical</span>
      <span class="card-desc">— Unrestricted key, Gemini enabled</span>
      <span class="card-count">$CRITICAL_COUNT $CL</span>
    </div>
    $CRITICAL_TABLE
  </div>
  <div class="card">
    <div class="card-header high">
      <span class="dot high"></span><span class="card-title">High</span>
      <span class="card-desc">— Unrestricted key, Gemini not enabled</span>
      <span class="card-count">$HIGH_COUNT $HL</span>
    </div>
    $HIGH_TABLE
  </div>
  <div class="card">
    <div class="card-header low">
      <span class="dot low"></span><span class="card-title">Low</span>
      <span class="card-desc">— Restricted key, Gemini enabled</span>
      <span class="card-count">$LOW_COUNT $LL</span>
    </div>
    $LOW_TABLE
  </div>
  <div class="card">
    <div class="card-header info">
      <span class="dot info"></span><span class="card-title">Info</span>
      <span class="card-desc">— Restricted key, Gemini not enabled</span>
      <span class="card-count">$INFO_COUNT $IL</span>
    </div>
    $INFO_TABLE
  </div>
</main>
<footer>AIzkaban &nbsp;·&nbsp; API Key Auditor &nbsp;·&nbsp; $SCAN_TIME</footer>
<script>
function toggleApis(row) {
  if (!row.classList.contains('data-row')) return;
  const next = row.nextElementSibling;
  if (next && next.classList.contains('apis-row')) {
    next.style.display = next.style.display === 'none' ? 'table-row' : 'none';
  }
}
document.querySelectorAll('tbody tr').forEach(tr => {
  if (!tr.classList.contains('apis-row')) tr.classList.add('data-row');
});
document.querySelectorAll('table').forEach(table => {
  table.querySelectorAll('th').forEach((th, col) => {
    let asc = true;
    th.addEventListener('click', () => {
      table.querySelectorAll('th').forEach(h => h.classList.remove('asc','desc'));
      const tbody = table.querySelector('tbody');
      const pairs = [];
      const rows = Array.from(tbody.querySelectorAll('tr'));
      for (let i = 0; i < rows.length; i++) {
        if (!rows[i].classList.contains('apis-row')) {
          pairs.push([rows[i], rows[i+1]]);
        }
      }
      pairs.sort((a, b) => {
        const av = a[0].cells[col]?.textContent.trim() ?? '';
        const bv = b[0].cells[col]?.textContent.trim() ?? '';
        return asc ? av.localeCompare(bv) : bv.localeCompare(av);
      });
      pairs.forEach(([dr, ar]) => { tbody.appendChild(dr); if (ar) tbody.appendChild(ar); });
      th.classList.add(asc ? 'asc' : 'desc');
      asc = !asc;
    });
  });
});
</script>
</body>
</html>
HTMLEOF

echo ""
echo "============================================================="
echo "✅ Audit complete: $REPORT_FILE"
echo "   Critical : $CRITICAL_COUNT"
echo "   High     : $HIGH_COUNT"
echo "   Low      : $LOW_COUNT"
echo "   Info     : $INFO_COUNT"
echo "============================================================="
