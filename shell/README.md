# AIzkaban — Shell

Standalone bash script that scans a Google Cloud organization and outputs a self-contained HTML report. No infrastructure required.

## Prerequisites

- `gcloud` CLI authenticated with org-level permissions (see root README)
- `jq` installed
- Cloud Asset API enabled on the active project:
  ```
  gcloud services enable cloudasset.googleapis.com
  ```

## Usage

```bash
chmod +x audit.sh

# Pass org ID via environment variable:
ORG_ID=123456789 ./audit.sh

# Or let the script prompt for it:
./audit.sh
```

Outputs a timestamped HTML file in the current directory:

```
aizkaban-20260525-143022.html
```

Open in any browser. Use browser Print → Save as PDF to export.

## Report Contents

- **Summary stats** — active projects in org, projects with findings, Gemini-enabled count, total keys by severity
- **Critical** — unrestricted keys in Gemini-enabled projects
- **High** — unrestricted keys in projects where Gemini is not enabled
- **Low** — restricted keys in Gemini-enabled projects; keys explicitly scoped to Gemini are marked with a ✦ icon
- **Info** — restricted keys in projects where Gemini is not enabled

Keys created before March 2023 are marked **Pre-Gemini** — these are the highest priority for review as they were likely deployed under the old guidance that API keys are safe to share publicly.

Click any row to expand the full list of APIs the key is scoped to.

Tables are sortable by clicking column headers.

## Security Note

The generated report contains org ID, project IDs, and key metadata. Treat it as sensitive and handle accordingly.
