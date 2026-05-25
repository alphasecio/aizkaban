# AIzkaban — Cloud Run

Persistent web dashboard deployed on Cloud Run. Scan results are held in memory and refreshed on demand via a Refresh button in the UI.

## Deploy

```bash
chmod +x deploy.sh
./deploy.sh
```

Prompts for Project ID, Organization ID, and region (default: `us-central1`).

### What deploy.sh does

1. Sets the active gcloud project
2. Enables required APIs (`run`, `cloudbuild`, `containerregistry`)
3. Creates a Service Account (`aizkaban-scanner@...`)
4. Binds two IAM roles at Organization level
5. Builds and pushes the Docker image via Cloud Build
6. Deploys the Cloud Run service (no public access, single instance)
7. Grants the deployer identity the Cloud Run Invoker role
8. Triggers an initial scan via `POST /refresh` — dashboard populates within ~2 minutes depending on org size

### Required permissions to run deploy.sh

Your gcloud identity needs:
- `roles/owner` or `roles/editor` on the deploy project
- `roles/resourcemanager.organizationAdmin` to bind org-level IAM roles in Step 4

## Post-deploy: Enable IAP

The service is deployed with `--no-allow-unauthenticated`. Enable IAP to control who can access the dashboard:

1. **Security → Identity-Aware Proxy** in the Google Cloud Console
2. Enable IAP on the Cloud Run service
3. Grant `roles/iap.httpsResourceAccessor` to users who need access

Full guide: https://cloud.google.com/iap/docs/enabling-cloud-run

## Architecture

- Single Cloud Run service, 1 worker, max 1 instance
- In-memory SQLite — holds the current scan snapshot only; no persistent storage, no GCS dependency
- Scan results are lost on container restart; click Refresh to repopulate (~2 min)
- Refresh is manual only — no Cloud Scheduler job
- All Google Cloud API calls use the attached Service Account via workload identity; no credentials in code

## Service Account IAM Roles

Bound at **Organization** level:

| Role | Purpose |
|---|---|
| `roles/cloudasset.viewer` | Query Cloud Asset Inventory org-wide |
| `roles/resourcemanager.organizationViewer` | Enumerate and resolve project IDs |

## Dashboard Features

- Summary stat cards — active projects, projects with findings, Gemini-enabled count, keys by severity
- Four finding cards: Critical, High, Low, Info
- Click any row to expand the full list of APIs the key is scoped to
- Keys explicitly scoped to `generativelanguage.googleapis.com` are marked with a ✦ icon in the Low card
- Keys created before March 2023 are flagged as **Pre-Gemini**
- Sortable columns in all tables
- System light/dark mode support
- Print-to-PDF via browser print

## Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/` | GET | Dashboard |
| `/refresh` | POST | Start scan (returns immediately, polls `/status` until complete) |
| `/status` | GET | `{"running": bool, "error": str\|null}` |
| `/health` | GET | Health check |
| `/favicon.svg` | GET | Favicon |

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `ORG_ID` | — | **Required.** Google Cloud Organization ID to scan |
| `PORT` | `8080` | HTTP port |
| `LOG_LEVEL` | `INFO` | Logging verbosity |

## Security Note

The dashboard displays org ID, project IDs, and key metadata. Ensure IAP is configured before sharing the URL.
