# AIzkaban — API Key Auditor

AIzkaban scans a Google Cloud organization for API keys, and flags keys
that may expose the Gemini API.

## The risk

Gemini for a project turns on when someone enables the Gemini API. Any
existing unrestricted key in that project then gains Gemini access. This
includes keys made for Maps, Firebase, or other public services. A key
placed in client-side code under old guidance can become a live Gemini
credential, with no warning.

## What it finds

| Severity | Meaning |
|---|---|
| 🔴 Critical | Unrestricted key, Gemini on |
| 🟠 High | Unrestricted key, Gemini off |
| 🟡 Low | Restricted key, Gemini on |
| 🔵 Info | Restricted key, Gemini off |

A key made before March 2023 cannot have been made for Gemini. AIzkaban
marks it **Pre-Gemini**. Review these keys first.

A key with Gemini explicitly listed in its restrictions gets a ✦ mark in
the Low card. This access is likely intentional, but the key is still a
usable Gemini credential if it leaks.

## Deploy

### 1. Enable APIs

Run this on the project that will host Cloud Run:

```bash
gcloud services enable run.googleapis.com cloudasset.googleapis.com \
  --project PROJECT_ID
```

Enable `cloudasset.googleapis.com` on this project. Not just the org.
The service calls this API from here.

### 2. Create a service account and grant two roles

```bash
gcloud iam service-accounts create aizkaban-sa \
  --display-name "AIzkaban scanner" --project PROJECT_ID

for ROLE in roles/cloudasset.viewer roles/resourcemanager.organizationViewer; do
  gcloud organizations add-iam-policy-binding ORG_ID \
    --member "serviceAccount:aizkaban-sa@PROJECT_ID.iam.gserviceaccount.com" \
    --role "$ROLE" --condition None --quiet
done
```

Grant both roles at the organization level, not the project level. Both
roles are read-only.

### 3. Create a bucket (optional, recommended)

Without a bucket, AIzkaban keeps the last scan in memory. A restart
loses it.

```bash
gcloud storage buckets create gs://PROJECT_ID-aizkaban \
  --location REGION --uniform-bucket-level-access \
  --public-access-prevention --project PROJECT_ID

gcloud storage buckets add-iam-policy-binding gs://PROJECT_ID-aizkaban \
  --member "serviceAccount:aizkaban-sa@PROJECT_ID.iam.gserviceaccount.com" \
  --role roles/storage.objectUser
```

### 4. Deploy

```bash
gcloud run deploy aizkaban \
  --source . \
  --region REGION \
  --project PROJECT_ID \
  --service-account aizkaban-sa@PROJECT_ID.iam.gserviceaccount.com \
  --set-env-vars ORG_ID=ORG_ID,BUCKET=PROJECT_ID-aizkaban \
  --no-allow-unauthenticated
```

Open the URL. The first load runs a scan. Later loads show the saved
result.

### 5. Grant access

The service requires authentication. Grant specific users the invoker
role:

```bash
gcloud run services add-iam-policy-binding aizkaban \
  --region REGION --project PROJECT_ID \
  --member "user:you@example.com" --role roles/run.invoker
```

## Configuration

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `ORG_ID` | Yes | — | Numeric Google Cloud organization ID |
| `BUCKET` | No | — | Bucket for the saved scan |
| `SNAPSHOT_KEY` | No | `snapshot.json` | Object name inside the bucket |
| `LOG_LEVEL` | No | `INFO` | Log verbosity |

`ORG_ID` must be a number. The service will not start without it.

## Usage

Click a row to see the full list of APIs a key allows. Click a column
header to sort. Click the scan icon to run a new scan. Click the
download icon to save the report as a standalone HTML file. Click the
printer icon to print or save as PDF.

## Security

This application does not contain a built-in authentication system, and relies on 
Identity-Aware Proxy (IAP) for authentication and coarse-grained authorisation. 
An unprotected deployment exposes organisation project identifiers and key metadata.

## Disclaimer

AIzkaban is an independent open-source project. It has no affiliation
with Google LLC or any other vendor. Results may be incomplete,
inaccurate, or out of date. Do not use AIzkaban as a substitute for a
professional security assessment. The author accepts no liability for
decisions made from this tool's output. Use it at your own risk.
