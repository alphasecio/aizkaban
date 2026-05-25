# AIzkaban — API Key Auditor

Scans a Google Cloud organization for API keys that may unintentionally expose the Gemini API, based on the privilege escalation vector documented by [TruffleHog (Feb 2026)](https://trufflesecurity.com/blog/google-api-keys-werent-secrets-but-then-gemini-changed-the-rules).

## The Risk

When the Gemini API is enabled on a GCP project, any existing unrestricted API key in that project silently gains access to Gemini endpoints — including keys originally created for Maps, Firebase, or other public-facing services. Keys deployed in client-side code under Google's prior guidance ("API keys are not secrets") can become live Gemini credentials with no warning and no notification.

## Findings

| Severity | Condition |
|---|---|
| 🔴 **Critical** | Unrestricted key, Gemini enabled — actively exploitable |
| 🟠 **High** | Unrestricted key, Gemini not enabled — one API enablement away from Critical |
| 🟡 **Low** | Restricted key, Gemini enabled — intentional but verify key is not publicly exposed |
| 🔵 **Info** | Restricted key, Gemini not enabled — no immediate risk |

Within the Low card, keys that explicitly include `generativelanguage.googleapis.com` in their API restrictions are marked with a ✦ icon — these directly grant Gemini access and warrant extra scrutiny if the key is exposed.

Keys created before **March 2023** (pre-Gemini API availability) are flagged as **Pre-Gemini** — highest priority for review, most likely deployed in public-facing code under the old guidance.

## Tools

| Tool | Description |
|---|---|
| [`shell/`](shell/) | Standalone bash script, outputs a self-contained HTML report |
| [`cloudrun/`](cloudrun/) | Persistent web dashboard deployed on Cloud Run, with on-demand refresh |

Both tools share identical detection logic and produce identical findings.

## Required IAM Roles (Organization level)

| Role | Purpose |
|---|---|
| `roles/cloudasset.viewer` | Query Cloud Asset Inventory org-wide |
| `roles/resourcemanager.organizationViewer` | Enumerate and resolve project IDs |

Both roles must be bound at **Organization** level, not project level.

## Remediation

For **Critical** and **High** findings:
1. Restrict the key to only the APIs it actually needs — **APIs & Services → Credentials → Edit key**
2. If the key is in client-side code or a public repository, **rotate it immediately**
3. Disable the Gemini API on projects where it is not intentionally in use

For **Low** findings:
1. Confirm the key is not embedded in client-side code or public repositories — a restricted key that leaks is still a usable credential
2. If Gemini access is not intentional, remove `generativelanguage.googleapis.com` from the key's API restrictions

## Security Note

The generated report and dashboard contain org ID, project IDs, and key metadata. Treat the output as sensitive — do not share it over unprotected channels or store it in public locations.

## References

- [TruffleHog: Google API Keys Weren't Secrets. But then Gemini Changed the Rules.](https://trufflesecurity.com/blog/google-api-keys-werent-secrets-but-then-gemini-changed-the-rules)
- [The Hacker News coverage](https://thehackernews.com/2026/02/thousands-of-public-google-cloud-api.html)
- [Google API Key Best Practices](https://cloud.google.com/docs/authentication/api-keys-best-practices)

## Disclaimer
AIzkaban is an independent open-source project with no affiliation to Google LLC or any other vendor. It is provided for educational and informational purposes only. Scan results may be incomplete, inaccurate, or out of date — do not rely on them as a substitute for a professional security assessment. The author accepts no liability for decisions made based on this tool's output. Use at your own risk.
