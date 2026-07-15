# Security Automation & Vulnerability Triage Prototype

A self-contained Python prototype simulating an end-to-end vulnerability
management workflow: CVE ingestion → severity triage → AI-assisted
mitigation drafting → JIRA ticket generation → Excel KPI reporting →
management-ready slide outline.

Built as a technical demo for a Working Student (Cybersecurity) interview,
reflecting the following responsibilities from the job description:

| Script Step | Function | Job Requirement |
|---|---|---|
| 1. Fetch CVEs | `fetch_cve_feed()` | Support vulnerability monitoring |
| 2. Triage | `filter_high_priority()` | Structuring risk assessments |
| 3. AI mitigation draft | `generate_mitigation_plan()` | Willingness to use AI to improve processes |
| 4. JIRA payload | `build_jira_payload()` | Integration of results into JIRA |
| 5. Terminal report | `print_report()` | Project tracking and reporting |
| 6. Excel dashboard | `export_to_excel()` | Excel-based reports/dashboards, KPI tracking |
| 7. Slide outline | `generate_slide_outline()` | PowerPoint prep for management alignment |

## Design notes

- **Fully offline / no API keys.** External calls (CVE feed, LLM, JIRA) are
  mocked so the script runs anywhere in seconds. Each mock function's
  docstring shows the real API call it stands in for.
- **AI steps are not live LLM calls**, they are deterministic
  so output is reproducible on any machine, but structured as a
  real prompt or response would be.

## Setup

```bash
pip install openpyxl
python3 triage_prototype.py
```

## Output

Running the script produces:
- Full terminal report of all fetched AI-generated CVEs and escalated tickets
- `vulnerability_report.xlsx` — two-sheet workbook (full dashboard + KPI
  summary, plus an "Escalated (JIRA)" sheet with AI mitigation plans)
- `management_slide_outline.md` — slide-by-slide outline for fast-tracking presentation production

## Path to production

- `fetch_cve_feed()` → NVD API or internal asset-inventory/scanner integration
- `generate_mitigation_plan()` / `generate_slide_outline()` → live Claude/OpenAI API call
- `build_jira_payload()` → authenticated JIRA REST `POST /rest/api/3/issue`
- `export_to_excel()` → scheduled job producing a weekly KPI report
- Whole pipeline → cron job / CI pipeline step for continuous monitoring