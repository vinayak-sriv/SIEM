# SIEM AI Agent

AI-enhanced SIEM alert enrichment for Wazuh using a local Ollama LLM.

This project tails Wazuh `alerts.json`, filters high-severity alerts, enriches them with a local model, stores analyst-ready reports, and displays everything in a Flask dashboard.

## Features

- Wazuh alert ingestion from `alerts.json`
- Severity filtering for high-value events
- Async batch enrichment through Ollama
- Structured LLM output: explanation, impact, remediation
- Rule-aware fallback enrichment when the LLM is unavailable
- Markdown and JSONL report persistence
- Analyst routing for email, Slack, and Teams
- Offline-friendly Flask dashboard
- Demo readiness check for hackathon/faculty presentation

## Architecture

```text
Wazuh alerts.json
      |
      v
Python middleware
      |
      v
Severity filter + async batching
      |
      v
Ollama local LLM
      |
      v
Reports + notifications + dashboard
```

## Repository Layout

```text
src/
  main.py              # CLI entry point and demo readiness check
  config_loader.py     # YAML config loading and validation
  config.yaml          # Demo/runtime configuration
  middleware.py        # Tail, filter, batch, enrich, dispatch
  models.py            # Alert and EnrichedAlert dataclasses
  ollama_service.py    # Prompting, Ollama API calls, parsing, fallback
  notifier.py          # Email/Slack/Teams analyst routing
  report_logger.py     # JSONL audit trail writer
  dashboard.py         # Flask dashboard
  install.sh           # Ubuntu/systemd installer helper

README_DEMO.md         # Faculty/demo runbook
requirements.txt       # Python dependencies
```

## Quick Start

Install dependencies:

```bash
python3 -m pip install -r requirements.txt
```

Requires Python 3.9 or newer.

Run a pre-demo status check:

```bash
python3 src/main.py --config src/config.yaml --demo-status
```

Start the middleware:

```bash
python3 src/main.py --config src/config.yaml
```

Start the dashboard:

```bash
python3 src/dashboard.py --config src/config.yaml --reports ./reports
```

Open:

```text
http://localhost:5000
```

## Demo Setup

The current demo configuration expects:

- Wazuh + middleware on Ubuntu VM: `10.99.85.19`
- Ollama + TinyLlama on Kali VM: `10.99.85.71`
- Ollama endpoint: `http://10.99.85.71:11434`
- Severity threshold: Wazuh rule level `>= 10`

See [README_DEMO.md](README_DEMO.md) for the full presentation runbook.

## Configuration

Main settings live in [src/config.yaml](src/config.yaml).

Environment variables can override sensitive or machine-specific values:

```bash
export OLLAMA_URL=http://10.99.85.71:11434
export OLLAMA_MODEL=tinyllama
export SEVERITY_LEVEL=10
export SMTP_PASSWORD=your-app-password
export SLACK_WEBHOOK=https://hooks.slack.com/services/...
export TEAMS_WEBHOOK=https://outlook.office.com/webhook/...
export SIEM_DASHBOARD_TOKEN=choose-a-local-demo-token
```

## Notes for GitHub

Large local model files, unfinished browser downloads, Python caches, logs, and generated reports are ignored by `.gitignore`.

Do not upload `.gguf` model files directly to GitHub. Use Ollama model pulls or Git LFS only if your project specifically requires publishing model artifacts.

Before uploading through GitHub's web UI or as a zip, move these local-only artifacts outside the project folder:

- `Unconfirmed 580948.crdownload`
- `custom-wazuh-model_gguf/*.gguf`
- `siem_agent.log`
- `__pycache__/` and `src/__pycache__/`
- `tmp_*` probe/report folders

Quick upload sanity check from PowerShell:

```powershell
Get-ChildItem -Recurse -Force | Where-Object { $_.Length -gt 100MB } | Select-Object FullName,Length
```

## License

Academic minor project by Vinayak Srivastava, UPES Dehradun.
