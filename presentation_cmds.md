# SIEM AI Agent Demo Runbook

## Demo Topology

| Component | Host | Purpose |
|---|---:|---|
| Wazuh Manager | Ubuntu VM `10.99.85.19` | Generates and stores Wazuh alerts |
| Middleware + Dashboard | Ubuntu VM `/media/sf_siem-minor` | Filters, enriches, stores, and displays alerts |
| Ollama + TinyLlama | Kali VM `10.99.85.71` | Local LLM inference endpoint |

## What to Show Faculty

This project demonstrates an AI-enhanced SIEM workflow:

1. Wazuh detects high-severity activity.
2. Python middleware tails `alerts.json`.
3. Alerts with rule level `>= 10` are batched and sent to Ollama.
4. TinyLlama returns explanation, impact, and remediation.
5. Reports are persisted as Markdown and JSONL.
6. The Flask dashboard shows analyst-ready alert summaries in real time.

## Pre-Demo Checklist

Run this on Ubuntu:

```bash
cd /media/sf_siem-minor
python3 src/main.py --config src/config.yaml --demo-status
```

Expected:

- Wazuh alerts file exists after Wazuh starts.
- Ollama endpoint is reachable at `http://10.99.85.71:11434`.
- Model is `tinyllama`.
- Reports directory exists or is created by the middleware.

## Demo Commands

Terminal 1, Ubuntu:

```bash
sudo /var/ossec/bin/wazuh-control start
```

Terminal 2, Ubuntu:

```bash
cd /media/sf_siem-minor
python3 src/main.py --config src/config.yaml
```

Terminal 3, Ubuntu:

```bash
cd /media/sf_siem-minor
python3 src/dashboard.py --config src/config.yaml --reports ./reports
```

Browser:

```text
http://localhost:5000
```

Kali attack simulation:

```bash
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://10.99.85.19 -t 4 -V
```

## Talking Points

- All LLM inference is local through Ollama, so alert data is not sent to a cloud provider.
- Async batching improves throughput during alert bursts.
- The fallback enrichment keeps the pipeline useful even if the model call times out.
- Analyst routing is based on Wazuh rule IDs and groups.
- The dashboard is offline-friendly and reads from the persistent audit trail.

## Troubleshooting

If Ollama is unreachable from Ubuntu:

```bash
curl http://10.99.85.71:11434/api/tags
```

On Kali, ensure Ollama is reachable only from the Ubuntu middleware host. If you must bind it to the bridged interface for the demo, firewall it to Ubuntu (`10.99.85.19`) before starting Ollama:

```bash
sudo ufw allow from 10.99.85.19 to any port 11434 proto tcp
OLLAMA_HOST=0.0.0.0 ollama serve
```

If no alerts appear:

```bash
sudo tail -f /var/ossec/logs/alerts/alerts.json
ls -lh ./reports
tail -f ./reports/alerts_enriched.jsonl
```

If Flask is missing:

```bash
python3 -m pip install -r requirements.txt
```
