"""
notifier.py

Routes enriched alerts to the right analyst via email, Slack, or Teams.

Routing is based on rule groups and rule IDs from config.yaml. The first
matching rule wins; if nothing matches, the alert goes to default_analyst.
"""

import json
import logging
import re
import smtplib
import ssl
import urllib.request
from ipaddress import ip_address
from html import escape
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Optional
from urllib.parse import urlparse

from models import EnrichedAlert, normalize_groups

log = logging.getLogger("NotificationAgent")

_CODE_FENCE_RE = re.compile(r"```(?:[A-Za-z0-9_-]+)?\s*\n?([\s\S]*?)```")
_ALLOWED_WEBHOOK_HOSTS = (
    "hooks.slack.com",
    "outlook.office.com",
    "office.com",
    "webhook.office.com",
)


def _html(value: object) -> str:
    """Escape dynamic values before inserting them into notification HTML."""
    return escape(str(value if value is not None else ""), quote=True)


def _chat_text(value: object) -> str:
    """Prevent alert text from triggering broad chat mentions."""
    return str(value if value is not None else "").replace("@", "@\u200b")


def _secret_value(value: object) -> str:
    """Return the real value from SecretStr-like wrappers without logging it."""
    reveal = getattr(value, "reveal", None)
    if callable(reveal):
        return reveal()
    return str(value if value is not None else "")


def _validate_webhook_url(url: str) -> None:
    parsed = urlparse(str(url or ""))
    host = (parsed.hostname or "").lower()
    if parsed.scheme != "https" or not host:
        raise ValueError("Webhook URL must be HTTPS")
    try:
        ip = ip_address(host)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
            raise ValueError("Webhook URL cannot target private or local IP addresses")
    except ValueError as exc:
        if "Webhook URL" in str(exc):
            raise
    if not any(host == allowed or host.endswith(f".{allowed}") for allowed in _ALLOWED_WEBHOOK_HOSTS):
        raise ValueError(f"Webhook host is not allowed: {host}")


def _route_analyst(enriched: EnrichedAlert, routing_rules: list) -> Optional[dict]:
    """
    Walk the routing rules and return the first analyst that matches.
    Matching checks rule IDs first, then group overlap.
    Returns None if no rule matches — caller should fall back to default_analyst.
    """
    raw_rule = enriched.originalAlert.raw.get("rule", {})
    alert_rule = raw_rule if isinstance(raw_rule, dict) else {}
    groups  = set(normalize_groups(alert_rule.get("groups", [])))
    rule_id = str(alert_rule.get("id", ""))

    for routing_rule in routing_rules:
        if not isinstance(routing_rule, dict):
            continue
        if rule_id in routing_rule.get("_rule_ids", set()):
            return routing_rule.get("analyst")
        if groups & routing_rule.get("_groups", set()):
            return routing_rule.get("analyst")
    return None


def _compile_routing_rules(routing_rules: list) -> list:
    """Normalize rule IDs and groups once instead of on every alert."""
    compiled = []
    for routing_rule in routing_rules or []:
        if not isinstance(routing_rule, dict):
            continue
        compiled_rule = dict(routing_rule)
        compiled_rule["_rule_ids"] = {str(r) for r in (routing_rule.get("rule_ids") or [])}
        compiled_rule["_groups"] = set(normalize_groups(routing_rule.get("groups")))
        compiled.append(compiled_rule)
    return compiled


def _render_html(enriched: EnrichedAlert, analyst: dict, d: Optional[dict] = None) -> str:
    """Build the HTML body for the alert email."""
    d = d or enriched.to_dict()
    level = d["severityLevel"]
    label = d["severityLabel"]

    bar_colors = {15: "#b71c1c", 12: "#e64a19", 10: "#f57f17", 0: "#546e7a"}
    bar_color  = next(v for k, v in bar_colors.items() if level >= k)

    def _md_to_html(text: str) -> str:
        parts = []
        last = 0
        for match in _CODE_FENCE_RE.finditer(str(text)):
            parts.append(_html(str(text)[last:match.start()]).replace("\n", "<br>"))
            code = _html(match.group(1).strip("\n"))
            parts.append(
                '<pre style="background:#1e1e1e;color:#d4d4d4;'
                'padding:12px;border-radius:4px;overflow-x:auto">'
                f"{code}</pre>"
            )
            last = match.end()
        parts.append(_html(str(text)[last:]).replace("\n", "<br>"))
        return "".join(parts)

    return f"""<!DOCTYPE html>
<html><body style="font-family:Arial,sans-serif;max-width:720px;margin:auto;color:#212121">
  <div style="background:{bar_color};color:#fff;padding:18px 22px;border-radius:6px 6px 0 0">
    <h2 style="margin:0">{_html(label)} — SIEM Alert</h2>
    <p style="margin:6px 0 0;opacity:.85;font-size:13px">
      {_html(d['generatedAt'])} &nbsp;|&nbsp; Report: <code>{_html(d['alertId'][:12])}</code>
    </p>
  </div>
  <div style="border:1px solid #e0e0e0;border-top:none;padding:22px;border-radius:0 0 6px 6px">
    <table style="width:100%;border-collapse:collapse;font-size:14px">
      {"".join(
        f'<tr style="background:{"#f5f5f5" if i%2 else "#fff"}">'
        f'<td style="padding:7px 10px;font-weight:bold;width:150px">{_html(k)}</td>'
        f'<td style="padding:7px 10px">{v}</td></tr>'
        for i,(k,v) in enumerate([
            ("Severity",    f"<b>Level {_html(level)}</b> — {_html(label)}"),
            ("Rule ID",     _html(d["ruleId"])),
            ("Description", _html(d["ruleDesc"])),
            ("Groups",      _html(", ".join(d["groups"]))),
            ("Agent",       _html(f"{d['agentName']} ({d['agentIP']})")),
            ("Source IP",   _html(d["sourceIP"])),
            ("Timestamp",   _html(d["timestamp"])),
        ])
      )}
    </table>
    <p style="font-size:13px;color:#555;margin:14px 0 4px"><b>Raw Log:</b></p>
    <pre style="background:#f5f5f5;padding:10px;border-radius:4px;font-size:12px;
                overflow-x:auto">{_html(d["fullLog"])}</pre>

    <h3 style="color:{bar_color};margin:20px 0 6px">📋 Explanation</h3>
    <div style="background:#fafafa;border-left:4px solid {bar_color};
                padding:12px 16px;border-radius:0 4px 4px 0">
      {_md_to_html(enriched.explanation)}
    </div>

    <h3 style="color:{bar_color};margin:20px 0 6px">💥 Impact</h3>
    <div style="background:#fafafa;border-left:4px solid {bar_color};
                padding:12px 16px;border-radius:0 4px 4px 0">
      {_md_to_html(enriched.impact)}
    </div>

    <h3 style="color:{bar_color};margin:20px 0 6px">🔧 Remediation</h3>
    <div style="background:#fafafa;border-left:4px solid {bar_color};
                padding:12px 16px;border-radius:0 4px 4px 0">
      {_md_to_html(enriched.remediation)}
    </div>

    <p style="margin-top:20px;color:#9e9e9e;font-size:11px">
      Routed to: <b>{_html(analyst.get("name","SOC Analyst"))}</b> —
      SIEM AI Agent &nbsp;|&nbsp; Wazuh + Ollama (Local, Private)
    </p>
  </div>
</body></html>"""


class NotificationAgent:
    """Sends enriched alerts to one or more channels (email, Slack, Teams)."""

    def __init__(self, config: dict):
        self._notify_cfg    = config.get("notifications", {})
        self._routing_rules = _compile_routing_rules(config.get("routing_rules", []))
        self._default       = config.get("default_analyst", {})
        self._channels      = [
            str(channel).strip().lower()
            for channel in (self._notify_cfg.get("channels") or [])
            if channel is not None and str(channel).strip()
        ]
        log.info(f"NotificationAgent ready — channels: {self._channels}")

    def send(self, enriched: EnrichedAlert) -> None:
        """Route and deliver an enriched alert to all configured channels."""
        analyst = _route_analyst(enriched, self._routing_rules) or self._default
        if not self._channels:
            log.info(f"Notification channels disabled — routed to {analyst.get('name','SOC Analyst')}")
            return

        log.info(f"Notifying {analyst.get('name','?')} via {self._channels}")

        for channel in self._channels:
            try:
                if   channel == "email":  self._email(enriched, analyst)
                elif channel == "slack":  self._slack(enriched, analyst)
                elif channel == "teams":  self._teams(enriched, analyst)
                else: log.warning(f"Unknown channel: {channel}")
            except Exception as e:
                log.error(f"{channel} notification failed: {e}", exc_info=True)

    def _email(self, enriched: EnrichedAlert, analyst: dict) -> None:
        smtp = self._notify_cfg.get("smtp", {})
        if not smtp.get("enabled", False):
            log.info("Email disabled — skipping")
            return

        d       = enriched.to_dict()
        subject = f"[SIEM] {d['severityLabel']} | Rule {d['ruleId']} | {d['agentName']}"

        plain = (
            f"{d['severityLabel']} — {d['ruleDesc']}\n"
            f"Agent : {d['agentName']} ({d['agentIP']})\n"
            f"Time  : {d['generatedAt']}\n\n"
            f"EXPLANATION\n{enriched.explanation}\n\n"
            f"IMPACT\n{enriched.impact}\n\n"
            f"REMEDIATION\n{enriched.remediation}"
        )

        msg            = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"]    = smtp["from_address"]
        msg["To"]      = analyst.get("email", smtp["from_address"])
        msg.attach(MIMEText(plain, "plain"))
        msg.attach(MIMEText(_render_html(enriched, analyst, d), "html"))

        tls_context = ssl.create_default_context()
        with smtplib.SMTP(smtp["host"], smtp.get("port", 587), timeout=smtp.get("timeout_seconds", 15)) as s:
            if smtp.get("use_tls", True):
                s.starttls(context=tls_context)
            if smtp.get("username"):
                try:
                    s.login(smtp["username"], _secret_value(smtp.get("password", "")))
                except Exception as exc:
                    raise RuntimeError("SMTP authentication failed; credentials were masked") from None
            s.send_message(msg)
        log.info(f"Email sent to {msg['To']}")

    def _slack(self, enriched: EnrichedAlert, analyst: dict) -> None:
        slack = self._notify_cfg.get("slack", {})
        if not slack.get("enabled", False):
            return

        d      = enriched.to_dict()
        colors = {15: "#b71c1c", 12: "#e64a19", 10: "#f57f17", 0: "#546e7a"}
        color  = next(v for k, v in colors.items() if d["severityLevel"] >= k)

        payload = {
            "text": _chat_text(f"*{d['severityLabel']} SIEM Alert* — {d['ruleDesc']}"),
            "attachments": [{
                "color": color,
                "fields": [
                    {"title": "Rule",        "value": _chat_text(f"{d['ruleId']} — {d['ruleDesc']}"), "short": False},
                    {"title": "Agent",       "value": _chat_text(f"{d['agentName']} ({d['agentIP']})"), "short": True},
                    {"title": "Source IP",   "value": _chat_text(d["sourceIP"]),             "short": True},
                    {"title": "Severity",    "value": str(d["severityLevel"]),               "short": True},
                    {"title": "Time",        "value": _chat_text(d["timestamp"]),             "short": True},
                    {"title": "Explanation", "value": _chat_text(enriched.explanation[:900]), "short": False},
                    {"title": "Impact",      "value": _chat_text(enriched.impact[:500]),      "short": False},
                    {"title": "Remediation", "value": _chat_text(enriched.remediation[:900]), "short": False},
                ],
                "footer": _chat_text(f"SIEM AI Agent | Routed to {analyst.get('name','SOC')}"),
            }],
        }
        _validate_webhook_url(slack["webhook_url"])
        self._post(slack["webhook_url"], payload)
        log.info("Slack notification sent")

    def _teams(self, enriched: EnrichedAlert, analyst: dict) -> None:
        teams = self._notify_cfg.get("teams", {})
        if not teams.get("enabled", False):
            return

        d     = enriched.to_dict()
        color = "b71c1c" if d["severityLevel"] >= 15 else "e64a19"

        payload = {
            "@type"    : "MessageCard",
            "@context" : "http://schema.org/extensions",
            "themeColor": color,
            "summary"  : _chat_text(f"SIEM Alert: {d['ruleDesc']}"),
            "sections" : [{
                "activityTitle"   : _chat_text(f"{d['severityLabel']} — {d['ruleDesc']}"),
                "activitySubtitle": d["generatedAt"],
                "facts": [
                    {"name": "Rule ID",     "value": d["ruleId"]},
                    {"name": "Agent",       "value": _chat_text(f"{d['agentName']} ({d['agentIP']})")},
                    {"name": "Source IP",   "value": _chat_text(d["sourceIP"])},
                    {"name": "Severity",    "value": str(d["severityLevel"])},
                    {"name": "Assigned To", "value": _chat_text(analyst.get("name", "SOC Analyst"))},
                ],
                "text": _chat_text(
                    f"**Explanation:** {enriched.explanation[:600]}\n\n"
                    f"**Impact:** {enriched.impact[:300]}\n\n"
                    f"**Remediation:**\n{enriched.remediation[:600]}"
                ),
            }],
        }
        _validate_webhook_url(teams["webhook_url"])
        self._post(teams["webhook_url"], payload)
        log.info("Teams notification sent")

    @staticmethod
    def _post(url: str, payload: dict) -> None:
        """POST JSON to a webhook URL."""
        data = json.dumps(payload).encode("utf-8")
        req  = urllib.request.Request(
            url, data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        context = ssl.create_default_context()
        with urllib.request.urlopen(req, timeout=15, context=context) as r:
            r.read()
