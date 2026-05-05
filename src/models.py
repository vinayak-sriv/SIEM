"""
models.py

Two dataclasses that carry alert data through the pipeline:

  Alert         — a parsed Wazuh JSON alert
  EnrichedAlert — the same alert after the LLM has had a look at it
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger("Models")

_FILENAME_SAFE = re.compile(r"[^A-Za-z0-9_.-]+")

_SEVERITY_MAP = {
    (15, 99): "CRITICAL",
    (12, 14): "HIGH",
    (10, 11): "MEDIUM-HIGH",
    (0,   9): "LOW",
}

_SEVERITY_ICONS = {
    "CRITICAL":    "🔴",
    "HIGH":        "🟠",
    "MEDIUM-HIGH": "🟡",
    "LOW":         "⚪",
}

def _severity_name(level) -> str:
    try:
        numeric_level = int(level)
    except (TypeError, ValueError):
        return "UNKNOWN"
        
    if numeric_level >= 15:
        return "CRITICAL"
    if numeric_level >= 12:
        return "HIGH"
    if numeric_level >= 10:
        return "MEDIUM-HIGH"
    if numeric_level >= 0:
        return "LOW"
    return "UNKNOWN"


def _severity_label(level: int) -> str:
    label = _severity_name(level)
    return f"{_SEVERITY_ICONS.get(label, '⚪')} {label}"


def _utc_now() -> datetime:
    """Return an explicit timezone-aware UTC timestamp."""
    return datetime.now(timezone.utc)


def _utc_now_iso() -> str:
    return _utc_now().isoformat().replace("+00:00", "Z")


def _console_safe(text: str) -> str:
    """Render text safely on terminals that do not support UTF-8."""
    encoding = getattr(sys.stdout, "encoding", None) or "utf-8"
    return text.encode(encoding, errors="replace").decode(encoding)


def _safe_filename_part(value: object, fallback: str = "UNK") -> str:
    """Return a short filename-safe token."""
    token = _FILENAME_SAFE.sub("_", str(value or fallback)).strip("._")
    return token[:40] or fallback


def _raw_field(raw: dict, key: str, default: str = "") -> str:
    value = raw.get(key, default)
    return str(value if value is not None else default)


def normalize_groups(value: object) -> list[str]:
    """Normalize Wazuh group values from lists or comma-separated strings."""
    if value is None:
        return []
    if isinstance(value, str):
        return [part.strip() for part in value.split(",") if part.strip()]
    if isinstance(value, (list, tuple, set)):
        groups = []
        for group in value:
            item = str(group).strip()
            if item:
                groups.append(item)
        return groups
    item = str(value).strip()
    return [item] if item else []


def _as_dict(value: object) -> dict:
    return value if isinstance(value, dict) else {}


def _as_int(value: object, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _markdown_cell(value: object) -> str:
    """Escape table-breaking and HTML-sensitive text for Markdown reports."""
    text = str(value if value is not None else "")
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("|", "\\|")
        .replace("\r", " ")
        .replace("\n", " ")
    )


def _markdown_code(value: object) -> str:
    return str(value if value is not None else "").replace("```", "`\u200b``")


@dataclass
class Alert:
    """A single Wazuh alert, parsed from its JSON representation."""

    _alertId   : str
    _timestamp : datetime
    _level     : int
    _ruleDesc  : str
    _sourceIP  : str
    _agentName : str
    _raw       : dict = field(default_factory=dict, repr=False)

    @classmethod
    def from_wazuh_json(cls, raw: dict) -> "Alert":
        """Build an Alert from the raw dict Wazuh writes to alerts.json."""
        if not isinstance(raw, dict):
            raise ValueError("Wazuh alert must be a JSON object")

        rule   = _as_dict(raw.get("rule", {}))
        agent  = _as_dict(raw.get("agent", {}))
        data   = _as_dict(raw.get("data", {}))
        ts_str = raw.get("timestamp", _utc_now_iso())

        # Fingerprint from high-signal alert fields so bursts do not collapse together.
        fingerprint_src = "\x1f".join(str(part if part is not None else "") for part in (
            rule.get("id"),
            ts_str,
            agent.get("id"),
            data.get("srcip"),
            raw.get("full_log", ""),
        ))
        alert_id = hashlib.sha256(fingerprint_src.encode("utf-8", errors="replace")).hexdigest()

        try:
            ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        except (AttributeError, TypeError, ValueError):
            ts = _utc_now()

        return cls(
            _alertId   = alert_id,
            _timestamp = ts,
            _level     = _as_int(rule.get("level", 0)),
            _ruleDesc  = str(rule.get("description", "Unknown")),
            _sourceIP  = str(data.get("srcip", "N/A")),
            _agentName = str(agent.get("name", "Unknown Agent")),
            _raw       = raw,
        )

    def to_json(self) -> str:
        """Serialize the alert's key fields to JSON."""
        rule = _as_dict(self._raw.get("rule", {}))
        agent = _as_dict(self._raw.get("agent", {}))
        return json.dumps({
            "alertId"   : self._alertId,
            "timestamp" : self._timestamp.isoformat(),
            "level"     : self._level,
            "ruleDesc"  : self._ruleDesc,
            "sourceIP"  : self._sourceIP,
            "agentName" : self._agentName,
            "ruleId"    : rule.get("id", "N/A"),
            "groups"    : normalize_groups(rule.get("groups", [])),
            "agentIP"   : agent.get("ip", "N/A"),
            "fullLog"   : _raw_field(self._raw, "full_log")[:500],
        }, indent=2)

    def toJSON(self) -> str:
        """Backward-compatible alias for older callers."""
        return self.to_json()

    def get_severity(self) -> str:
        return _severity_label(self._level)

    def getSeverity(self) -> str:
        """Backward-compatible alias for older callers."""
        return self.get_severity()

    def severity_name(self) -> str:
        return _severity_name(self._level)

    @property
    def alertId(self)   -> str:      return self._alertId
    @property
    def timestamp(self) -> datetime: return self._timestamp
    @property
    def level(self)     -> int:      return self._level
    @property
    def ruleDesc(self)  -> str:      return self._ruleDesc
    @property
    def sourceIP(self)  -> str:      return self._sourceIP
    @property
    def agentName(self) -> str:      return self._agentName
    @property
    def raw(self)       -> dict:     return self._raw

    def __repr__(self) -> str:
        return (f"Alert(id={self._alertId[:8]}, level={self._level}, "
                f"agent={self._agentName}, rule={self._ruleDesc[:40]})")


@dataclass
class EnrichedAlert:
    """An Alert with LLM-generated explanation, impact assessment, and remediation steps."""

    originalAlert : Alert
    explanation   : str
    impact        : str
    remediation   : str
    generatedAt   : str = field(default_factory=_utc_now_iso)
    _dict_cache   : dict = field(default_factory=dict, init=False, repr=False)

    def display(self) -> None:
        """Print a formatted summary to stdout."""
        sep  = "=" * 70
        sev  = self.originalAlert.severity_name()
        rule = self.originalAlert.ruleDesc
        ts   = self.originalAlert.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")

        print(_console_safe(f"\n{sep}"))
        print(_console_safe(f"  {sev}  |  {rule}"))
        print(_console_safe(
            f"  Agent : {self.originalAlert.agentName}  |  "
            f"Source IP : {self.originalAlert.sourceIP}  |  {ts}"
        ))
        print(_console_safe(sep))
        print(_console_safe(f"\nEXPLANATION\n{self.explanation}\n"))
        print(_console_safe(f"IMPACT\n{self.impact}\n"))
        print(_console_safe(f"REMEDIATION\n{self.remediation}"))
        print(_console_safe(f"{sep}\n"))

    def log_to_file(self, report_dir: str = "reports") -> Path:
        """Write a Markdown report file and return its path."""
        out_dir  = Path(report_dir)
        out_dir.mkdir(parents=True, exist_ok=True)

        try:
            generated_at = datetime.fromisoformat(self.generatedAt.replace("Z", "+00:00"))
            ts_str = generated_at.strftime("%Y%m%d_%H%M%S")
        except ValueError:
            ts_str = _safe_filename_part(self.generatedAt)
        rule = _as_dict(self.originalAlert.raw.get("rule", {}))
        rule_id  = _safe_filename_part(rule.get("id", "UNK"))
        filename = f"alert_{ts_str}_rule{rule_id}_{self.originalAlert.alertId[:8]}.md"
        filepath = out_dir / filename

        filepath.write_text(self._render_markdown(), encoding="utf-8")
        try:
            os.chmod(filepath, 0o600)
        except OSError:
            pass
        log.info(f"Report written: {filepath}")
        return filepath

    def logToFile(self, report_dir: str = "reports") -> Path:
        """Backward-compatible alias for older callers."""
        return self.log_to_file(report_dir=report_dir)

    def _payload_dict(self) -> dict:
        """Build the flat alert payload once; callers treat it as read-only."""
        if self._dict_cache:
            return self._dict_cache
        rule = _as_dict(self.originalAlert.raw.get("rule", {}))
        agent = _as_dict(self.originalAlert.raw.get("agent", {}))
        self._dict_cache = {
            "alertId"      : self.originalAlert.alertId,
            "generatedAt"  : self.generatedAt,
            "severityLevel": self.originalAlert.level,
            "severityLabel": self.originalAlert.get_severity(),
            "ruleId"       : rule.get("id"),
            "ruleDesc"     : self.originalAlert.ruleDesc,
            "groups"       : normalize_groups(rule.get("groups", [])),
            "agentName"    : self.originalAlert.agentName,
            "agentIP"      : agent.get("ip", "N/A"),
            "sourceIP"     : self.originalAlert.sourceIP,
            "timestamp"    : self.originalAlert.timestamp.isoformat(),
            "fullLog"      : _raw_field(self.originalAlert.raw, "full_log")[:500],
            "explanation"  : self.explanation,
            "impact"       : self.impact,
            "remediation"  : self.remediation,
        }
        return self._dict_cache

    def to_dict(self) -> dict:
        """Serialize to a flat dict suitable for JSONL logging or notification payloads."""
        return dict(self._payload_dict())

    def _render_markdown(self) -> str:
        d = self._payload_dict()
        groups = ", ".join(str(group) for group in d["groups"])
        return f"""# {d['severityLabel']} — SIEM Enriched Alert

**Report ID** : `{d['alertId']}`
**Generated** : {d['generatedAt']}

---

## Alert Metadata

| Field | Value |
|-------|-------|
| Severity Level | **{_markdown_cell(d['severityLevel'])}** — {_markdown_cell(d['severityLabel'])} |
| Rule ID | {_markdown_cell(d['ruleId'])} |
| Rule Description | {_markdown_cell(d['ruleDesc'])} |
| Groups | {_markdown_cell(groups)} |
| Agent Name | {_markdown_cell(d['agentName'])} |
| Agent IP | {_markdown_cell(d['agentIP'])} |
| Source IP | {_markdown_cell(d['sourceIP'])} |
| Timestamp | {_markdown_cell(d['timestamp'])} |

**Raw Log:**
```
{_markdown_code(d['fullLog'])}
```

---

## 📋 Explanation
{self.explanation}

## 💥 Impact
{self.impact}

## 🔧 Remediation
{self.remediation}

## Analyst Notes
- Correlate with Wazuh agent logs and authentication history.
- Preserve relevant logs before applying destructive remediation.
- Escalate if the same source IP, account, or host repeats across alerts.

---
*Generated by SIEM AI Agent — Wazuh + Ollama (Local, Private)*
"""
