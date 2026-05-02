"""
middleware.py

PythonMiddleware is the main orchestrator. It tails alerts.json, filters
out noise, batches qualifying alerts, and ships them to Ollama for enrichment.

The async batch queue exists to avoid calling Ollama one-at-a-time; alerts
accumulate until either batch_size is reached or flush_interval_seconds
elapses, then they're all sent concurrently.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from collections import deque
from pathlib import Path
from typing import Optional

from models import Alert, EnrichedAlert, normalize_groups
from ollama_service import OllamaService
from notifier import NotificationAgent
from report_logger import ReportLogger

log = logging.getLogger("PythonMiddleware")


def _log_safe(value: object, limit: int = 90) -> str:
    """Keep attacker-controlled alert text from injecting fake log lines."""
    text = str(value if value is not None else "")
    text = text.replace("\r", "\\r").replace("\n", "\\n")
    return text[:limit] + ("..." if len(text) > limit else "")


def _file_identity(stat_result: object):
    """Return a stable file identity when the platform exposes one."""
    inode = getattr(stat_result, "st_ino", None)
    device = getattr(stat_result, "st_dev", None)
    return (device, inode) if inode else None


class PythonMiddleware:
    """
    Central orchestrator for the five-stage pipeline:

        1. Log collection   — Wazuh agents write to alerts.json
        2. Wazuh analysis   — handled by the Wazuh daemon before we see it
        3. Alert generation — JSON already in alerts.json on arrival
        4. Severity filter  — filterBySeverity()
        5. LLM enrichment   — callOllama() / OllamaService
    """

    def __init__(self, config: dict):
        self.filePath  : str = config["wazuh"]["alerts_json_path"]
        self._alerts_path = Path(self.filePath)
        self.threshold : int = config["filter"]["min_severity_level"]
        self.lastPos   : int = 0
        self._file_id  = None
        self._alerts_fp = None

        self._ollama   = OllamaService(config)
        self._notifier = NotificationAgent(config)
        self._reporter = ReportLogger(config)
        self._write_markdown: bool = config.get("output", {}).get("write_markdown", True)

        self._seen_ids : set = set()
        self._seen_order = deque()
        self._max_seen_ids: int = config["filter"].get("dedupe_cache_size", 10000)

        self._batch_size          : int   = config["filter"].get("batch_size", 5)
        self._flush_interval_secs : float = config["filter"].get("flush_interval_seconds", 3.0)
        self._poll_interval       : float = config["filter"].get("poll_interval_seconds", 1.0)
        self._max_lines_per_poll  : int   = config["filter"].get("max_lines_per_poll", 200)
        self._ignore_groups       : set   = {
            str(group) for group in (config["filter"].get("ignore_groups") or [])
        }

        self._pending_batch : list = []
        self._batch_lock    = asyncio.Lock()
        self._last_flush    : float = time.monotonic()

        log.info("PythonMiddleware ready")
        log.info(f"  file      = {self.filePath}")
        log.info(f"  threshold = level >= {self.threshold}")
        log.info(f"  batch     = {self._batch_size} alerts, flush every {self._flush_interval_secs}s")
        log.info(f"  drain     = up to {self._max_lines_per_poll} new log lines per poll")

    def tail_read(self) -> Optional[Alert]:
        """
        Read the next unread line from alerts.json.
        Tracks the byte offset in self.lastPos so we never re-read old lines.
        Returns None if there's nothing new.

        Also handles log rotation: if the file is smaller than our saved
        position (Wazuh rotated it), we reset to the top so nothing is missed.
        """
        alerts = self.tail_read_many(1)
        return alerts[0] if alerts else None

    def tail_read_many(self, max_lines: Optional[int] = None) -> list[Alert]:
        """Read up to max_lines new alerts using one file open/seek cycle."""
        if not self._alerts_path.exists():
            self._close_alerts_file()
            return []

        stat_result = self._alerts_path.stat()
        current_file_id = _file_identity(stat_result)
        if current_file_id is not None:
            if self._file_id is None:
                self._file_id = current_file_id
            elif current_file_id != self._file_id:
                log.warning("Log rotation detected — file identity changed; resetting read position")
                self._file_id = current_file_id
                self.lastPos = 0
                self._close_alerts_file()

        current_size = stat_result.st_size
        if current_size < self.lastPos:
            log.warning("Log rotation detected — resetting read position to start of file")
            self.lastPos = 0
            self._close_alerts_file()

        alerts = []
        lines_read = 0

        fp = self._open_alerts_file()
        fp.seek(self.lastPos)
        while max_lines is None or lines_read < max_lines:
            pos_before = fp.tell()
            raw_line = fp.readline()
            if not raw_line:
                break
            if not raw_line.endswith(b"\n"):
                log.debug("Partial alert line detected — waiting for next poll")
                fp.seek(pos_before)
                break

            line = raw_line.decode("utf-8", errors="replace")
            lines_read += 1
            try:
                alert = self._parse_alert_line(line)
            except (AttributeError, TypeError, ValueError) as e:
                log.warning(f"Skipping malformed alert line: {_log_safe(e)}")
                self.lastPos = fp.tell()
                continue
            self.lastPos = fp.tell()
            if alert:
                alerts.append(alert)

        return alerts

    def _open_alerts_file(self):
        if self._alerts_fp is None or self._alerts_fp.closed:
            self._alerts_fp = open(self._alerts_path, "rb")
        return self._alerts_fp

    def _close_alerts_file(self) -> None:
        if self._alerts_fp is not None:
            try:
                self._alerts_fp.close()
            finally:
                self._alerts_fp = None

    @staticmethod
    def _parse_alert_line(line: str) -> Optional[Alert]:
        """Parse one alerts.json line into an Alert, returning None for noise."""
        line = line.strip()
        if not line:
            return None

        try:
            raw_dict = json.loads(line)
        except json.JSONDecodeError:
            log.debug(f"Skipping non-JSON line: {line[:60]}")
            return None

        return Alert.from_wazuh_json(raw_dict)

    def tailRead(self) -> Optional[Alert]:
        """Backward-compatible alias for older callers."""
        return self.tail_read()

    def filter_by_severity(self, alert: Alert) -> bool:
        """
        Decide whether an alert should proceed to LLM enrichment.

        An alert is rejected if:
          - we've already processed it (duplicate fingerprint)
          - its level is below the configured threshold
          - it belongs to a suppressed group (e.g. 'ossec' health checks)
        """
        if alert.alertId in self._seen_ids:
            return False

        if alert.level < self.threshold:
            return False

        rule = alert.raw.get("rule", {})
        groups = rule.get("groups", []) if isinstance(rule, dict) else []
        alert_groups = set(normalize_groups(groups))
        if alert_groups & self._ignore_groups:
            log.debug(f"Suppressed by group filter: {alert_groups}")
            return False

        self._remember_alert_id(alert.alertId)
        return True

    def _remember_alert_id(self, alert_id: str) -> None:
        """Keep duplicate detection bounded so long-running demos stay stable."""
        self._seen_ids.add(alert_id)
        self._seen_order.append(alert_id)

        while len(self._seen_order) > self._max_seen_ids:
            old_id = self._seen_order.popleft()
            self._seen_ids.discard(old_id)

    def filterBySeverity(self, alert: Alert) -> bool:
        """Backward-compatible alias for older callers."""
        return self.filter_by_severity(alert)

    def build_prompt(self, alert: Alert) -> str:
        """Delegate to OllamaService for prompt construction."""
        return OllamaService._build_prompt(alert)

    def buildPrompt(self, alert: Alert) -> str:
        """Backward-compatible alias for older callers."""
        return self.build_prompt(alert)

    def call_ollama(self, alert: Alert) -> EnrichedAlert:
        """Synchronous single-alert enrichment. Mainly useful for testing."""
        return self._ollama.enrich_alert(alert)

    def callOllama(self, alert: Alert) -> EnrichedAlert:
        """Backward-compatible alias for older callers."""
        return self.call_ollama(alert)

    def _dispatch(self, enriched: EnrichedAlert) -> None:
        """Print, save, and notify for one enriched alert."""
        try:
            enriched.display()
        except Exception as e:
            log.error(f"Console display failed for {enriched.originalAlert.alertId[:8]}: {_log_safe(e)}", exc_info=True)

        try:
            if self._write_markdown:
                enriched.log_to_file(report_dir=self._reporter.output_dir)
            self._reporter.save_jsonl(enriched)
        except Exception as e:
            log.error(f"Report persistence failed for {enriched.originalAlert.alertId[:8]}: {_log_safe(e)}", exc_info=True)

        try:
            self._notifier.send(enriched)
        except Exception as e:
            log.error(f"Notification dispatch failed for {enriched.originalAlert.alertId[:8]}: {_log_safe(e)}", exc_info=True)

    async def _flush_batch(self) -> None:
        """
        Send all pending alerts to Ollama concurrently, then dispatch each result.
        Clears the batch regardless of whether enrichment succeeds.
        """
        async with self._batch_lock:
            if not self._pending_batch:
                return

            batch = self._pending_batch.copy()
            self._pending_batch.clear()
            self._last_flush = time.monotonic()

            log.info(f"Flushing {len(batch)} alert(s) to Ollama")
            enriched_list = await self._ollama.async_enrich_batch(batch)

            for enriched in enriched_list:
                self._dispatch(enriched)

    async def run(self) -> None:
        """
        Main monitoring loop. Tails alerts.json, filters, batches, and flushes.

        Seeks to the end of the file on startup to skip historical alerts —
        only new alerts written after the agent starts are processed.
        """
        log.info("Monitoring loop started")

        if self._alerts_path.exists():
            stat_result = self._alerts_path.stat()
            self._file_id = _file_identity(stat_result)
            self.lastPos = stat_result.st_size
            log.info(f"Seeked to end of {self.filePath} (offset {self.lastPos})")

        while True:
            try:
                alerts = self.tail_read_many(self._max_lines_per_poll)

                for alert in alerts:
                    if self.filter_by_severity(alert):
                        log.warning(f"QUEUED | {alert.severity_name()} L{alert.level} | "
                                    f"{_log_safe(alert.ruleDesc, 55)} | {_log_safe(alert.agentName, 55)}")
                        self._pending_batch.append(alert)

                        if len(self._pending_batch) >= self._batch_size:
                            await self._flush_batch()

                interval_lapsed = (
                    self._pending_batch and
                    (time.monotonic() - self._last_flush) >= self._flush_interval_secs
                )

                if interval_lapsed:
                    await self._flush_batch()
                elif not alerts:
                    await asyncio.sleep(self._poll_interval)
                else:
                    await asyncio.sleep(0.05)

            except asyncio.CancelledError:
                log.info("Shutdown signal — flushing remaining alerts")
                await self._flush_batch()
                self._close_alerts_file()
                break
            except Exception as e:
                log.error(f"Loop error: {e}", exc_info=True)
                await asyncio.sleep(5)

    async def run_batch_file(self, file_path: str, limit: Optional[int] = None) -> None:
        """
        Process a static JSONL file instead of tailing alerts.json.
        Useful for replaying historical alerts or running the test set.

        Accepts both raw Wazuh JSON lines and the training-set format
        where the alert JSON is nested under an "input" key.
        """
        log.info(f"Batch file: {file_path}")
        pending: list = []

        with open(file_path, "r", encoding="utf-8") as f:
            for i, line in enumerate(f, 1):
                if limit is not None and i > limit:
                    log.info(f"Batch limit reached after {limit} record(s)")
                    break
                if i % 1000 == 0:
                    log.info(f"Batch progress: read {i} record(s)")
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                    if not isinstance(record, dict):
                        raise ValueError("batch record must be a JSON object")
                    if "input" in record:
                        if isinstance(record["input"], str):
                            raw = json.loads(record["input"])
                        elif isinstance(record["input"], dict):
                            raw = record["input"]
                        else:
                            raise ValueError("batch input must be a JSON object or JSON string")
                    else:
                        raw = record
                    alert = Alert.from_wazuh_json(raw)
                except (AttributeError, TypeError, json.JSONDecodeError, KeyError, ValueError) as e:
                    log.debug(f"Line {i} skipped: {e}")
                    continue

                if not self.filter_by_severity(alert):
                    continue

                pending.append(alert)

                if len(pending) >= self._batch_size:
                    self._pending_batch.extend(pending)
                    pending.clear()
                    await self._flush_batch()

        if pending:
            self._pending_batch.extend(pending)
            pending.clear()
            await self._flush_batch()

        log.info("Batch file processing complete")
