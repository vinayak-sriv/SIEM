"""
report_logger.py

Handles persistence for enriched alerts.

Individual .md report files are written by EnrichedAlert.logToFile().
This module appends every alert to a master JSONL file so you have a
machine-readable audit trail for later analysis or ingestion into a SOAR.
"""

import json
import logging
import os
import shutil
from datetime import datetime, timezone
from pathlib import Path

from models import EnrichedAlert

log = logging.getLogger("ReportLogger")


def _secure_jsonl_opener(path, flags):
    """Create JSONL files with owner-only permissions when the OS supports it."""
    return os.open(path, flags, 0o600)


class ReportLogger:

    def __init__(self, config: dict):
        output_cfg = config.get("output", {})
        self.output_dir = output_cfg.get("report_dir", "reports")
        self._output_path = Path(self.output_dir).resolve()
        if self._output_path.is_symlink():
            raise ValueError(f"Report directory cannot be a symlink: {self._output_path}")
        self._output_path.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self._output_path, 0o700)
        except OSError:
            pass
        self._jsonl_path = self._output_path / "alerts_enriched.jsonl"
        # Fresh-session report rotation is disabled to preserve the previous
        # behavior: keep old .md reports and append to alerts_enriched.jsonl.
        # To restore it later, uncomment these lines and the two config.yaml
        # output keys: fresh_session_on_start + archive_previous_reports.
        # self._fresh_session_on_start = bool(output_cfg.get("fresh_session_on_start", False))
        # self._archive_previous_reports = bool(output_cfg.get("archive_previous_reports", True))
        # if self._fresh_session_on_start:
        #     self.start_fresh_session(archive_previous=self._archive_previous_reports)
        self._jsonl_file = None
        log.info(f"ReportLogger ready — writing to {self.output_dir}")

    def start_fresh_session(self, archive_previous: bool = True) -> None:
        """
        Move or delete previous run reports, then initialize a clean JSONL file.

        This keeps each demo command/run visually clean while preserving prior
        evidence under reports/archive/ by default.
        """
        self.close()
        previous_reports = [
            path for path in self._output_path.iterdir()
            if path.is_file() and (
                path.name == "alerts_enriched.jsonl" or
                path.name.startswith("alert_") and path.suffix == ".md"
            )
        ]

        if previous_reports:
            if archive_previous:
                archive_dir = self._output_path / "archive" / self._session_name()
                archive_dir.mkdir(parents=True, exist_ok=True)
                for path in previous_reports:
                    shutil.move(str(path), str(archive_dir / path.name))
                log.info(f"Archived {len(previous_reports)} previous report file(s) to {archive_dir}")
            else:
                for path in previous_reports:
                    path.unlink()
                log.info(f"Deleted {len(previous_reports)} previous report file(s)")

        self._jsonl_path.write_text("", encoding="utf-8")
        try:
            os.chmod(self._jsonl_path, 0o600)
        except OSError:
            pass

    def _open_jsonl_file(self):
        if self._jsonl_file is None or self._jsonl_file.closed:
            self._jsonl_file = open(
                self._jsonl_path,
                "a",
                encoding="utf-8",
                buffering=1,
                opener=_secure_jsonl_opener,
            )
        return self._jsonl_file

    @staticmethod
    def _session_name() -> str:
        return "session_" + datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    def save_jsonl(self, enriched: EnrichedAlert) -> None:
        """Append one enriched alert to the master JSONL log."""
        f = self._open_jsonl_file()
        payload = enriched._payload_dict() if hasattr(enriched, "_payload_dict") else enriched.to_dict()
        f.write(json.dumps(payload, ensure_ascii=False) + "\n")
        log.debug(f"Appended to {self._jsonl_path.name}")

    def close(self) -> None:
        """Close the append handle, if open."""
        handle = getattr(self, "_jsonl_file", None)
        if handle is not None and not handle.closed:
            handle.close()
