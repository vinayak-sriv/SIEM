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
from pathlib import Path

from models import EnrichedAlert

log = logging.getLogger("ReportLogger")


class ReportLogger:

    def __init__(self, config: dict):
        self.output_dir = config.get("output", {}).get("report_dir", "reports")
        self._output_path = Path(self.output_dir).resolve()
        if self._output_path.is_symlink():
            raise ValueError(f"Report directory cannot be a symlink: {self._output_path}")
        self._output_path.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self._output_path, 0o700)
        except OSError:
            pass
        self._jsonl_path = self._output_path / "alerts_enriched.jsonl"
        log.info(f"ReportLogger ready — writing to {self.output_dir}")

    def save_jsonl(self, enriched: EnrichedAlert) -> None:
        """Append one enriched alert to the master JSONL log."""
        with self._jsonl_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(enriched.to_dict(), ensure_ascii=False) + "\n")
        try:
            os.chmod(self._jsonl_path, 0o600)
        except OSError:
            pass
        log.debug(f"Appended to {self._jsonl_path.name}")
