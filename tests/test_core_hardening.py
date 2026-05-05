import json
import shutil
import unittest
import uuid
from contextlib import contextmanager
from pathlib import Path

import sys

SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))

from config_loader import _validate_config
from middleware import PythonMiddleware
from models import Alert
from notifier import _validate_webhook_url
from ollama_service import LLMParseError, OllamaService
from report_logger import ReportLogger

WORKSPACE_TMP = Path(__file__).resolve().parents[1]


@contextmanager
def workspace_tempdir():
    path = WORKSPACE_TMP / f"_test_{uuid.uuid4().hex}"
    path.mkdir()
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


def sample_alert(rule_id="5763", timestamp="2026-05-02T10:00:00Z", srcip="10.0.0.5"):
    return {
        "timestamp": timestamp,
        "rule": {
            "id": rule_id,
            "level": 12,
            "description": "SSHD brute force attack",
            "groups": ["sshd", "authentication_failures"],
        },
        "agent": {"id": "001", "name": "ubuntu-manager", "ip": "10.99.85.19"},
        "data": {"srcip": srcip},
        "full_log": f"Failed password for root from {srcip}",
    }


def config(alerts_path, reports_dir, ollama_url="http://10.99.85.71:11434"):
    return {
        "wazuh": {"alerts_json_path": str(alerts_path)},
        "filter": {
            "min_severity_level": 10,
            "batch_size": 2,
            "flush_interval_seconds": 1,
            "poll_interval_seconds": 1,
            "max_lines_per_poll": 10,
        },
        "ollama": {
            "base_url": ollama_url,
            "model": "tinyllama",
            "timeout_seconds": 1,
            "max_retries": 1,
            "max_concurrent_calls": 1,
            "max_tokens": 64,
        },
        "output": {"report_dir": str(reports_dir), "write_markdown": False},
        "notifications": {"channels": []},
    }


class CoreHardeningTests(unittest.TestCase):
    def test_alert_fingerprint_is_sha256_and_uses_source_ip(self):
        first = Alert.from_wazuh_json(sample_alert(srcip="10.0.0.5"))
        second = Alert.from_wazuh_json(sample_alert(srcip="10.0.0.6"))

        self.assertEqual(64, len(first.alertId))
        self.assertNotEqual(first.alertId, second.alertId)

    def test_tail_preserves_valid_alert_before_malformed_line(self):
        with workspace_tempdir() as tmp_path:
            alerts_path = tmp_path / "alerts.json"
            reports_dir = tmp_path / "reports"
            alerts_path.write_text(
                json.dumps(sample_alert()) + "\n"
                "{bad-json\n",
                encoding="utf-8",
            )

            mw = PythonMiddleware(config(alerts_path, reports_dir))
            try:
                alerts = mw.tail_read_many(10)
            finally:
                mw._close_alerts_file()

            self.assertEqual(1, len(alerts))
            self.assertEqual("5763", alerts[0].raw["rule"]["id"])

    def test_tail_waits_for_partial_line(self):
        with workspace_tempdir() as tmp_path:
            alerts_path = tmp_path / "alerts.json"
            reports_dir = tmp_path / "reports"
            raw = json.dumps(sample_alert())
            alerts_path.write_text(raw, encoding="utf-8")

            mw = PythonMiddleware(config(alerts_path, reports_dir))
            try:
                self.assertEqual([], mw.tail_read_many(10))
                self.assertEqual(0, mw.lastPos)

                alerts_path.write_text(raw + "\n", encoding="utf-8")
                alerts = mw.tail_read_many(10)
            finally:
                mw._close_alerts_file()
            self.assertEqual(1, len(alerts))

    def test_ollama_http_public_url_is_rejected(self):
        cfg = config("alerts.json", "reports", ollama_url="http://8.8.8.8:11434")
        with self.assertRaises(ValueError):
            _validate_config(cfg, Path("config.yaml"))

        cfg = config("alerts.json", "reports", ollama_url="https://example.com")
        with self.assertRaises(ValueError):
            _validate_config(cfg, Path("config.yaml"))

    def test_webhook_private_url_is_rejected(self):
        with self.assertRaises(ValueError):
            _validate_webhook_url("https://10.0.0.5/hook")

    def test_empty_ollama_response_triggers_parse_error(self):
        service = OllamaService(config("alerts.json", "reports"))
        with self.assertRaises(LLMParseError):
            service.parse_response('{"response": ""}')

    def test_report_logger_keeps_previous_reports_on_start(self):
        with workspace_tempdir() as tmp_path:
            reports_dir = tmp_path / "reports"
            reports_dir.mkdir()
            (reports_dir / "alerts_enriched.jsonl").write_text('{"old": true}\n', encoding="utf-8")
            (reports_dir / "alert_old_rule5763_deadbeef.md").write_text("old report", encoding="utf-8")

            cfg = config("alerts.json", reports_dir)
            # Fresh-session report rotation is intentionally disabled while
            # the project uses the previous append-in-place report behavior.
            # To restore rotation, re-enable the ReportLogger block and update
            # this test to expect reports/archive/session_*.

            ReportLogger(cfg)

            self.assertEqual('{"old": true}\n', (reports_dir / "alerts_enriched.jsonl").read_text(encoding="utf-8"))
            self.assertTrue((reports_dir / "alert_old_rule5763_deadbeef.md").exists())
            self.assertFalse((reports_dir / "archive").exists())


if __name__ == "__main__":
    unittest.main()
