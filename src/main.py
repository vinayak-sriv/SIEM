#!/usr/bin/env python3
"""
main.py — SIEM AI Agent entry point.

Wires together the pipeline and decides whether to run in live-monitoring
mode (tailing alerts.json) or batch mode (replaying a JSONL file).

Usage:
    python3 main.py                                   # live monitoring
    python3 main.py --batch wazuh-training-set.jsonl  # batch / test mode
    python3 main.py --config /opt/siem/config.yaml    # custom config path
    SEVERITY_LEVEL=12 python3 main.py                 # env-var override
"""

import argparse
import asyncio
import json
import logging
import os
import ssl
import sys
import urllib.error
import urllib.request
from logging.handlers import RotatingFileHandler
from pathlib import Path

from config_loader import load_config
from middleware import PythonMiddleware

DEFAULT_CONFIG_PATH = Path(__file__).resolve().with_name("config.yaml")


def _build_log_handlers() -> list:
    """Create console logging plus a bounded file log when the path is writable."""
    handlers = [logging.StreamHandler(sys.stdout)]
    log_path = Path(os.environ.get("SIEM_AGENT_LOG", "logs/siem_agent.log"))
    try:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = RotatingFileHandler(
            log_path,
            maxBytes=2_000_000,
            backupCount=5,
            encoding="utf-8",
        )
        handlers.append(file_handler)
        try:
            os.chmod(log_path, 0o640)
        except OSError:
            pass
    except OSError as exc:
        print(f"Log file disabled ({log_path}): {exc}", file=sys.stderr)
    return handlers


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)-8s] %(name)s — %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=_build_log_handlers(),
)
log = logging.getLogger("Main")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="SIEM AI Agent — Wazuh + Ollama",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--config",
        default=str(DEFAULT_CONFIG_PATH),
        help=f"Path to config.yaml (default: {DEFAULT_CONFIG_PATH})",
    )
    parser.add_argument(
        "--batch",
        metavar="JSONL_FILE",
        help="Process a static JSONL file instead of live tailing",
    )
    parser.add_argument(
        "--limit",
        type=int,
        help="Maximum number of records to read in batch mode",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable DEBUG-level logging",
    )
    parser.add_argument(
        "--demo-status",
        action="store_true",
        help="Check Wazuh path, Ollama reachability, and report storage, then exit",
    )
    return parser.parse_args()


def _startup_banner(config: dict) -> None:
    """Print the short status block you want visible during a faculty demo."""
    report_dir = config.get("output", {}).get("report_dir", "./reports")
    ollama = config.get("ollama", {})
    filt = config.get("filter", {})

    log.info("SIEM AI Agent ready")
    log.info(f"  Wazuh alerts : {config['wazuh']['alerts_json_path']}")
    log.info(f"  LLM          : {ollama.get('model')} @ {ollama.get('base_url')}")
    log.info(f"  Threshold    : level >= {filt.get('min_severity_level')}")
    log.info(f"  Batch        : {filt.get('batch_size', 5)} alerts / {filt.get('flush_interval_seconds', 3.0)}s")
    log.info(f"  Reports      : {report_dir}")


def _demo_status(config: dict) -> int:
    """Run a fast pre-demo readiness check without starting the monitor."""
    alerts_path = Path(config["wazuh"]["alerts_json_path"])
    report_dir = Path(config.get("output", {}).get("report_dir", "./reports"))
    ollama_url = config["ollama"]["base_url"].rstrip("/")
    model = config["ollama"]["model"]

    def _model_aliases(name: str):
        base = str(name).split(":", 1)[0]
        return {str(name), base, f"{base}:latest"}

    log.info("Demo readiness check")
    log.info(f"  Wazuh alerts file : {'OK' if alerts_path.exists() else 'MISSING'} - {alerts_path}")
    log.info(f"  Reports directory : {'OK' if report_dir.exists() else 'MISSING'} - {report_dir}")
    log.info(f"  Configured model  : {model}")

    try:
        context = ssl.create_default_context() if ollama_url.startswith("https://") else None
        with urllib.request.urlopen(f"{ollama_url}/api/tags", timeout=5, context=context) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
        configured_names = _model_aliases(model)
        available_models = set()
        for item in data.get("models", []):
            available_models.update(_model_aliases(item.get("name", "")))
        model_found = bool(configured_names & available_models)
        log.info(f"  Ollama endpoint   : OK - {ollama_url}")
        log.info(f"  Model available   : {'OK' if model_found else 'CHECK'} - {model}")
        return 0 if model_found else 2
    except (urllib.error.URLError, TimeoutError, ValueError) as exc:
        log.error(f"  Ollama endpoint   : UNREACHABLE - {ollama_url} ({exc})")
        return 2


async def _run(args: argparse.Namespace, config: dict) -> None:
    middleware = PythonMiddleware(config)

    if args.batch:
        log.info(f"Batch mode: {args.batch}")
        await middleware.run_batch_file(args.batch, limit=args.limit)
    else:
        log.info("Live monitoring mode")
        await middleware.run()


def main() -> None:
    args = parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    log.info("SIEM AI Agent starting")

    try:
        config = load_config(args.config)
    except (FileNotFoundError, ImportError, ValueError) as e:
        log.error(str(e))
        sys.exit(1)

    _startup_banner(config)

    if args.demo_status:
        sys.exit(_demo_status(config))

    try:
        asyncio.run(_run(args, config))
    except KeyboardInterrupt:
        log.info("Agent shut down cleanly.")


if __name__ == "__main__":
    main()
