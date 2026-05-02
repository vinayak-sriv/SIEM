"""
config_loader.py

Loads config.yaml and lets a handful of environment variables override
sensitive fields (passwords, webhook URLs) so you don't have to put
secrets in the config file.
"""

import logging
import os
from ipaddress import ip_address
from pathlib import Path
from urllib.parse import urlparse

log = logging.getLogger("Config")

# Maps env-var name → dotted path inside the config dict.
_ENV_OVERRIDES = {
    "SMTP_PASSWORD" : ["notifications", "smtp",  "password"],
    "SLACK_WEBHOOK" : ["notifications", "slack", "webhook_url"],
    "TEAMS_WEBHOOK" : ["notifications", "teams", "webhook_url"],
    "OLLAMA_MODEL"  : ["ollama", "model"],
    "OLLAMA_URL"    : ["ollama", "base_url"],
    "SEVERITY_LEVEL": ["filter", "min_severity_level"],
    "REPORT_DIR"    : ["output", "report_dir"],
}


class SecretStr:
    """Small wrapper that keeps secrets masked in repr/log output."""

    def __init__(self, value: str):
        self._value = value

    def reveal(self) -> str:
        return self._value

    def __bool__(self) -> bool:
        return bool(self._value)

    def __repr__(self) -> str:
        return "********"

    def __str__(self) -> str:
        return "********"


def _resolve_config_path(path: str) -> Path:
    """Resolve a config path from either the current working directory or src/."""
    config_path = Path(path)
    if config_path.exists():
        return config_path

    if config_path.is_absolute():
        return config_path

    src_dir = Path(__file__).resolve().parent
    for candidate in (src_dir / config_path, src_dir / config_path.name):
        if candidate.exists():
            return candidate

    return src_dir / config_path


def load_config(path: str) -> dict:
    """Load YAML config from disk, apply any env-var overrides, and return it."""
    config_path = _resolve_config_path(path)
    if not config_path.exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")

    try:
        import yaml
        with open(config_path, "r", encoding="utf-8") as f:
            cfg = yaml.safe_load(f) or {}
    except ImportError:
        raise ImportError("PyYAML is required. Install with: pip install pyyaml")

    _apply_env_overrides(cfg)
    _validate_config(cfg, config_path)
    log.info(f"Config loaded from {config_path}")
    return cfg


def _validate_config(cfg: dict, config_path: Path) -> None:
    """Fail fast with demo-friendly messages when required config is missing."""
    required_paths = [
        ("wazuh", "alerts_json_path"),
        ("filter", "min_severity_level"),
        ("ollama", "base_url"),
        ("ollama", "model"),
        ("output", "report_dir"),
    ]

    missing = []
    for section, key in required_paths:
        section_cfg = cfg.get(section, {})
        value = section_cfg.get(key) if isinstance(section_cfg, dict) else None
        if not isinstance(section_cfg, dict) or key not in section_cfg or _is_blank(value):
            missing.append(f"{section}.{key}")

    if missing:
        raise ValueError(
            f"Config file {config_path} is missing required setting(s): "
            f"{', '.join(missing)}"
        )

    casted_values = {}
    try:
        casted_values[("filter", "min_severity_level")] = int(cfg["filter"]["min_severity_level"])
    except (TypeError, ValueError) as exc:
        raise ValueError("filter.min_severity_level must be an integer") from exc

    for numeric_path in [
        ("filter", "batch_size", int),
        ("filter", "flush_interval_seconds", float),
        ("filter", "poll_interval_seconds", float),
        ("ollama", "timeout_seconds", int),
        ("ollama", "max_retries", int),
        ("ollama", "max_concurrent_calls", int),
        ("ollama", "max_tokens", int),
        ("ollama", "circuit_breaker_failures", int),
        ("ollama", "circuit_breaker_cooldown_seconds", int),
        ("filter", "dedupe_cache_size", int),
        ("filter", "max_lines_per_poll", int),
    ]:
        section, key, caster = numeric_path
        section_cfg = cfg.get(section, {})
        if isinstance(section_cfg, dict) and key in section_cfg:
            try:
                casted_values[(section, key)] = caster(section_cfg[key])
            except (TypeError, ValueError) as exc:
                raise ValueError(f"{section}.{key} must be a number") from exc

    positive_settings = [
        ("filter", "batch_size", 1),
        ("filter", "flush_interval_seconds", 3.0),
        ("filter", "poll_interval_seconds", 1.0),
        ("filter", "dedupe_cache_size", 10000),
        ("filter", "max_lines_per_poll", 200),
        ("ollama", "timeout_seconds", 120),
        ("ollama", "max_retries", 3),
        ("ollama", "max_concurrent_calls", 1),
        ("ollama", "max_tokens", 1024),
        ("ollama", "circuit_breaker_failures", 2),
        ("ollama", "circuit_breaker_cooldown_seconds", 45),
    ]
    for section, key, default in positive_settings:
        section_cfg = cfg.get(section, {})
        value = casted_values.get(
            (section, key),
            section_cfg.get(key, default) if isinstance(section_cfg, dict) else default,
        )
        try:
            is_positive = value > 0
        except TypeError as exc:
            raise ValueError(f"{section}.{key} must be greater than 0") from exc
        if not is_positive:
            raise ValueError(f"{section}.{key} must be greater than 0")

    _validate_ollama_base_url(str(cfg["ollama"]["base_url"]))
    _warn_if_config_contains_secrets(cfg, config_path)

    for (section, key), value in casted_values.items():
        cfg[section][key] = value


def _validate_ollama_base_url(base_url: str) -> None:
    """Restrict Ollama calls to local or private lab endpoints."""
    parsed = urlparse(base_url)
    host = (parsed.hostname or "").lower()
    if parsed.scheme not in {"http", "https"} or not host:
        raise ValueError("ollama.base_url must be an http(s) URL with a hostname")

    if host in {"localhost", "127.0.0.1", "::1"}:
        return

    try:
        ip = ip_address(host)
    except ValueError as exc:
        raise ValueError(
            "ollama.base_url must point to localhost or a private lab IP address"
        ) from exc

    if ip.is_loopback or (ip.is_private and not (ip.is_link_local or ip.is_unspecified or ip.is_multicast)):
        return

    raise ValueError(
        "ollama.base_url cannot target public, link-local, multicast, or unspecified addresses"
    )


def _warn_if_config_contains_secrets(cfg: dict, config_path: Path) -> None:
    """Nudge users toward env vars without breaking old demo configs."""
    smtp = cfg.get("notifications", {}).get("smtp", {})
    if isinstance(smtp, dict):
        password = smtp.get("password")
        if password and not isinstance(password, SecretStr) and not os.environ.get("SMTP_PASSWORD"):
            log.warning(
                f"{config_path} contains notifications.smtp.password; "
                "prefer SMTP_PASSWORD in the environment for demos and GitHub uploads"
            )

    for section, key, env_key in [
        ("slack", "webhook_url", "SLACK_WEBHOOK"),
        ("teams", "webhook_url", "TEAMS_WEBHOOK"),
    ]:
        channel = cfg.get("notifications", {}).get(section, {})
        if (
            isinstance(channel, dict) and
            channel.get(key) and
            not os.environ.get(env_key)
        ):
            log.warning(
                f"{config_path} contains notifications.{section}.{key}; "
                f"prefer {env_key} in the environment"
            )


def _is_blank(value) -> bool:
    """Treat null and empty strings as absent for required settings."""
    return value is None or (isinstance(value, str) and value.strip() == "")


def _apply_env_overrides(cfg: dict) -> None:
    """Walk the override table and inject any environment variables that are set."""
    for env_key, key_path in _ENV_OVERRIDES.items():
        val = os.environ.get(env_key)
        if val is None:
            continue

        # SEVERITY_LEVEL needs to be an int, everything else is a string.
        if env_key == "SEVERITY_LEVEL":
            try:
                val = int(val)
            except ValueError as exc:
                raise ValueError("SEVERITY_LEVEL environment variable must be an integer") from exc
        elif env_key == "SMTP_PASSWORD":
            val = SecretStr(val)

        node = cfg
        for part in key_path[:-1]:
            node = node.setdefault(part, {})
        node[key_path[-1]] = val
        log.debug(f"Env override applied: {env_key} → {'.'.join(key_path)}")
