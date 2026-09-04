from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlparse


class ConfigError(ValueError):
    """Raised when portal configuration violates the read-only contract."""


_ALLOWED_CONNECTORS = {"json_file", "http_json", "static"}
_ALLOWED_STATES = {"healthy", "degraded", "stale", "unavailable", "unauthorized", "unknown", "planned"}


def _web_url(value: str, field: str) -> None:
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc or parsed.username or parsed.password:
        raise ConfigError(f"{field} must be an http or https URL without embedded credentials")


def _origin(value: str) -> str:
    parsed = urlparse(value)
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return f"{parsed.scheme.lower()}://{(parsed.hostname or '').lower()}:{port}"


def load_config(path: Path) -> dict:
    try:
        config = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigError("portal configuration is unreadable") from exc
    if not isinstance(config, dict):
        raise ConfigError("portal configuration must be an object")
    portal = config.get("portal")
    integrations = config.get("integrations")
    if not isinstance(portal, dict) or not isinstance(portal.get("title"), str):
        raise ConfigError("portal.title is required")
    refresh = portal.get("refresh_seconds", 60)
    if not isinstance(refresh, int) or not 10 <= refresh <= 3600:
        raise ConfigError("portal.refresh_seconds must be between 10 and 3600")
    if not isinstance(integrations, list):
        raise ConfigError("integrations must be a list")
    seen: set[str] = set()
    for spec in integrations:
        if not isinstance(spec, dict):
            raise ConfigError("each integration must be an object")
        integration_id = spec.get("id")
        if not isinstance(integration_id, str) or not integration_id or integration_id in seen:
            raise ConfigError("integration ids must be unique non-empty strings")
        seen.add(integration_id)
        if not isinstance(spec.get("name"), str) or not isinstance(spec.get("category"), str):
            raise ConfigError(f"integration {integration_id} requires name and category")
        connector = spec.get("connector")
        if connector not in _ALLOWED_CONNECTORS:
            raise ConfigError(f"integration {integration_id} has unsupported connector")
        max_age = spec.get("max_age_seconds")
        if not isinstance(max_age, int) or max_age <= 0:
            raise ConfigError(f"integration {integration_id} requires positive max_age_seconds")
        if spec.get("deep_link") is not None:
            _web_url(spec["deep_link"], "deep_link")
        if connector == "json_file" and not isinstance(spec.get("path"), str):
            raise ConfigError(f"integration {integration_id} requires path")
        if connector == "http_json":
            _web_url(spec.get("url", ""), "url")
            if spec.get("method", "GET").upper() != "GET":
                raise ConfigError("http_json connectors permit GET only")
            allowed_origins = spec.get("allowed_origins")
            if not isinstance(allowed_origins, list) or not allowed_origins:
                raise ConfigError(f"integration {integration_id} requires allowed_origins")
            for allowed in allowed_origins:
                if not isinstance(allowed, str):
                    raise ConfigError(f"integration {integration_id} has invalid allowed_origins")
                _web_url(allowed, "allowed_origins")
            if _origin(spec["url"]) not in {_origin(value) for value in allowed_origins}:
                raise ConfigError(f"integration {integration_id} URL is outside allowed_origins")
        if connector == "static" and spec.get("state", "unknown") not in _ALLOWED_STATES:
            raise ConfigError(f"integration {integration_id} has invalid static state")
    return config
