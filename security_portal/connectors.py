from __future__ import annotations

import json
import os
import ssl
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path
from typing import Any

from .model import classify_snapshot


_MISSING = object()


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse redirects so credentials never cross an unreviewed target."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def dotted_get(document: Any, path: str | None, default: Any = None) -> Any:
    if not path:
        return default
    value = document
    for part in path.split("."):
        if isinstance(value, dict) and part in value:
            value = value[part]
        else:
            return default
    return value


def _summary(document: dict, paths: dict[str, str]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for label, path in paths.items():
        value = dotted_get(document, path, _MISSING)
        if value is _MISSING:
            continue
        result[label] = len(value) if isinstance(value, list) else value
    return result


def _source_state(document: dict, spec: dict) -> str:
    explicit = dotted_get(document, spec.get("state_path"), _MISSING)
    if explicit is not _MISSING:
        return str(explicit).lower()
    healthy = dotted_get(document, spec.get("healthy_path"), _MISSING)
    if healthy is True:
        return "healthy"
    if healthy is False:
        return "degraded"
    return "unknown"


def _result(spec: dict, document: dict, now: datetime | None) -> dict:
    return classify_snapshot(
        integration_id=spec["id"],
        name=spec["name"],
        category=spec.get("category"),
        collected_at=dotted_get(document, spec.get("collected_at_path")),
        max_age_seconds=spec["max_age_seconds"],
        source_state=_source_state(document, spec),
        summary=_summary(document, spec.get("summary_paths") or {}),
        deep_link=spec.get("deep_link"),
        now=now,
    )


def _error(spec: dict, state: str, reason_code: str, now: datetime | None) -> dict:
    return classify_snapshot(
        integration_id=spec["id"],
        name=spec["name"],
        category=spec.get("category"),
        collected_at=None,
        max_age_seconds=spec["max_age_seconds"],
        source_state=state,
        summary={},
        deep_link=spec.get("deep_link"),
        now=now,
        reason_code=reason_code,
        detail="The source could not be collected. Review server-side portal logs.",
    )


def collect_integration(spec: dict, now: datetime | None = None) -> dict:
    connector = spec["connector"]
    if connector == "static":
        document = {
            "state": spec.get("state", "unknown"),
            "collected_at": spec.get("collected_at"),
            "summary": spec.get("summary", {}),
        }
        normalized = dict(spec)
        normalized.setdefault("state_path", "state")
        normalized.setdefault("collected_at_path", "collected_at")
        normalized.setdefault("summary_paths", {key: f"summary.{key}" for key in document["summary"]})
        return _result(normalized, document, now)
    if connector == "json_file":
        try:
            document = json.loads(Path(spec["path"]).read_text(encoding="utf-8"))
            if not isinstance(document, dict):
                raise ValueError("source is not an object")
            return _result(spec, document, now)
        except (OSError, ValueError, json.JSONDecodeError):
            return _error(spec, "unavailable", "source_unavailable", now)
    if connector == "http_json":
        headers = {"Accept": "application/json", "User-Agent": "Security-Visibility-Portal/1.0"}
        for header, env_name in (spec.get("header_env") or {}).items():
            secret = os.environ.get(env_name)
            if secret:
                headers[header] = secret
        request = urllib.request.Request(spec["url"], headers=headers, method="GET")
        context = ssl.create_default_context(cafile=spec.get("ca_file"))
        opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=context),
            NoRedirect(),
        )
        try:
            with opener.open(request, timeout=spec.get("timeout_seconds", 10)) as response:
                document = json.load(response)
            if not isinstance(document, dict):
                raise ValueError("source is not an object")
            return _result(spec, document, now)
        except urllib.error.HTTPError as exc:
            if exc.code in {301, 302, 303, 307, 308}:
                return _error(spec, "unavailable", "source_redirect_refused", now)
            if exc.code in {401, 403}:
                return _error(spec, "unauthorized", "source_unauthorized", now)
            return _error(spec, "unavailable", "source_http_error", now)
        except (OSError, ValueError, json.JSONDecodeError, urllib.error.URLError):
            return _error(spec, "unavailable", "source_unavailable", now)
    return _error(spec, "unknown", "connector_unsupported", now)
