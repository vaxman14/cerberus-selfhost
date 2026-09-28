"""Josi CE-style provider profiles, discovery, probes, and secure LLM bridge."""
from __future__ import annotations

import ipaddress
import json
import re
import socket
import time
from urllib.parse import urlparse

import requests

from . import persistence
from .vault import load_master_key, open_sealed, seal


CATALOG_VERSION = "2026-09-08"
PROVIDERS = [
    {
        "kind": "openai_compatible", "label": "A model on your own hardware",
        "external": False, "base_url": "", "base_url_required": True,
        "api_key_required": False,
        "residency": "Nothing leaves this server except traffic to the address you provide.",
    },
    {
        "kind": "openai", "label": "OpenAI", "external": True,
        "base_url": "https://api.openai.com/v1", "api_key_required": True,
        "residency": "Requests are processed by OpenAI under your account terms.",
    },
    {
        "kind": "xai", "label": "xAI", "external": True,
        "base_url": "https://api.x.ai/v1", "api_key_required": True,
        "residency": "Requests are processed by xAI under your account terms.",
    },
    {
        "kind": "deepseek", "label": "DeepSeek", "external": True,
        "base_url": "https://api.deepseek.com/v1", "api_key_required": True,
        "residency": "Requests are processed by DeepSeek; check its terms and data region.",
    },
    {
        "kind": "qwen", "label": "Alibaba Qwen", "external": True,
        "base_url": "https://dashscope-intl.aliyuncs.com/compatible-mode/v1",
        "api_key_required": True,
        "residency": "Requests use the selected DashScope endpoint and its region.",
    },
    {
        "kind": "mistral", "label": "Mistral", "external": True,
        "base_url": "https://api.mistral.ai/v1", "api_key_required": True,
        "residency": "Requests are processed by Mistral under your account terms.",
    },
    {
        "kind": "moonshot", "label": "Moonshot (Kimi)", "external": True,
        "base_url": "https://api.moonshot.ai/v1", "api_key_required": True,
        "residency": "Requests are processed by Moonshot under your account terms.",
    },
    {
        "kind": "zhipu", "label": "Zhipu GLM", "external": True,
        "base_url": "https://open.bigmodel.cn/api/paas/v4", "api_key_required": True,
        "residency": "Requests are processed by Zhipu; check its terms and data region.",
    },
    {
        "kind": "openrouter", "label": "OpenRouter", "external": True,
        "base_url": "https://openrouter.ai/api/v1", "api_key_required": True,
        "residency": "OpenRouter forwards requests to the upstream provider for the chosen model.",
    },
]
PROVIDER_MAP = {provider["kind"]: provider for provider in PROVIDERS}
MODEL_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/+\-]{0,179}$")
NON_CHAT = re.compile(
    r"embedding|^tts-|^whisper|^dall-e|^gpt-image|moderation|-audio(?:-|$)|"
    r"-realtime(?:-|$)|transcribe|^sora|guard|-tts(?:-|$)", re.I
)


class LLMError(RuntimeError):
    def __init__(self, message: str, *, category: str = "unknown", status: int = 400):
        super().__init__(message)
        self.category = category
        self.status = status


def provider_catalog() -> list[dict]:
    return [dict(provider) for provider in PROVIDERS]


def _blocked_address(address: str) -> str | None:
    try:
        value = ipaddress.ip_address(address)
    except ValueError:
        return "unparseable address"
    if value.is_link_local:
        return "link-local / cloud metadata"
    if isinstance(value, ipaddress.IPv6Address) and value.ipv4_mapped:
        return _blocked_address(str(value.ipv4_mapped))
    if value.is_multicast:
        return "multicast"
    if value.is_unspecified:
        return "unspecified address"
    if value.is_reserved:
        return "reserved"
    if str(value).lower().startswith("fd00:ec2"):
        return "cloud metadata"
    return None


def validate_endpoint(raw: str) -> dict:
    parsed = urlparse(raw)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise LLMError("the endpoint must be a valid http or https URL")
    if parsed.username or parsed.password:
        raise LLMError("put credentials in the API key field, not in the URL")
    if parsed.query or parsed.fragment:
        raise LLMError("the API base URL must not contain a query string or fragment")
    try:
        rows = socket.getaddrinfo(parsed.hostname, parsed.port or 443, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise LLMError("that hostname could not be resolved from this server", category="network") from exc
    addresses = sorted({row[4][0] for row in rows})
    for address in addresses:
        reason = _blocked_address(address)
        if reason:
            raise LLMError(f"that address is not allowed ({reason})")
    local = all(ipaddress.ip_address(address).is_private or ipaddress.ip_address(address).is_loopback
                for address in addresses)
    return {"url": raw.rstrip("/"), "addresses": addresses, "local": local}


def _category(status: int) -> tuple[str, str]:
    if status == 401:
        return "authentication", "The provider rejected the credential; reconnect with a valid key."
    if status == 403:
        return "authorization", "The credential is valid but cannot use this model."
    if status == 404:
        return "model_unavailable", "This account cannot use that model."
    if status == 429:
        return "rate_limit", "The provider is rate limiting this installation or the account has no credit."
    if status in {400, 422}:
        return "malformed_request", "The provider rejected the request shape or model name."
    if status >= 500:
        return "provider_outage", "The provider had a server error; try again shortly."
    return "unknown", "The provider refused the request."


def _profile_with_secret(profile_id: str) -> tuple[dict, str]:
    profile = persistence.get_llm_profile(profile_id, include_ciphertext=True)
    if not profile:
        raise LLMError("no such model profile", status=404)
    secret = ""
    if profile.get("api_key_enc"):
        secret = str(open_sealed(load_master_key(), profile["api_key_enc"]).get("api_key", ""))
    return profile, secret


def save_profile(body: dict) -> dict:
    provider = str(body.get("provider", ""))[:40]
    model = str(body.get("model", "")).strip()[:180]
    label = str(body.get("label", "")).strip()[:80] or model
    profile_id = str(body.get("id", "")).strip() or None
    if profile_id and not re.fullmatch(r"[0-9a-f]{16}", profile_id):
        raise LLMError("invalid model profile id")
    api_key = str(body.get("api_key", ""))
    item = PROVIDER_MAP.get(provider)
    if not item:
        raise LLMError("choose a supported model provider")
    if not model or not MODEL_ID.fullmatch(model):
        raise LLMError("enter a valid model name")
    base_url = str(body.get("base_url", "")).strip() or str(item.get("base_url", ""))
    if item.get("base_url_required") and not base_url:
        raise LLMError("a base URL is required for a self-hosted endpoint")
    endpoint = validate_endpoint(base_url)
    acknowledged = body.get("external_acknowledged") is True
    if item["external"] and not acknowledged:
        raise LLMError(
            "acknowledge that prompts and source-derived context leave this server for the provider"
        )
    if item["external"] and urlparse(endpoint["url"]).scheme != "https":
        raise LLMError("hosted providers require an https API base URL")
    existing = persistence.get_llm_profile(profile_id, include_ciphertext=True) if profile_id else None
    existing_ciphertext = (
        existing.get("api_key_enc") if existing and existing.get("provider") == provider else None
    )
    if item.get("api_key_required") and not api_key and not existing_ciphertext:
        raise LLMError("an API key is required for this provider")
    sealed = seal(load_master_key(), {"api_key": api_key}) if api_key else existing_ciphertext
    return persistence.save_llm_profile(
        profile_id=profile_id, label=label, provider=provider, model=model,
        base_url=endpoint["url"], api_key_enc=sealed,
        external_acknowledged=acknowledged,
    )


def _discover_models(base_url: str, api_key: str) -> dict:
    endpoint = validate_endpoint(base_url)
    headers = {"Accept": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    try:
        response = requests.get(
            f"{endpoint['url']}/models", headers=headers, timeout=20, allow_redirects=False
        )
    except requests.RequestException as exc:
        raise LLMError("the provider could not be reached from this server", category="network", status=502) from exc
    if 300 <= response.status_code < 400:
        response.close()
        raise LLMError("the model endpoint redirected; configure the final API URL directly")
    if not response.ok:
        category, message = _category(response.status_code)
        response.close()
        raise LLMError(message, category=category, status=502)
    try:
        payload = response.json()
    except ValueError as exc:
        raise LLMError("the endpoint did not return a readable model list") from exc
    finally:
        response.close()
    rows = payload.get("data") if isinstance(payload, dict) else None
    if not isinstance(rows, list) and isinstance(payload, dict):
        rows = payload.get("models")
    if not isinstance(rows, list):
        raise LLMError("the endpoint did not return an OpenAI-compatible model list")
    models = []
    seen = set()
    for row in rows:
        model_id = str(row.get("id", "")).strip() if isinstance(row, dict) else ""
        if not MODEL_ID.fullmatch(model_id) or model_id in seen:
            continue
        seen.add(model_id)
        models.append({"id": model_id, "likely_non_chat": bool(NON_CHAT.search(model_id))})
        if len(models) >= 500:
            break
    models.sort(key=lambda value: value["id"])
    return {"models": models, "catalog_version": CATALOG_VERSION}


def discover_models(profile_id: str) -> dict:
    profile, api_key = _profile_with_secret(profile_id)
    return _discover_models(profile["base_url"] or "", api_key)


def discover_connection(body: dict) -> dict:
    provider = str(body.get("provider", ""))[:40]
    item = PROVIDER_MAP.get(provider)
    if not item:
        raise LLMError("choose a supported model provider")
    base_url = str(body.get("base_url", "")).strip() or str(item.get("base_url", ""))
    api_key = str(body.get("api_key", ""))
    if item.get("api_key_required") and not api_key:
        raise LLMError("an API key is required to discover models")
    if item["external"] and body.get("external_acknowledged") is not True:
        raise LLMError("acknowledge external processing before contacting the provider")
    endpoint = validate_endpoint(base_url)
    if item["external"] and urlparse(endpoint["url"]).scheme != "https":
        raise LLMError("hosted providers require an https API base URL")
    return _discover_models(base_url, api_key)


def _chat(profile: dict, api_key: str, body: dict, *, stream: bool = False) -> requests.Response:
    endpoint = validate_endpoint(profile["base_url"] or "")
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    try:
        response = requests.post(
            f"{endpoint['url']}/chat/completions", headers=headers, json=body,
            timeout=(10, 300), allow_redirects=False, stream=stream,
        )
    except requests.RequestException as exc:
        raise LLMError("the provider could not be reached from this server", category="network", status=502) from exc
    if 300 <= response.status_code < 400:
        response.close()
        raise LLMError("the model endpoint redirected; configure the final API URL directly")
    if not response.ok:
        category, message = _category(response.status_code)
        response.close()
        raise LLMError(message, category=category, status=502)
    return response


def _probe_call(profile: dict, key: str, body: dict) -> tuple[dict, int]:
    started = time.monotonic()
    response = _chat(profile, key, body)
    try:
        payload = response.json()
    except ValueError as exc:
        raise LLMError("the provider returned unreadable JSON") from exc
    finally:
        response.close()
    return payload, round((time.monotonic() - started) * 1000)


def probe_profile(profile_id: str) -> dict:
    profile, key = _profile_with_secret(profile_id)
    model = profile["model"]
    capabilities = {"chat": False, "structured_output": False, "tool_calling": False,
                    "context_tokens": None}
    steps = []
    try:
        payload, latency = _probe_call(profile, key, {
            "model": model, "messages": [{"role": "user", "content": "Reply with the single word: ready"}],
            "temperature": 0, "max_tokens": 32,
        })
        text = str(payload.get("choices", [{}])[0].get("message", {}).get("content", "")).strip()
        capabilities["chat"] = bool(text)
        steps.append({"id": "chat", "passed": bool(text), "latency_ms": latency,
                      "detail": "The model answered." if text else "The model returned an empty reply."})
    except LLMError as exc:
        steps.append({"id": "chat", "passed": False, "detail": str(exc)})
        result = persistence.save_llm_probe(profile_id, capabilities, steps, active=False)
        return {"profile": result, "fatal": str(exc)}
    try:
        payload, latency = _probe_call(profile, key, {
            "model": model,
            "messages": [{"role": "user", "content": "Return JSON with exactly one key ok set to true."}],
            "response_format": {"type": "json_object"}, "temperature": 0, "max_tokens": 64,
        })
        text = str(payload.get("choices", [{}])[0].get("message", {}).get("content", ""))
        value = json.loads(text.strip().removeprefix("```json").removeprefix("```").removesuffix("```").strip())
        passed = isinstance(value, dict) and value.get("ok") is True
    except (LLMError, ValueError, TypeError, IndexError, KeyError):
        passed, latency = False, 0
    capabilities["structured_output"] = passed
    steps.append({"id": "structured_output", "passed": passed, "latency_ms": latency,
                  "detail": "The model returned valid JSON." if passed else "Structured output failed."})
    try:
        payload, latency = _probe_call(profile, key, {
            "model": model, "messages": [{"role": "user", "content": "Record the number 7 using the tool."}],
            "tools": [{"type": "function", "function": {"name": "record_number",
                "description": "Record a number", "parameters": {"type": "object",
                "properties": {"value": {"type": "number"}}, "required": ["value"]}}}],
            "tool_choice": "auto", "temperature": 0, "max_tokens": 128,
        })
        calls = payload.get("choices", [{}])[0].get("message", {}).get("tool_calls", [])
        passed = any(call.get("function", {}).get("name") == "record_number" for call in calls)
    except (LLMError, TypeError, IndexError, KeyError):
        passed, latency = False, 0
    capabilities["tool_calling"] = passed
    steps.append({"id": "tool_calling", "passed": passed, "latency_ms": latency,
                  "detail": "The model called the offered tool." if passed else "Tool calling failed."})
    try:
        filler = "word " * 6400
        payload, latency = _probe_call(profile, key, {
            "model": model, "messages": [{"role": "user", "content": filler + "\nReply only: ok"}],
            "temperature": 0, "max_tokens": 32,
        })
        passed = bool(str(payload.get("choices", [{}])[0].get("message", {}).get("content", "")).strip())
    except (LLMError, TypeError, IndexError, KeyError):
        passed, latency = False, 0
    capabilities["context_tokens"] = 8000 if passed else None
    steps.append({"id": "context", "passed": passed, "latency_ms": latency,
                  "detail": "The model handled about 8,000 tokens." if passed else "Usable context check failed."})
    active = capabilities["chat"] and capabilities["structured_output"] and capabilities["tool_calling"]
    result = persistence.save_llm_probe(profile_id, capabilities, steps, active=active)
    return {"profile": result, "active": active}


def authenticate_bridge(header: str) -> str | None:
    if not header.startswith("Bearer "):
        return None
    return persistence.profile_for_llm_bridge_token(header[7:].strip())


def bridge_models(profile_id: str) -> dict:
    profile = persistence.get_llm_profile(profile_id)
    return {
        "object": "list",
        "data": ([{"id": "cerberus", "object": "model", "owned_by": "cerberus-vault"}]
                 if profile and profile.get("activated_at") else []),
    }


def bridge_chat(profile_id: str, body: dict) -> requests.Response:
    if str(body.get("model", "")) != "cerberus":
        raise LLMError("unknown Cerberus model alias", status=404)
    profile, key = _profile_with_secret(profile_id)
    if not profile.get("activated_at"):
        raise LLMError("that model profile has not passed its capability probe", status=409)
    outbound = dict(body)
    outbound["model"] = profile["model"]
    return _chat(profile, key, outbound, stream=body.get("stream") is True)


def engine_connection(profile_id: str) -> dict:
    profile = persistence.get_llm_profile(profile_id)
    if not profile or not profile.get("activated_at"):
        raise LLMError("choose a model profile that passed its capability probe", status=409)
    return {
        "model": "cerberus",
        "api_key": persistence.issue_llm_bridge_token(profile_id),
        "api_base": "http://cerberus:8099/internal/llm/v1",
    }
