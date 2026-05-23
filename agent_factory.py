"""Shared LLM-model factory and configuration for BinCodeQL agents.

Both the interactive agent (`agent.py`) and the per-finding triage
agent (`triage_agent.py`, scan-mode) construct their LiteLlm models
through this module so prompt-caching, retry, and extended-thinking
configuration stay consistent across entry-points.

Reads configuration from environment variables on every call (no
module-level capture) so .env edits between agent invocations take
effect immediately.
"""

from __future__ import annotations

import json
import os
from typing import Optional

from google.adk.models.lite_llm import LiteLlm


def resolve_api_key(model_name: Optional[str] = None) -> Optional[str]:
    """Pick the right API key for the active model.

    Resolution order:
      1. `API_KEY` — direct one-shot override (highest priority)
      2. `MODEL_API_KEY_ENV` — name of an env var holding the key
         (e.g. set `MODEL_API_KEY_ENV=NVIDIA_API_KEY` to use the
         NVIDIA build endpoint while keeping the key in a clearly
         named var)
      3. Provider prefix on `MODEL_NAME` — `anthropic/*` →
         `ANTHROPIC_API_KEY`, `openai/*` → `OPENAI_API_KEY`
      4. Fallback to whichever of the two provider keys is set.
    """
    explicit = os.getenv("API_KEY")
    if explicit:
        return explicit
    indirect = os.getenv("MODEL_API_KEY_ENV")
    if indirect:
        val = os.getenv(indirect)
        if val:
            return val
    name = model_name if model_name is not None else os.getenv("MODEL_NAME", "")
    if name.startswith("anthropic/"):
        return os.getenv("ANTHROPIC_API_KEY")
    if name.startswith("openai/"):
        return os.getenv("OPENAI_API_KEY")
    if name.startswith("deepseek/"):
        return os.getenv("DEEPSEEK_API_KEY")
    return os.getenv("OPENAI_API_KEY") or os.getenv("ANTHROPIC_API_KEY") or os.getenv("DEEPSEEK_API_KEY")


def create_model(lite: bool = False) -> LiteLlm:
    """Build the LiteLlm model with provider-specific optimizations.

    For Anthropic models we enable prompt caching on the system prompt
    via LiteLLM's `cache_control_injection_points` — critical for
    long-running agent sessions because a large system prompt would
    otherwise be re-sent (and re-billed) on every turn. With caching
    enabled, the second turn onward reads the system prompt from the
    Anthropic cache at ~10% (5m TTL) or ~8% (1h TTL) of the normal
    input-token cost, which keeps the session comfortably under
    Anthropic's per-minute input-token rate limit.

    Caching works across the ADK → LiteLLM boundary because the
    `**kwargs` the ADK LiteLlm wrapper accepts are forwarded verbatim
    to `litellm.acompletion()`, and LiteLLM's Anthropic adapter
    handles the `cache_control_injection_points` param natively. The
    1-hour TTL requires Anthropic's `extended-cache-ttl-2025-04-11`
    beta header, which we add via `extra_headers`.

    Configuration is read from env vars each call:
      MODEL_NAME              — provider/model id (default Sonnet 4.6)
      LITE_MODEL_NAME         — cheaper model for sub-agents / bootstrapping.
                                Falls back to MODEL_NAME when unset.
                                Pass lite=True to create_model() to use it.
      MODEL_BASE_URL          — OpenAI-compatible endpoint base URL.
                                Set when pointing at a self-hosted
                                inference server or a third-party OAI-
                                compatible API (e.g. NVIDIA build
                                `https://integrate.api.nvidia.com/v1`).
                                Forwarded to LiteLLM as `api_base`.
                                Combine with an `openai/<id>` model
                                name so LiteLLM uses the OpenAI client.
      MODEL_API_KEY_ENV       — name of the env var holding the API key
                                (e.g. `NVIDIA_API_KEY`). See
                                `resolve_api_key`.
      MODEL_TIMEOUT           — per-request timeout in seconds (180)
      MODEL_NUM_RETRIES       — automatic retries on 429 etc. (4)
      MODEL_MAX_TOKENS        — max output tokens (auto-derived)
      MODEL_CACHE_TTL         — "5m" or "1h" (default 1h, anthropic/* only)
      MODEL_THINKING_BUDGET   — extended-thinking budget tokens (10000;
                                set 0 to disable; anthropic/* only)
      MODEL_THINKING          — tri-state cross-provider toggle, "on" /
                                "off" / "" (default "" = no-op).
                                When set, synthesizes the right dialect
                                for the active model family:
                                - anthropic/*: maps "off" to
                                  thinking_budget=0; "on" keeps the
                                  configured budget (or defaults to it).
                                - openai/*: merges
                                  `chat_template_kwargs.thinking` AND
                                  `chat_template_kwargs.enable_thinking`
                                  into `extra_body`, covering DeepSeek /
                                  GLM (key `thinking`) and Qwen3
                                  (key `enable_thinking`) in one shot.
                                  Servers that don't recognize the keys
                                  ignore them silently.
                                User-supplied MODEL_EXTRA_BODY keys take
                                precedence — this only fills missing
                                ones, so per-model overrides still win.
      MODEL_TEMPERATURE       — sampling temperature (float). When unset,
                                anthropic/* with thinking forces 1.0;
                                everything else lets LiteLLM use the
                                model default.
      MODEL_TOP_P             — nucleus-sampling cutoff (float). Some
                                NVIDIA-build / vLLM models require an
                                explicit top_p (e.g. deepseek-v4-pro
                                wants 0.95).
      MODEL_EXTRA_BODY        — JSON object passed as `extra_body` on
                                each request. Used for provider-
                                specific knobs the OpenAI client doesn't
                                model directly, e.g. to disable
                                deepseek's internal reasoning pass:
                                `{"chat_template_kwargs":{"thinking":false}}`
    """
    primary = os.getenv("MODEL_NAME", "anthropic/claude-sonnet-4-6")
    model_name = (os.getenv("LITE_MODEL_NAME") or primary) if lite else primary
    base_url = os.getenv("MODEL_BASE_URL", "").strip()
    timeout = int(os.getenv("MODEL_TIMEOUT", "180"))
    num_retries = int(os.getenv("MODEL_NUM_RETRIES", "4"))
    cache_ttl = os.getenv("MODEL_CACHE_TTL", "1h").lower()
    thinking_budget = int(os.getenv("MODEL_THINKING_BUDGET", "10000"))

    # Cross-provider thinking toggle (acts on top of MODEL_THINKING_BUDGET).
    thinking_mode = os.getenv("MODEL_THINKING", "").strip().lower()
    if thinking_mode == "off":
        thinking_budget = 0  # disables Anthropic's thinking config below
    max_tokens = int(
        os.getenv("MODEL_MAX_TOKENS",
                  str(max(4096, thinking_budget + 4096)))
    )

    kwargs: dict = {
        "model": model_name,
        "api_key": resolve_api_key(model_name),
        "timeout": timeout,
        "num_retries": num_retries,
        "max_tokens": max_tokens,
    }

    if base_url:
        kwargs["api_base"] = base_url

    top_p_str = os.getenv("MODEL_TOP_P", "").strip()
    if top_p_str:
        kwargs["top_p"] = float(top_p_str)

    temperature_str = os.getenv("MODEL_TEMPERATURE", "").strip()
    if temperature_str:
        kwargs["temperature"] = float(temperature_str)

    extra_body_str = os.getenv("MODEL_EXTRA_BODY", "").strip()
    if extra_body_str:
        kwargs["extra_body"] = json.loads(extra_body_str)

    # MODEL_THINKING tri-state — synthesize provider-specific keys.
    # Only fills MISSING keys, so user's MODEL_EXTRA_BODY wins on conflict.
    if thinking_mode in ("on", "off") and not model_name.startswith("anthropic/"):
        flag = (thinking_mode == "on")
        eb = kwargs.setdefault("extra_body", {})
        ctk = eb.setdefault("chat_template_kwargs", {})
        ctk.setdefault("thinking", flag)         # DeepSeek / GLM family
        ctk.setdefault("enable_thinking", flag)  # Qwen3 family

    if model_name.startswith("anthropic/"):
        control: dict = {"type": "ephemeral"}
        if cache_ttl == "1h":
            control["ttl"] = "1h"
            # Opt into the extended-TTL beta. LiteLLM auto-adds
            # `prompt-caching-2024-07-31`; we concatenate the
            # extended-TTL flag so both are active. Anthropic accepts
            # comma-separated betas in a single header.
            kwargs["extra_headers"] = {
                "anthropic-beta":
                    "prompt-caching-2024-07-31,extended-cache-ttl-2025-04-11",
            }
        elif cache_ttl not in ("5m", ""):
            # Unknown value — fall back silently to 5m rather than
            # erroring so a typo in .env never blocks the agent from
            # starting.
            pass

        # Cache the system prompt (message index 0). Anthropic caches
        # all content up to the marked point, so this also caches the
        # tool schemas that appear before the system message in the
        # final API request. One cache breakpoint is enough — we have
        # up to 4.
        kwargs["cache_control_injection_points"] = [
            {
                "location": "message",
                "role": "system",
                "index": 0,
                "control": control,
            },
        ]

        # Extended thinking. When enabled, Anthropic runs an internal
        # reasoning pass of up to `budget_tokens` before producing the
        # final answer. Thinking tokens are billed but don't
        # participate in the cache, so the cache-read path stays
        # cheap. Temperature is forced to 1 by Anthropic when thinking
        # is active; we set it explicitly to avoid the mismatch error
        # some LiteLLM paths raise.
        if thinking_budget > 0:
            kwargs["thinking"] = {
                "type": "enabled",
                "budget_tokens": thinking_budget,
            }
            kwargs["temperature"] = 1.0

    return LiteLlm(**kwargs)
