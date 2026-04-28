# Open-source / open-weight model candidates for BinCodeQL evaluation

Curated 2026-04-28 to evaluate BinCodeQL against non-frontier models.
Workload demands: heavy tool calling, multi-step reasoning over fact
tables, long context for the triage prompt + per-finding evidence,
and instruction-following discipline (anti-confabulation).

All models listed are reachable via NVIDIA build's OpenAI-compatible
endpoint (`https://integrate.api.nvidia.com/v1`). Same `agent_factory`
plumbing (`MODEL_BASE_URL` + `MODEL_API_KEY_ENV` + `MODEL_NAME` with
`openai/<id>` prefix) works for all of them.

## Recommended evaluation set (ranked for our workload)

| # | Model ID | Context | Why it fits BinCodeQL | Released |
|---|---|---|---|---|
| 1 | `z-ai/glm-5.1` | 131K | Built for "agentic engineering" — sustains thousands of tool calls without strategy collapse, top of SWE-Bench Pro. Closest open match to Sonnet/Opus on our exact pattern. | 2026-04-17 |
| 2 | `moonshotai/kimi-k2.6` (or `kimi-k2-instruct` if 2.6 not yet GA on NIM) | 128K+ | Strong code+tool-use; "agent swarm" orchestration heritage; AIME 96.1%. Good fallback if GLM hits issues. | 2026-04-20 |
| 3 | `deepseek-ai/deepseek-v4-pro` | 1M | Sparse-attention MoE, very long context. Slow on NVIDIA build (90-300s/turn) but the 1M window swallows our whole prompt + per-finding evidence trivially. Already wired in `.env`. | 2026 |
| 4 | `qwen/qwen3.5-122b-a10b` (and the larger `qwen3.5-397b-a17b` if listed) | 256K+ | Alibaba's Qwen3 line is the most consistent open performer for code + tool use; native function-calling format works cleanly with LiteLLM. | Late 2025 / 2026 |
| 5 | `minimaxai/minimax-m2.7` | 256K | Sanjay's original example. Frontier-class open weights. Good reasoning baseline; less battle-tested for tool calling than #1-#4. | 2026 |
| 6 | `openai/gpt-oss-120b` | 128K | Useful "OpenAI-flavor" baseline — different RLHF lineage than the Chinese-developed models above. Sanity check that results don't depend on a single training tradition. | 2025 |

**Verify exact slugs before running** — the model catalog at
<https://build.nvidia.com/models> is the ground truth; ids drift
between releases (e.g. GLM-5 was deprecated 2026-04-20 in favor of
5.1; Kimi K2.6 is brand-new and may or may not be live on NIM yet).

## Per-model `.env` recipes

All recipes share these "common" lines — set them once and only
`MODEL_NAME` (and any per-model sampling tweaks) change between
candidates:

```
MODEL_BASE_URL="https://integrate.api.nvidia.com/v1"
MODEL_API_KEY_ENV="NVIDIA_API_KEY"
MODEL_TIMEOUT="600"
MODEL_THINKING="off"   # or "on" — see notes per model below
```

`MODEL_THINKING` synthesizes the right toggle for whichever family is
active (DeepSeek/GLM use `chat_template_kwargs.thinking`, Qwen3 uses
`enable_thinking`; the agent_factory sets both, servers ignore the
one they don't know).

### GLM-5.1 (#1 pick)
```
MODEL_NAME="openai/z-ai/glm-5.1"
MODEL_TOP_P="0.95"
MODEL_TEMPERATURE="1.0"
```

### Kimi K2.x
```
MODEL_NAME="openai/moonshotai/kimi-k2.6"
MODEL_TEMPERATURE="0.6"
```

### DeepSeek V4-Pro (already wired)
```
MODEL_NAME="openai/deepseek-ai/deepseek-v4-pro"
MODEL_TOP_P="0.95"
MODEL_TEMPERATURE="1.0"
```

### Qwen3
```
MODEL_NAME="openai/qwen/qwen3.5-122b-a10b"
MODEL_TEMPERATURE="0.7"
MODEL_TOP_P="0.8"
```

### MiniMax M2.7
```
MODEL_NAME="openai/minimaxai/minimax-m2.7"
```

### gpt-oss
```
MODEL_NAME="openai/openai/gpt-oss-120b"
```

## Practical evaluation notes

- **Test each on the same finding.** Use the same scan-mode candidate
  (e.g. the FFmpeg `slice_table` sentinel collision we already
  validated) and compare verdict quality + evidence-citation
  discipline. That's the only meaningful benchmark for our hybrid.
- **Per-model `MODEL_EXTRA_BODY` quirks.** DeepSeek wants
  `{"chat_template_kwargs":{"thinking":false}}` to skip reasoning
  pass. GLM-5.1 and Qwen3 have similar toggles. Check each model
  card before running.
- **Bump `MODEL_TIMEOUT` to 600s minimum** — NVIDIA build queueing
  varies wildly.
- **Rate limit:** NVIDIA build's free tier caps at ~40 RPM and 1000
  credits. For a serious sweep across 6 models × N findings,
  consider Together / Fireworks / Anyscale (also OpenAI-compatible —
  same `MODEL_BASE_URL` mechanism) for higher throughput.
- **Tool-call format gotchas.** Some open-weight models emit
  malformed tool-call JSON under load. If `tool_compose_datalog`
  gets parse errors, that's a model-format issue, not our code — log
  a representative failure and switch model rather than working
  around it.

## Deliberately excluded (and why)

- **Dense Llama-3 / Mistral-Large** — weaker tool calling than the
  MoE models above on agent-style workloads.
- **Phi-4 / smaller-than-30B-active** — too small for our system
  prompt + tool schemas; anti-confabulation discipline collapses.
- **Code-only fine-tunes (Codestral, Qwen2.5-Coder)** — strong on
  pure-code tasks but weak on the reasoning-over-evidence loop our
  triage requires.

## Sources

- <https://build.nvidia.com/models>
- <https://build.nvidia.com/z-ai/glm-5.1>
- <https://build.nvidia.com/moonshotai/kimi-k2-instruct>
- <https://build.nvidia.com/qwen>
- <https://build.nvidia.com/deepseek-ai>
- <https://www.mindstudio.ai/blog/best-open-source-llms-agentic-coding-2026>
- <https://www.buildfastwithai.com/blogs/best-ai-models-april-2026>
- <https://www.buildfastwithai.com/blogs/qwen-3-6-plus-vs-glm-5-1-vs-kimi-2-5-coding-2026>
- <https://www.siliconflow.com/articles/en/best-open-source-LLM-for-Agent-Workflow>
- <https://www.buildfastwithai.com/blogs/deepseek-v4-pro-review-2026>
