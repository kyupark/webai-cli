# chatmux

Use this skill whenever the user wants to run provider chat from CLI, either single-provider or ask-all, especially:

- ChatGPT
- Claude
- Gemini
- Grok
- Perplexity

This skill is for local `chatmux` usage with browser cookies (no API key setup).

## Auto Trigger Guidance

Treat requests like these as a direct match for this skill:

- "chatgpt로 물어봐"
- "claude로 답해줘"
- "gemini 써서 테스트"
- "grok command 실행"
- "perplexity로 검색해"
- "ask-all 돌려"
- "all providers 비교해줘"
- "chatmux로 답변 받아"

If the user mentions one or more of `chatgpt`, `claude`, `gemini`, `grok`, `perplexity`, or `ask-all`, use this skill first.

Single-provider is fully supported. Ask-all is optional.

## Core Commands

```bash
chatmux chatgpt ask "question"
chatmux claude ask "question"
chatmux gemini ask "question"
chatmux grok ask "question"
chatmux perplexity ask "question"
```

```bash
chatmux ask-all "compare providers"
```

`ask-all` prints:

- per-provider `Conversation: <id>`
- bundle `Ask-all conversation: <id>`

Default usage pattern (recommended): after running `ask-all`, summarize:

- key point from each provider
- interesting differences/conflicts
- best combined conclusion

Continue exact multi-provider thread:

```bash
chatmux ask-all -c <id> "follow up"
```

Install this OpenClaw skill bundle directly:

```bash
chatmux install-openclaw-skill
```
