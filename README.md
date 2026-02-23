# webai-cli

Unified local CLI for ChatGPT, Claude, Gemini, Grok, and Perplexity using browser cookies (no API keys).

## Install

```bash
go install ./cmd/webai-cli
```

### Install via Homebrew (macOS)

```bash
brew tap kyupark/tap
brew install webai-cli
```

If `webai-cli` is not found, add Go bin to your shell profile:

```bash
export PATH="$HOME/go/bin:$PATH"
```

## Quick Start

```bash
webai-cli chatgpt ask "hello"
webai-cli claude ask "hello"
webai-cli gemini ask "hello"
webai-cli grok ask "hello"
webai-cli perplexity ask "hello"
```

```bash
webai-cli ask-all "say hello in one sentence"
webai-cli ask-all -c <id> "follow up"
```

## OpenClaw Skill (included)

This repo includes an OpenClaw skill at `skills/webai-cli`.

Install CLI + skill on macOS:

```bash
./scripts/onboard-macos.sh
```
