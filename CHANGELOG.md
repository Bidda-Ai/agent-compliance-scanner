# Changelog

## [0.1.0] — 2026-04-28

Initial public release. MVP scope.

### Added
- Composite GitHub Action with 7 configurable inputs (`api-url`, `paths`, `domains`, `severity`, `max-nodes`, `fail-on`, `github-token`)
- Pure-Node scanner with zero npm dependencies (only Node 20 stdlib)
- 12 AI/agent code patterns:
  - LangChain / CrewAI / AutoGen / Pydantic AI imports
  - OpenAI-style and Anthropic-style system prompts
  - MCP tool definitions (`@mcp.tool`, `FastMCP`)
  - Biometric identification (EU AI Act Annex III high-risk)
  - HR / resume scoring (NYC LL 144 + EU AI Act)
  - Credit decisioning (GDPR Art 22 + ECOA + EU AI Act)
  - Web scraping / browser automation
  - Critical/production third-party ICT usage (DORA Art 28)
- Bidda discovery API integration — relevant compliance nodes surfaced per pattern
- Idempotent PR comment (updates the same comment on each push, never spams)
- Advisory by default (`fail-on: never`); opt-in blocking via `fail-on: warn` or `block`
- Suppression via `[skip-bidda]` in PR description
- MIT license

### Privacy
- All pattern matching is local to the GitHub-hosted runner.
- Calls only the public Bidda discovery API (`bidda.com/api/v1/nodes/index.json`) — no auth, no PII.
- Diff content, prompts, repo contents are **never** transmitted off the runner.
