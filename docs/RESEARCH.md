# Research notes: how existing projects work

We studied four open-source projects before designing Warden. This file records what each
does, how it is built, and what we borrowed or improved.

## 1. CaMeL (google-research/camel-prompt-injection)

**Idea:** make prompt injection impossible *by design* instead of detecting it.

**Architecture**
- A **privileged LLM** sees only the user's request and writes a plan as Python-like code.
- A custom **interpreter** runs the plan. Every value is a `CaMeLValue` carrying
  `Capabilities(sources_set, readers_set)`: where the data came from and who may read it.
- A **quarantined LLM** parses untrusted text into structured data. It has no tool access,
  so an injection there can't call tools.
- Before each tool call, a `SecurityPolicyEngine.check_policy(tool, kwargs, dependencies)` runs:
  - Tools in `no_side_effect_tools` (reads) are always allowed.
  - A state-changing tool that depends on non-public values is denied.
  - Per-tool policies matched by `fnmatch` (e.g. `send_email_policy`: allowed if recipients
    are trusted, i.e. came from the user; otherwise the body must be readable by the recipients).
  - **No matching policy → denied** (fail closed).

**Borrowed:** source labels on data, trusted-vs-untrusted origin of tool arguments,
per-tool policies, read tools vs. side-effect tools, default deny.
**Limitation we avoid:** CaMeL needs the agent rebuilt around its interpreter.
Warden recovers argument provenance *from the outside* (see ARCHITECTURE.md §4),
so it works as a drop-in layer.

## 2. Gateward (mcpgatehq/mcpgate)

**Idea:** a stdio proxy between an MCP client and an MCP server that inspects every
JSON-RPC message in both directions.

**Architecture**
- `proxy.py` spawns the real server, pumps messages both ways, runs `rules.evaluate()`
  on each and replaces blocked messages with a synthesized JSON-RPC error.
- `rules.py`: ordered rules, first block wins; lifecycle messages (`initialize`, `ping`)
  are always allowed. Rules: injection phrases in tool results, destructive shell commands,
  secrets in responses, path traversal, suspicious tool descriptions, schema drift,
  encoded payloads (base64 / URL / hex decoded and re-scanned), SSRF, exfil URLs, cross-repo access.
- `schema_store.py`: SHA-256 fingerprint of each tool's description and schema in SQLite;
  a changed hash on a later session is reported as a **rug pull**.
- `canary.py`: appends a random marker to each tool response; if a marker shows up in a
  later outbound call, data is being copied out (exfil tripwire).

**Borrowed:** the proxy shape, tool fingerprint pinning, description scanning,
encoded-payload decoding, the idea of watching data *leave* rather than only matching attacks.
**Improved:** Gateward mostly blocks on patterns. Warden decides on provenance,
gives allow / deny / **require approval**, and explains with evidence.

## 3. Invariant mcp-scan / Invariant Gateway

**Idea:** scan MCP client configs for risky servers, and optionally proxy live traffic.

**Architecture**
- Gateway wraps the server command (`invariant-gateway mcp --exec <server…>`).
- Risk taxonomy (docs/risks.md): `prompt_injection_tool_desc`, `untrusted_content`,
  `private_data`, `destructive_capabilities`. Scores 100 / 300 / 600 / 1000.
- Their key insight is "toxic flows": danger comes from *combining* a server that
  ingests untrusted content with one that holds private data and one that can send data out.

**Borrowed:** the four capability classes (Warden tags every tool with them),
and the toxic-flow rule (untrusted influence + private data + egress = block).
**Improved:** fully local analysis (mcp-scan sends descriptions to a cloud API).

## 4. Enkrypt Secure MCP Gateway

**Idea:** a gateway with input guardrails (before the tool runs) and output guardrails
(after the tool returns), plus auth, caching and central policy.

**Borrowed:** checking both directions; per-server policy config.
**Improved:** Enkrypt's detectors are mostly ML classifiers. Warden's core decision is
deterministic, so the same input always gets the same answer and the reason is inspectable.

## Summary table

| | CaMeL | Gateward | mcp-scan | Enkrypt | Warden |
|---|---|---|---|---|---|
| Drop-in (no agent rewrite) | no | yes | yes | yes | yes |
| Provenance of tool arguments | yes (interpreter) | no | flows only | no | yes (external) |
| Tool pinning / rug pull | no | yes | partial | no | yes |
| Allow / deny / approve | allow/deny | allow/block/warn | n/a | allow/block | all three |
| Evidence-cited reasons | short | rule id | evidence text | detector name | source + line |
| Before/after benchmark | AgentDojo | no | no | no | built in |
