# Warden architecture

> "The AI can be fooled. Warden can't."

Warden is a policy enforcement point that sits between an AI agent and its tools.
Every tool call passes through it. Warden decides **allow**, **deny** or
**require approval**, explains why with evidence, and writes a tamper-evident audit log.
It does not ask a model whether something looks malicious: the core decision is
deterministic and based on **where each argument came from**.

## 1. Big picture

```
            user request (TRUSTED)
                    │
                    ▼
   ┌──────────────────────────────┐
   │  Agent (scripted or real LLM)│  ← may be fooled by injected text
   └──────────────┬───────────────┘
                  │ tool call: name + args
                  ▼
   ┌──────────────────────────────────────────────────────────┐
   │                        WARDEN                            │
   │  1. Tool integrity   (pinned hash, poisoned description) │
   │  2. Task contract    (is this tool allowed for this task)│
   │  3. Provenance       (where did each argument come from) │
   │  4. Data sensitivity (does the call carry secrets/PII)   │
   │  5. Policy rules     → allow / deny / require approval   │
   │  6. Approval queue   (human decides high-impact actions) │
   │  7. Audit log        (hash-chained)                      │
   └──────────────┬────────────────────────────▲──────────────┘
                  │ (only if allowed)          │ tool output
                  ▼                            │ labeled UNTRUSTED + scanned
   ┌──────────────────────────────────────────────────────────┐
   │ Tools: read_inbox, read_email, list_files, read_file,    │
   │        browse, send_email, http_post, delete_file, ...   │
   └──────────────────────────────────────────────────────────┘
```

## 2. Components (code map)

Backend (`backend/warden/`, Python standard library only):

| Module | Responsibility |
|---|---|
| `config.py` | Project paths; loads `config/*.json` and `data/*.json` (with `.local.json` overrides). |
| `core/labels.py` | Trust and sensitivity labels. |
| `core/detectors.py` | Pattern detectors: injection phrases (English, Hindi, Kannada), secrets, hidden text, encoded payloads. Evidence, not the sole decision. |
| `core/provenance.py` | The ledger of everything the agent has seen; answers "where did this value come from?" |
| `core/contract.py` | Turns the user's request into a least-privilege task contract. |
| `core/policy.py` | Rules R0–R11 → a `Decision` with verdict, risk and cited reasons. Any exception → deny. |
| `core/tool_pins.py` | Tool fingerprints, poisoned-description scan, rug-pull detection. |
| `core/signing.py` | Signed tool metadata (HMAC-SHA256) that survives across sessions. |
| `core/audit.py` | Append-only, hash-chained audit log. |
| `core/gateway.py` | The enforcement point: runs the checks, queues approvals, labels outputs, writes the log. |
| `workspace/world.py`, `tools.py`, `scenarios.py` | The synthetic workspace, its tools, and the attack library. |
| `agents/` | `scripted.py` (always fooled), `claude.py` (Anthropic API), `ollama.py` (local model). |
| `runner.py` | Drives one agent through a gateway; pauses and resumes on approvals. |
| `benchmark.py` | Every scenario with and without Warden. |
| `mcp/proxy.py` | Real MCP stdio gateway: wraps any MCP server. |
| `mcp/workspace_server.py` | The synthetic workspace served as an MCP server. |
| `mcp/client_config.py` | Config for Claude Desktop / Claude Code. |
| `api/handlers.py`, `api/server.py` | JSON endpoints and the HTTP server. |

Frontend (`frontend/`): `index.html`, `css/styles.css`, `js/api.js` (fetch with offline fallback),
`js/app.js` (views and rendering), `js/demo-data.js` (recorded results, generated).

## 3. Labels

Every piece of content carries a **label**:

- **trust**: `trusted` (typed by the user) or `untrusted` (anything a tool returned:
  emails, web pages, files, tool descriptions).
- **sensitivity**: `public`, `internal`, `confidential`, `secret`.
- **origin**: a human-readable pointer such as `email:e3 (from billing@evil-corp.example)`
  or `file:secrets/.env`.

Tool outputs are labeled by the tool definition. For example `read_email` output is
`untrusted / internal`, `read_file("secrets/.env")` is `untrusted / secret`.

## 4. Provenance without rebuilding the agent

CaMeL tracks data flow inside its own interpreter. Warden can't see inside the model, so it
recovers provenance from the outside:

1. Every user message and every tool output is stored as a **segment** with its label.
2. When a tool call arrives, each argument value is checked against the segments:
   - found in the **user's request** → `trusted`;
   - found only in **untrusted segments** → `tainted`, with the exact segment and line as evidence;
   - found **nowhere** → `unknown` (the model made it up). Unknown provenance on a
     high-impact argument is never auto-allowed.
3. For long arguments (email bodies, POST payloads) Warden checks whether they contain
   **sensitive material** it has seen: secret tokens, lines from confidential files.
   Matching survives obfuscation: Warden also compares with separators stripped,
   reversed, base64, hex and URL-encoded forms.

Destinations (recipients, URLs, file paths to delete) are the key: an attacker's
injection only works if the agent sends data **somewhere the user never asked for**,
or acts on **a target the user never named**. Those values must come from somewhere,
and that is what Warden checks.

## 5. Task contract (least privilege)

The user's request is mapped to capabilities with simple, predictable rules:

| Request mentions | Allowed tools |
|---|---|
| email, inbox, mail, summarize messages | `read_inbox`, `read_email` |
| file, document, report, notes | `list_files`, `read_file` |
| website, page, url, browse, docs | `browse` |
| send, email … to, forward, reply | `send_email` |
| post, upload, webhook, notify | `http_post` |
| delete, remove, clean up | `delete_file` |

Email addresses, URLs and file names typed by the user become the contract's trusted
recipients, URLs and paths. A tool outside the contract is denied: "beyond task permission".

## 6. Policy rules (evaluated in order, strictest verdict wins)

| # | Rule | Verdict |
|---|---|---|
| R0 | Unknown tool, malformed call, or internal error | deny (fail closed) |
| R1 | Tool manifest poisoned or changed since pinned | deny |
| R2 | Tool not in the task contract | deny |
| R3 | Egress call carries secret material (any encoding) | deny |
| R4 | Egress destination came from untrusted content (not named by user) | deny |
| R5 | Destructive/write target came from untrusted content | deny |
| R6 | Reading a secret resource the user did not name | deny |
| R7 | Confidential data leaving to an external domain | deny |
| R8 | Destination on blocklist / lookalike of internal domain | deny |
| R9 | Destination has unknown provenance | require approval |
| R10 | High-impact action (external send, delete, POST) | require approval |
| R11 | Egress body echoes text from a segment flagged as an injection | require approval |
| — | Otherwise | allow |

Each rule that fires adds a **reason** with evidence (`segment`, `line`, `quote`) and adds
to a 0–100 **risk score**.

## 7. Approval queue

A `require_approval` decision pauses the agent. The UI shows the exact call, payload
preview, risk score and reasons. The human picks Approve or Deny. The decision is logged.
In benchmarks, pending approvals count as **stopped** (nothing happens without a human).

## 8. Audit log

Each entry contains `prev_hash` and `hash = sha256(prev_hash + canonical_json(entry))`.
`verify()` walks the chain; editing any entry breaks every later hash. The UI has a
"tamper" button to show this live.

## 9. Threat model

- **Assets:** API keys and passwords in `secrets/`, confidential documents
  (`reports/q3_financials.txt`), the user's inbox, files that could be deleted.
- **Attacker:** anyone who can put text where the agent reads it: an email sender,
  a web page author, a shared document editor, or a malicious / compromised tool publisher.
  The attacker **cannot** type into the user's chat or change Warden's policy.
- **Attacks covered:** indirect prompt injection (email, web, file), hidden and encoded
  instructions, multilingual instructions, fake authority, secret exfiltration (direct and
  obfuscated), forwarding confidential data, destructive actions, tools beyond task scope,
  sensitive reads, tool poisoning, rug pulls, lookalike domains, URL-parameter exfiltration.
- **Out of scope / limits:**
  - A user who is socially engineered into typing the attacker's address themselves.
  - Paraphrased leaks of confidential *meaning* (e.g. the model summarizes the
    financials in its own words). Warden matches verbatim content and known encodings.
  - Side channels outside the tool interface.

## 10. Safety and privacy

All data is synthetic. Domains use `.example` (reserved, never resolves).
No network calls are made except the optional LLM mode. Detection runs locally.
