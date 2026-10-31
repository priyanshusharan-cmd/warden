# Warden in the real world: implementation plan

Today Warden is a working prototype: a real decision engine (provenance, policy rules, approvals,
audit chain) running against a simulated inbox, a scripted agent, and simulated sends. This plan
turns it into something a person or a company actually runs in front of real AI agents, on real
email, files, chat and code, and widens it from "one demo inbox" to every kind of agent tool.

---

## 1. What changes, in one picture

```
 TODAY (prototype)                          REAL WORLD
 ─────────────────                          ──────────
 data/world.json (fake inbox)               Gmail / Outlook / Slack / Drive / GitHub / DBs / shell
 ScriptedAgent (always fooled)              Any agent: Claude, Claude Code, Cursor, ChatGPT apps,
                                            LangChain/CrewAI apps, in-house agents
 simulated sends                            real sends, gated by Warden
 one process, in memory                     a gateway service with storage, users, policies per team
 console for demos                          approvals inbox, audit search, policy editor, alerts
```

The engine stays. What gets added is **where Warden sits** (integration points), **what it can see**
(connectors), **what it remembers** (a durable ledger), and **who decides** (approval routing).

---

## 2. Where Warden sits: four integration points

An enforcement point is only useful if every tool call has to pass through it. There are four
places to stand, from easiest to strongest. Build them in this order.

| # | Mode | How it intercepts | Who uses it | Status |
|---|---|---|---|---|
| A | **MCP gateway** | Wraps any MCP server (stdio and HTTP). Agents connect to Warden instead of the server. | Claude Desktop, Claude Code, Cursor, any MCP client | stdio prototype exists (`warden/mcp_proxy.py`) |
| B | **SDK middleware** | A library: `warden.guard(tools)` wraps the app's tool functions in Python / TypeScript. | Teams building their own agent | to build |
| C | **API proxy** | Sits between the app and the model API; inspects `tool_use` blocks before the app runs them, and tool results on the way back. | Apps you can't modify, but whose model traffic you route | to build |
| D | **Connector-native** | Warden *owns* the credentials to Gmail/Slack/Drive and exposes safe tools itself. The agent never holds the real token. | Companies; the strongest mode | to build |

**Why D matters most:** in A–C, a determined agent with its own credentials could go around Warden.
In D, the agent only ever gets Warden's tools, and Warden holds the OAuth tokens. That makes it
"complete mediation", the property every real access-control system needs.

---

## 3. Where the data comes from: connectors

Each connector is a set of tools with the same shape the engine already uses
(`capability`, `destination_params`, `target_params`, `payload_params`, output label).

### Phase 1 connectors (personal use)

| Connector | Read tools | Action tools | Auth |
|---|---|---|---|
| **Email (IMAP/SMTP)** | list unread, read message, search | send, reply, forward | app password (Gmail with 2-step, Outlook, Fastmail, Zoho) |
| **Gmail API** | same, plus labels and threads | same, plus drafts | Google OAuth (`gmail.readonly`, `gmail.send` as separate scopes) |
| **Local files** | list, read | write, move, delete | a folder you choose, never the whole disk |
| **Web** | fetch page | POST/webhook | none; outbound allowlist |

### Phase 2 connectors (teams)

Microsoft 365 (Outlook, OneDrive, Teams), Slack, Google Drive and Docs, Notion, GitHub (issues,
PRs, repo contents), Jira/Linear, Postgres/MySQL (read-only by default), S3, shell commands
(for coding agents), calendar.

### Labelling real data (replaces the hand-written sensitivity in `world.json`)

Real data doesn't arrive tagged `secret` or `confidential`. Warden derives labels from:

1. **Source metadata.** Drive and SharePoint labels, Gmail labels, Slack channel type (private or shared),
   repo visibility, file path rules in policy (`**/.env`, `**/secrets/**`, `*.pem` → secret).
2. **Secret scanners.** Known key formats (AWS, Stripe, GitHub, Slack, Google, private keys) and
   high-entropy strings, the same patterns as `data/detectors.json` but widened.
3. **PII detectors.** Emails, phone numbers, card numbers (Luhn check), Aadhaar and PAN, IBAN.
4. **Sender trust.** Mail from your own domain that passes SPF/DKIM/DMARC is "internal"; anything
   else is untrusted. **Display names are never trusted**: a spoofed "CEO" is still untrusted.
5. **Admin rules.** "Everything in /Finance is confidential", "#exec-chat is confidential".

---

## 4. Which agent does the work

| Agent | Use |
|---|---|
| **Claude (real model)** through the tool runner, with Warden as the tool layer | the default for real use |
| **Bring your own agent** via mode A, B or C | most real deployments |
| **ScriptedAgent** (always obeys planted text) | stays as the *red-team* agent for tests and the benchmark |

The red-team agent stays important: a real model *sometimes* resists an injection, so tests that use
it are flaky. The scripted agent always takes the bait, so it proves Warden holds even in the worst case.

---

## 5. Bugs and gaps in the current engine

Each item below was checked against the code (`python3 -m unittest` covers the fixed ones).

| # | Problem | Impact | Status |
|---|---|---|---|
| 1 | **Partial-value trust.** `origin_of` used substring matching, so `bob@acme.example` counted as user-typed when the user wrote `jimbob@acme.example`. | An attacker registers a suffix of an address the user mentions. | **Fixed:** values must match whole. |
| 2 | **URL prefix trust.** `https://site/api` counted as user-named when the user wrote `https://site/api/v2/guide`. | A redirect or upload endpoint on a parent path looks trusted. | **Fixed** (same change). |
| 3 | **Negation ignored.** "Summarize my emails but **don't send** anything" granted `send_email`. | The contract was wider than the user asked. | **Fixed:** negated actions don't grant tools. |
| 4 | **Keyword contract is coarse.** "emails about the documents" also grants file tools; it can't express "only reply to this thread". | Over-permission (fails open in scope, not in safety). | Open: replace with a structured task contract (§6.2). |
| 5 | **Paraphrased leaks aren't caught.** "Revenue was about 48 crore, up 18%" passes; only verbatim text and known encodings are matched. | Confidential *meaning* can leave through a summary. | Open: semantic matching and numeric fingerprints (§6.4). |
| 6 | **One run, one ledger.** Provenance lives in memory for a single run. A planted value read yesterday and used today shows as `unknown` (approval) instead of `tainted` (deny). | Weaker evidence across sessions; lost on restart. | Open: durable ledger (§6.1). |
| 7 | **Values are matched as text only.** `Bob <bob@x.com>`, `mailto:`, case and Unicode tricks, and URL shorteners or redirects aren't normalised. | Bypass by formatting the same address differently. | Open: canonicalisers per value type (§6.3). |
| 8 | **Tool output is trusted to be one source.** A forwarded email contains another sender's text, but the whole body gets one label. | Coarse evidence; the inner author isn't named. | Open: nested provenance (quoted parts, attachments). |
| 9 | **Lookalike check knows one domain.** Only `internal_domain` is protected; partners and vendors aren't. | Impersonating a known partner isn't flagged. | Open: a "known domains" list with lookalike checks for each. |
| 10 | **The MCP proxy blocks on any approval.** There's no way for a human to approve from the client. | Real users get stuck on legitimate external sends. | Open: approval channel (§7). |
| 11 | **The audit chain is in memory and unsigned.** Tamper-evident, but lost on restart; whoever runs the server could rewrite the whole chain. | Not usable as evidence. | Open: append-only storage plus periodic signed checkpoints (§6.6). |
| 12 | **No authentication on the console/API.** It binds to localhost only, but anyone on the machine can approve. | Fine for a demo, not for a shared host. | Open: login plus per-user approval rights. |
| 13 | **Arguments are coerced to strings in LLM mode.** Lists and objects (multiple recipients, attachments) are flattened. | Multiple recipients might be checked as one string. | Open: typed argument schema; check each recipient. |

---

## 6. Engine upgrades (widening the scope)

### 6.1 Durable provenance ledger
- Store segments in SQLite (local) or Postgres (team) with content hashes, labels, origin, time.
- Index *values*, not just text: every email address, URL, domain, file path, phone number and
  account number seen in untrusted content goes in a value index with a pointer to its source line.
- Lookups by exact canonical value: fast, and no substring tricks (fixes 1, 2 and 6 for good).
- Retention policy (e.g. 30 days), with encryption at rest for segment text.

### 6.2 Structured task contract
Replace keyword intents with a small, typed contract produced from the user's request:
```
{ goal: "summarize unread email", tools: ["email.list", "email.read"],
  may_send_to: [], may_modify: [], data_scope: "inbox:unread" }
```
- Produced by a **separate model that only sees the user's message** (CaMeL's "privileged planner"
  idea), never tool output, so injected text can't widen it.
- Shown to the user as a one-line "This task may: read your unread email" chip, which they can edit.
- Keyword intents stay as the offline fallback.

### 6.3 Value canonicalisation (fixes 7)
Per type, before any lookup: emails (strip display names and `mailto:`, lowercase, IDN to punycode,
optional `+tag` folding), URLs (resolve known shorteners and redirects by HEAD with no body, strip
tracking parameters, normalise host), paths (resolve `..` and symlinks), phone numbers (E.164).

### 6.4 Data-flow checks beyond verbatim (narrows 5)
- **Numeric fingerprints.** Distinctive numbers from confidential sources (48.2, 21.4, deal sizes)
  appearing in outbound text raise R7 even when the words differ.
- **Semantic similarity.** Embedding similarity between outbound text and confidential segments,
  above a threshold, means approval (never auto-deny, because it's probabilistic).
- **Canary tokens.** Invisible unique markers added to confidential documents when read; if a marker
  shows up outbound, it's a definite leak (Gateward's tripwire idea).

### 6.5 Wider rule set

| New rule | What it stops |
|---|---|
| Recipient-set rule | Adding an unnamed CC/BCC to an otherwise legitimate send |
| Attachment rule | Attaching a file the user didn't name, or a secret or confidential file |
| Rate and volume rule | Mass email, bulk download, or 500 deletes in a minute |
| Permission-change rule | Sharing a Drive file publicly, adding a collaborator, changing a mail-forwarding rule |
| Code-execution rule | Shell commands built from untrusted text, or `curl … | sh` patterns |
| Money rule | Payments and refunds always need approval, and must name a user-typed payee |
| Cross-tenant rule | Data from customer A's workspace reaching customer B |
| Time-of-day / anomaly rule | Actions far outside the user's normal pattern need approval |

### 6.6 Trustworthy audit (fixes 11)
Append-only table plus hash chain (as today), plus a signed checkpoint every N entries
(Ed25519 key held outside the app server), exported to the company's SIEM (Splunk, Elastic,
Datadog) and to write-once storage (S3 Object Lock).

---

## 7. Human approvals in the real world (fixes 10)

| Channel | How |
|---|---|
| Console | Today's inline Allow/Block, plus an approvals inbox |
| Slack / Teams | A message with the evidence and **Allow once** / **Block** buttons |
| Email / push | A one-tap link, with a short expiry and signed |
| MCP client | Return a "needs approval" result with a link; the agent tells the user and retries after approval |

Rules: approvals expire (e.g. 10 minutes); the approver sees the exact payload; "allow always for
this recipient" creates a scoped policy exception, logged; nobody can approve their own exception
in team mode (two-person rule for high risk).

---

## 8. Architecture for a team deployment

```
  agents ──► Warden gateway (stateless, horizontally scaled)
               │  policy engine  ◄── policy store (versioned, reviewed like code)
               │  connectors     ◄── secrets vault (OAuth tokens, app passwords)
               │  ledger         ◄── Postgres (+ value index)
               │  audit          ──► append-only store + SIEM export
               └─ approvals      ──► Slack / Teams / console
```

- **Policy as code:** `policy.json` grows into versioned policy files reviewed in pull requests,
  with a "dry run" mode that logs what *would* be blocked before it's enforced.
- **Multi-tenant:** every ledger entry, policy and audit record carries a workspace id.
- **Latency budget:** under 20 ms per decision (all rules are deterministic lookups), so it never
  slows the agent.
- **Fail closed:** if Warden or its database is down, tool calls are refused (as today with R0).

---

## 9. Security of Warden itself

- Warden holds powerful tokens: store them in a vault (macOS Keychain locally; AWS Secrets Manager,
  GCP Secret Manager or HashiCorp Vault in teams), never in `settings.json`.
- Least-privilege OAuth scopes per connector (read and send as separate grants; no "full mailbox" unless needed).
- Console behind login (SSO in teams), CSRF protection, approvals bound to a session.
- Untrusted content is never rendered as HTML in the console (already escaped today).
- Threat-model review and an external pen test before any company use.

---

## 10. Phased delivery

| Phase | Scope | Done when |
|---|---|---|
| **1. Personal real mode** (1–2 weeks) | IMAP/SMTP connector, local-folder connector, real Claude agent via tool runner, only the protected lane on real data, approvals in the console, sends off by default ("show what would be sent") | You ask "summarize my inbox", it runs on your real mail, and a planted test email is blocked with evidence |
| **2. MCP gateway, production grade** (2 weeks) | HTTP + stdio transports, approval links, durable SQLite ledger, canonicalisers, attachment and CC rules | Claude Desktop and Claude Code use Warden-wrapped servers daily without getting stuck |
| **3. Connector-native for teams** (4–6 weeks) | Gmail/M365/Slack/Drive/GitHub via OAuth, Postgres, policy-as-code, Slack approvals, SIEM export, login | A 10-person team runs it for a month; zero leaks in red-team tests; false-block rate under 1% |
| **4. Smarter data flow** (ongoing) | Structured contracts from a planner model, numeric fingerprints, canary tokens, semantic similarity, anomaly rules | The benchmark adds paraphrase attacks, and catch rate is measured and published |

### Testing that carries over
- Keep `python3 -m warden.bench`, and add real-connector **replay tests** (recorded API responses).
- A **red-team suite** per connector: planted emails, Slack messages, Drive comments, GitHub issues, PR descriptions.
- Run public benchmarks (AgentDojo, InjecAgent) with a real model behind Warden and report attack
  success rate and task completion, as the prototype does today.

---

## 11. What to build first (the next pull request)

1. `warden/connectors/email_imap.py`: read-only IMAP (stdlib `imaplib`, app password from the
   Keychain or an environment variable), mapping messages to `read_inbox` / `read_email`.
2. `warden/connectors/smtp.py`: send, **disabled unless `settings.json → real_mode.allow_send` is true**.
3. A **Real mode** tab: connect a mailbox, type a request, watch the protected agent work on real
   mail, approve or block sends.
4. A **"Scan my inbox"** button that needs no AI key: it flags every real email that contains
   instructions aimed at an AI, with the line highlighted.
