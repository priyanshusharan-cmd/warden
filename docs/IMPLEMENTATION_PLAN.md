# Warden: detailed implementation plan

This plan turns `ARCHITECTURE.md` into buildable work. It follows the shape of the
projects in `RESEARCH.md`:

- **Gateward / Invariant Gateway:** the gateway shape. A proxy inspects every call in both
  directions, and each rule returns a small decision object.
- **CaMeL:** the policy engine. Per-tool policies, read tools vs. side-effect tools, default deny.
- **Gateward's schema store:** tool fingerprint pinning.
- **mcp-scan:** the capability classes (untrusted content, private data, egress, destructive).
- **Enkrypt:** input and output checks, plus policy kept in config.

Stack: Python 3 standard library only (no installs) for the backend, plain HTML/CSS/JS for
the frontend. One command runs everything.

---

## Status

| Module | State |
|---|---|
| `world.py`, `labels.py`, `tools.py`, `detectors.py` | done, tested |
| `provenance.py`, `contract.py`, `integrity.py`, `audit.py` | done, tested |
| `policy.py`, `gateway.py`, `agent.py`, `scenarios.py`, `bench.py` | done, tested |
| `server.py`, `ui/`, `mcp_proxy.py`, tests | done, tested (59 tests) |
| Phase 6 rehearsal, backup video, other-laptop test | for the team to do |

---

## Phase 0: Project setup (30 min)

**Tasks**
1. Add `README.md` with the run command and a one-paragraph pitch.
2. Add `tests/` with `python3 -m unittest` as the runner.
3. Add `run.sh`: `python3 -m warden.server --port 8000`.
4. Add `policy.json` (see Phase 1.1) so rules are tunable without code changes, like Enkrypt's config.

**Done when** `python3 -m unittest` runs (even with zero tests) and the README explains how to start.

---

## Phase 1: Decision core (4–5 h)

### 1.1 `policy.py`: the policy engine

Modeled on CaMeL's `SecurityPolicyEngine` and Gateward's `Decision`.

**Data types**
```
Decision
  verdict: "allow" | "require_approval" | "deny"
  risk: int 0..100
  reasons: list of {rule, verdict, text, evidence: [{origin, line, quote}]}
  add(rule, verdict, text, evidence) -> strictest verdict wins
```

**Engine**
```
PolicyEngine(registry, ledger, contract, pins, config)
  evaluate(tool_name, args) -> Decision
    try: run rules R0..R11 in order, collect every reason
    except anything: deny with "R0 fail-closed"
```

**Rules** (from ARCHITECTURE.md §6). Each rule is a small function `rule(ctx) -> None`
that calls `decision.add(...)`, so rules can be unit-tested one by one.

| Rule | Input it reads | Verdict |
|---|---|---|
| R0 unknown / malformed | registry, arg types | deny |
| R1 tool integrity | `pins.check(manifest)` | deny |
| R2 beyond task | `contract.tools` | deny |
| R3 secrets leaving | `ledger.sensitive_in(payload)`, sensitivity = secret | deny |
| R4 untrusted destination | `ledger.origin_of(dest)` = tainted | deny (approval if internal and no injection evidence) |
| R5 untrusted target | `ledger.origin_of(target)` on write/destructive | deny if injection evidence, else approval |
| R6 secret read not asked for | file sensitivity + `contract.paths` | deny; approval if user named it |
| R7 confidential to external | sensitivity = confidential, external domain | deny |
| R8 bad / lookalike domain | blocklist, internal-name lookalike | deny |
| R9 unknown destination | `origin_of` = unknown | approval |
| R10 high impact | egress to external, any destructive | approval |
| R11 echoes flagged text | payload contains lines from flagged segments | approval |

**Risk score** = base by capability (read 5, write 30, egress 40, destructive 50)
+ 40 per deny reason + 20 per approval reason, capped at 100.

**Config (`policy.json`)**: internal domain, blocklisted domains, which tools are
high-impact, whether internal sends need approval. Load once at start; a missing or
invalid file means the engine refuses to start (fail closed at boot too).

**Tests (`tests/test_policy.py`)**: one test per rule, plus:
- an engine exception is caught → deny
- several rules firing → the strictest verdict wins and all reasons are kept

### 1.2 `gateway.py`: the enforcement point

Modeled on Gateward's `proxy.py` (inspect both directions) and Enkrypt's input/output guardrails.

```
Gateway(world, registry, prompt, protected=True, config)
  on start: ledger.add(prompt, trusted); pins.pin_all(registry.manifests());
            ledger.add(each tool description, untrusted "tool:<name> description")
  call(tool, args) -> Step
    if not protected: execute directly, record step with verdict "unprotected"
    decision = policy.evaluate(tool, args)
    audit.append("decision", ...)
    allow    -> execute, label output, ledger.add(output), audit "executed"
    deny     -> do not execute, step.output = None
    approval -> create Approval(id, tool, args, decision), status "waiting"
  resolve(approval_id, approved: bool) -> Step
    approved -> execute; denied -> record; audit "human_decision"
```

**Step** (what the UI renders):
`{seq, tool, args, verdict, risk, reasons, output_preview, label, status}`.

**Tests**: allowed calls execute and land in the ledger. Denied calls never touch the
world (check the sinks). An approval executes only after `resolve(True)`. The audit chain verifies after a run.

### 1.3 Smoke test the existing modules

Write `tests/test_core.py` for the modules that already exist:
- `provenance`: a value typed by the user is trusted, a value seen only in a tool output is
  tainted (with the right segment and line), an unseen value is unknown, and secrets are found
  with separators removed, reversed, and base64.
- `contract`: example prompts map to the expected tool sets, recipients and paths.
- `integrity`: changing a description after pinning is reported, and a description with
  two or more red flags is reported.
- `audit`: verify passes, then tamper makes it fail at the edited entry.

**Phase 1 done when** all tests pass and the four required scenarios get the right
verdicts in a unit test: legitimate task, untrusted-content instruction, sensitive-data
request, tool beyond permission.

---

## Phase 2: Agent, scenarios, scoreboard (3–4 h)

### 2.1 `agent.py`

**`ScriptedAgent`**: a deterministic stand-in for an easily misled model. It is how the demo
stays reliable on stage (no randomness, no network).
- Plans from the prompt with the same intent rules as `contract.py`
  (inbox → `read_inbox` then `read_email` per id, named file → `read_file`, and so on).
- After each read, it follows any instruction-like request it finds in the content.
  This models the worst case: a model that is always fooled. Warden must hold anyway.
- Step-based run with pause/resume:

```
Run(id, prompt, world, gateway, agent)
  advance() -> runs until done or a step is waiting for approval
  resume(approval_id, approved) -> resolve, then advance()
  state() -> {status, steps, sinks, contract, ledger}
```

**`LLMAgent`** (optional, Phase 4): the same `Run` interface, with a real model choosing the tool calls.

### 2.2 `scenarios.py`

Each scenario is data, not code:
```
Scenario(id, title, category, prompt, setup(world, registry), success(world) -> bool, benign: bool)
```
- **Categories** (aim for about 20 attack scenarios + 8 normal tasks):
  untrusted email, untrusted web page, shared document, hidden text, encoded text,
  Hindi, Kannada, fake authority, disguised secrets, confidential report to an outside
  address, deletion request, out-of-scope tool, sensitive read, tampered tool description,
  tool changed after approval, lookalike domain, data in a URL.
- **Success checks** read the world's sinks: did a secret value reach an outside domain,
  was a file deleted, was a secret file read, did confidential lines leave.
- **Normal tasks** check that the user's goal finished (summary produced, the right email sent).
- Keep fixture text short, synthetic, and `.example` domains only.

### 2.3 `bench.py`

```
run_all(protected: bool) -> per scenario: {succeeded, verdicts, blocked_by_rules, approvals}
summary -> attack success rate (with / without), normal task completion,
           false positives, approvals raised, most-fired rules
```
- Simulated human for approvals in benchmarks: approve only when the destination or
  target is in the task contract, otherwise deny. Say so in the UI.

**Phase 2 done when** every attack succeeds without Warden, none succeeds with Warden,
and every normal task completes (approvals included).

---

## Phase 3: Server and API (1.5 h)

`server.py` uses `http.server.ThreadingHTTPServer`, serves `ui/` statically and a JSON API.
Runs are kept in memory behind a lock.

| Method | Path | Body | Returns |
|---|---|---|---|
| GET | `/api/scenarios` | – | list of `{id, title, category, prompt, benign}` |
| POST | `/api/run` | `{scenario_id}` or `{custom: {prompt, email}}` | `{open: RunState, guarded: RunState}` |
| POST | `/api/approve` | `{run_id, approval_id, approved}` | updated guarded `RunState` |
| POST | `/api/bench` | – | scoreboard summary + per-scenario rows |
| GET | `/api/tools` | – | integrity report |
| POST | `/api/tools/drift` | `{tool}` | simulate a changed definition, return report |
| GET | `/api/audit` | – | entries |
| POST | `/api/audit/verify` | – | `{ok, broken_at, total}` |
| POST | `/api/audit/tamper` | `{seq}` | demo only |

Errors return `{error: "plain sentence of what went wrong"}` with a 4xx code.
Bind to `127.0.0.1` only.

**Done when** each endpoint has a test using `urllib` against a server started on a random port.

---

## Phase 4: Frontend (6–8 h)

The design brief and system are in the section **Frontend design** below.

**Files**: `ui/index.html`, `ui/styles.css`, `ui/app.js` (state + rendering),
`ui/api.js` (fetch wrapper that falls back to bundled demo data when the server is off),
`ui/demo-data.js`.

**Build order**
1. Tokens and type scale in CSS variables. Masthead and tabs.
2. Live run: scenario picker, two lanes, strip component, playback (steps appear one at a time).
3. Strip detail: the "why" trace.
4. Inline approval on a waiting strip.
5. "What left the company" panel under the unprotected lane.
6. Results view, tool checks view, audit view.
7. Write-your-own view.
8. Responsive pass (lanes stack on narrow screens), keyboard pass, reduced-motion pass.

---

## Phase 5: Real-world mode (3 h, optional)

- **`mcp_proxy.py`**: a stdio proxy shaped like Gateward and Invariant
  (`python3 -m warden.mcp_proxy -- <server command>`).
  - Reads line-delimited JSON-RPC.
  - `tools/list` responses: pin and scan the tools.
  - `tools/call` requests: run the policy (with a configurable default contract).
  - Results: add them to the ledger as untrusted.
  - Blocked calls get a JSON-RPC error with the reason.
  - `initialize`, `ping` and notifications pass through untouched (Gateward does the same).
- **`examples/demo_mcp_server.py`**: a tiny server with a normal tool and a tampered one, for the integration test.
- **`LLMAgent`** behind an environment variable, off by default.

## Phase 6: Polish and rehearsal (2 h)

- README with screenshots, threat model summary, limits.
- Rehearse the 2-minute demo (PHASES.md) three times. Record a backup video.
- Fresh-clone test: unzip on another laptop, run one command, and it works.

---

## Frontend design

### Brief
- **Who looks at it:** judges with 2 minutes, and security engineers.
- **Its one job:** make "the agent tried something it shouldn't, Warden stopped it, here's why"
  obvious in five seconds.

### Inspiration (from research)
- **"Editing is the design"** (Contra case study): show fewer widgets; the run board is the product.
- **"Confidence, not fear"** (Sentrix case study): calm colors, red only where something was stopped.
- **Air-traffic-control flight progress strips:** a real working artifact where each item
  is a strip on a board, colored by state, read at a glance. Each tool call becomes one strip.
- **Border checkpoint stamps:** Warden "stamps" each strip. This is the one bold moment.

### Not doing (tells of generated design)
- No neon-on-black "hacker" look, no acid-green accent.
- No identical rounded cards with the same soft shadow.
- No all-caps eyebrow labels, no "01 / 02 / 03" markers on things that aren't steps.
- No gradient washes, no fade-up animation on every section.

### Tokens

| Name | Hex | Use |
|---|---|---|
| Chart paper | `#E9EEF0` | page background |
| Strip | `#FBFCFC` | strip and panel surfaces |
| Ink | `#1B2A33` | text, rules |
| Graphite | `#5E6E78` | secondary text |
| Pine | `#3F7D5C` | allowed |
| Ochre | `#C58B1A` | waiting for you |
| Brick | `#B2402F` | blocked, leaked data |

Dark theme (follows the system setting): ink `#0F1A20` background, `#16242C` strips,
`#DCE5E9` text, with the same three signal colors lifted about 10% in lightness.

**Type**
- Schibsted Grotesk (interface): 15px body, 1.5 line height, scale 13 / 15 / 18 / 24 / 36.
- IBM Plex Sans Condensed 500 (strip data: tool names, verdicts).
- IBM Plex Mono 400 for argument values only.

**Shape and space**
- Strips have square corners on the left (the colored state edge, 6px wide) and 4px on the right.
- Panels have 8px corners.
- 8px spacing grid, left-aligned text everywhere.

### Layout

```
┌───────────────────────────────────────────────────────────────────────┐
│ ◈ Warden   Live run  Write an attack  Results  Tool checks  Audit log │
├───────────────────────────────────────────────────────────────────────┤
│ Scenario [ Poisoned invoice ▾ ]   You asked "Summarize my unread…"    │
│                                                 [ Run both agents ]   │
├──────────────────────────────────┬────────────────────────────────────┤
│ Without Warden                   │ With Warden                        │
│ ▌read_inbox                  ran │ ▌read_inbox                Allowed │
│ ▌read_email e4               ran │ ▌read_email e4             Allowed │
│ ▌send_email  to: outside     ran │ ▌send_email  to: outside  [BLOCKED]│
│                                  │   Why ───────────────────────────  │
│ What left the company            │   You never named this address.    │
│ ┌──────────────────────────────┐ │   It came from email e4, line 3.   │
│ │ 1 email to an outside address│ │   "…quoted line…"                  │
│ │ contained: API key           │ │   Rules: R2, R3, R4                │
│ └──────────────────────────────┘ │                                    │
└──────────────────────────────────┴────────────────────────────────────┘
```

On screens under 900px the lanes stack, with the guarded lane first.

### Components
- **Strip:** colored state edge, tool name (condensed), key argument (mono, truncated),
  verdict text at the right. Click or Enter expands it.
- **Why trace:** a vertical path of three nodes: *where the value came from* (origin,
  line, quote) → *which argument* → *decision*, with the rules that fired listed under it.
- **Inline approval:** the waiting strip expands in place with a payload preview and two buttons,
  "Allow this once" and "Block". The button label matches the stamp that follows.
- **Leak panel:** appears only when something left. It lists each item with where it went.
  The heading says what happened ("1 email left the company with your API key"), not "Alert".
- **Scoreboard:** per category, two thin horizontal bars (without / with). One sentence on
  top states the result. No donut charts.
- **Audit view:** a vertical chain of entries with short hashes. Verifying draws a check down the
  chain; after tampering, the chain turns brick from the edited entry onward.

### Motion
- **The one orchestrated moment:** when a strip is blocked, the stamp drops in
  (scale 1.15 → 1, rotate −4°, 180ms, ease-out), and the strip's edge turns brick.
- **Playback:** each new strip slides in 8px from the left, 120ms, staggered by the run timing,
  not by decoration.
- **Responsive motion:** the approval expands with a height transition, the why trace draws its
  connecting line top to bottom (240ms), the leak panel grows when an item arrives.
- `prefers-reduced-motion`: no transforms, and changes are instant.

### Copy
Sentence case, plain verbs, and the button says what happens:
- "Run both agents"
- "Allow this once", which produces the stamp "Allowed by you"
- "Block", which produces "Blocked by you"
- An empty lane says "Pick a scenario and run it to see each tool call here."

### Quality floor
- Keyboard: tabs, strips and approvals all reachable, with a visible focus ring
  (2px ink outline, offset 2px).
- Contrast: AA for all text, and verdicts never rely on color alone (text label always present).
- Works at 360px wide with no horizontal scroll.

---

## Testing plan

| Layer | How |
|---|---|
| Rules | one unit test per rule |
| Engine | fail-closed, strictest-wins, reasons kept |
| Gateway | denied calls leave sinks untouched; approvals pause and resume |
| Scenarios | bench test: 100% of attacks succeed unprotected, 0% protected, normal tasks 100% |
| API | each endpoint against a live server on a random port |
| UI | manual checklist + screenshots at 1440px and 375px, light and dark |
| MCP proxy | integration test against the demo server |

## Risks and fallbacks

| Risk | Fallback |
|---|---|
| Demo laptop has no internet | Everything is local. Fonts fall back to system fonts if Google Fonts can't load. |
| Server crash on stage | UI falls back to bundled demo data, and a recorded video is ready. |
| A judge's own attack isn't followed by the scripted agent | The UI says so honestly ("the agent didn't act on this"), and you show the scoreboard instead. |
| Over-scoping | Phases 1–4 are the product. Phase 5 is bonus only. |

## Suggested split for 4 people

| Person | Owns |
|---|---|
| A | Phase 1 (policy, gateway) |
| B | Phase 2 (agent, scenarios, bench) |
| C | Phase 4 (frontend) |
| D | Phase 0, Phase 3 (server), tests, README, pitch and demo script |
