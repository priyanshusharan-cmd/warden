# Warden

> The AI can be fooled. Warden can't.

Warden is a firewall between an AI agent and its tools. Every tool call goes through it, and
Warden decides **allow**, **block** or **ask you**, based on *where each value came from*: your
own request, or text the agent read in an email, web page, file or tool description. Every
decision cites the exact source line and goes into a tamper-evident audit log. No AI is asked
whether something "looks malicious".

![Home](docs/screenshots/home.png)

## Quick start

```bash
./run.sh        # then open http://127.0.0.1:8000
./test.sh       # 73 backend tests
```

Python 3.10+, standard library only. With the server off, the page shows recorded results.

**Presenting it?** Follow the script in [docs/DEMO.md](docs/DEMO.md).

## Screens

| Screen | What it does |
|---|---|
| **Home** | What Warden is, how it works, headline numbers |
| **Demo** | Same task, two agents: one unprotected, one behind Warden. Click any step for the proof. |
| **Attack lab** | Write your own malicious email and try to get past Warden |
| **Results** | Every built-in attack, with and without Warden |
| **Data** | Edit the inbox, files, pages and secrets the agent works with |
| **Tools** | Tool fingerprints, tampering, signing, and the Claude Desktop/Code setup |
| **Audit** | Verify the hash chain, tamper with an entry, open a Claude session log |

![Demo](docs/screenshots/demo.png)

## Agents

Pick one on the Demo screen:

| Agent | Needs |
|---|---|
| **Scripted** | Nothing. Always falls for the trick, so you see what Warden stops. |
| **Local model** | [Ollama](https://ollama.com) running and `ollama pull qwen2.5:3b`. Free and private. |
| **Claude** | `pip install anthropic` and `export ANTHROPIC_API_KEY=...` before `./run.sh`. |
| **Auto** (default) | Local model if it's running, else Claude, else Scripted. |

## Project layout

```
backend/
  warden/
    core/        the engine: provenance ledger, contract, policy rules, tool pins, signing, audit, gateway
    workspace/   the synthetic world, its tools, the attack scenarios
    agents/      scripted, Claude and Ollama agents
    mcp/         MCP proxy, the workspace as an MCP server, client config
    api/         HTTP server and JSON endpoints
    config.py    paths and config/data loading
    runner.py    drives an agent through the gateway
    benchmark.py runs every scenario with and without Warden
  tests/
frontend/        index.html, css/, js/
config/          settings.json (server, agents, UI), policy.json (what's allowed)
data/            world, scenarios, tools, rules, detector phrases (edits go to *.local.json)
scripts/         build_demo_data.py, print_mcp_config.py
examples/        a small MCP server used in tests
docs/            demo script, architecture, research, real-world plan
```

## How it decides

1. Everything the agent sees is stored with a label: **trusted** (you typed it) or
   **untrusted** (it came from a tool), plus sensitivity and origin.
2. For each call, every destination, target and payload is traced to its source.
3. Twelve rules give a verdict; the strictest wins. Any internal error means **block**.

| Rule | Verdict |
|---|---|
| R0 unknown tool, malformed call, internal error | block |
| R1 tool definition poisoned, changed, or signature broken | block |
| R2 tool not needed for the task (least privilege) | block |
| R3 secret leaving, including reversed, base64, hex, split | block |
| R4 destination came from untrusted content | block (ask if internal, no injection) |
| R5 write/delete target came from untrusted content | block / ask |
| R6 reading a secret file you didn't name | block |
| R7 confidential data to an outside domain | block (ask if you named it) |
| R8 blocklisted or lookalike domain | block |
| R9 destination of unknown origin | ask |
| R10 high-impact action (outside send, delete) | ask |
| R11 outgoing text repeats an injected instruction | ask |

Results (`PYTHONPATH=backend python3 -m warden.benchmark`): 21 attacks in 17 categories succeed
100% of the time without Warden and 0% with it; all 8 normal tasks still finish; 0 false positives.

## Use it with real Claude

```bash
python3 scripts/print_mcp_config.py                    # Claude Code: save as .mcp.json, run `claude`
python3 scripts/print_mcp_config.py --client desktop   # Claude Desktop: add to its config, restart
```

Blocked calls come back to Claude with the reason; Claude's own permission prompt asks you about
the rest. Each session's log lands in `.warden/session-audit.jsonl`; open it from the Audit screen.
Any other stdio MCP server works too:

```bash
PYTHONPATH=backend python3 -m warden.mcp.proxy --audit audit.jsonl -- <server command>
```

Signed tools: `PYTHONPATH=backend python3 -m warden.core.signing sign -- <server command>`, or
**Sign tools** on the Tools screen. A signed tool that changes is blocked, even in a later session.

## Scope

The workspace is synthetic (the hackathon requires it) and nothing is ever really sent. Going to
production: [docs/REAL_WORLD_PLAN.md](docs/REAL_WORLD_PLAN.md). Internals:
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). Prior work: [docs/RESEARCH.md](docs/RESEARCH.md).
