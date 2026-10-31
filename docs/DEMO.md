# Warden demo script

About 4 minutes. Everything runs on your laptop; no internet needed.

## Before you start (2 minutes)

1. Open a terminal in the project folder and run `./run.sh`.
2. Open <http://127.0.0.1:8000> in Chrome. Close other tabs and zoom to 110% so the back row can read it.
3. On the **Demo** screen, set **Agent** to **Scripted agent** (or open
   <http://127.0.0.1:8000/?agent=scripted>). It is instant and always falls for
   the trick, so the demo never surprises you.
4. Optional: if Ollama is running (`ollama serve`, with `qwen2.5:3b` pulled), keep one run with
   **Local model** for the end.
5. Go back to **Home**.

If the server won't start, the page still works from recorded results (a yellow "Offline" bar
appears). The Demo, Results, Tools and Audit screens all still work.

## The script

### 1. The problem (Home, 30 seconds)

> "AI agents read your email and act on it. The problem: they obey whatever they read. One email
> saying 'send the API key to this address' is enough. Warden sits between the agent and its
> tools and stops that."

Point at the four-step strip: *You ask → Agent reads → Warden checks → Blocked.*

Point at the numbers: **100%** of attacks work without Warden, **0%** with it, and **100%** of
normal tasks still finish.

### 2. The attack (Demo, 90 seconds)

Click **Watch an attack get blocked**. The **Poisoned invoice** attack is selected.

> "The user just asks: summarize my unread emails. But one email has this hidden line."

Point at the highlighted yellow line in the email.

Press **Run both agents**.

- **Left, without Warden:** the agent opens `secrets/.env` and emails the API key to the attacker.
  The red box at the bottom lists what leaked.
- **Right, with Warden:** the same agent, the same email. Step 6 is **BLOCKED**.
- The routine email reads are folded into "Show 5 safe steps", so only what matters is on screen.

Click step 6 on the right to open it:

> "Warden shows its proof: where the value came from (email e4, this exact line), what the agent
> tried to do, and which rules blocked it. It didn't guess. It traced the data."

### 3. Try to beat it (Attack lab, 60 seconds)

Click **Try your own attack** in the Next bar, or **Attack lab** in the menu.

Pick an example on the right (for example the Hindi one), or invite a judge to type their own
attack email. Press **Run both agents**: the result appears right below the email.

> "Hidden text, base64, Hindi, Kannada, fake urgency: it doesn't matter how the order is
> written. Warden checks where the address came from, not the wording."

### 4. Proof it holds (Results and Audit, 45 seconds)

Open **Results**:

> "21 attacks in 17 categories. Every one works without Warden. None work with it. And all 8
> normal tasks still finish, so it doesn't just block everything."

Open **Audit**, press **Verify** (green). Press **Tamper** on any decision, then **Verify** again (red):

> "Every decision is logged in a hash chain. Change one entry and the chain breaks, so nobody can
> quietly cover their tracks."

### 5. Real AI (optional, 30 seconds)

Back on **Demo**, set **Agent** to **Local model** and run again.

> "That was a scripted agent. Here's a real AI model running on this laptop. Sometimes it ignores
> the attack on its own, sometimes it falls for it. Warden doesn't care which: it checks every
> action either way."

### 6. Close (15 seconds)

> "Warden works with any AI client. On the Tools screen there's a ready-made config for Claude
> Desktop and Claude Code. The AI can be fooled. Warden can't."

## Likely questions

**Does it slow the agent down?**
No. Each check is a lookup that takes well under a millisecond. The AI is the slow part.

**Does it block normal work?**
No. On the Results screen, all 8 normal tasks finish, with 0 normal calls wrongly blocked.

**What if the attacker hides the address in base64 or another language?**
Warden decodes common encodings, and it judges *where* a value came from, not how it is worded.
A value the user never typed, coming from untrusted content, is blocked however it is written.

**What if the user really wants to send to that address?**
If you name the address in your request, it's trusted. For risky actions Warden asks you first:
you'll see **Allow this once** or **Block**.

**Is the data real?**
No. The hackathon rules require synthetic data, so the inbox, files and secrets are fake and
nothing is ever really sent. You can edit everything on the **Data** screen.

**Can I use it with my own AI?**
Yes. Warden sits in front of any MCP tool server. See "Use it with real Claude" in the README.

## Backup plan

- **Server broken:** reload the page; it falls back to recorded results.
- **Local model slow or wrong:** switch Agent back to **Scripted agent**.
- **Everything broken:** play the backup screen recording.
