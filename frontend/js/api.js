// Fetch wrapper. When the server is off, answers come from recorded engine output (demo-data.js).
(function () {
  const demo = window.WARDEN_DEMO;
  let offline = false;
  let offlineRuns = {};       // run id -> scenario id, for offline approvals
  let offlineAudit = null;

  class ApiError extends Error {}

  async function call(method, path, body) {
    if (!offline) {
      try {
        const res = await fetch(path, {
          method,
          headers: body ? { "Content-Type": "application/json" } : {},
          body: body ? JSON.stringify(body) : undefined,
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) throw new ApiError(data.error || `The server answered ${res.status}.`);
        return data;
      } catch (e) {
        if (e instanceof ApiError || !demo) throw e;
        offline = true;
        document.dispatchEvent(new CustomEvent("warden:offline"));
      }
    }
    return fallback(method, path, body);
  }

  const clone = (x) => JSON.parse(JSON.stringify(x));

  function fallback(method, path, body) {
    switch (path) {
      case "/api/meta": return clone(demo.meta);
      case "/api/scenarios": return clone(demo.scenarios);
      case "/api/run": {
        if (body.custom) throw new ApiError("Writing your own attack needs the server. Start it with ./run.sh.");
        const rec = demo.runs[body.scenario_id];
        if (!rec) throw new ApiError("That scenario isn't in the recorded results.");
        offlineRuns[rec.guarded.id] = body.scenario_id;
        return clone(rec);
      }
      case "/api/approve": {
        const rec = demo.runs[offlineRuns[body.run_id]];
        const next = rec && rec[body.approved ? "approve" : "block"];
        if (!next) throw new ApiError("This run has no recorded answer for that choice.");
        next.id = body.run_id;
        return clone(next);
      }
      case "/api/bench": return clone(demo.bench);
      case "/api/tools": return clone(demo.tools);
      case "/api/tools/drift": return clone(demo.tools_drifted);
      case "/api/tools/reset": return clone(demo.tools);
      case "/api/audit":
        offlineAudit = offlineAudit || clone(demo.audit.entries);
        return { entries: offlineAudit };
      case "/api/audit/verify": {
        const t = (offlineAudit || []).find((e) => e.data && e.data.tampered);
        return { ok: !t, broken_at: t ? t.seq : null, total: (offlineAudit || []).length };
      }
      case "/api/audit/tamper": {
        const e = (offlineAudit || []).find((x) => x.seq === body.seq);
        if (!e) throw new ApiError(`There is no audit entry ${body.seq}.`);
        e.data = { ...e.data, verdict: "allow", tampered: true };
        return { entries: offlineAudit, verify: { ok: false, broken_at: body.seq, total: offlineAudit.length } };
      }
      case "/api/audit/reset": offlineAudit = []; return { entries: [] };
      case "/api/tools/sign": throw new ApiError("Signing tools needs the server. Start it with ./run.sh.");
      case "/api/connect": throw new ApiError("Connecting Claude needs the server. Start it with ./run.sh.");
      case "/api/audit/import": throw new ApiError("Opening a session file needs the server. Start it with ./run.sh.");
    }
    throw new ApiError(`No recorded answer for ${path}.`);
  }

  window.api = {
    get: (p) => call("GET", p),
    post: (p, b) => call("POST", p, b || {}),
    isOffline: () => offline,
    ApiError,
  };
})();
