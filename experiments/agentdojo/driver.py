"""Run AgentDojo cases against an ACP (v1) harness, with AgentDojo's tools served over MCP.

Per case: build the AgentDojo env + MCP bridge (mcp_bridge.py, in-process thread), spawn the
harness over stdio, ACP initialize -> session/new (cwd = fresh empty temp dir, mcp_servers = the
bridge as HTTP server "agentdojo") -> session/prompt(user task PROMPT), wait (per-case timeout),
then score with AgentDojo's own task checks (utility, attack_success) using the bridge trace.
One JSON line per case is appended to --out; cases already in --out are skipped (resumable).

Examples:
  # OpenCode
  .venv/bin/python driver.py --harness opencode --opencode-config opencode.json \
      --cases cases.jsonl --out runs/opencode.jsonl --workers 3 --permissions allow
  # Rust gateway (config template gets {MCP_URL} and {WORKDIR} substituted per case)
  #   runs: /srv/gateway/gw-bench/target/release/gateway --acp-v1 --config <worker>/<template name>
  .venv/bin/python driver.py --harness gateway --gateway-template gateway.toml.tmpl \
      --cases cases.jsonl --out runs/gateway.jsonl
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import shlex
import shutil
import sys
import tempfile
import time
import traceback
from pathlib import Path

from acp import PROTOCOL_VERSION, spawn_agent_process, text_block
from acp.interfaces import Client
from acp.schema import (
    AllowedOutcome,
    ClientCapabilities,
    DeniedOutcome,
    HttpMcpServer,
    Implementation,
    RequestPermissionResponse,
)

sys.path.insert(0, str(Path(__file__).resolve().parent))
from mcp_bridge import BENCHMARK_VERSION, MODEL_NAME, Bridge, Case  # noqa: E402

HERE = Path(__file__).resolve().parent


def case_id(c: dict) -> str:
    return f"{c['suite']}/{c['user_task']}/{c.get('injection_task') or 'none'}/{c.get('attack') or 'none'}"


def dump(obj):
    if hasattr(obj, "model_dump"):
        return obj.model_dump(mode="json", by_alias=True, exclude_none=True)
    return obj


# ---------------------------------------------------------------- ACP client
class RecordingClient(Client):
    def __init__(self, permissions: str, t0: float):
        self.permissions = permissions
        self.t0 = t0
        self.events: list[dict] = []  # session updates, chunks coalesced
        self.perm_log: list[dict] = []
        self.usage_updates: list[dict] = []

    def _t(self):
        return round(time.time() - self.t0, 3)

    async def session_update(self, session_id, update, **kw):
        d = dump(update)
        kind = d.get("sessionUpdate")
        if kind in ("agent_message_chunk", "agent_thought_chunk", "user_message_chunk"):
            content = d.get("content") or {}
            text = content.get("text", "") if isinstance(content, dict) else ""
            last = self.events[-1] if self.events else None
            if last and last["type"] == kind:
                last["text"] += text
                last["t_end"] = self._t()
            else:
                self.events.append({"type": kind, "t": self._t(), "t_end": self._t(), "text": text})
            return
        if kind == "usage_update":
            self.usage_updates.append(d)
        self.events.append({"type": kind, "t": self._t(), "update": d})

    async def request_permission(self, options, session_id, tool_call, **kw):
        opts = [dump(o) for o in options]
        want = ("allow_once", "allow_always") if self.permissions == "allow" else ("reject_once", "reject_always")
        chosen = next((o for k in want for o in opts if o.get("kind") == k), None)
        if chosen is not None:
            resp = RequestPermissionResponse(outcome=AllowedOutcome(option_id=chosen["optionId"], outcome="selected"))
        else:
            resp = RequestPermissionResponse(outcome=DeniedOutcome(outcome="cancelled"))
        rec = {"t": self._t(), "tool_call": dump(tool_call), "options": opts, "answer": dump(resp)}
        self.perm_log.append(rec)
        self.events.append({"type": "permission_request", "t": rec["t"],
                            "tool": (rec["tool_call"] or {}).get("title"), "answer": rec["answer"]})
        return resp

    # Capabilities we do not advertise; refuse loudly if an agent calls them anyway.
    async def read_text_file(self, *a, **k):
        raise RuntimeError("fs not supported by benchmark client")

    async def write_text_file(self, *a, **k):
        raise RuntimeError("fs not supported by benchmark client")

    async def create_terminal(self, *a, **k):
        raise RuntimeError("terminal not supported by benchmark client")

    def final_text(self) -> str:
        """Text of the agent's last message: message chunks after the last tool activity
        (AgentDojo scores the content of the final assistant message)."""
        last_tool = max((i for i, e in enumerate(self.events)
                         if e["type"] in ("tool_call", "tool_call_update", "permission_request")), default=-1)
        return "".join(e["text"] for e in self.events[last_tool + 1:] if e["type"] == "agent_message_chunk")

    def all_text(self) -> str:
        return "".join(e["text"] for e in self.events if e["type"] == "agent_message_chunk")


# ---------------------------------------------------------------- launch specs
def launch_spec(args, worker_dir: Path, mcp_url: str) -> tuple[list[str], dict]:
    if args.harness == "opencode":
        cmd = [args.opencode_bin, "acp"] + (["--pure"] if args.opencode_pure else [])
        return cmd, {
            "OPENCODE_CONFIG": str(Path(args.opencode_config).resolve()),
            # Without this, OpenCode walks up from cwd and a project opencode.json (e.g. this
            # repo's) silently overrides OPENCODE_CONFIG.
            "OPENCODE_DISABLE_PROJECT_CONFIG": "1",
            # Keep ~/.claude skills/CLAUDE.md and other external prompt sources out of the run.
            "OPENCODE_DISABLE_CLAUDE_CODE": "1",
            "OPENCODE_DISABLE_CLAUDE_CODE_PROMPT": "1",
            "OPENCODE_DISABLE_CLAUDE_CODE_SKILLS": "1",
            "OPENCODE_DISABLE_EXTERNAL_SKILLS": "1",
            "OPENCODE_DISABLE_AUTOUPDATE": "1",
            "OPENCODE_DISABLE_MODELS_FETCH": "1",
            "OPENCODE_DISABLE_LSP_DOWNLOAD": "1",
        }
    if args.harness == "gateway":
        tmpl = Path(args.gateway_template).read_text()
        cfg = tmpl.replace("{MCP_URL}", mcp_url).replace("{WORKDIR}", str(worker_dir))
        cfg_path = worker_dir / Path(args.gateway_template).name.replace(".tmpl", "")
        cfg_path.write_text(cfg)
        # The config is passed as a flag (not only via env) so the gateway can never silently fall
        # back to its production config. SPARK_CONFIG is set too, pointing at the same file.
        return shlex.split(args.gateway_cmd) + ["--config", str(cfg_path)], {"SPARK_CONFIG": str(cfg_path)}
    raise ValueError(args.harness)


# ---------------------------------------------------------------- one case
async def run_case(c: dict, args, worker: int) -> dict:
    rec: dict = {"id": case_id(c), **{k: c.get(k) for k in ("kind", "suite", "user_task", "injection_task", "attack")},
                 "harness": args.harness, "label": args.label, "benchmark_version": BENCHMARK_VERSION,
                 "attack_model_name": c.get("model_name", MODEL_NAME), "attack_user_name": c.get("user_name"),
                 "permissions": args.permissions, "started_at": time.strftime("%Y-%m-%dT%H:%M:%S%z")}
    case = await asyncio.to_thread(lambda: Case(
        c["suite"], c["user_task"], c.get("injection_task"), c.get("attack"),
        model_name=c.get("model_name", MODEL_NAME), user_name=c.get("user_name")).build())
    rec["prompt"] = case.prompt
    rec["injections"] = case.injections
    worker_dir = Path(args.workdir) / f"worker-{worker}"
    worker_dir.mkdir(parents=True, exist_ok=True)
    cwd = Path(tempfile.mkdtemp(prefix="case-", dir=worker_dir))  # fresh empty dir per case
    stderr_path = worker_dir / "harness.stderr.log"
    t0 = time.time()
    client = RecordingClient(args.permissions, t0)
    status, stop_reason, usage, error = "ok", None, None, None
    with Bridge(case) as bridge:
        cmd, env = launch_spec(args, worker_dir, bridge.url)
        rec["launch"] = {"cmd": cmd, "env": env, "mcp_url": bridge.url}
        # Explicitly inherit the parent environment: acp's spawn helpers otherwise start the
        # child from a minimal default environment.
        full_env = {**os.environ, **env}
        with open(stderr_path, "ab") as errf:
            errf.write(f"\n===== {rec['id']} {rec['started_at']}\n".encode())
            errf.flush()
            try:
                async with spawn_agent_process(client, cmd[0], *cmd[1:], env=full_env, cwd=str(cwd),
                                               transport_kwargs={"stderr": errf, "limit": 64 * 1024 * 1024}) as (conn, proc):
                    init = await asyncio.wait_for(conn.initialize(
                        protocol_version=PROTOCOL_VERSION, client_capabilities=ClientCapabilities(),
                        client_info=Implementation(name="agentdojo-acp-driver", version="0.1")), 120)
                    rec["agent_init"] = dump(init)
                    mcp = HttpMcpServer(type="http", name="agentdojo", url=bridge.url, headers=[])
                    sess = await asyncio.wait_for(conn.new_session(cwd=str(cwd), mcp_servers=[mcp]), 120)
                    rec["session_id"] = sess.session_id
                    try:
                        pr = await asyncio.wait_for(
                            conn.prompt(session_id=sess.session_id, prompt=[text_block(case.prompt)]), args.timeout)
                        prd = dump(pr)
                        stop_reason = prd.get("stopReason")
                        usage = prd.get("usage")
                        rec["prompt_meta"] = prd.get("_meta")
                        rec["spark_meta"] = (prd.get("_meta") or {}).get("spark")  # gateway: rounds, tool_calls, tokens, hit_round_limit
                    except asyncio.TimeoutError:
                        status = "timeout"
                        try:
                            await asyncio.wait_for(conn.cancel(session_id=sess.session_id), 5)
                            await asyncio.sleep(3)
                        except Exception:
                            pass
            except Exception as e:
                status = "error"
                error = f"{type(e).__name__}: {e}\n{traceback.format_exc()[-3000:]}"
    rec["wall_s"] = round(time.time() - t0, 2)
    rec["status"], rec["stop_reason"], rec["error"] = status, stop_reason, error
    rec["usage"] = usage
    rec["usage_updates"] = client.usage_updates
    final = client.final_text()
    rec["final_text"] = final
    rec.update(case.score(final))  # utility, attack_success (+ *_error if a checker crashed)
    rec["trace"] = [{"function": f.function, "args": dict(f.args)} for f in case.trace]
    rec["bridge_calls"] = [vars(x) for x in case.calls]
    rec["n_tool_calls"] = len(case.trace)
    rec["permission_requests"] = client.perm_log
    rec["events"] = client.events
    shutil.rmtree(cwd, ignore_errors=True)
    return rec


# ---------------------------------------------------------------- main
def load_cases(path: str, args) -> list[dict]:
    cases = [json.loads(l) for l in Path(path).read_text().splitlines() if l.strip()]
    if args.kind:
        cases = [c for c in cases if c.get("kind") == args.kind]
    if args.suite:
        cases = [c for c in cases if c["suite"] in args.suite]
    if args.ids:
        want = set(args.ids)
        cases = [c for c in cases if case_id(c) in want]
    return cases


async def amain(args):
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    done = set()
    if out.exists():
        for l in out.read_text().splitlines():
            try:
                r = json.loads(l)
            except json.JSONDecodeError:
                continue
            if r.get("status") == "ok" or not args.retry_failed:
                done.add(r["id"])
    cases = [c for c in load_cases(args.cases, args) if case_id(c) not in done]
    if args.limit:
        cases = cases[: args.limit]
    print(f"{len(done)} already done, {len(cases)} to run, workers={args.workers}", flush=True)
    q: asyncio.Queue = asyncio.Queue()
    for c in cases:
        q.put_nowait(c)
    lock = asyncio.Lock()

    async def worker(i):
        while not q.empty():
            c = q.get_nowait()
            try:
                rec = await run_case(c, args, i)
            except Exception as e:
                rec = {"id": case_id(c), "harness": args.harness, "label": args.label, "status": "error",
                       "error": f"{type(e).__name__}: {e}\n{traceback.format_exc()[-3000:]}"}
            async with lock:
                with out.open("a") as f:
                    f.write(json.dumps(rec, default=str) + "\n")
            print(f"[w{i}] {rec['id']}: status={rec.get('status')} utility={rec.get('utility')} "
                  f"attack_success={rec.get('attack_success')} tools={rec.get('n_tool_calls')} "
                  f"wall={rec.get('wall_s')}s", flush=True)

    await asyncio.gather(*(worker(i) for i in range(args.workers)))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--harness", choices=["opencode", "gateway"], required=True)
    ap.add_argument("--label", default=None, help="free-form run label stored in each record")
    ap.add_argument("--cases", default=str(HERE / "cases.jsonl"))
    ap.add_argument("--out", required=True)
    ap.add_argument("--workers", type=int, default=1)
    ap.add_argument("--timeout", type=float, default=600, help="per-case prompt timeout, seconds")
    ap.add_argument("--permissions", choices=["allow", "deny"], default="allow")
    ap.add_argument("--kind", choices=["benign", "injection"])
    ap.add_argument("--suite", nargs="*")
    ap.add_argument("--ids", nargs="*", help="explicit case ids suite/user_task/injection_task|none/attack|none")
    ap.add_argument("--limit", type=int)
    ap.add_argument("--retry-failed", action="store_true", help="re-run cases whose recorded status != ok")
    # Outside this repo on purpose: harnesses that walk up from cwd looking for project config
    # must not find anything.
    ap.add_argument("--workdir", default=os.path.join(tempfile.gettempdir(), "agentdojo-acp-work"))
    ap.add_argument("--opencode-bin", default=os.path.expanduser("~/.local/bin/opencode"))
    ap.add_argument("--opencode-config", default=str(HERE / "opencode.json"))
    ap.add_argument("--opencode-pure", action="store_true", help="pass --pure (no external plugins)")
    ap.add_argument("--gateway-cmd", default="/srv/gateway/gw-bench/target/release/gateway --acp-v1",
                    help="gateway command; the driver appends --config <generated config>")
    ap.add_argument("--gateway-template")
    args = ap.parse_args()
    if args.workers > 3:
        ap.error("the vLLM box is shared: keep --workers <= 3")
    if args.harness == "gateway" and not args.gateway_template:
        ap.error("--harness gateway needs --gateway-template")
    args.label = args.label or args.harness
    asyncio.run(amain(args))


if __name__ == "__main__":
    main()
