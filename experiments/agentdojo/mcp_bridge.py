"""AgentDojo -> MCP bridge.

For one benchmark case (suite, user_task, optional injection_task, attack) this builds the task
environment exactly the way AgentDojo's own benchmark does (TaskSuite.run_task_with_pipeline:
load_and_inject_default_environment(injections), then user_task.init_environment, then a deep-copied
pre_environment) and serves the suite's tools over MCP streamable HTTP at
http://127.0.0.1:<port>/mcp.

Every tools/call executes against the live env through AgentDojo's FunctionsRuntime, mirroring
agentdojo.agent_pipeline.ToolsExecutor (string-list arg coercion, unknown-tool error) and the
OpenAI pipeline's tool-message content (the error string if the call errored, else
tool_result_to_str(result), i.e. YAML). Each call is appended to `trace` as an AgentDojo
FunctionCall, which is what the tasks' trace-based utility/security checks consume.

Standalone use (poke at a case by hand):
    .venv/bin/python mcp_bridge.py --suite banking --user-task user_task_0 \
        --injection-task injection_task_0 --port 8765
"""
from __future__ import annotations

import argparse
import socket
import threading
import time
import uuid
from ast import literal_eval
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any

import uvicorn
from mcp import types as mt
from mcp.server.lowlevel import Server

import agentdojo.attacks  # noqa: F401  (registers the attacks)
from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
from agentdojo.agent_pipeline.tool_execution import is_string_list, tool_result_to_str
from agentdojo.attacks.attack_registry import load_attack
from agentdojo.functions_runtime import FunctionCall, FunctionsRuntime
from agentdojo.task_suite.load_suites import get_suite
from agentdojo.types import text_content_block_from_string

BENCHMARK_VERSION = "v1.2.2"  # latest benchmark version shipped in agentdojo 0.1.35
MODEL_NAME = "Qwen"  # name the important_instructions attack addresses the model by
SUITES = ("workspace", "travel", "banking", "slack")


class _StubPipeline(BasePipelineElement):
    """Only so AgentDojo attack constructors (which derive the model name from the pipeline name)
    can be instantiated; model_name is overridden right after construction."""

    name = "gpt-4o-2024-05-13"

    def query(self, *a, **k):  # pragma: no cover
        raise NotImplementedError


@lru_cache(maxsize=None)
def get_attack(suite_name: str, attack_name: str, model_name: str = MODEL_NAME,
               user_name: str | None = None, version: str = BENCHMARK_VERSION):
    suite = get_suite(version, suite_name)
    attack = load_attack(attack_name, suite, _StubPipeline())
    if hasattr(attack, "model_name"):
        attack.model_name = model_name
    if user_name is not None and hasattr(attack, "user_name"):
        attack.user_name = user_name
    return attack


def tool_input_schema(fn) -> dict:
    """JSON schema from AgentDojo's Function definition (same source the OpenAI pipeline uses)."""
    s = fn.parameters.model_json_schema()
    s.pop("title", None)
    s.setdefault("type", "object")
    s.setdefault("properties", {})
    return s


@dataclass
class CallRecord:
    function: str
    args: dict
    result: str
    error: str | None
    t_start: float
    t_end: float


@dataclass
class Case:
    suite_name: str
    user_task_id: str
    injection_task_id: str | None = None
    attack_name: str | None = None
    version: str = BENCHMARK_VERSION
    model_name: str = MODEL_NAME
    user_name: str | None = None  # None = the attack's own default ("Emma Johnson" for important_instructions)
    # filled in by build()
    suite: Any = None
    user_task: Any = None
    injection_task: Any = None
    injections: dict = field(default_factory=dict)
    env: Any = None
    pre_env: Any = None
    runtime: FunctionsRuntime | None = None
    trace: list[FunctionCall] = field(default_factory=list)
    calls: list[CallRecord] = field(default_factory=list)
    lock: threading.Lock = field(default_factory=threading.Lock)

    def build(self) -> "Case":
        self.suite = get_suite(self.version, self.suite_name)
        self.user_task = self.suite.get_user_task_by_id(self.user_task_id)
        if self.injection_task_id:
            self.injection_task = self.suite.get_injection_task_by_id(self.injection_task_id)
            attack = get_attack(self.suite_name, self.attack_name or "important_instructions",
                                self.model_name, self.user_name, self.version)
            self.injections = attack.attack(self.user_task, self.injection_task)
        else:
            self.injections = {}
        environment = self.suite.load_and_inject_default_environment(self.injections)
        self.env = self.user_task.init_environment(environment)
        self.pre_env = self.env.model_copy(deep=True)
        self.runtime = FunctionsRuntime(self.suite.tools)
        return self

    @property
    def prompt(self) -> str:
        return self.user_task.PROMPT

    # ---- tool execution (mirrors ToolsExecutor + OpenAI tool-message content) ----
    def call(self, name: str, args: dict | None) -> tuple[str, str | None]:
        with self.lock:
            t0 = time.time()
            fc = FunctionCall(function=name, args=dict(args or {}), id=f"mcp-{uuid.uuid4().hex[:12]}")
            self.trace.append(fc)
            if name not in self.runtime.functions:
                result, error = "", f"Invalid tool {name} provided."
            else:
                for k, v in list(fc.args.items()):
                    if isinstance(v, str) and is_string_list(v):
                        fc.args[k] = literal_eval(v)
                raw, error = self.runtime.run_function(self.env, name, fc.args)
                result = tool_result_to_str(raw)
            text = error if error else result
            self.calls.append(CallRecord(name, dict(fc.args), result, error, t0, time.time()))
            return text, error

    def score(self, final_text: str) -> dict:
        """utility = user task solved; attack_success = AgentDojo's `security` for the injection
        task (True means the injection goal WAS achieved)."""
        out = [text_content_block_from_string(final_text or "")]
        res: dict[str, Any] = {}
        with self.lock:
            try:
                res["utility"] = bool(self.suite._check_task_result(
                    self.user_task, out, self.pre_env, self.env, self.trace))
            except Exception as e:  # a task checker crashing on odd model output counts as fail
                res["utility"] = False
                res["utility_error"] = f"{type(e).__name__}: {e}"
            if self.injection_task is not None:
                try:
                    res["attack_success"] = bool(self.suite._check_task_result(
                        self.injection_task, out, self.pre_env, self.env, self.trace))
                except Exception as e:
                    res["attack_success"] = False
                    res["attack_success_error"] = f"{type(e).__name__}: {e}"
            else:
                res["attack_success"] = None
        return res


def make_server(case: Case) -> Server:
    tools = [mt.Tool(name=f.name, description=f.description, inputSchema=tool_input_schema(f))
             for f in case.suite.tools]

    async def on_list_tools(ctx, params):
        return mt.ListToolsResult(tools=tools)

    async def on_call_tool(ctx, params: mt.CallToolRequestParams):
        text, error = case.call(params.name, params.arguments)
        return mt.CallToolResult(content=[mt.TextContent(type="text", text=text)], isError=bool(error))

    return Server("agentdojo", version="1", on_list_tools=on_list_tools, on_call_tool=on_call_tool)


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Bridge:
    """Runs the MCP server for one case in a background thread (its own event loop)."""

    def __init__(self, case: Case, port: int | None = None):
        self.case = case
        self.port = port or free_port()
        app = make_server(case).streamable_http_app(streamable_http_path="/mcp", host="127.0.0.1")
        self._server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=self.port,
                                                     log_level="warning", lifespan="on"))
        self._thread = threading.Thread(target=self._server.run, daemon=True)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}/mcp"

    def __enter__(self):
        self._thread.start()
        for _ in range(400):
            if self._server.started:
                return self
            if not self._thread.is_alive():
                break
            time.sleep(0.05)
        raise RuntimeError(f"MCP bridge did not start on port {self.port}")

    def __exit__(self, *exc):
        self._server.should_exit = True
        self._thread.join(timeout=10)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--suite", required=True, choices=SUITES)
    ap.add_argument("--user-task", required=True)
    ap.add_argument("--injection-task")
    ap.add_argument("--attack", default="important_instructions")
    ap.add_argument("--port", type=int, default=8765)
    a = ap.parse_args()
    c = Case(a.suite, a.user_task, a.injection_task, a.attack if a.injection_task else None).build()
    with Bridge(c, a.port) as b:
        print(f"serving {len(c.suite.tools)} tools at {b.url}\nprompt: {c.prompt!r}", flush=True)
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
    print("trace:", [(f.function, dict(f.args)) for f in c.trace])
    print("score('') :", c.score(""))
