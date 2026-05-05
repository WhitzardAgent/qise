"""CLI entry point for Qise.

Subcommands:
    qise check <tool_name> <tool_args_json>  — Single security check
    qise serve                                — Start MCP Server
    qise proxy start                          — Start HTTP proxy server
    qise bridge start                         — Start Python Bridge server
    qise context <tool_name>                  — Get security context text
    qise guards                               — List registered guards
    qise version                              — Print version
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys

from qise.core.models import GuardContext


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="qise",
        description="Qise — AI-first runtime security framework for AI agents",
    )
    parser.add_argument("--config", help="Path to shield.yaml", default=None)
    subparsers = parser.add_subparsers(dest="command")

    # qise check
    check_parser = subparsers.add_parser("check", help="Run a single security check")
    check_parser.add_argument("tool_name", help="Tool name (e.g., bash, write_file)")
    check_parser.add_argument("tool_args", help="Tool arguments as JSON string")
    check_parser.add_argument(
        "--pipeline",
        choices=["ingress", "egress", "output"],
        default="egress",
        help="Pipeline to run (default: egress)",
    )
    check_parser.add_argument("--session-id", help="Session ID for tracking")

    # qise serve
    serve_parser = subparsers.add_parser("serve", help="Start MCP Server")
    serve_parser.add_argument(
        "--transport",
        choices=["stdio", "sse"],
        default="stdio",
        help="MCP transport (default: stdio)",
    )

    # qise proxy
    proxy_parser = subparsers.add_parser("proxy", help="Proxy server commands")
    proxy_subparsers = proxy_parser.add_subparsers(dest="proxy_command")

    # qise proxy start
    proxy_start = proxy_subparsers.add_parser("start", help="Start HTTP proxy server")
    proxy_start.add_argument("--port", type=int, default=None, help="Listen port (default: from config)")
    proxy_start.add_argument("--host", default=None, help="Listen host (default: 127.0.0.1)")
    proxy_start.add_argument("--upstream", default=None, help="Upstream LLM API base URL")
    proxy_start.add_argument("--upstream-key", default=None, help="Upstream LLM API key")
    proxy_start.add_argument("--no-inject", action="store_true", help="Disable security context injection")
    proxy_start.add_argument("--observe", action="store_true", help="Never block, only warn (observe mode)")
    proxy_start.add_argument("--no-reload", action="store_true", help="Disable config hot-reload")

    # qise context
    context_parser = subparsers.add_parser("context", help="Get security context for a tool")
    context_parser.add_argument("tool_name", help="Tool name")
    context_parser.add_argument("--tool-args", help="Tool arguments as JSON string", default=None)

    # qise guards
    guards_parser = subparsers.add_parser("guards", help="List registered guards")
    guards_parser.add_argument("--metrics", action="store_true", help="Show runtime metrics")

    # qise version
    subparsers.add_parser("version", help="Print version")

    # qise init
    init_parser = subparsers.add_parser("init", help="Generate shield.yaml configuration file")
    init_parser.add_argument("--force", action="store_true", help="Overwrite existing shield.yaml")

    # qise adapters
    adapters_parser = subparsers.add_parser("adapters", help="Framework adapter integration")
    adapters_subparsers = adapters_parser.add_subparsers(dest="adapter_name")

    # qise adapters nanobot
    adapters_subparsers.add_parser("nanobot", help="Show Nanobot integration code snippet")

    # qise adapters hermes
    adapters_subparsers.add_parser("hermes", help="Show Hermes integration code snippet")

    # qise adapters nexau
    adapters_subparsers.add_parser("nexau", help="Show NexAU integration code snippet")

    # qise adapters langgraph
    adapters_subparsers.add_parser("langgraph", help="Show LangGraph integration code snippet")

    # qise adapters openai-agents
    adapters_subparsers.add_parser("openai-agents", help="Show OpenAI Agents SDK integration code snippet")

    # qise bridge
    from qise.bridge.cli import add_bridge_parser
    add_bridge_parser(subparsers)

    return parser


def _get_shield(config_path: str | None = None):
    from qise.core.shield import Shield
    return Shield.from_config(config_path)


def _cmd_check(args: argparse.Namespace) -> int:
    shield = _get_shield(args.config)

    try:
        tool_args = json.loads(args.tool_args)
    except json.JSONDecodeError as e:
        print(f"Error: invalid JSON in tool_args: {e}", file=sys.stderr)
        return 1

    ctx = GuardContext(
        tool_name=args.tool_name,
        tool_args=tool_args,
        session_id=args.session_id,
    )

    pipeline_map = {
        "ingress": shield.pipeline.run_ingress,
        "egress": shield.pipeline.run_egress,
        "output": shield.pipeline.run_output,
    }
    result = pipeline_map[args.pipeline](ctx)

    # Record in session tracker if session_id provided
    if args.session_id:
        for gr in result.results:
            shield.session_tracker.record_guard_result(args.session_id, gr)

    response: dict = {
        "verdict": result.verdict,
        "blocked_by": result.blocked_by,
        "warnings": result.warnings,
    }
    for gr in result.results:
        if gr.risk_attribution:
            response["risk_attribution"] = gr.risk_attribution.model_dump()
            break

    print(json.dumps(response, indent=2))
    return 1 if result.should_block else 0


def _cmd_serve(args: argparse.Namespace) -> int:
    if args.transport != "stdio":
        print(f"Error: transport '{args.transport}' not yet supported", file=sys.stderr)
        return 1

    from qise.mcp_server import main as mcp_main
    asyncio.run(mcp_main())
    return 0


def _cmd_context(args: argparse.Namespace) -> int:
    shield = _get_shield(args.config)

    tool_args = None
    if args.tool_args:
        try:
            tool_args = json.loads(args.tool_args)
        except json.JSONDecodeError as e:
            print(f"Error: invalid JSON in --tool-args: {e}", file=sys.stderr)
            return 1

    context_text = shield.get_security_context(args.tool_name, tool_args)
    if context_text:
        print(context_text)
    return 0


def _cmd_guards(args: argparse.Namespace) -> int:
    shield = _get_shield(args.config)

    # Header
    print(f"{'Name':<20} {'Pipeline':<10} {'Strategy':<12} {'Mode':<10}")
    print("-" * 52)

    ingress_names = {g.name for g in shield.pipeline.ingress.guards}
    egress_names = {g.name for g in shield.pipeline.egress.guards}
    output_names = {g.name for g in shield.pipeline.output.guards}

    for guard in shield.pipeline.all_guards:
        if guard.name in ingress_names:
            pipeline = "ingress"
        elif guard.name in egress_names:
            pipeline = "egress"
        elif guard.name in output_names:
            pipeline = "output"
        else:
            pipeline = "unknown"

        mode = shield.config.guard_mode(guard.name)
        print(f"{guard.name:<20} {pipeline:<10} {guard.primary_strategy:<12} {mode:<10}")

    print(f"\nTotal: {len(shield.pipeline.all_guards)} guards")

    if args.metrics:
        metrics = shield.get_metrics()
        print("\n--- Metrics ---")
        print(json.dumps(metrics, indent=2, default=str))

    return 0


def _cmd_version(args: argparse.Namespace) -> int:
    from importlib.metadata import version as pkg_version

    try:
        v = pkg_version("qise")
    except Exception:
        v = "0.1.0"
    print(f"qise {v}")
    return 0


def _cmd_proxy(args: argparse.Namespace) -> int:
    """Start the HTTP proxy server."""
    if not args.proxy_command:
        print("Error: specify a proxy subcommand (e.g., 'qise proxy start')", file=sys.stderr)
        return 1

    if args.proxy_command != "start":
        print(f"Error: unknown proxy subcommand '{args.proxy_command}'", file=sys.stderr)
        return 1

    from qise.proxy.config import ProxyConfig
    from qise.proxy.server import ProxyServer

    shield = _get_shield(args.config)
    proxy_config = ProxyConfig.from_shield_config(shield.config)

    # Apply CLI overrides
    if args.port is not None:
        proxy_config.listen_port = args.port
    if args.host is not None:
        proxy_config.listen_host = args.host
    if args.upstream is not None:
        proxy_config.upstream_base_url = args.upstream.rstrip("/")
    if args.upstream_key is not None:
        proxy_config.upstream_api_key = args.upstream_key
    if args.no_inject:
        proxy_config.inject_security_context = False
    if args.observe:
        proxy_config.block_on_guard_block = False

    server = ProxyServer(shield, proxy_config)

    # Config hot-reload (enabled by default, disabled with --no-reload)
    watcher = None
    if not args.no_reload:
        try:
            from qise.core.config_watcher import ConfigWatcher
            config_path = args.config or "shield.yaml"
            from pathlib import Path
            if Path(config_path).exists():
                watcher = ConfigWatcher(config_path, shield.reconfigure)
        except Exception:
            pass  # Non-critical: hot-reload is optional

    async def _run() -> None:
        if watcher:
            watcher.start()
        await server.start()
        print(f"Qise proxy running on {proxy_config.listen_host}:{proxy_config.listen_port}")
        print(f"Upstream: {proxy_config.upstream_base_url or '(not configured)'}")
        if watcher and watcher.is_running:
            print(f"Config hot-reload: watching {watcher.config_path}")
        print("Press Ctrl+C to stop")
        try:
            # Run forever until interrupted
            import signal

            loop = asyncio.get_event_loop()
            stop_event = asyncio.Event()

            def _signal_handler() -> None:
                stop_event.set()

            loop.add_signal_handler(signal.SIGINT, _signal_handler)
            loop.add_signal_handler(signal.SIGTERM, _signal_handler)

            await stop_event.wait()
        finally:
            await server.stop()
            if watcher:
                watcher.stop()

    try:
        asyncio.run(_run())
    except KeyboardInterrupt:
        pass
    return 0


def _cmd_init(args: argparse.Namespace) -> int:
    """Generate a shield.yaml configuration file."""
    from pathlib import Path

    config_path = Path("shield.yaml")
    if config_path.exists() and not args.force:
        print(f"Error: {config_path} already exists. Use --force to overwrite.", file=sys.stderr)
        return 1

    content = _default_shield_yaml()
    config_path.write_text(content)
    print(f"Created {config_path}")
    print("Edit this file to customize guard modes, model endpoints, and data paths.")
    return 0


def _cmd_bridge(args: argparse.Namespace) -> int:
    """Start the Python Bridge server."""
    from qise.bridge.cli import cmd_bridge
    return cmd_bridge(args)


def _default_shield_yaml() -> str:
    """Return the default shield.yaml content."""
    return """\
version: "1.0"

# Integration mode: proxy | mcp | sdk
integration:
  mode: sdk
  proxy:
    port: 8822
    auto_takeover: true
    crash_recovery: true

# Model configuration (leave empty for rule-only mode)
models:
  slm:
    base_url: ""
    model: ""
    timeout_ms: 200
  llm:
    base_url: ""
    model: ""
    timeout_ms: 5000
  embedding:
    base_url: ""
    model: ""

# Guard configuration
guards:
  enabled:
    - prompt
    - command
    - credential
    - reasoning
    - filesystem
    - network
    - exfil
    - resource
    - audit
    - tool_sanity
    - context
    - output
    - tool_policy
    - supply_chain
  config:
    # AI-first guards default to observe (need SLM for reliable detection)
    prompt:
      mode: observe
    reasoning:
      mode: observe
    exfil:
      mode: observe
    tool_sanity:
      mode: observe
    context:
      mode: observe
    supply_chain:
      mode: observe
    output:
      mode: observe
    audit:
      mode: observe
    resource:
      mode: observe

    # Rules-based guards default to enforce (low false-positive rate)
    # Uncomment to change:
    # command:
    #   mode: enforce
    # filesystem:
    #   mode: enforce
    # network:
    #   mode: enforce
    # credential:
    #   mode: enforce
    # tool_policy:
    #   mode: enforce

# Data paths
data:
  threat_patterns_dir: "./data/threat_patterns"
  security_contexts_dir: "./data/security_contexts"
  baselines_dir: "./data/baselines"

# Logging
logging:
  level: INFO
  format: json
  output: stderr
"""


def _nexau_snippet() -> str:
    return """\
# NexAU Integration
#
# 1. Install Qise:
#    pip install qise
#
# 2. Add the middleware to your NexAU Agent:

from qise import Shield
from qise.adapters.nexau import QiseNexauMiddleware

shield = Shield.from_config()
middleware = QiseNexauMiddleware(shield)

# Register with NexAU Agent
agent = NexAUAgent(middlewares=[middleware])

# The middleware will:
#   - before_agent: check agent startup args
#   - after_agent: check agent output for leaks
#   - before_model: inject SecurityContext into messages
#   - after_model: check reasoning + filter dangerous tool calls
#   - before_tool: secondary egress check before tool execution
#   - after_tool: check tool results for injection
#
# 3. Configuration (optional):
#    Create shield.yaml to customize guard modes:
#
#    guards:
#      config:
#        command:
#          mode: enforce    # Block dangerous commands
#        prompt:
#          mode: enforce    # Block injection attempts
"""


def _langgraph_snippet() -> str:
    return """\
# LangGraph Integration
#
# 1. Install Qise:
#    pip install qise
#
# 2. Wrap your tools with Qise security checks:

from qise import Shield
from qise.adapters.langgraph import QiseLangGraphWrapper

shield = Shield.from_config()
wrapper = QiseLangGraphWrapper(shield)

# Wrap tools for LangGraph ToolNode
safe_tools = [wrapper.wrap_tool_call(tool) for tool in my_tools]

# Or use async version for async tools
safe_tools = [wrapper.awrap_tool_call(tool) for tool in my_async_tools]

# Add pre-model hook for SecurityContext injection
graph.add_node("pre_model", wrapper.qise_pre_model_hook)

# The wrapper will:
#   - wrap_tool_call: check tool args, raise ToolException on block
#   - awrap_tool_call: async version of wrap_tool_call
#   - qise_pre_model_hook: inject SecurityContext into state messages
#
# 3. Configuration (optional):
#    Create shield.yaml to customize guard modes:
#
#    guards:
#      config:
#        command:
#          mode: enforce    # Block dangerous commands
#        filesystem:
#          mode: enforce    # Block path traversal
"""


def _openai_agents_snippet() -> str:
    return """\
# OpenAI Agents SDK Integration
#
# 1. Install Qise:
#    pip install qise
#
# 2. Add guardrails to your Agent:

from qise import Shield
from qise.adapters.openai_agents import QiseOpenAIAgentsGuardrails

shield = Shield.from_config()
guardrails = QiseOpenAIAgentsGuardrails(shield)

# Register with OpenAI Agent
agent = Agent(
    name="my-agent",
    guardrails=[
        guardrails.input_guardrail,
        guardrails.output_guardrail,
    ],
)

# Wrap tools with tool guardrails
for tool in tools:
    tool = guardrails.wrap_tool(tool)

# The guardrails will:
#   - input_guardrail: check user input for injection
#   - output_guardrail: check agent output for leaks
#   - tool_input_guardrail: check tool call arguments
#   - tool_output_guardrail: check tool results for injection
#
# 3. Configuration (optional):
#    Create shield.yaml to customize guard modes:
#
#    guards:
#      config:
#        command:
#          mode: enforce    # Block dangerous commands
#        credential:
#          mode: enforce    # Block credential leaks
"""


def _cmd_adapters(args: argparse.Namespace) -> int:
    """Show adapter integration code snippets."""
    if not args.adapter_name:
        # List all adapters
        print("Available adapters:\n")
        print("  nanobot       — Nanobot AgentHook integration (recommended)")
        print("  hermes        — Hermes Plugin hook integration")
        print("  nexau         — NexAU Middleware integration (6 hooks)")
        print("  langgraph     — LangGraph tool wrapper integration")
        print("  openai-agents — OpenAI Agents SDK guardrails integration")
        print("\nUse 'qise adapters <name>' for integration code snippet.")
        return 0

    snippets = {
        "nanobot": _nanobot_snippet(),
        "hermes": _hermes_snippet(),
        "nexau": _nexau_snippet(),
        "langgraph": _langgraph_snippet(),
        "openai-agents": _openai_agents_snippet(),
    }

    snippet = snippets.get(args.adapter_name)
    if snippet is None:
        print(f"Error: unknown adapter '{args.adapter_name}'", file=sys.stderr)
        return 1

    print(snippet)
    return 0


def _nanobot_snippet() -> str:
    return """\
# Nanobot Integration
#
# 1. Install Qise:
#    pip install qise
#
# 2. Add the hook to your AgentLoop:

from qise import Shield
from qise.adapters.nanobot import QiseNanobotHook

shield = Shield.from_config()
hook = QiseNanobotHook(shield)

# Pass the hook to your AgentLoop
loop = AgentLoop(hooks=[hook])

# The hook will:
#   - before_execute_tools: check each tool call, remove dangerous ones
#   - after_iteration: check tool results for injection, output for leaks
#
# 3. Configuration (optional):
#    Create shield.yaml to customize guard modes:
#
#    guards:
#      config:
#        command:
#          mode: enforce    # Block dangerous commands
#        prompt:
#          mode: enforce    # Block injection attempts
#        credential:
#          mode: enforce    # Block credential leaks
#
# Default mode is "observe" (log only, never block).
"""


def _hermes_snippet() -> str:
    return """\
# Hermes Integration
#
# 1. Install Qise:
#    pip install qise
#
# 2. Create a Hermes plugin:
#
#    plugins/qise/plugin.yaml:
#      name: qise-security
#      provides_hooks: [pre_tool_call, post_tool_call, transform_tool_result, post_llm_call]
#
#    plugins/qise/__init__.py:

from qise import Shield
from qise.adapters.hermes import QiseHermesAdapter

def register(ctx):
    shield = Shield.from_config()
    adapter = QiseHermesAdapter(shield)
    # Wrap tools with security checks before passing to Agent
    # Note: Hermes-ai does not have a plugin/hook system,
    # so use adapter.wrap_tool() on each tool function.

# The adapter will:
#   - wrap_tool: block dangerous tool calls (raises RuntimeError)
#   - check_agent_output: check LLM output for credential/PII leaks
# For full protection, use Proxy mode instead.
#
# 3. Configuration (optional):
#    Create shield.yaml to customize guard modes:
#
#    guards:
#      config:
#        command:
#          mode: enforce    # Block dangerous commands
#        prompt:
#          mode: enforce    # Block injection attempts
#        credential:
#          mode: enforce    # Block credential leaks
#
# Default mode is "observe" (log only, never block).
"""


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help(sys.stderr)
        sys.exit(1)

    dispatch = {
        "check": _cmd_check,
        "serve": _cmd_serve,
        "proxy": _cmd_proxy,
        "bridge": _cmd_bridge,
        "init": _cmd_init,
        "adapters": _cmd_adapters,
        "context": _cmd_context,
        "guards": _cmd_guards,
        "version": _cmd_version,
    }

    exit_code = dispatch[args.command](args)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
