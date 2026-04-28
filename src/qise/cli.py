"""CLI entry point for Qise.

Subcommands:
    qise check <tool_name> <tool_args_json>  — Single security check
    qise serve                                — Start MCP Server
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

    # qise context
    context_parser = subparsers.add_parser("context", help="Get security context for a tool")
    context_parser.add_argument("tool_name", help="Tool name")
    context_parser.add_argument("--tool-args", help="Tool arguments as JSON string", default=None)

    # qise guards
    subparsers.add_parser("guards", help="List registered guards")

    # qise version
    subparsers.add_parser("version", help="Print version")

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
    return 0


def _cmd_version(args: argparse.Namespace) -> int:
    from importlib.metadata import version as pkg_version

    try:
        v = pkg_version("qise")
    except Exception:
        v = "0.1.0"
    print(f"qise {v}")
    return 0


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help(sys.stderr)
        sys.exit(1)

    dispatch = {
        "check": _cmd_check,
        "serve": _cmd_serve,
        "context": _cmd_context,
        "guards": _cmd_guards,
        "version": _cmd_version,
    }

    exit_code = dispatch[args.command](args)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
