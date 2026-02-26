#!/usr/bin/env python3
"""
ToolShield CLI — generate test cases and distill experiences in sequence.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import sqlite3
import subprocess
import sys
from pathlib import Path
from typing import Dict, Optional, Tuple

from toolshield._paths import default_agent_config, default_eval_dir, repo_root


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _require_env() -> Tuple[str, str]:
    model = os.getenv("TOOLSHIELD_MODEL_NAME")
    api_key = os.getenv("OPENROUTER_API_KEY")
    if not model or not api_key:
        raise RuntimeError(
            "Missing env vars. Set TOOLSHIELD_MODEL_NAME and OPENROUTER_API_KEY."
        )
    return model, api_key


def _update_config_toml(path: Path, model: str, api_key: str) -> None:
    if not path.exists():
        raise FileNotFoundError(f"Agent config not found: {path}")
    if model and not model.startswith("openrouter/"):
        model = f"openrouter/{model}"
    lines = path.read_text().splitlines(keepends=True)

    def replace_in_section(section: str, key: str, value: str) -> None:
        start = None
        end = len(lines)
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith("[") and stripped.endswith("]"):
                name = stripped.strip("[]")
                if name == section:
                    start = i
                elif start is not None:
                    end = i
                    break
        if start is None:
            lines.extend([f"\n[{section}]\n", f'{key} = "{value}"\n'])
            return

        for i in range(start + 1, end):
            stripped = lines[i].strip()
            if stripped.startswith(f"{key}"):
                lines[i] = f'{key} = "{value}"\n'
                return
        lines.insert(end, f'{key} = "{value}"\n')

    replace_in_section("llm.agent", "model", model)
    replace_in_section("llm.agent", "api_key", api_key)
    replace_in_section("llm.env", "model", model)
    replace_in_section("llm.env", "api_key", api_key)

    path.write_text("".join(lines))


def _resolve_openclaw_workspace() -> Path:
    """Locate the OpenClaw workspace directory, respecting env overrides and legacy paths."""
    home = Path.home()

    # Explicit state-dir override
    state_override = os.environ.get("OPENCLAW_STATE_DIR", "").strip()
    if state_override:
        base = Path(state_override).expanduser()
    else:
        # Check new dir first, then legacy names
        candidates = [
            home / ".openclaw",
            home / ".clawdbot",
            home / ".moltbot",
            home / ".moldbot",
        ]
        base = next((c for c in candidates if c.is_dir()), candidates[0])

    # Profile-aware workspace sub-directory
    profile = os.environ.get("OPENCLAW_PROFILE", "").strip()
    if profile and profile.lower() != "default":
        return base / f"workspace-{profile}"
    return base / "workspace"


def _resolve_cursor_db() -> Path:
    """Locate the Cursor state database across platforms."""
    system = platform.system()
    if system == "Darwin":
        db = Path.home() / "Library" / "Application Support" / "Cursor" / "User" / "globalStorage" / "state.vscdb"
    elif system == "Windows":
        appdata = os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming")
        db = Path(appdata) / "Cursor" / "User" / "globalStorage" / "state.vscdb"
    else:  # Linux
        db = Path.home() / ".config" / "Cursor" / "User" / "globalStorage" / "state.vscdb"
    return db


_CURSOR_RULES_KEY = "aicontext.personalContext"


def _cursor_read_rules(db_path: Path) -> str:
    """Read the current user rules from Cursor's SQLite database."""
    if not db_path.exists():
        return ""
    conn = sqlite3.connect(str(db_path))
    try:
        row = conn.execute(
            "SELECT value FROM ItemTable WHERE key = ?", (_CURSOR_RULES_KEY,)
        ).fetchone()
        if not row or row[0] is None:
            return ""
        val = row[0]
        return val.decode("utf-8", errors="replace") if isinstance(val, bytes) else str(val)
    finally:
        conn.close()


def _cursor_write_rules(db_path: Path, content: str) -> None:
    """Write user rules back to Cursor's SQLite database."""
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    try:
        conn.execute(
            "CREATE TABLE IF NOT EXISTS ItemTable (key TEXT UNIQUE, value BLOB)"
        )
        conn.execute(
            "INSERT OR REPLACE INTO ItemTable (key, value) VALUES (?, ?)",
            (_CURSOR_RULES_KEY, content),
        )
        conn.commit()
    finally:
        conn.close()


_OPENHANDS_MICROAGENT_FILE = "toolshield.md"


def _resolve_openhands_microagent() -> Path:
    """Path to the ToolShield microagent inside the user-level OpenHands dir."""
    return Path.home() / ".openhands" / "microagents" / _OPENHANDS_MICROAGENT_FILE


def _build_openhands_microagent(exp_path: Path, experiences: Dict[str, str]) -> str:
    """Build a complete OpenHands microagent markdown file from experiences."""
    tool_name = _sanitize_tool_name(exp_path.stem.split("_")[-1])
    block = _format_experience_block(experiences, 0)
    return (
        "---\n"
        "name: toolshield\n"
        "type: repo\n"
        "version: 1.0.0\n"
        "agent: CodeActAgent\n"
        "---\n\n"
        f"{EXPERIENCE_HEADER}\n\n"
        "The following guidelines have been identified from analyzing similar tasks. "
        "Please carefully consider these rules before taking any actions:\n\n"
        f"Guidelines for the {tool_name}: \n\n"
        f"{block}"
    )


def _detect_agent_installed(agent: str) -> bool:
    """Check whether the target agent appears to be installed."""
    home = Path.home()
    if agent == "claude_code":
        return (home / ".claude").is_dir()
    if agent == "codex":
        return (home / ".codex").is_dir()
    if agent == "openclaw":
        for name in [".openclaw", ".clawdbot", ".moltbot", ".moldbot"]:
            if (home / name).is_dir():
                return True
        return False
    if agent == "cursor":
        return _resolve_cursor_db().exists()
    if agent == "openhands":
        return (home / ".openhands").is_dir()
    return False


def _find_agent_file(agent: str, source_location: Optional[str] = None) -> Path:
    if source_location:
        return Path(source_location).expanduser()

    home = Path.home()
    if agent == "claude_code":
        preferred = home / ".claude" / "CLAUDE.md"
    elif agent == "openclaw":
        preferred = _resolve_openclaw_workspace() / "AGENTS.md"
    else:
        preferred = home / ".codex" / "AGENTS.md"

    preferred.parent.mkdir(parents=True, exist_ok=True)
    if not preferred.exists():
        preferred.write_text("")
    return preferred


_INJECTION_PATTERNS = [
    re.compile(r"IGNORE\s+(ALL\s+)?PREVIOUS\s+INSTRUCTIONS", re.IGNORECASE),
    re.compile(r"YOU\s+ARE\s+NOW\s+", re.IGNORECASE),
    re.compile(r"NEW\s+INSTRUCTIONS?\s*:", re.IGNORECASE),
    re.compile(r"SYSTEM\s*:\s*", re.IGNORECASE),
    re.compile(r"\[SYSTEM\]", re.IGNORECASE),
    re.compile(r"<<\s*SYS\s*>>", re.IGNORECASE),
    re.compile(r"<\|im_start\|>system", re.IGNORECASE),
]


def _sanitize_experience_value(value: str) -> str:
    """Strip markdown syntax and prompt injection markers from experience values."""
    cleaned = re.sub(r"^#{1,6}\s+", "", value, flags=re.MULTILINE)
    cleaned = cleaned.replace("**", "").replace("__", "")
    cleaned = cleaned.replace("```", "")
    for pattern in _INJECTION_PATTERNS:
        if pattern.search(cleaned):
            raise ValueError(
                f"Experience value contains suspected prompt injection pattern: "
                f"{pattern.pattern!r}"
            )
    return cleaned


def _sanitize_tool_name(raw: str) -> str:
    """Strip special characters from tool names extracted from filenames."""
    return re.sub(r"[^a-zA-Z0-9_\-]", "", raw)


def _load_experiences(exp_path: Path) -> Dict[str, str]:
    if not exp_path.exists():
        raise FileNotFoundError(f"Experience file not found: {exp_path}")
    with open(exp_path, "r") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError("Experience file must be a JSON object")
    validated: Dict[str, str] = {}
    for key, value in data.items():
        if not isinstance(key, str) or not isinstance(value, str):
            raise ValueError(
                f"Experience entries must be string->string. "
                f"Got {type(key).__name__}->{type(value).__name__} for key {key!r}"
            )
        validated[key] = _sanitize_experience_value(value)
    return validated


def _get_max_exp_index(text: str) -> int:
    matches = re.findall(r"exp\.(\d+)", text)
    if not matches:
        return 0
    nums = [int(m) for m in matches if m.isdigit()]
    return max(nums) if nums else 0


def _format_experience_block(experiences: Dict[str, str], start_index: int) -> str:
    lines = []
    idx = start_index
    for _, rule in sorted(experiences.items(), key=lambda kv: kv[0]):
        idx += 1
        escaped_rule = rule.replace("**", "").replace("```", "").replace("##", "")
        lines.append(f"**\u2022 exp.{idx}: {escaped_rule}**")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Sub-commands
# ---------------------------------------------------------------------------

def _build_guidelines_text(
    exp_path: Path, experiences: Dict[str, str], existing_content: str,
) -> str:
    """Build the text to append given existing content and new experiences."""
    intro = (
        "The following guidelines have been identified from analyzing similar tasks. "
        "Please carefully consider these rules before taking any actions:\n\n"
    )
    tool_name = _sanitize_tool_name(exp_path.stem.split("_")[-1])
    tool_line = f"Guidelines for the {tool_name}: \n\n"

    max_idx = _get_max_exp_index(existing_content)
    block = _format_experience_block(experiences, max_idx)

    if EXPERIENCE_HEADER in existing_content:
        return "\n" + tool_line + block
    return "\n" + EXPERIENCE_HEADER + "\n\n" + intro + tool_line + block


def _bundled_experience_dir(model: str = "claude-sonnet-4.5") -> Path:
    """Return the path to bundled experiences shipped with the package."""
    return Path(__file__).resolve().parent / "experiences" / model


def list_experiences(_args: argparse.Namespace) -> None:
    """Print all bundled models and their experience files."""
    base = Path(__file__).resolve().parent / "experiences"
    if not base.is_dir():
        print("No bundled experiences found.")
        return
    models = sorted(d.name for d in base.iterdir() if d.is_dir())
    if not models:
        print("No bundled experiences found.")
        return
    print(f"{'Model':<30} Experience files")
    print("-" * 70)
    for model in models:
        files = sorted(f.name for f in (base / model).glob("*.json"))
        print(f"{model:<30} {', '.join(files)}")


def import_experiences(args: argparse.Namespace) -> None:
    # Handle --all: import every bundled experience file for the selected model
    if getattr(args, "import_all", False):
        model = getattr(args, "model", "claude-sonnet-4.5") or "claude-sonnet-4.5"
        exp_dir = _bundled_experience_dir(model)
        if not exp_dir.is_dir():
            print(f"Bundled experience directory not found: {exp_dir}")
            sys.exit(1)
        exp_files = sorted(exp_dir.glob("*.json"))
        if not exp_files:
            print(f"No experience files found in {exp_dir}")
            sys.exit(1)
        for ef in exp_files:
            print(f"\n--- Importing {ef.name} ---")
            single_args = argparse.Namespace(
                exp_file=str(ef),
                agent=args.agent,
                source_location=getattr(args, "source_location", None),
                import_all=False,
            )
            import_experiences(single_args)
        print(f"\nImported {len(exp_files)} experience file(s) into {args.agent}.")
        return

    if not args.exp_file:
        print("Error: --exp-file is required when --all is not set.")
        sys.exit(1)

    raw = args.exp_file
    candidate = Path(raw).expanduser()
    if candidate.exists():
        exp_path = candidate
    elif "/" not in raw and "\\" not in raw:
        # Bare name — resolve against bundled experiences
        model = getattr(args, "model", "claude-sonnet-4.5") or "claude-sonnet-4.5"
        bundled = _bundled_experience_dir(model) / raw
        if not raw.endswith(".json"):
            bundled = _bundled_experience_dir(model) / (raw + ".json")
        if bundled.exists():
            exp_path = bundled
        else:
            avail = sorted(p.name for p in _bundled_experience_dir(model).glob("*.json")) if _bundled_experience_dir(model).is_dir() else []
            msg = f"Experience file not found: {raw!r}"
            if avail:
                msg += f"\nAvailable bundled experiences for {model}: {', '.join(avail)}"
            else:
                models = sorted(p.name for p in (Path(__file__).resolve().parent / "experiences").iterdir() if p.is_dir())
                msg += f"\nNo bundled experiences for model {model!r}. Available models: {', '.join(models)}"
            print(msg)
            sys.exit(1)
    else:
        exp_path = candidate
    experiences = _load_experiences(exp_path)
    if not experiences:
        print("No experiences found in the JSON file. Nothing to import.")
        return

    if not args.source_location and not _detect_agent_installed(args.agent):
        print(
            f"Warning: {args.agent} does not appear to be installed "
            f"(no config directory found).\n"
            f"If it is installed in a non-default location, "
            f"pass the path with --source_location <path>."
        )
        sys.exit(1)

    if args.agent == "openhands" and not args.source_location:
        target = _resolve_openhands_microagent()
        if target.exists():
            # Append new tool section to existing microagent
            content = target.read_text()
            tool_name = _sanitize_tool_name(exp_path.stem.split("_")[-1])
            max_idx = _get_max_exp_index(content)
            block = _format_experience_block(experiences, max_idx)
            target.write_text(content + f"\nGuidelines for the {tool_name}: \n\n{block}")
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(_build_openhands_microagent(exp_path, experiences))
        print(f"Injected {len(experiences)} guidelines into OpenHands microagent: {target}")
        return

    if args.agent == "cursor" and not args.source_location:
        db = _resolve_cursor_db()
        content = _cursor_read_rules(db)
        append_text = _build_guidelines_text(exp_path, experiences, content)
        _cursor_write_rules(db, content + append_text)
        print(f"Injected {len(experiences)} guidelines into Cursor user rules: {db}")
        return

    target = _find_agent_file(args.agent, args.source_location)
    content = target.read_text() if target.exists() else ""
    append_text = _build_guidelines_text(exp_path, experiences, content)
    target.write_text(content + append_text)
    print(f"Injected {len(experiences)} guidelines into: {target}")


EXPERIENCE_HEADER = "## Guidelines from Previous Experience"


def unload_experiences(args: argparse.Namespace) -> None:
    """Remove all ToolShield-injected guidelines from the agent file."""
    if not args.source_location and not _detect_agent_installed(args.agent):
        print(
            f"Warning: {args.agent} does not appear to be installed "
            f"(no config directory found).\n"
            f"If it is installed in a non-default location, "
            f"pass the path with --source_location <path>."
        )
        sys.exit(1)

    if args.agent == "openhands" and not args.source_location:
        target = _resolve_openhands_microagent()
        if not target.exists():
            print("No ToolShield microagent found for OpenHands.")
            return
        target.unlink()
        print(f"Removed ToolShield microagent: {target}")
        return

    if args.agent == "cursor" and not args.source_location:
        db = _resolve_cursor_db()
        content = _cursor_read_rules(db)
        if not content or EXPERIENCE_HEADER not in content:
            print("No ToolShield guidelines found in Cursor user rules.")
            return
        cleaned = content[:content.index(EXPERIENCE_HEADER)].rstrip() + "\n"
        _cursor_write_rules(db, cleaned)
        print(f"Removed ToolShield guidelines from Cursor user rules: {db}")
        return

    target = _find_agent_file(args.agent, args.source_location)
    if not target.exists():
        print(f"Agent file not found: {target}")
        return

    content = target.read_text()
    if EXPERIENCE_HEADER not in content:
        print(f"No ToolShield guidelines found in: {target}")
        return

    # Remove everything from the header onward
    cleaned = content[:content.index(EXPERIENCE_HEADER)].rstrip() + "\n"
    target.write_text(cleaned)
    print(f"Removed ToolShield guidelines from: {target}")


def _run_iterative_runner(
    task_root: Path,
    output_dir: Path,
    exp_file: Path,
    mcp_name: str,
    agent_config: Path,
    eval_dir: Path,
    server_hostname: str,
    debug: bool = False,
) -> None:
    env = os.environ.copy()
    env.update({
        "TOOLSHIELD_REPO_ROOT": str(repo_root()),
        "TOOLSHIELD_TASK_ROOT": str(task_root),
        "TOOLSHIELD_TASK_BASE_DIR": str(task_root),
        "TOOLSHIELD_OUTPUT_DIR": str(output_dir),
        "TOOLSHIELD_STATE_BASE_DIR": str(output_dir),
        "TOOLSHIELD_EXPERIENCE_FILE": str(exp_file),
        "TOOLSHIELD_TREE_PATH": str(task_root / f"{mcp_name.lower()}_safety_tree.json"),
        "TOOLSHIELD_EVAL_DIR": str(eval_dir),
    })

    output_dir.mkdir(parents=True, exist_ok=True)
    exp_file.parent.mkdir(parents=True, exist_ok=True)

    runner = Path(__file__).resolve().parent / "iterative_exp_runner.py"
    cmd = [
        sys.executable,
        str(runner),
        "--task-root", str(task_root),
        "--output-dir", str(output_dir),
        "--experience-file", str(exp_file),
        "--eval-dir", str(eval_dir),
        "--agent-llm-config", "agent",
        "--agent-llm-config-file", str(agent_config),
        "--env-llm-config", "env",
        "--env-llm-config-file", str(agent_config),
        "--server-hostname", server_hostname,
    ]
    if debug:
        cmd.append("--debug")
    result = subprocess.run(cmd, env=env, check=False)
    if result.returncode != 0:
        raise RuntimeError(f"iterative_exp_runner failed with exit code {result.returncode}")


def generate(args: argparse.Namespace) -> None:
    from toolshield import tree_generation
    from toolshield.inspector import inspect_mcp_tools

    if getattr(args, "multi_turn", False):
        print("Note: --multi-turn is always enabled; flag is ignored.")
    model, api_key = _require_env()
    _update_config_toml(args.agent_config, model, api_key)

    tool_description, tool_actions = inspect_mcp_tools(args.mcp_server)

    output_dir = Path(args.output_path)
    tree_generation.run_generation(
        mcp_name=args.mcp_name,
        tools_list=tool_actions,
        tool_description=tool_description,
        context_guideline=args.context_guideline,
        output_dir=output_dir,
        enable_multi_turn=True,
        skip_benign=True,
        debug=args.debug,
    )

    if args.exp_file:
        exp_file = Path(args.exp_file)
    else:
        tool_name = args.mcp_name.lower()
        exp_file = output_dir.parent / f"{tool_name}-mcp.json"
    state_output = output_dir.parent / "exp_output"
    _run_iterative_runner(
        task_root=output_dir,
        output_dir=state_output,
        exp_file=exp_file,
        mcp_name=args.mcp_name,
        agent_config=args.agent_config,
        eval_dir=args.eval_dir,
        server_hostname=args.server_hostname,
        debug=args.debug,
    )
    if not args.debug:
        print(f"Done. Experience file updated at: {exp_file}")


def _build_import_args_from_generate(args: argparse.Namespace, exp_file: Path) -> argparse.Namespace:
    return argparse.Namespace(
        exp_file=str(exp_file),
        agent=args.agent,
        source_location=args.source_location,
    )


def auto_discover(args: argparse.Namespace) -> None:
    """Scan localhost for MCP servers, run ToolShield pipeline for each, and import results."""
    import asyncio

    from toolshield.mcp_scan import main as scan_main

    start_port = getattr(args, "start_port", 8000)
    end_port = getattr(args, "end_port", 10000)

    found = asyncio.run(scan_main(start_port, end_port))
    if not found:
        print("No MCP servers discovered. Nothing to do.")
        return

    model, _ = _require_env()
    # Sanitize model name for directory/filenames: "anthropic/claude-sonnet-4.5" -> "anthropic-claude-sonnet-4.5"
    model_slug = model.replace("/", "-")

    results = []
    for server in found:
        server_name = server["name"].lower().replace(" ", "-")
        label = f"{model_slug}_{server_name}"
        output_path = Path("output") / label
        print(f"\n{'='*60}")
        print(f"Processing: {server['name']} at {server['url']}")
        print(f"Output: {output_path}")
        print(f"{'='*60}")

        gen_args = argparse.Namespace(
            mcp_name=server["name"],
            mcp_server=server["url"],
            output_path=str(output_path),
            context_guideline=None,
            exp_file=None,
            multi_turn=False,
            agent_config=args.agent_config,
            eval_dir=args.eval_dir,
            server_hostname=args.server_hostname,
            debug=args.debug,
        )
        try:
            generate(gen_args)
        except Exception as e:
            print(f"Error processing {server['name']}: {e}")
            results.append((server["name"], "FAILED", str(e)))
            continue

        # Derive experience file path (matches generate() convention)
        tool_name = server["name"].lower()
        exp_file = output_path.parent / f"{tool_name}-mcp.json"

        if exp_file.exists():
            imp_args = argparse.Namespace(
                exp_file=str(exp_file),
                agent=args.agent,
                source_location=getattr(args, "source_location", None),
                import_all=False,
            )
            try:
                import_experiences(imp_args)
                results.append((server["name"], "OK", str(exp_file)))
            except Exception as e:
                print(f"Error importing experiences for {server['name']}: {e}")
                results.append((server["name"], "IMPORT_FAILED", str(e)))
        else:
            print(f"Warning: expected experience file not found: {exp_file}")
            results.append((server["name"], "NO_EXP_FILE", str(exp_file)))

    # Summary
    print(f"\n{'='*60}")
    print("Auto-discover summary:")
    print(f"{'='*60}")
    for name, status, detail in results:
        print(f"  {name:<25} {status:<15} {detail}")


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="toolshield",
        description="ToolShield \u2014 training-free defense for tool-using AI agents",
    )
    parser.add_argument("--mcp_name", help="MCP tool name (e.g., PostgreSQL)")
    parser.add_argument("--mcp_server", help="MCP server base URL (e.g., http://localhost:8000)")
    parser.add_argument("--context_guideline", default=None, help="Optional context guideline")
    parser.add_argument("--output_path", help="Output directory for generated tasks")
    parser.add_argument("--exp_file", default=None, help="Experience JSON path (optional)")
    parser.add_argument("--agent", choices=["claude_code", "codex", "openclaw", "cursor", "openhands"], default=None, help="Target agent type")
    parser.add_argument("--source_location", default=None, help="Optional target file path")
    parser.add_argument("--agent-config", type=Path, default=default_agent_config(), help="Agent config TOML")
    parser.add_argument("--eval-dir", type=Path, default=default_eval_dir(), help="Evaluation directory")
    parser.add_argument("--server-hostname", default=os.environ.get("SERVER_HOST", "localhost"), help="Runtime server hostname")
    parser.add_argument("--debug", action="store_true", help="Show verbose logs and underlying runner output")
    sub = parser.add_subparsers(dest="command", required=False)

    gen = sub.add_parser("generate", help="Generate test cases and distill experiences")
    gen.add_argument("--mcp_name", required=True, help="MCP tool name (e.g., PostgreSQL)")
    gen.add_argument("--mcp_server", required=True, help="MCP server base URL (e.g., http://localhost:8000)")
    gen.add_argument("--context_guideline", default=None, help="Optional context guideline")
    gen.add_argument("--output_path", required=True, help="Output directory for generated tasks")
    gen.add_argument("--exp_file", default=None, help="Experience JSON path (optional)")
    gen.add_argument("--multi-turn", action="store_true", help=argparse.SUPPRESS)
    gen.add_argument("--agent-config", type=Path, default=default_agent_config(), help="Agent config TOML")
    gen.add_argument("--eval-dir", type=Path, default=default_eval_dir(), help="Evaluation directory")
    gen.add_argument("--server-hostname", default=os.environ.get("SERVER_HOST", "localhost"), help="Runtime server hostname")
    gen.add_argument("--debug", action="store_true", help="Show verbose logs and underlying runner output")
    gen.add_argument("--agent", choices=["claude_code", "codex", "openclaw", "cursor", "openhands"], default=None, help="Target agent type")
    gen.add_argument("--source_location", default=None, help="Optional target file path")
    gen.set_defaults(func=generate)

    imp = sub.add_parser("import", help="Inject experience guidelines into agent instructions")
    imp.add_argument("--exp-file", default=None, help="Experience JSON to inject (name or path; required unless --all)")
    imp.add_argument("--model", default="claude-sonnet-4.5", help="Bundled model to use (default: claude-sonnet-4.5)")
    imp.add_argument("--all", action="store_true", dest="import_all", help="Import all bundled experiences for the selected model")
    imp.add_argument(
        "--agent",
        choices=["claude_code", "codex", "openclaw", "cursor", "openhands"],
        default="claude_code",
        help="Target agent type",
    )
    imp.add_argument("--source_location", default=None, help="Optional target file path")
    imp.set_defaults(func=import_experiences)

    lst = sub.add_parser("list", help="List all bundled experience files")
    lst.set_defaults(func=list_experiences)

    auto_p = sub.add_parser("auto", help="Auto-discover MCP servers on localhost and run full pipeline")
    auto_p.add_argument(
        "--agent",
        required=True,
        choices=["claude_code", "codex", "openclaw", "cursor", "openhands"],
        help="Target agent type",
    )
    auto_p.add_argument("--source_location", default=None, help="Optional target file path")
    auto_p.add_argument("--start-port", type=int, default=8000, help="Start of port scan range (default: 8000)")
    auto_p.add_argument("--end-port", type=int, default=10000, help="End of port scan range (default: 10000)")
    auto_p.add_argument("--agent-config", type=Path, default=default_agent_config(), help="Agent config TOML")
    auto_p.add_argument("--eval-dir", type=Path, default=default_eval_dir(), help="Evaluation directory")
    auto_p.add_argument("--server-hostname", default=os.environ.get("SERVER_HOST", "localhost"), help="Runtime server hostname")
    auto_p.add_argument("--debug", action="store_true", help="Show verbose logs")
    auto_p.set_defaults(func=auto_discover)

    unl = sub.add_parser("unload", help="Remove injected experience guidelines from agent instructions")
    unl.add_argument(
        "--agent",
        choices=["claude_code", "codex", "openclaw", "cursor", "openhands"],
        default="claude_code",
        help="Target agent type",
    )
    unl.add_argument("--source_location", default=None, help="Optional target file path")
    unl.set_defaults(func=unload_experiences)

    args = parser.parse_args()
    if args.command is None:
        missing = [name for name in ["mcp_name", "mcp_server", "output_path", "agent"] if not getattr(args, name)]
        if missing:
            parser.error(f"Missing required arguments for end-to-end mode: {', '.join('--' + m for m in missing)}")
        generate(args)
        exp_file = Path(args.exp_file) if args.exp_file else None
        if exp_file is None:
            tool_name = args.mcp_name.lower()
            exp_file = Path(args.output_path).parent / f"{tool_name}-mcp.json"
        import_experiences(_build_import_args_from_generate(args, exp_file))
        return

    args.func(args)


if __name__ == "__main__":
    main()
