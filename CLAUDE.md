# mac-assess — Claude Code Guide

## What This Project Is

A LangGraph-based AI security assessment agent for macOS endpoints. It answers: *"If this endpoint was compromised, what would be the impact?"*

It is **not malware** — it is an authorized assessment tool intended for use on systems the operator owns or has explicit permission to assess.

## Quick Start

```bash
pip install -e ".[anthropic]"
export ANTHROPIC_API_KEY="sk-ant-..."
mac-assess "What credentials are accessible on this system?"
```

## Project Layout

```
src/mac_assess/
├── agent.py      # LangGraph graph: planner → executor → tools → reporter
├── cli.py        # argparse CLI entry point; run via `mac-assess` command
├── llm.py        # LLM provider factory (Anthropic, OpenAI, Google, Vertex)
├── state.py      # AgentState (TypedDict) + AssessmentPlan (Pydantic model)
└── tools/
    ├── __init__.py       # get_all_tools() aggregator; get_tools_by_category()
    ├── base.py           # run_command(), CommandResult, shared utilities
    ├── system/           # get_system_info, get_current_user
    ├── credentials/      # list_keychains, find_ssh_keys, find_aws_credentials, find_cloud_configs
    ├── network/          # get_network_connections, get_network_interfaces
    ├── processes/        # list_running_processes, list_installed_apps, list_launch_agents
    ├── browser/          # find_browser_data
    ├── filesystem/       # find_sensitive_files
    └── shell/            # run_shell_command (generic fallback)
```

## Agent Flow

```
planner → executor → [tools → executor]* → reporter → END
```

- **planner**: Parses objective into an `AssessmentPlan` (objective + ordered steps)
- **executor**: Runs the current plan step; calls tools via `bind_tools`
- **tools**: LangGraph `ToolNode` that executes tool calls returned by executor
- **advance**: Increments `plan.current_step`
- **reporter**: Produces the final structured security report

The `should_continue` conditional edge drives routing:
tool calls → `tools`, plan complete → `reporter`, otherwise → `advance` or loop back to `executor`.

## Tool Architecture

Each tool category follows this pattern:

```
tools/<category>/
├── __init__.py   # get_tools() returns List[BaseTool]
└── <name>.py     # @tool decorated functions using run_command()
```

All tools use `run_command()` from `base.py` which wraps `subprocess.run` with timeout and error handling. Tools return plain strings for the LLM to interpret.

## Adding a Tool

1. Create `src/mac_assess/tools/<category>/<name>.py` with a `@tool` decorated function
2. Import it in `src/mac_assess/tools/<category>/__init__.py` and add to `get_tools()`
3. For a new category, also register it in `src/mac_assess/tools/__init__.py`

## LLM Configuration

`llm.py` stores a global `_current_config: LLMConfig`. Call `llm.configure(provider=...)` before `create_llm()`. Provider packages are optional extras — at least one must be installed.

Default models: Anthropic `claude-sonnet-4-20250514`, OpenAI `gpt-4o`, Google/Vertex `gemini-2.0-flash`.

## Key Commands

```bash
# Install with all providers (dev mode)
pip install -e ".[all,dev]"

# Run assessment
mac-assess "Assess credential exposure"

# Verbose (shows tool outputs)
mac-assess -v "Full security audit"

# Interactive REPL
mac-assess -i

# List providers
mac-assess --list-providers

# Specify provider/model
mac-assess -p openai -m gpt-4-turbo "Check SSH keys"
```

## State Model

`AgentState` (TypedDict):
- `messages`: accumulates via LangGraph `add_messages` reducer
- `plan`: `AssessmentPlan | None`
- `findings`: `list[dict]` (populated by tools, currently passed through)
- `phase`: `"planning" | "executing" | "complete"`

## Testing

```bash
pytest  # requires dev extras: pip install -e ".[dev]"
```

No tests currently exist — adding tests for individual tool functions is the highest-value next step.

## Security Notes

- Runs real shell commands on the local system via `subprocess`
- Only run on systems you own or are authorized to assess
- Output may contain sensitive data — handle reports carefully
