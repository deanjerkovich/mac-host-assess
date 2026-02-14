# mac-assess

A LangGraph-based AI agent for security assessments of macOS endpoints. Designed to answer the question: *"If this endpoint was compromised, what would be the impact?"*

- Where could an attacker pivot?
- What data could be stolen?
- What credentials could be taken?

## Architecture

The agent follows a **Plan → Execute → Report** flow using LangGraph:

```
┌──────────┐     ┌──────────┐     ┌───────┐     ┌──────────┐
│ Planner  │────▶│ Executor │◀───▶│ Tools │────▶│ Reporter │
└──────────┘     └──────────┘     └───────┘     └──────────┘
                      │                              │
                      │         ┌─────────┐          │
                      └────────▶│ Advance │──────────┘
                                └─────────┘
```

1. **Planner Node**: Takes an objective and creates a structured assessment plan
2. **Executor Node**: Works through each step using available tools
3. **Tool Node**: Executes security assessment tools
4. **Advance Node**: Moves to the next step in the plan
5. **Reporter Node**: Generates a final security report with findings

## Requirements

- Python 3.9+
- macOS (target platform for assessments)
- API key for at least one LLM provider

## Installation

```bash
# Clone and install with default provider (Anthropic)
git clone <repo-url>
cd mac-host-assess
pip install -e ".[anthropic]"

# Install with specific provider
pip install -e ".[openai]"      # OpenAI GPT
pip install -e ".[google]"      # Google AI Studio
pip install -e ".[vertex]"      # Google Vertex AI

# Install all providers
pip install -e ".[all]"

# Install with dev dependencies
pip install -e ".[all,dev]"
```

## LLM Providers

The agent supports multiple LLM providers. Use `--list-providers` to see available options:

```bash
mac-assess --list-providers
```

| Provider | Description | Environment Variable | Default Model |
|----------|-------------|---------------------|---------------|
| `anthropic` | Anthropic Claude | `ANTHROPIC_API_KEY` | claude-sonnet-4-20250514 |
| `openai` | OpenAI GPT | `OPENAI_API_KEY` | gpt-4o |
| `google` | Google AI Studio | `GOOGLE_API_KEY` | gemini-2.0-flash |
| `vertex` | Google Vertex AI | `GOOGLE_CLOUD_PROJECT` | gemini-2.0-flash |

### Configuration

Set the API key for your chosen provider:

```bash
# Anthropic (default)
export ANTHROPIC_API_KEY="sk-ant-..."

# OpenAI
export OPENAI_API_KEY="sk-..."

# Google AI Studio
export GOOGLE_API_KEY="..."

# Google Vertex AI (requires GCP authentication)
export GOOGLE_CLOUD_PROJECT="your-project-id"
gcloud auth application-default login
```

## Usage

### Command Line

```bash
# Run with default provider (Anthropic)
mac-assess "What credentials are accessible on this system?"

# Specify a provider
mac-assess --provider openai "Assess lateral movement opportunities"
mac-assess -p google "Find sensitive files"

# Specify a model
mac-assess --provider openai --model gpt-4-turbo "Check for SSH keys"
mac-assess -p google -m gemini-2.5-pro-preview-05-06 "Full security audit"

# Pass API key directly (not recommended for production)
mac-assess --provider openai --api-key "sk-..." "Quick scan"

# Vertex AI with project
mac-assess --provider vertex --project my-gcp-project "Assess endpoint"

# Verbose mode (shows tool outputs)
mac-assess -v "Find all SSH keys and cloud credentials"

# Interactive mode
mac-assess -i
mac-assess -p openai -i  # Interactive with OpenAI
```

### As a Library

```python
from langchain_core.messages import HumanMessage
from mac_assess.agent import create_agent
from mac_assess.state import AgentState
from mac_assess import llm

# Configure the provider
llm.configure(
    provider="openai",  # or "anthropic", "google", "vertex"
    model="gpt-4o",     # optional, uses default if not specified
)

# Create and run the agent
agent = create_agent()

initial_state: AgentState = {
    "messages": [HumanMessage(content="What credentials are accessible?")],
    "plan": None,
    "findings": [],
    "phase": "planning",
}

for event in agent.stream(initial_state):
    print(event)
```

## Tool Categories

Tools are organized into modular categories, each designed for independent development and testing:

| Category | Module | Tools |
|----------|--------|-------|
| **System** | `tools/system/` | `get_system_info`, `get_current_user` |
| **Credentials** | `tools/credentials/` | `list_keychains`, `find_ssh_keys`, `find_aws_credentials`, `find_cloud_configs` |
| **Network** | `tools/network/` | `get_network_connections`, `get_network_interfaces` |
| **Processes** | `tools/processes/` | `list_running_processes`, `list_installed_apps`, `list_launch_agents` |
| **Browser** | `tools/browser/` | `find_browser_data` |
| **Filesystem** | `tools/filesystem/` | `find_sensitive_files` |
| **Shell** | `tools/shell/` | `run_shell_command` |

## Project Structure

```
mac-host-assess/
├── main.py                         # Entry point
├── pyproject.toml                  # Package configuration
├── requirements.txt                # Dependencies
└── src/mac_assess/
    ├── __init__.py
    ├── agent.py                    # LangGraph agent definition
    ├── cli.py                      # Command-line interface
    ├── llm.py                      # LLM provider configuration
    ├── state.py                    # AgentState and AssessmentPlan models
    └── tools/                      # Modular tool system
        ├── __init__.py             # Tool registry and loader
        ├── base.py                 # Shared utilities (run_command, etc.)
        ├── system/                 # System information tools
        │   ├── __init__.py
        │   ├── info.py             # get_system_info
        │   └── user.py             # get_current_user
        ├── credentials/            # Credential discovery tools
        │   ├── __init__.py
        │   ├── keychain.py         # list_keychains
        │   ├── ssh.py              # find_ssh_keys
        │   ├── aws.py              # find_aws_credentials
        │   └── cloud.py            # find_cloud_configs
        ├── network/                # Network analysis tools
        │   ├── __init__.py
        │   ├── connections.py      # get_network_connections
        │   └── interfaces.py       # get_network_interfaces
        ├── processes/              # Process analysis tools
        │   ├── __init__.py
        │   ├── running.py          # list_running_processes
        │   ├── apps.py             # list_installed_apps
        │   └── persistence.py      # list_launch_agents
        ├── browser/                # Browser data tools
        │   ├── __init__.py
        │   └── data.py             # find_browser_data
        ├── filesystem/             # Filesystem analysis tools
        │   ├── __init__.py
        │   └── sensitive.py        # find_sensitive_files
        └── shell/                  # Generic shell tools
            ├── __init__.py
            └── command.py          # run_shell_command
```

## Adding Custom Tools

### Adding a Tool to an Existing Category

Add a new tool to the appropriate category module:

```python
# src/mac_assess/tools/credentials/vault.py
"""HashiCorp Vault credential discovery."""

from __future__ import annotations

from langchain_core.tools import tool

from ..base import run_command


@tool
def find_vault_tokens() -> str:
    """Find HashiCorp Vault tokens in common locations."""
    result = run_command("cat ~/.vault-token 2>/dev/null || echo 'No token found'")
    return result.output
```

Then register it in the category's `__init__.py`:

```python
# src/mac_assess/tools/credentials/__init__.py
from .vault import find_vault_tokens

def get_tools():
    return [
        # ... existing tools ...
        find_vault_tokens,
    ]
```

### Creating a New Tool Category

1. Create the category directory:

```bash
mkdir src/mac_assess/tools/my_category
```

2. Create the tool module:

```python
# src/mac_assess/tools/my_category/my_tool.py
from __future__ import annotations

from langchain_core.tools import tool

from ..base import run_command


@tool
def my_custom_tool() -> str:
    """Description of what this tool does."""
    result = run_command("your-command-here")
    return result.output
```

3. Create the category `__init__.py`:

```python
# src/mac_assess/tools/my_category/__init__.py
from __future__ import annotations

from typing import List
from langchain_core.tools import BaseTool

from .my_tool import my_custom_tool


def get_tools() -> List[BaseTool]:
    """Get all tools in this category."""
    return [my_custom_tool]
```

4. Register the category in `tools/__init__.py`:

```python
# Add import
from . import my_category

# Add to get_all_tools()
def get_all_tools():
    tools = []
    # ... existing categories ...
    tools.extend(my_category.get_tools())
    return tools
```

## Example Output

```
$ mac-assess --provider openai "What credentials could be stolen?"

Starting macOS Security Assessment
Provider: openai | Model: gpt-4o
Objective: What credentials could be stolen from this system?

Planning assessment...

╭─ Agent ─────────────────────────────────────────────────────╮
│ OBJECTIVE: Identify stealable credentials on this macOS    │
│ STEPS:                                                      │
│ 1. Enumerate SSH keys and their permissions                 │
│ 2. Check for cloud provider credentials (AWS, GCP, Azure)   │
│ 3. List accessible keychains                                │
│ 4. Search for credential files and environment variables    │
│ 5. Check browser password stores                            │
╰─────────────────────────────────────────────────────────────╯

Calling tool: find_ssh_keys
Calling tool: find_cloud_configs
...

╭─ Agent ─────────────────────────────────────────────────────╮
│ ## EXECUTIVE SUMMARY                                        │
│ This endpoint has multiple credential exposure risks...     │
│                                                             │
│ ## CRITICAL FINDINGS                                        │
│ - AWS credentials found in ~/.aws/credentials               │
│ - SSH private key without passphrase at ~/.ssh/id_rsa      │
│ ...                                                         │
╰─────────────────────────────────────────────────────────────╯

Assessment Complete
```

## Security Considerations

- This tool executes shell commands on the local system
- Intended for **authorized security assessments only**
- Review tool outputs carefully - they may contain sensitive information
- Consider running in a sandboxed environment for testing
- Assessment reports may contain sensitive data - handle appropriately

## Dependencies

- [LangGraph](https://github.com/langchain-ai/langgraph) - Agent orchestration
- [LangChain](https://github.com/langchain-ai/langchain) - LLM framework
- [Rich](https://github.com/Textualize/rich) - Terminal formatting

### LLM Provider Packages (install as needed)

- `langchain-anthropic` - Anthropic Claude
- `langchain-openai` - OpenAI GPT
- `langchain-google-genai` - Google AI Studio
- `langchain-google-vertexai` - Google Vertex AI

## License

MIT
