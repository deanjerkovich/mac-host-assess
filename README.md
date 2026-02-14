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

## Included Tools

| Category | Tools | Description |
|----------|-------|-------------|
| **System** | `get_system_info` | OS version, hardware, hostname |
| | `get_current_user` | Current user and group memberships |
| **Credentials** | `list_keychains` | Accessible macOS keychains |
| | `find_ssh_keys` | SSH keys in ~/.ssh |
| | `find_aws_credentials` | AWS credential files |
| | `find_cloud_configs` | AWS, GCP, Azure, K8s configs |
| **Network** | `get_network_connections` | Active connections and listening ports |
| | `get_network_interfaces` | Network interface configuration |
| **Processes** | `list_running_processes` | Running processes with users |
| | `list_installed_apps` | Applications in /Applications |
| | `list_launch_agents` | LaunchAgents (persistence mechanisms) |
| **Browser** | `find_browser_data` | Chrome, Firefox, Safari data locations |
| **Files** | `find_sensitive_files` | Keys, configs, credential files |
| **Generic** | `run_shell_command` | Execute arbitrary commands |

## Adding Custom Tools

Add new tools to `src/mac_assess/tools.py`:

```python
from langchain_core.tools import tool

@tool
def check_sudo_access() -> str:
    """Check if the current user has sudo access without a password."""
    result = run_command("sudo -n true 2>&1")
    if result["returncode"] == 0:
        return "WARNING: User has passwordless sudo access"
    return "User requires password for sudo"

# Add to the registry
ALL_TOOLS = [
    # ... existing tools ...
    check_sudo_access,
]
```

Tools are automatically available to the agent once added to `ALL_TOOLS`.

## Project Structure

```
mac-host-assess/
├── main.py                     # Entry point
├── pyproject.toml              # Package configuration
├── requirements.txt            # Dependencies
└── src/mac_assess/
    ├── __init__.py
    ├── llm.py                  # LLM provider configuration
    ├── state.py                # AgentState and AssessmentPlan models
    ├── tools.py                # Security assessment tools
    ├── agent.py                # LangGraph agent definition
    └── cli.py                  # Command-line interface
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
