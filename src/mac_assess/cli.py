"""Command-line interface for the macOS security assessment agent."""

from __future__ import annotations

import argparse
import sys

from langchain_core.messages import HumanMessage
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.table import Table

from .agent import create_agent
from .state import AgentState
from . import llm


console = Console()


def print_message(role: str, content: str) -> None:
    """Pretty-print a message."""
    if role == "human":
        console.print(Panel(content, title="[blue]User[/blue]", border_style="blue"))
    elif role == "ai":
        # Render as markdown for better formatting
        md = Markdown(content)
        console.print(Panel(md, title="[green]Agent[/green]", border_style="green"))
    elif role == "tool":
        console.print(Panel(content[:500] + "..." if len(content) > 500 else content,
                           title="[yellow]Tool Result[/yellow]", border_style="yellow"))


def list_providers() -> None:
    """Display available LLM providers."""
    table = Table(title="Available LLM Providers")
    table.add_column("Provider", style="cyan")
    table.add_column("Description", style="white")
    table.add_column("Environment Variable", style="yellow")
    table.add_column("Default Model", style="green")

    for provider in llm.list_providers():
        table.add_row(
            provider["name"],
            provider["description"],
            provider["env_var"],
            provider["default_model"],
        )

    console.print(table)
    console.print("\n[dim]Install providers with: pip install mac-assess[provider][/dim]")
    console.print("[dim]Install all providers: pip install mac-assess[all][/dim]")


def run_assessment(objective: str, verbose: bool = False) -> None:
    """Run a security assessment with the given objective."""
    config = llm.get_config()

    console.print(f"\n[bold]Starting macOS Security Assessment[/bold]")
    console.print(f"Provider: [cyan]{config.provider.value}[/cyan] | Model: [cyan]{config.get_default_model()}[/cyan]")
    console.print(f"Objective: {objective}\n")

    try:
        agent = create_agent()
    except ValueError as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)

    initial_state: AgentState = {
        "messages": [HumanMessage(content=objective)],
        "plan": None,
        "findings": [],
        "phase": "planning",
    }

    console.print("[dim]Planning assessment...[/dim]\n")

    try:
        # Stream the agent execution
        for event in agent.stream(initial_state):
            for node_name, node_state in event.items():
                if verbose:
                    console.print(f"[dim]Node: {node_name}[/dim]")

                if "messages" in node_state:
                    for msg in node_state["messages"]:
                        msg_type = msg.__class__.__name__.replace("Message", "").lower()

                        if hasattr(msg, "content") and msg.content:
                            if msg_type == "ai":
                                print_message("ai", msg.content)
                            elif verbose and msg_type == "tool":
                                print_message("tool", msg.content)

                        # Show tool calls
                        if hasattr(msg, "tool_calls") and msg.tool_calls:
                            for tool_call in msg.tool_calls:
                                console.print(f"[cyan]Calling tool:[/cyan] {tool_call['name']}")
                                if verbose:
                                    console.print(f"  Args: {tool_call['args']}")

        console.print("\n[bold green]Assessment Complete[/bold green]\n")

    except Exception as e:
        console.print(f"\n[red]Error during assessment:[/red] {e}")
        sys.exit(1)


def interactive_mode(verbose: bool = False) -> None:
    """Run in interactive mode, allowing multiple assessments."""
    config = llm.get_config()

    console.print("[bold]macOS Security Assessment Agent[/bold]")
    console.print(f"Provider: [cyan]{config.provider.value}[/cyan] | Model: [cyan]{config.get_default_model()}[/cyan]")
    console.print("Enter an assessment objective, or 'quit' to exit.\n")

    while True:
        try:
            objective = console.input("[blue]Objective:[/blue] ").strip()
            if objective.lower() in ("quit", "exit", "q"):
                break
            if not objective:
                continue
            run_assessment(objective, verbose=verbose)
        except KeyboardInterrupt:
            console.print("\n[yellow]Interrupted[/yellow]")
            break

    console.print("Goodbye!")


def main() -> None:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="macOS Security Assessment Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s "What credentials are accessible on this system?"
  %(prog)s --provider openai "Assess lateral movement opportunities"
  %(prog)s --provider google --model gemini-2.5-pro-preview-05-06 "Find sensitive files"
  %(prog)s --interactive
  %(prog)s --list-providers

Environment Variables:
  ANTHROPIC_API_KEY     API key for Anthropic Claude
  OPENAI_API_KEY        API key for OpenAI
  GOOGLE_API_KEY        API key for Google AI Studio
  GOOGLE_CLOUD_PROJECT  GCP project for Vertex AI
        """,
    )

    parser.add_argument(
        "objective",
        nargs="?",
        help="The assessment objective (what to investigate)",
    )

    parser.add_argument(
        "-p", "--provider",
        choices=["anthropic", "openai", "google", "vertex"],
        default="anthropic",
        help="LLM provider to use (default: anthropic)",
    )

    parser.add_argument(
        "-m", "--model",
        help="Specific model to use (uses provider default if not specified)",
    )

    parser.add_argument(
        "--api-key",
        help="API key (overrides environment variable)",
    )

    parser.add_argument(
        "--project",
        help="GCP project ID (for Vertex AI provider)",
    )

    parser.add_argument(
        "-i", "--interactive",
        action="store_true",
        help="Run in interactive mode",
    )

    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show detailed output including tool results",
    )

    parser.add_argument(
        "--list-providers",
        action="store_true",
        help="List available LLM providers and exit",
    )

    args = parser.parse_args()

    # Handle --list-providers
    if args.list_providers:
        list_providers()
        sys.exit(0)

    # Configure LLM provider
    try:
        llm.configure(
            provider=args.provider,
            model=args.model,
            api_key=args.api_key,
            project_id=args.project,
        )
    except ValueError as e:
        console.print(f"[red]Configuration error:[/red] {e}")
        sys.exit(1)

    # Run assessment
    if args.interactive:
        interactive_mode(verbose=args.verbose)
    elif args.objective:
        run_assessment(args.objective, verbose=args.verbose)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
