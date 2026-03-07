"""LangGraph agent for macOS security assessment.

Architecture
------------
planner     → Creates a human-readable assessment plan (LLM, temperature=0).
tool_runner → Runs EVERY security tool deterministically (no LLM involvement).
reporter    → Analyses all tool outputs and writes the findings report (LLM, temperature=0).

The tool_runner is intentionally non-LLM so that the same tools always run in
the same order, making findings reproducible across multiple runs on the same system.
"""

from __future__ import annotations

from langchain_core.messages import HumanMessage, SystemMessage
from langgraph.graph import StateGraph, END

from .state import AgentState, AssessmentPlan
from .tools import get_all_tools
from .llm import create_llm


# All tools, indexed by name. run_shell_command is a generic escape hatch
# excluded from the deterministic scan to keep outputs consistent.
_ALL_TOOLS = get_all_tools()
_TOOL_MAP: dict[str, object] = {
    t.name: t for t in _ALL_TOOLS if t.name != "run_shell_command"
}

# Per-tool output cap sent to the reporter LLM.
# Full output is preserved in state["findings"] and audit.ndjson.
_REPORTER_OUTPUT_MAX = 2500


# =============================================================================
# Prompts
# =============================================================================

_SYSTEM_PROMPT = """You are a security assessment agent analysing a macOS endpoint.
Your goal is to identify potential security risks and answer:
- If this endpoint was compromised, what would be the impact?
- Where could an attacker pivot to?
- What data could be stolen?
- What credentials could be taken?
"""

_PLANNER_PROMPT = """Based on the user's objective, create a security assessment plan.

Respond in this exact format:
OBJECTIVE: <one line summary>
STEPS:
1. <first area to assess>
2. <second area to assess>
...

List the security areas you intend to cover (5-10 items). Be specific.
"""

_REPORTER_PROMPT = """\
The following are the complete outputs of {n_tools} security assessment tools
run on this macOS system. Analyse them and produce a structured findings report.

Use EXACTLY these section headings in this order — no extras, no omissions:

## Executive Summary
2-3 sentences: overall risk level and the single most critical issue found.

## Critical Findings
Each entry: what was found | where (path/tool) | security impact.
Only include findings with concrete evidence from the tool outputs.

## Credential Exposure
Every credential, key, token, or secret discovered. Type and location for each.
If none found, write "(none identified)".

## Pivot Opportunities
Concrete lateral-movement paths an attacker with access to this machine could use.
Base each entry on specific tool evidence (SSH keys, VPN configs, mounts, etc.).
If none found, write "(none identified)".

## Data at Risk
Specific sensitive data categories and their locations on disk.
If none found, write "(none identified)".

## Recommendations
Numbered list, most critical first. Each item must reference a specific finding above.

Ground rules:
- Report only what the tools actually found. Do not speculate.
- Be specific: include file paths, usernames, service names from the output.
- If a section has nothing to report, write "(none identified)" — do not omit the section.
"""


# =============================================================================
# Nodes
# =============================================================================

def planner_node(state: AgentState) -> AgentState:
    """Create an assessment plan from the user objective."""
    llm = create_llm()
    messages = [
        SystemMessage(content=_SYSTEM_PROMPT + "\n\n" + _PLANNER_PROMPT),
        *state["messages"],
    ]
    response = llm.invoke(messages)
    content = response.content

    objective = ""
    steps: list[str] = []
    parsing_steps = False
    for line in content.strip().split("\n"):
        if line.startswith("OBJECTIVE:"):
            objective = line.replace("OBJECTIVE:", "").strip()
        elif line.startswith("STEPS:"):
            parsing_steps = True
        elif parsing_steps and line.strip():
            step = line.strip()
            if step[0].isdigit():
                step = step.split(".", 1)[-1].strip()
            elif step.startswith("-"):
                step = step[1:].strip()
            if step:
                steps.append(step)

    plan = AssessmentPlan(objective=objective or "Security assessment", steps=steps)
    return {
        **state,
        "plan": plan,
        "phase": "executing",
        "messages": state["messages"] + [response],
    }


def tool_runner_node(state: AgentState) -> AgentState:
    """Run every security assessment tool and collect outputs.

    Tools are called in a fixed order (sorted by name) so that audit logs
    are comparable across runs. No LLM is involved here.
    """
    findings: list[dict] = []
    for name in sorted(_TOOL_MAP):
        tool_obj = _TOOL_MAP[name]
        try:
            output = str(tool_obj.invoke({}))
        except Exception as exc:
            output = f"ERROR: {exc}"
        findings.append({"tool": name, "output": output})

    return {**state, "phase": "executing", "findings": findings}


def reporter_node(state: AgentState) -> AgentState:
    """Generate the structured findings report from all tool outputs."""
    llm = create_llm()
    findings = state.get("findings", [])

    # Build the tool-output block, truncating each to keep the prompt manageable
    tool_sections: list[str] = []
    for f in findings:
        out = f["output"]
        if len(out) > _REPORTER_OUTPUT_MAX:
            out = (
                out[:_REPORTER_OUTPUT_MAX]
                + f"\n... [{len(f['output']) - _REPORTER_OUTPUT_MAX} chars truncated]"
            )
        tool_sections.append(f"### {f['tool']}\n{out}")

    tool_block = "\n\n".join(tool_sections)
    prompt = _REPORTER_PROMPT.format(n_tools=len(findings))

    messages = [
        SystemMessage(content=_SYSTEM_PROMPT),
        *state["messages"],
        HumanMessage(content=f"Tool outputs:\n\n{tool_block}"),
        HumanMessage(content=prompt),
    ]

    response = llm.invoke(messages)
    return {
        **state,
        "phase": "complete",
        "messages": state["messages"] + [response],
    }


# =============================================================================
# Graph
# =============================================================================

def create_agent_graph() -> StateGraph:
    graph = StateGraph(AgentState)
    graph.add_node("planner",     planner_node)
    graph.add_node("tool_runner", tool_runner_node)
    graph.add_node("reporter",    reporter_node)

    graph.set_entry_point("planner")
    graph.add_edge("planner",     "tool_runner")
    graph.add_edge("tool_runner", "reporter")
    graph.add_edge("reporter",    END)

    return graph.compile()


def create_agent():
    """Create and return the compiled agent."""
    return create_agent_graph()
