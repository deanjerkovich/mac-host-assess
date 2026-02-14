"""LangGraph agent for macOS security assessment."""

from __future__ import annotations

from typing import Literal

from langchain_core.messages import HumanMessage, SystemMessage
from langgraph.graph import StateGraph, END
from langgraph.prebuilt import ToolNode

from .state import AgentState, AssessmentPlan
from .tools import ALL_TOOLS
from .llm import create_llm


# =============================================================================
# System Prompts
# =============================================================================

SYSTEM_PROMPT = """You are a security assessment agent analyzing a macOS endpoint.
Your goal is to identify potential security risks and answer:
- If this endpoint was compromised, what would be the impact?
- Where could an attacker pivot to?
- What data could be stolen?
- What credentials could be taken?

You operate in phases:
1. PLANNING: Create a structured assessment plan based on the objective
2. EXECUTING: Execute your plan using available tools
3. REPORTING: Summarize findings and their security implications

Be thorough but efficient. Focus on high-impact findings.
Always explain the security implications of what you discover.
"""

PLANNER_PROMPT = """Based on the user's objective, create a security assessment plan.

You must respond with a structured plan in this exact format:
OBJECTIVE: <one line summary of what we're assessing>
STEPS:
1. <first step>
2. <second step>
...

Keep steps concrete and actionable. Focus on the most impactful checks first.
Typically 5-10 steps is appropriate for a focused assessment.
"""


# =============================================================================
# Agent Nodes
# =============================================================================

def planner_node(state: AgentState) -> AgentState:
    """Create an assessment plan based on the objective."""
    llm = create_llm()

    messages = [
        SystemMessage(content=SYSTEM_PROMPT + "\n\n" + PLANNER_PROMPT),
        *state["messages"],
    ]

    response = llm.invoke(messages)
    content = response.content

    # Parse the plan from the response
    lines = content.strip().split("\n")
    objective = ""
    steps = []

    parsing_steps = False
    for line in lines:
        if line.startswith("OBJECTIVE:"):
            objective = line.replace("OBJECTIVE:", "").strip()
        elif line.startswith("STEPS:"):
            parsing_steps = True
        elif parsing_steps and line.strip():
            # Remove numbering like "1. " or "- "
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


def executor_node(state: AgentState) -> AgentState:
    """Execute the current step in the plan using tools."""
    llm = create_llm()
    llm_with_tools = llm.bind_tools(ALL_TOOLS)

    plan = state["plan"]
    current_step = plan.next_step() if plan else "Perform a general security assessment"

    step_prompt = f"""Current assessment step: {current_step}

Execute this step using the available tools. Be thorough and note any security-relevant findings.
When done with this step, summarize what you found before moving on."""

    messages = [
        SystemMessage(content=SYSTEM_PROMPT),
        *state["messages"],
        HumanMessage(content=step_prompt),
    ]

    response = llm_with_tools.invoke(messages)

    return {
        **state,
        "messages": state["messages"] + [HumanMessage(content=step_prompt), response],
    }


def reporter_node(state: AgentState) -> AgentState:
    """Generate a final assessment report."""
    llm = create_llm()

    report_prompt = """Based on all the findings from this assessment, generate a security report.

Structure your report as:
1. EXECUTIVE SUMMARY - Key risks in 2-3 sentences
2. CRITICAL FINDINGS - High-impact issues requiring immediate attention
3. CREDENTIAL EXPOSURE - Any credentials, keys, or secrets found
4. PIVOT OPPORTUNITIES - Where an attacker could move laterally
5. DATA AT RISK - Sensitive data that could be exfiltrated
6. RECOMMENDATIONS - Prioritized remediation steps

Be specific and actionable."""

    messages = [
        SystemMessage(content=SYSTEM_PROMPT),
        *state["messages"],
        HumanMessage(content=report_prompt),
    ]

    response = llm.invoke(messages)

    return {
        **state,
        "phase": "complete",
        "messages": state["messages"] + [HumanMessage(content=report_prompt), response],
    }


def should_continue(state: AgentState) -> Literal["tools", "advance", "report", "executor"]:
    """Determine the next step based on state."""
    messages = state["messages"]
    last_message = messages[-1]

    # If the last message has tool calls, execute them
    if hasattr(last_message, "tool_calls") and last_message.tool_calls:
        return "tools"

    # Check if plan is complete
    plan = state.get("plan")
    if plan and plan.is_complete():
        return "report"

    # If we just finished tools, continue executing
    if state["phase"] == "executing":
        return "advance"

    return "executor"


def advance_plan(state: AgentState) -> AgentState:
    """Advance to the next step in the plan."""
    plan = state["plan"]
    if plan:
        plan.advance()
    return {**state, "plan": plan}


# =============================================================================
# Graph Construction
# =============================================================================

def create_agent_graph() -> StateGraph:
    """Create the assessment agent graph."""
    # Create tool node
    tool_node = ToolNode(ALL_TOOLS)

    # Build the graph
    graph = StateGraph(AgentState)

    # Add nodes
    graph.add_node("planner", planner_node)
    graph.add_node("executor", executor_node)
    graph.add_node("tools", tool_node)
    graph.add_node("advance", advance_plan)
    graph.add_node("reporter", reporter_node)

    # Set entry point
    graph.set_entry_point("planner")

    # Add edges from planner
    graph.add_edge("planner", "executor")

    # Add conditional edges from executor
    graph.add_conditional_edges(
        "executor",
        should_continue,
        {
            "tools": "tools",
            "advance": "advance",
            "report": "reporter",
            "executor": "executor",
        },
    )

    # Tools return to executor
    graph.add_edge("tools", "executor")

    # Advance goes back to executor
    graph.add_edge("advance", "executor")

    # Reporter ends the graph
    graph.add_edge("reporter", END)

    return graph.compile()


def create_agent():
    """Create and return the compiled agent."""
    return create_agent_graph()
