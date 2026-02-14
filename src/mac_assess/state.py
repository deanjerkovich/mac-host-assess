"""Agent state definitions."""

from __future__ import annotations

from typing import Annotated, TypedDict, Optional
from langgraph.graph.message import add_messages
from pydantic import BaseModel


class AssessmentPlan(BaseModel):
    """A structured plan for the security assessment."""

    objective: str
    steps: list[str]
    current_step: int = 0
    findings: list[str] = []

    def next_step(self) -> Optional[str]:
        """Get the next step to execute."""
        if self.current_step < len(self.steps):
            return self.steps[self.current_step]
        return None

    def advance(self) -> None:
        """Move to the next step."""
        self.current_step += 1

    def is_complete(self) -> bool:
        """Check if all steps are done."""
        return self.current_step >= len(self.steps)


class AgentState(TypedDict):
    """State maintained throughout the agent's execution."""

    # Conversation messages (accumulates via add_messages reducer)
    messages: Annotated[list, add_messages]

    # The current assessment plan
    plan: Optional[AssessmentPlan]

    # Collected findings from tool executions
    findings: list[dict]

    # Current phase: "planning" | "executing" | "reporting"
    phase: str
