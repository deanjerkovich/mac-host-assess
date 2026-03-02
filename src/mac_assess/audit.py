"""Audit logging for security assessments.

Writes every LLM request/response and tool call to an NDJSON file
so that nothing is lost and reports can be regenerated without re-running
an assessment.
"""

from __future__ import annotations

import datetime
import json
from pathlib import Path
from typing import Any, Dict, List, Union

from langchain_core.callbacks import BaseCallbackHandler
from langchain_core.outputs import ChatGeneration, LLMResult


class AuditLog:
    """Appends structured audit events to an NDJSON file."""

    def __init__(self, path: Path) -> None:
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        self._file = open(path, "w", encoding="utf-8")
        self._start = datetime.datetime.utcnow()

    def write(self, event_type: str, data: dict) -> None:
        """Append one event to the log."""
        event = {
            "ts": datetime.datetime.utcnow().isoformat() + "Z",
            "type": event_type,
            "data": data,
        }
        self._file.write(json.dumps(event, default=str) + "\n")
        self._file.flush()

    @property
    def elapsed_seconds(self) -> float:
        return (datetime.datetime.utcnow() - self._start).total_seconds()

    def close(self) -> None:
        self._file.close()


def _serialize_message(msg: Any) -> dict:
    """Flatten a LangChain message to a plain dict."""
    role = msg.__class__.__name__.replace("Message", "").lower()
    d: dict = {"role": role}
    if hasattr(msg, "content") and msg.content:
        d["content"] = msg.content
    if hasattr(msg, "tool_calls") and msg.tool_calls:
        d["tool_calls"] = [
            {"name": tc["name"], "args": tc.get("args", {}), "id": tc.get("id")}
            for tc in msg.tool_calls
        ]
    if hasattr(msg, "name") and msg.name:
        d["name"] = msg.name
    if hasattr(msg, "tool_call_id") and msg.tool_call_id:
        d["tool_call_id"] = msg.tool_call_id
    return d


class AuditCallbackHandler(BaseCallbackHandler):
    """LangChain callback handler that logs all LLM and tool events."""

    raise_error = False  # don't let logging errors crash the assessment

    def __init__(self, log: AuditLog) -> None:
        super().__init__()
        self._log = log

    def on_chat_model_start(
        self,
        serialized: Dict[str, Any],
        messages: List[List[Any]],
        **kwargs: Any,
    ) -> None:
        model = (
            serialized.get("kwargs", {}).get("model")
            or serialized.get("kwargs", {}).get("model_name")
            or serialized.get("name", "unknown")
        )
        self._log.write("llm_request", {
            "model": model,
            "messages": [
                _serialize_message(msg)
                for batch in messages
                for msg in batch
            ],
        })

    def on_llm_end(self, response: LLMResult, **kwargs: Any) -> None:
        generations = []
        for gen_list in response.generations:
            for gen in gen_list:
                if isinstance(gen, ChatGeneration):
                    generations.append(_serialize_message(gen.message))
                else:
                    generations.append({"role": "ai", "content": gen.text})

        usage: dict = {}
        if response.llm_output:
            usage = (
                response.llm_output.get("usage")
                or response.llm_output.get("token_usage")
                or {}
            )

        self._log.write("llm_response", {
            "generations": generations,
            "usage": usage,
        })

    def on_tool_start(
        self,
        serialized: Dict[str, Any],
        input_str: str,
        **kwargs: Any,
    ) -> None:
        self._log.write("tool_call", {
            "name": serialized.get("name", "unknown"),
            "input": input_str,
        })

    def on_tool_end(self, output: Any, **kwargs: Any) -> None:
        self._log.write("tool_result", {"output": str(output)})

    def on_tool_error(
        self, error: Union[Exception, KeyboardInterrupt], **kwargs: Any
    ) -> None:
        self._log.write("tool_error", {"error": str(error)})
