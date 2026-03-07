"""
guardclaw/adapters/crewai.py

CrewAI adapter for GuardClaw.

Install:
    pip install guardclaw[crewai]

Usage:
    from guardclaw.adapters.crewai import GuardClawCrewAdapter

    adapter = GuardClawCrewAdapter(agent_id="my-crew")

    crew = Crew(
        agents=[...],
        tasks=[...],
        step_callback=adapter.record_step,
        task_callback=adapter.record_task,
    )
"""

import sys
import uuid

# Optional dependency check
try:
    import crewai  # noqa: F401
except ImportError:
    raise ImportError(
        "CrewAI is required for this adapter.\n"
        "Install with: pip install crewai"
    )

from guardclaw.api import record_action


MAX_PAYLOAD = 1000


def _truncate(value) -> str:
    """Convert any value to string and truncate."""
    return str(value)[:MAX_PAYLOAD]


def _safe_metadata(metadata: dict) -> dict:
    """Ensure metadata values are truncated strings."""
    return {k: _truncate(v) for k, v in metadata.items()}


class GuardClawCrewAdapter:
    """
    CrewAI adapter that records agent steps and task completions
    into the GuardClaw ledger as signed ExecutionEnvelope entries.
    """

    def __init__(self, agent_id: str):
        self.agent_id = agent_id
        self._run_id = str(uuid.uuid4())

    def _record(self, action: str, result: str, metadata: dict):
        """
        Send event to GuardClaw ledger.

        Never crashes the agent runtime.
        """
        try:
            safe = _safe_metadata(metadata)

            safe.update({
                "framework": "crewai",
                "adapter": "guardclaw",
                "run_id": self._run_id,
            })

            record_action(
                agent_id=self.agent_id,
                action=action,
                result=result,
                metadata=safe,
            )

        except Exception as e:
            print(f"[GuardClaw] adapter error: {e}", file=sys.stderr)

    # -------------------------
    # Agent step callback
    # -------------------------

    def record_step(self, step) -> None:
        """
        Records each agent step.

        Supports both:
        - AgentAction
        - AgentFinish
        """

        # AgentAction: tool invocation
        if hasattr(step, "tool"):
            self._record(
                action=_truncate(step.tool),
                result="STARTED",
                metadata={
                    "event": "step",
                    "action": _truncate(step.tool),
                    "observation": _truncate(getattr(step, "tool_input", "")),
                    "agent_role": _truncate(getattr(step, "agent_role", "")),
                    "task_description": _truncate(
                        getattr(step, "task_description", "")
                    ),
                },
            )

        # AgentFinish: step completed
        elif hasattr(step, "return_values"):

            if isinstance(step.return_values, dict):
                output = step.return_values.get("output", "")
            else:
                output = step.return_values

            self._record(
                action="agent_finish",
                result="SUCCESS",
                metadata={
                    "event": "step_finish",
                    "observation": _truncate(output),
                    "agent_role": _truncate(getattr(step, "agent_role", "")),
                    "task_description": _truncate(
                        getattr(step, "task_description", "")
                    ),
                },
            )

        # Unknown step type
        else:
            self._record(
                action="unknown_step",
                result="UNKNOWN",
                metadata={
                    "event": "step",
                    "observation": _truncate(step),
                },
            )

    # -------------------------
    # Task completion callback
    # -------------------------

    def record_task(self, task_output) -> None:
        """Records task completion."""

        if hasattr(task_output, "raw"):
            output = task_output.raw
        elif hasattr(task_output, "result"):
            output = task_output.result
        else:
            output = str(task_output)

        self._record(
            action="task_complete",
            result="SUCCESS",
            metadata={
                "event": "task_complete",
                "output": _truncate(output),
                "task_description": _truncate(
                    getattr(task_output, "description", "")
                ),
                "agent_role": _truncate(
                    getattr(task_output, "agent", "")
                ),
            },
        )

    # -------------------------
    # Error logging
    # -------------------------

    def record_error(self, error, agent_role: str = "") -> None:
        """Records tool or agent error."""

        self._record(
            action="agent_error",
            result="ERROR",
            metadata={
                "event": "tool_error",
                "error": _truncate(error),
                "agent_role": _truncate(agent_role),
            },
        )