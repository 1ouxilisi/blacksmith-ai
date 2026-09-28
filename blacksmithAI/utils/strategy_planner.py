"""
Strategy Planner - AI-powered strategy planning for penetration testing.
Automatically decides the next best action based on current progress and findings.
"""
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from enum import Enum
from agents.base import init_model
from langchain_core.messages import HumanMessage, SystemMessage
from utils.audit_logger import audit_logger


class ActionType(Enum):
    RECON = "recon"
    SCAN = "scan"
    ENUMERATE = "enumerate"
    EXPLOIT = "exploit"
    POST_EXPLOIT = "post_exploit"
    REPORT = "report"
    WAIT = "wait"


@dataclass
class PlannedAction:
    """A planned next action."""
    action_type: ActionType
    description: str
    target: str
    priority: int  # 1-10
    reason: str
    estimated_duration: str = "unknown"


class StrategyPlanner:
    """AI-powered penetration testing strategy planner."""

    SYSTEM_PROMPT = """You are a senior penetration tester planning the next steps of an engagement.
Based on the current progress and findings, decide the most effective next action.

Consider:
1. What information have we gathered so far?
2. What are the most promising attack surfaces?
3. What should we prioritize next?
4. What's the most efficient path to maximum impact?

Be strategic, not just reactive. Think like a red team operator.

Output your plan as JSON:
{
    "next_action": "recon|scan|enumerate|exploit|post_exploit|report",
    "target": "specific target or scope",
    "priority": 1-10,
    "reason": "why this is the best next step",
    "estimated_duration": "e.g. 5 minutes, 30 minutes",
    "alternative_actions": ["other actions to consider"]
}"""

    def __init__(self):
        self.llm = init_model().get_model()
        self.history: List[PlannedAction] = []

    def plan_next_action(
        self,
        target: str,
        current_progress: str,
        findings: List[Dict[str, Any]],
    ) -> PlannedAction:
        """Plan the next best action."""

        findings_summary = "\n".join([
            f"- {f.get('title', 'Unknown')} ({f.get('severity', 'unknown')})"
            for f in findings[:10]
        ])

        user_prompt = f"""Target: {target}

Current Progress:
{current_progress}

Findings So Far:
{findings_summary if findings_summary else "No findings yet"}

What should we do next?"""

        try:
            response = self.llm.invoke([
                SystemMessage(content=self.SYSTEM_PROMPT),
                HumanMessage(content=user_prompt),
            ])

            content = response.content if hasattr(response, 'content') else str(response)

            import json
            import re
            json_match = re.search(r'\{[^}]+\}', content, re.DOTALL)

            if json_match:
                data = json.loads(json_match.group())
                action = PlannedAction(
                    action_type=ActionType(data.get("next_action", "scan")),
                    description=data.get("reason", ""),
                    target=data.get("target", target),
                    priority=int(data.get("priority", 5)),
                    reason=data.get("reason", ""),
                    estimated_duration=data.get("estimated_duration", "unknown"),
                )
            else:
                action = PlannedAction(
                    action_type=ActionType.SCAN,
                    description="Continue scanning",
                    target=target,
                    priority=5,
                    reason=content[:200],
                )

        except Exception as e:
            action = PlannedAction(
                action_type=ActionType.SCAN,
                description=f"Planning error: {e}",
                target=target,
                priority=5,
                reason="Fallback to default scanning",
            )

        self.history.append(action)
        audit_logger.log_decision(
            agent="StrategyPlanner",
            decision=f"Next action: {action.action_type.value} on {action.target}",
            rationale=action.reason,
        )

        return action

    def generate_full_plan(self, target: str, scope: str = "") -> List[PlannedAction]:
        """Generate a full engagement plan."""
        prompt = f"""Create a penetration testing plan for: {target}
Scope: {scope if scope else "full assessment"}

Output a step-by-step plan as a JSON array:
[
    {{
        "step": 1,
        "action": "recon",
        "description": "what to do",
        "priority": 10
    }}
]"""

        try:
            response = self.llm.invoke([
                SystemMessage(content="You are a penetration testing planning expert."),
                HumanMessage(content=prompt),
            ])
            content = response.content if hasattr(response, 'content') else str(response)
            return [PlannedAction(
                action_type=ActionType.SCAN,
                description=content[:500],
                target=target,
                priority=5,
                reason="Full plan generated",
            )]
        except Exception as e:
            return []


# Global instance
strategy_planner = StrategyPlanner()
