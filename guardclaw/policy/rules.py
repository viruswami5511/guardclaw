"""
Policy rule definitions and evaluation logic.

ALIGNED TO: Canonical schema v1.1
"""

from dataclasses import dataclass
from enum import Enum
from typing import Any, Optional

from guardclaw.core.models import DecisionType


class ConditionOperator(Enum):
    """Operators for rule conditions"""
    EQUALS = "equals"
    NOT_EQUALS = "not_equals"
    CONTAINS = "contains"
    NOT_CONTAINS = "not_contains"
    IN = "in"
    NOT_IN = "not_in"
    GREATER_THAN = "greater_than"
    LESS_THAN = "less_than"
    REGEX_MATCH = "regex_match"


@dataclass
class RuleCondition:
    """A single condition that must be satisfied"""
    field: str
    operator: ConditionOperator
    value: Any
    
    def evaluate(self, context: dict) -> bool:
        """Evaluate this condition against context"""
        # Get field value from context (supports nested access like "context.size")
        field_value = self._get_field_value(context, self.field)
        
        if field_value is None:
            return False
        
        # Evaluate based on operator
        if self.operator == ConditionOperator.EQUALS:
            return field_value == self.value
        elif self.operator == ConditionOperator.NOT_EQUALS:
            return field_value != self.value
        elif self.operator == ConditionOperator.CONTAINS:
            return self.value in str(field_value)
        elif self.operator == ConditionOperator.NOT_CONTAINS:
            return self.value not in str(field_value)
        elif self.operator == ConditionOperator.IN:
            return field_value in self.value
        elif self.operator == ConditionOperator.NOT_IN:
            return field_value not in self.value
        elif self.operator == ConditionOperator.GREATER_THAN:
            return float(field_value) > float(self.value)
        elif self.operator == ConditionOperator.LESS_THAN:
            return float(field_value) < float(self.value)
        elif self.operator == ConditionOperator.REGEX_MATCH:
            import re
            return bool(re.match(self.value, str(field_value)))
        else:
            return False
    
    def _get_field_value(self, context: dict, field_path: str) -> Optional[Any]:
        """Get field value from context, supporting nested paths"""
        parts = field_path.split('.')
        value = context
        
        for part in parts:
            if isinstance(value, dict) and part in value:
                value = value[part]
            else:
                return None
        
        return value
    
    @staticmethod
    def from_dict(data: dict) -> "RuleCondition":
        """Create condition from dictionary"""
        return RuleCondition(
            field=data["field"],
            operator=ConditionOperator(data["operator"]),
            value=data["value"],
        )


@dataclass
class RuleAction:
    """Action to take when rule matches"""
    decision: DecisionType
    reason: str


@dataclass
class Rule:
    """A policy rule with conditions and action"""
    rule_id: str
    description: str
    conditions: list[RuleCondition]
    action: RuleAction
    priority: int = 0
    enabled: bool = True
    
    def matches(self, context: dict) -> bool:
        """
        Check if this rule matches the given context.
        
        ALL conditions must be satisfied (AND logic).
        """
        if not self.conditions:
            return True  # No conditions = always match
        
        return all(condition.evaluate(context) for condition in self.conditions)
    
    @staticmethod
    def from_dict(data: dict) -> "Rule":
        """Create rule from dictionary"""
        conditions = [
            RuleCondition.from_dict(c) for c in data.get("conditions", [])
        ]
        
        action_data = data["action"]
        action = RuleAction(
            decision=DecisionType(action_data["decision"]),
            reason=action_data["reason"],
        )
        
        return Rule(
            rule_id=data["rule_id"],
            description=data.get("description", ""),
            conditions=conditions,
            action=action,
            priority=data.get("priority", 0),
            enabled=data.get("enabled", True),
        )
