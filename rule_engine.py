import logging
from datetime import datetime, timedelta
from typing import Tuple

from Entities import EmailRule, RuleCondition, RuleAction
from imap_client import EmailMessage, IMAPClient


class ConditionEvaluator:
    """Evaluates individual rule conditions against email messages."""

    def __init__(self, logger: logging.Logger):
        """
        Initialize condition evaluator.

        Args:
            logger: Logger instance
        """
        self.logger = logger

    def evaluate(self, email: EmailMessage, condition: RuleCondition) -> Tuple[bool, str]:
        """
        Evaluate a single condition against an email.

        Args:
            email: EmailMessage to evaluate
            condition: RuleCondition to check

        Returns:
            Tuple of (matched: bool, reason: str)
        """
        field_value = self._extract_field_value(email, condition)
        if field_value is None:
            return False, f"Field '{condition.field}' not found"

        try:
            matched = self._apply_operator(field_value, condition.operator, condition.value, email.date)
            reason = f"{condition.field} {condition.operator} '{condition.value}'"

            if matched:
                reason = f"Matched: {reason}"
            else:
                reason = f"Not matched: {reason}"

            self.logger.debug(f"Condition evaluation: {reason}")
            return matched, reason

        except Exception as e:
            self.logger.error(f"Error evaluating condition: {e}")
            return False, f"Error: {str(e)}"

    def _extract_field_value(self, email: EmailMessage, condition: RuleCondition) -> str:
        """Extract field value from email based on condition field."""
        field = condition.field.lower()

        if field == 'from':
            return email.sender
        elif field == 'subject':
            return email.subject
        elif field == 'body':
            return email.body_text if email.body_text else email.body_html
        elif field == 'to':
            return ', '.join(email.recipients)
        elif field == 'header':
            header_name = condition.value.split(':')[0] if ':' in condition.value else condition.value
            return email.headers.get(header_name, '')
        else:
            return None

    def _apply_operator(self, field_value: str, operator: str, compare_value: str, email_date: datetime) -> bool:
        """Apply operator to compare field value with expected value."""
        operator = operator.lower()

        if operator == 'contains':
            return compare_value.lower() in field_value.lower()

        elif operator == 'equals':
            return field_value.lower() == compare_value.lower()

        elif operator == 'not_equals':
            return field_value.lower() != compare_value.lower()

        elif operator == 'starts_with':
            return field_value.lower().startswith(compare_value.lower())

        elif operator == 'ends_with':
            return field_value.lower().endswith(compare_value.lower())

        elif operator == 'greater_than':
            try:
                return float(field_value) > float(compare_value)
            except ValueError:
                return False

        elif operator == 'less_than':
            try:
                return float(field_value) < float(compare_value)
            except ValueError:
                return False

        elif operator == 'greater_equal':
            try:
                return float(field_value) >= float(compare_value)
            except ValueError:
                return False

        elif operator == 'less_equal':
            try:
                return float(field_value) <= float(compare_value)
            except ValueError:
                return False

        elif operator == 'date_older_than':
            try:
                days = int(compare_value)
                age = datetime.now() - email_date
                return age.days > days
            except ValueError:
                return False

        else:
            self.logger.warning(f"Unknown operator: {operator}")
            return False


class RuleEngine:
    """Orchestrates rule evaluation and action execution."""

    def __init__(self, imap_client: IMAPClient, logger: logging.Logger):
        """
        Initialize rule engine.

        Args:
            imap_client: IMAPClient instance
            logger: Logger instance
        """
        self.imap = imap_client
        self.evaluator = ConditionEvaluator(logger)
        self.logger = logger

    def evaluate_rule(self, email: EmailMessage, rule: EmailRule, conditions: list[RuleCondition]) -> Tuple[bool, dict]:
        """
        Evaluate all conditions of a rule.

        Args:
            email: EmailMessage to evaluate
            rule: EmailRule to check
            conditions: List of RuleCondition objects

        Returns:
            Tuple of (matched: bool, details: dict)
        """
        if not conditions:
            self.logger.warning(f"Rule {rule.name} has no conditions")
            return False, {'logic': rule.condition, 'condition_results': [], 'overall_match': False}

        condition_results = []
        for condition in conditions:
            matched, reason = self.evaluator.evaluate(email, condition)
            condition_results.append({
                'field': condition.field,
                'operator': condition.operator,
                'value': condition.value,
                'matched': matched,
                'reason': reason
            })

        logic = rule.condition.upper()
        if logic == 'AND':
            overall_match = all(c['matched'] for c in condition_results)
        elif logic == 'OR':
            overall_match = any(c['matched'] for c in condition_results)
        else:
            self.logger.warning(f"Unknown logic: {logic}, defaulting to AND")
            overall_match = all(c['matched'] for c in condition_results)

        details = {
            'logic': logic,
            'condition_results': condition_results,
            'overall_match': overall_match
        }

        self.logger.info(f"Rule '{rule.name}' evaluation: {overall_match}")
        return overall_match, details

    def execute_actions(self, email: EmailMessage, actions: list[RuleAction], dry_run: bool = False) -> list[str]:
        """
        Execute all actions for a matched rule.

        Args:
            email: EmailMessage to act upon
            actions: List of RuleAction objects
            dry_run: If True, only simulate actions

        Returns:
            List of action descriptions
        """
        if not actions:
            return []

        action_logs = []

        sorted_actions = self._sort_actions(actions)

        for action in sorted_actions:
            try:
                description = self._execute_action(email, action, dry_run)
                action_logs.append(description)
                self.logger.info(f"{'[DRY-RUN] ' if dry_run else ''}Action: {description}")

            except Exception as e:
                error_msg = f"Failed to execute action {action.action_type}: {e}"
                self.logger.error(error_msg)
                action_logs.append(error_msg)

        return action_logs

    def _sort_actions(self, actions: list[RuleAction]) -> list[RuleAction]:
        """Sort actions by execution priority."""
        priority_order = {
            'mark_as_read': 1,
            'add_label': 2,
            'copy_to_folder': 3,
            'modify_subject': 4,
            'move_to_folder': 5,
            'delete': 6
        }

        return sorted(actions, key=lambda a: priority_order.get(a.action_type, 99))

    def _execute_action(self, email: EmailMessage, action: RuleAction, dry_run: bool) -> str:
        """Execute a single action."""
        action_type = action.action_type.lower()

        if action_type == 'move_to_folder':
            target_folder = action.folder or action.action_value
            if not dry_run:
                self.imap.move_to_folder(email.uid, target_folder)
            return f"move_to_folder: {target_folder}"

        elif action_type == 'copy_to_folder':
            target_folder = action.folder or action.action_value
            if not dry_run:
                self.imap.copy_to_folder(email.uid, target_folder)
            return f"copy_to_folder: {target_folder}"

        elif action_type == 'add_label':
            label_name = action.label or action.action_value
            if not dry_run:
                self.imap.add_flag(email.uid, label_name)
            return f"add_label: {label_name}"

        elif action_type == 'mark_as_read':
            if not dry_run:
                self.imap.mark_as_read(email.uid)
            return "mark_as_read"

        elif action_type == 'delete':
            if not dry_run:
                self.imap.delete_email(email.uid)
            return "delete"

        elif action_type == 'modify_subject':
            return f"modify_subject: {action.action_value} (not implemented)"

        else:
            self.logger.warning(f"Unknown action type: {action_type}")
            return f"unknown_action: {action_type}"
