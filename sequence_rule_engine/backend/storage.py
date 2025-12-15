from abc import ABC, abstractmethod
from typing import List, Optional
import os
import yaml  # type: ignore
from .models import Rule


class RuleStorage(ABC):
    @abstractmethod
    def list_rules(self) -> List[Rule]:
        pass

    @abstractmethod
    def create_rule(self, rule: Rule) -> Rule:
        pass

    @abstractmethod
    def get_rule(self, rule_id: str) -> Optional[Rule]:
        pass

    @abstractmethod
    def update_rule(self, rule_id: str, rule: Rule) -> Optional[Rule]:
        pass

    @abstractmethod
    def delete_rule(self, rule_id: str) -> bool:
        pass


class FileStorage(RuleStorage):
    def __init__(self, rules_dir: str):
        self.rules_dir = rules_dir
        os.makedirs(self.rules_dir, exist_ok=True)

    def _get_file_path(self, rule_id: str) -> str:
        return os.path.join(self.rules_dir, f"{rule_id}.yaml")

    def list_rules(self) -> List[Rule]:
        rules = []
        for filename in os.listdir(self.rules_dir):
            if filename.endswith(".yaml"):
                file_path = os.path.join(self.rules_dir, filename)
                try:
                    with open(file_path, "r") as f:
                        data = yaml.safe_load(f)
                        rules.append(Rule(**data))
                except Exception as e:
                    print(f"Error loading rule from {filename}: {e}")
        return rules

    def create_rule(self, rule: Rule) -> Rule:
        file_path = self._get_file_path(rule.id)
        if os.path.exists(file_path):
            raise ValueError(f"Rule with id {rule.id} already exists")

        with open(file_path, "w") as f:
            yaml.dump(rule.dict(by_alias=True), f)
        return rule

    def get_rule(self, rule_id: str) -> Optional[Rule]:
        file_path = self._get_file_path(rule_id)
        if not os.path.exists(file_path):
            return None

        try:
            with open(file_path, "r") as f:
                data = yaml.safe_load(f)
                return Rule(**data)
        except Exception as e:
            print(f"Error loading rule {rule_id}: {e}")
            return None

    def update_rule(self, rule_id: str, rule: Rule) -> Optional[Rule]:
        file_path = self._get_file_path(rule_id)
        if not os.path.exists(file_path):
            return None

        # If ID changes, we might need to handle file rename, but for now assuming ID in body matches path or we overwrite based on ID in path?
        # The prompt says PUT /rules/{id}.
        # Usually PUT replaces the resource.
        # If rule.id != rule_id, we have a mismatch.

        if rule.id != rule_id:
            # If we want to allow ID change, we would rename the file.
            # But let's enforce that ID in payload matches path for simplicity, or just use the payload ID.
            # If we overwrite, we might be creating a new file if we use rule.id for filename.

            # Let's clean up the old file if the ID changed
            self.delete_rule(rule_id)
            return self.create_rule(rule)

        with open(file_path, "w") as f:
            yaml.dump(rule.dict(by_alias=True), f)
        return rule

    def delete_rule(self, rule_id: str) -> bool:
        file_path = self._get_file_path(rule_id)
        if os.path.exists(file_path):
            os.remove(file_path)
            return True
        return False


class SQLiteStorage(RuleStorage):
    def __init__(self, db_path: str):
        # Placeholder for SQLite implementation
        pass

    def list_rules(self) -> List[Rule]:
        return []

    def create_rule(self, rule: Rule) -> Rule:
        return rule

    def get_rule(self, rule_id: str) -> Optional[Rule]:
        return None

    def update_rule(self, rule_id: str, rule: Rule) -> Optional[Rule]:
        return None

    def delete_rule(self, rule_id: str) -> bool:
        return False
