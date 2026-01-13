"""Persistent storage for learned PII patterns."""

import json
import os
from typing import Dict, Set, Optional
from datetime import datetime


class LearningStore:
    """
    Stores and manages learned PII patterns.

    This persists user feedback about what is/isn't PII so the detector
    improves over time without repeatedly asking about the same values.
    """

    def __init__(self, filepath: Optional[str] = None):
        """
        Initialize learning store.

        Args:
            filepath: Path to persist learned patterns. If None, uses
                     ~/.ready_for_ai/learned_patterns.json
        """
        if filepath is None:
            config_dir = os.path.expanduser("~/.ready_for_ai")
            os.makedirs(config_dir, exist_ok=True)
            filepath = os.path.join(config_dir, "learned_patterns.json")

        self.filepath = filepath
        self.learned_pii: Dict[str, Set[str]] = {}  # pii_type -> set of values
        self.learned_safe: Set[str] = set()  # Values confirmed as NOT PII
        self.custom_patterns: Dict[str, str] = {}  # name -> regex pattern
        self.metadata: Dict = {}

        self._load()

    def _load(self):
        """Load learned patterns from disk."""
        if not os.path.exists(self.filepath):
            return

        try:
            with open(self.filepath, 'r') as f:
                data = json.load(f)

            self.learned_pii = {
                k: set(v) for k, v in data.get('pii', {}).items()
            }
            self.learned_safe = set(data.get('safe', []))
            self.custom_patterns = data.get('custom_patterns', {})
            self.metadata = data.get('metadata', {})

        except (json.JSONDecodeError, IOError) as e:
            print(f"Warning: Could not load learned patterns: {e}")

    def _save(self):
        """Save learned patterns to disk."""
        data = {
            'version': 1,
            'pii': {k: list(v) for k, v in self.learned_pii.items()},
            'safe': list(self.learned_safe),
            'custom_patterns': self.custom_patterns,
            'metadata': {
                **self.metadata,
                'last_updated': datetime.utcnow().isoformat(),
            }
        }

        try:
            with open(self.filepath, 'w') as f:
                json.dump(data, f, indent=2)
        except IOError as e:
            print(f"Warning: Could not save learned patterns: {e}")

    def learn_pii(self, value: str, pii_type: str):
        """
        Learn that a value is PII of a certain type.

        Args:
            value: The PII value
            pii_type: Type of PII (e.g., 'email', 'person_name')
        """
        if pii_type not in self.learned_pii:
            self.learned_pii[pii_type] = set()

        self.learned_pii[pii_type].add(value)

        # Remove from safe list if present
        self.learned_safe.discard(value.lower())

        self._save()

    def learn_safe(self, value: str):
        """
        Learn that a value is NOT PII.

        Args:
            value: The value confirmed as not being PII
        """
        self.learned_safe.add(value.lower())

        # Remove from PII lists if present
        for values in self.learned_pii.values():
            values.discard(value)
            values.discard(value.lower())

        self._save()

    def add_custom_pattern(self, name: str, pattern: str, pii_type: str):
        """
        Add a custom regex pattern for detection.

        Args:
            name: Unique name for this pattern
            pattern: Regex pattern
            pii_type: Type of PII this pattern detects
        """
        self.custom_patterns[name] = {
            'pattern': pattern,
            'pii_type': pii_type,
            'created_at': datetime.utcnow().isoformat(),
        }
        self._save()

    def remove_custom_pattern(self, name: str):
        """Remove a custom pattern."""
        if name in self.custom_patterns:
            del self.custom_patterns[name]
            self._save()

    def is_known_pii(self, value: str) -> Optional[str]:
        """
        Check if a value is known PII.

        Returns:
            PII type if known, None otherwise
        """
        for pii_type, values in self.learned_pii.items():
            if value in values or value.lower() in values:
                return pii_type
        return None

    def is_known_safe(self, value: str) -> bool:
        """Check if a value is known to be safe (not PII)."""
        return value.lower() in self.learned_safe

    def get_learned_data(self) -> Dict:
        """
        Get learned data for use by PIIDetector.

        Returns:
            Dict with 'pii' and 'safe' keys
        """
        return {
            'pii': {k: list(v) for k, v in self.learned_pii.items()},
            'safe': list(self.learned_safe),
        }

    def get_custom_patterns(self) -> Dict:
        """Get all custom patterns."""
        return self.custom_patterns.copy()

    def stats(self) -> Dict:
        """Get statistics about learned patterns."""
        pii_count = sum(len(v) for v in self.learned_pii.values())
        return {
            'total_pii_values': pii_count,
            'total_safe_values': len(self.learned_safe),
            'custom_patterns': len(self.custom_patterns),
            'pii_by_type': {k: len(v) for k, v in self.learned_pii.items()},
        }

    def clear(self):
        """Clear all learned patterns."""
        self.learned_pii.clear()
        self.learned_safe.clear()
        self.custom_patterns.clear()
        self._save()

    def export_to_file(self, filepath: str):
        """Export learned patterns to a different file."""
        data = {
            'version': 1,
            'pii': {k: list(v) for k, v in self.learned_pii.items()},
            'safe': list(self.learned_safe),
            'custom_patterns': self.custom_patterns,
            'metadata': {
                'exported_at': datetime.utcnow().isoformat(),
            }
        }
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)

    def import_from_file(self, filepath: str, merge: bool = True):
        """
        Import learned patterns from a file.

        Args:
            filepath: Path to import from
            merge: If True, merge with existing patterns. If False, replace.
        """
        with open(filepath, 'r') as f:
            data = json.load(f)

        if not merge:
            self.learned_pii.clear()
            self.learned_safe.clear()
            self.custom_patterns.clear()

        # Import PII patterns
        for pii_type, values in data.get('pii', {}).items():
            if pii_type not in self.learned_pii:
                self.learned_pii[pii_type] = set()
            self.learned_pii[pii_type].update(values)

        # Import safe values
        self.learned_safe.update(data.get('safe', []))

        # Import custom patterns
        self.custom_patterns.update(data.get('custom_patterns', {}))

        self._save()
