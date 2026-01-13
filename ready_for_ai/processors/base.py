"""Base document processor interface."""

from abc import ABC, abstractmethod
from typing import List, Optional, Callable, Tuple
from dataclasses import dataclass

from ..detectors.pii_detector import PIIDetector
from ..detectors.patterns import PIIMatch
from ..storage.mapping_store import MappingStore


@dataclass
class ProcessingResult:
    """Result of document processing."""
    input_path: str
    output_path: str
    total_redactions: int
    redactions_by_type: dict
    uncertain_count: int
    mapping_file: Optional[str] = None
    redacted_text: Optional[str] = None  # For text-based processors


class BaseProcessor(ABC):
    """
    Abstract base class for document processors.

    All processors must implement extract_text, redact, and restore methods.
    """

    SUPPORTED_EXTENSIONS: List[str] = []

    def __init__(
        self,
        detector: PIIDetector,
        mapping_store: MappingStore,
        interactive: bool = True,
        user_callback: Optional[Callable[[PIIMatch], Optional[bool]]] = None,
    ):
        """
        Initialize processor.

        Args:
            detector: PII detector instance
            mapping_store: Mapping store for tracking replacements
            interactive: Whether to prompt for uncertain detections
            user_callback: Callback for uncertain detections.
                          Returns True (is PII), False (not PII), or None (skip)
        """
        self.detector = detector
        self.mapping_store = mapping_store
        self.interactive = interactive
        self.user_callback = user_callback

    @classmethod
    def supports(cls, extension: str) -> bool:
        """Check if this processor supports the given file extension."""
        return extension.lower() in cls.SUPPORTED_EXTENSIONS

    @abstractmethod
    def extract_text(self, input_path: str) -> str:
        """
        Extract all text from a document.

        Args:
            input_path: Path to the document

        Returns:
            Extracted text content
        """
        pass

    @abstractmethod
    def process(
        self,
        input_path: str,
        output_path: Optional[str] = None,
    ) -> ProcessingResult:
        """
        Process a document, redacting PII.

        Args:
            input_path: Path to input file
            output_path: Path for output file

        Returns:
            ProcessingResult with statistics
        """
        pass

    def process_text(self, text: str) -> Tuple[str, dict]:
        """
        Process text, replacing PII with placeholders.

        Args:
            text: Input text

        Returns:
            Tuple of (processed_text, stats_dict)
        """
        stats = {'redacted': 0, 'uncertain': 0, 'by_type': {}}

        if not text.strip():
            return text, stats

        # Detect PII
        result = self.detector.detect(text)

        # Collect matches to redact
        matches_to_redact: List[PIIMatch] = list(result.matches)

        # Handle uncertain detections
        for match in result.uncertain:
            if self.interactive and self.user_callback:
                decision = self.user_callback(match)
                if decision is True:
                    matches_to_redact.append(match)
                    self.detector.learn_pii(match.text, match.pii_type)
                elif decision is False:
                    self.detector.learn_safe(match.text)
            stats['uncertain'] += 1

        if not matches_to_redact:
            return text, stats

        # Sort by position (reverse for replacement)
        matches_to_redact.sort(key=lambda m: m.start, reverse=True)

        # Apply replacements
        processed_text = text
        for match in matches_to_redact:
            placeholder = self.mapping_store.add_mapping(
                match.text,
                match.pii_type.value
            )
            processed_text = (
                processed_text[:match.start] +
                placeholder +
                processed_text[match.end:]
            )

            stats['redacted'] += 1
            pii_type = match.pii_type.value
            stats['by_type'][pii_type] = stats['by_type'].get(pii_type, 0) + 1

        return processed_text, stats


class BaseRestorer(ABC):
    """Abstract base class for document restorers."""

    def __init__(self, mapping_store: MappingStore):
        """
        Initialize restorer.

        Args:
            mapping_store: Mapping store with placeholder->original mappings
        """
        self.mapping_store = mapping_store

    @abstractmethod
    def restore(
        self,
        input_path: str,
        output_path: Optional[str] = None,
    ) -> Tuple[str, int]:
        """
        Restore a redacted document.

        Args:
            input_path: Path to redacted file
            output_path: Path for restored file

        Returns:
            Tuple of (output_path, restoration_count)
        """
        pass

    def restore_text(self, text: str) -> Tuple[str, int]:
        """
        Restore placeholders in text.

        Args:
            text: Text containing placeholders

        Returns:
            Tuple of (restored_text, count)
        """
        restorations = self.mapping_store.get_all_restorations()
        if not restorations:
            return text, 0

        restored_text = text
        count = 0

        for placeholder, original in restorations.items():
            if placeholder in restored_text:
                occurrences = restored_text.count(placeholder)
                restored_text = restored_text.replace(placeholder, original)
                count += occurrences

        return restored_text, count
