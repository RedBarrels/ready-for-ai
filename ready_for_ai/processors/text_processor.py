"""Plain text and markdown document processor for PII redaction."""

import os
from typing import Optional, Callable, Tuple

from .base import BaseProcessor, BaseRestorer, ProcessingResult
from ..detectors.pii_detector import PIIDetector
from ..detectors.patterns import PIIMatch
from ..storage.mapping_store import MappingStore


class TextProcessor(BaseProcessor):
    """
    Process plain text and markdown files to redact PII.

    Supports: .txt, .md, .markdown, .text
    """

    SUPPORTED_EXTENSIONS = ['.txt', '.md', '.markdown', '.text']

    def __init__(
        self,
        detector: PIIDetector,
        mapping_store: MappingStore,
        interactive: bool = True,
        user_callback: Optional[Callable[[PIIMatch], Optional[bool]]] = None,
    ):
        super().__init__(detector, mapping_store, interactive, user_callback)

    def extract_text(self, input_path: str) -> str:
        """Extract text from a plain text file."""
        with open(input_path, 'r', encoding='utf-8') as f:
            return f.read()

    def process(
        self,
        input_path: str,
        output_path: Optional[str] = None,
    ) -> ProcessingResult:
        """
        Process a text file, redacting PII.

        Args:
            input_path: Path to input text file
            output_path: Path for output file. If None, creates <input>_redacted.<ext>

        Returns:
            ProcessingResult with statistics
        """
        if output_path is None:
            base, ext = os.path.splitext(input_path)
            output_path = f"{base}_redacted{ext}"

        # Read file
        text = self.extract_text(input_path)

        # Process text
        redacted_text, stats = self.process_text(text)

        # Write output
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(redacted_text)

        return ProcessingResult(
            input_path=input_path,
            output_path=output_path,
            total_redactions=stats['redacted'],
            redactions_by_type=stats['by_type'],
            uncertain_count=stats['uncertain'],
            redacted_text=redacted_text,
        )

    def process_string(self, text: str) -> Tuple[str, dict]:
        """
        Process a string directly (for web UI).

        Args:
            text: Input text

        Returns:
            Tuple of (redacted_text, stats)
        """
        return self.process_text(text)


class TextRestorer(BaseRestorer):
    """Restore redacted text files using mapping store."""

    def __init__(self, mapping_store: MappingStore):
        super().__init__(mapping_store)

    def restore(
        self,
        input_path: str,
        output_path: Optional[str] = None,
    ) -> Tuple[str, int]:
        """
        Restore a redacted text file.

        Args:
            input_path: Path to redacted text file
            output_path: Path for restored file

        Returns:
            Tuple of (output_path, restoration_count)
        """
        if output_path is None:
            base, ext = os.path.splitext(input_path)
            if base.endswith('_redacted'):
                base = base[:-9]
            output_path = f"{base}_restored{ext}"

        # Read file
        with open(input_path, 'r', encoding='utf-8') as f:
            text = f.read()

        # Restore text
        restored_text, count = self.restore_text(text)

        # Write output
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(restored_text)

        return output_path, count

    def restore_string(self, text: str) -> Tuple[str, int]:
        """
        Restore placeholders in a string directly (for web UI).

        Args:
            text: Text containing placeholders

        Returns:
            Tuple of (restored_text, count)
        """
        return self.restore_text(text)
