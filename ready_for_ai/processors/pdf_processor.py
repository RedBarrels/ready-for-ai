"""PDF document processor for PII redaction."""

import os
from typing import List, Tuple, Optional, Callable
from dataclasses import dataclass
import io

import pdfplumber
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib.units import inch
from PyPDF2 import PdfReader, PdfWriter

from ..detectors.pii_detector import PIIDetector, DetectionResult
from ..detectors.patterns import PIIMatch, PIIType
from ..storage.mapping_store import MappingStore


@dataclass
class PDFProcessingResult:
    """Result of PDF processing."""
    input_path: str
    output_path: str
    total_redactions: int
    redactions_by_type: dict
    uncertain_count: int
    pages_processed: int
    mapping_file: Optional[str] = None


class PdfProcessor:
    """
    Process PDF files to redact PII.

    Note: PDF redaction is more complex than DOCX. This implementation
    extracts text, redacts it, and creates a new text-based PDF.
    For PDFs with complex layouts, images, or forms, the output
    may differ from the original formatting.
    """

    def __init__(
        self,
        detector: PIIDetector,
        mapping_store: MappingStore,
        interactive: bool = True,
        user_callback: Optional[Callable[[PIIMatch], Optional[bool]]] = None,
    ):
        """
        Initialize PDF processor.

        Args:
            detector: PII detector instance
            mapping_store: Mapping store for tracking replacements
            interactive: Whether to prompt for uncertain detections
            user_callback: Callback for uncertain detections
        """
        self.detector = detector
        self.mapping_store = mapping_store
        self.interactive = interactive
        self.user_callback = user_callback

    def process(
        self,
        input_path: str,
        output_path: Optional[str] = None,
    ) -> PDFProcessingResult:
        """
        Process a PDF file, redacting PII.

        Args:
            input_path: Path to input PDF file
            output_path: Path for output file. If None, creates <input>_redacted.pdf

        Returns:
            PDFProcessingResult with statistics
        """
        if output_path is None:
            base, ext = os.path.splitext(input_path)
            output_path = f"{base}_redacted{ext}"

        redaction_counts = {}
        total_redactions = 0
        uncertain_count = 0
        pages_processed = 0

        # Extract text and process
        all_pages_text = []

        with pdfplumber.open(input_path) as pdf:
            for page in pdf.pages:
                pages_processed += 1
                text = page.extract_text() or ""

                # Process this page's text
                processed_text, stats = self._process_text(text)
                all_pages_text.append(processed_text)

                total_redactions += stats['redacted']
                uncertain_count += stats['uncertain']
                for pii_type, count in stats['by_type'].items():
                    redaction_counts[pii_type] = redaction_counts.get(pii_type, 0) + count

        # Create new PDF with redacted text
        self._create_redacted_pdf(all_pages_text, output_path)

        return PDFProcessingResult(
            input_path=input_path,
            output_path=output_path,
            total_redactions=total_redactions,
            redactions_by_type=redaction_counts,
            uncertain_count=uncertain_count,
            pages_processed=pages_processed,
        )

    def _process_text(self, text: str) -> Tuple[str, dict]:
        """
        Process text, replacing PII with placeholders.

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

    def _create_redacted_pdf(self, pages_text: List[str], output_path: str):
        """
        Create a new PDF with redacted text.

        This creates a simple text PDF. For more complex layouts,
        consider using a more sophisticated PDF library.
        """
        c = canvas.Canvas(output_path, pagesize=letter)
        width, height = letter

        for page_text in pages_text:
            if not page_text.strip():
                c.showPage()
                continue

            # Write text to page
            text_object = c.beginText(0.75 * inch, height - 0.75 * inch)
            text_object.setFont("Helvetica", 10)

            # Split into lines and write
            lines = page_text.split('\n')
            for line in lines:
                # Handle long lines by wrapping
                max_width = width - 1.5 * inch
                words = line.split()
                current_line = ""

                for word in words:
                    test_line = f"{current_line} {word}".strip()
                    if c.stringWidth(test_line, "Helvetica", 10) < max_width:
                        current_line = test_line
                    else:
                        if current_line:
                            text_object.textLine(current_line)
                        current_line = word

                if current_line:
                    text_object.textLine(current_line)

                # Check if we need a new page
                if text_object.getY() < 0.75 * inch:
                    c.drawText(text_object)
                    c.showPage()
                    text_object = c.beginText(0.75 * inch, height - 0.75 * inch)
                    text_object.setFont("Helvetica", 10)

            c.drawText(text_object)
            c.showPage()

        c.save()

    def extract_text(self, input_path: str) -> str:
        """
        Extract all text from a PDF file.

        Useful for inspection or alternative processing.
        """
        all_text = []
        with pdfplumber.open(input_path) as pdf:
            for page in pdf.pages:
                text = page.extract_text() or ""
                all_text.append(text)
        return "\n\n--- Page Break ---\n\n".join(all_text)


class PdfRestorer:
    """Restore redacted PDF files using mapping store."""

    def __init__(self, mapping_store: MappingStore):
        """
        Initialize restorer.

        Args:
            mapping_store: Mapping store with placeholder->original mappings
        """
        self.mapping_store = mapping_store

    def restore(
        self,
        input_path: str,
        output_path: Optional[str] = None,
    ) -> Tuple[str, int]:
        """
        Restore a redacted PDF file.

        Args:
            input_path: Path to redacted PDF file
            output_path: Path for restored file

        Returns:
            Tuple of (output_path, restoration_count)
        """
        if output_path is None:
            base, ext = os.path.splitext(input_path)
            if base.endswith('_redacted'):
                base = base[:-9]
            output_path = f"{base}_restored{ext}"

        # Get all restorations
        restorations = self.mapping_store.get_all_restorations()
        if not restorations:
            raise ValueError("No mappings available for restoration")

        # Extract text, restore, and create new PDF
        all_pages_text = []
        restoration_count = 0

        with pdfplumber.open(input_path) as pdf:
            for page in pdf.pages:
                text = page.extract_text() or ""

                # Apply restorations
                for placeholder, original in restorations.items():
                    if placeholder in text:
                        count = text.count(placeholder)
                        text = text.replace(placeholder, original)
                        restoration_count += count

                all_pages_text.append(text)

        # Create restored PDF
        self._create_pdf(all_pages_text, output_path)

        return output_path, restoration_count

    def _create_pdf(self, pages_text: List[str], output_path: str):
        """Create PDF from text pages."""
        c = canvas.Canvas(output_path, pagesize=letter)
        width, height = letter

        for page_text in pages_text:
            if not page_text.strip():
                c.showPage()
                continue

            text_object = c.beginText(0.75 * inch, height - 0.75 * inch)
            text_object.setFont("Helvetica", 10)

            lines = page_text.split('\n')
            for line in lines:
                max_width = width - 1.5 * inch
                words = line.split()
                current_line = ""

                for word in words:
                    test_line = f"{current_line} {word}".strip()
                    if c.stringWidth(test_line, "Helvetica", 10) < max_width:
                        current_line = test_line
                    else:
                        if current_line:
                            text_object.textLine(current_line)
                        current_line = word

                if current_line:
                    text_object.textLine(current_line)

                if text_object.getY() < 0.75 * inch:
                    c.drawText(text_object)
                    c.showPage()
                    text_object = c.beginText(0.75 * inch, height - 0.75 * inch)
                    text_object.setFont("Helvetica", 10)

            c.drawText(text_object)
            c.showPage()

        c.save()
