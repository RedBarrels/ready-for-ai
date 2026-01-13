"""Factory for creating document processors based on file type."""

import os
from typing import Optional, Callable, Type, Tuple

from .base import BaseProcessor, BaseRestorer
from .docx_processor import DocxProcessor, DocxRestorer
from .pdf_processor import PdfProcessor, PdfRestorer
from .text_processor import TextProcessor, TextRestorer
from .xlsx_processor import XlsxProcessor, XlsxRestorer
from .pptx_processor import PptxProcessor, PptxRestorer

from ..detectors.pii_detector import PIIDetector
from ..detectors.patterns import PIIMatch
from ..storage.mapping_store import MappingStore


# Map extensions to processor classes
PROCESSOR_MAP = {
    '.docx': (DocxProcessor, DocxRestorer),
    '.pdf': (PdfProcessor, PdfRestorer),
    '.txt': (TextProcessor, TextRestorer),
    '.text': (TextProcessor, TextRestorer),
    '.md': (TextProcessor, TextRestorer),
    '.markdown': (TextProcessor, TextRestorer),
    '.xlsx': (XlsxProcessor, XlsxRestorer),
    '.xlsm': (XlsxProcessor, XlsxRestorer),
    '.pptx': (PptxProcessor, PptxRestorer),
}

SUPPORTED_EXTENSIONS = list(PROCESSOR_MAP.keys())


def get_supported_extensions() -> list:
    """Get list of all supported file extensions."""
    return SUPPORTED_EXTENSIONS.copy()


def is_supported(filepath: str) -> bool:
    """Check if a file type is supported."""
    ext = os.path.splitext(filepath)[1].lower()
    return ext in PROCESSOR_MAP


def get_processor(
    filepath: str,
    detector: PIIDetector,
    mapping_store: MappingStore,
    interactive: bool = True,
    user_callback: Optional[Callable[[PIIMatch], Optional[bool]]] = None,
) -> BaseProcessor:
    """
    Get the appropriate processor for a file.

    Args:
        filepath: Path to the file (used to determine extension)
        detector: PII detector instance
        mapping_store: Mapping store for tracking replacements
        interactive: Whether to prompt for uncertain detections
        user_callback: Callback for uncertain detections

    Returns:
        Appropriate processor instance

    Raises:
        ValueError: If file type is not supported
    """
    ext = os.path.splitext(filepath)[1].lower()

    if ext not in PROCESSOR_MAP:
        raise ValueError(
            f"Unsupported file type: {ext}. "
            f"Supported: {', '.join(SUPPORTED_EXTENSIONS)}"
        )

    processor_class, _ = PROCESSOR_MAP[ext]

    return processor_class(
        detector=detector,
        mapping_store=mapping_store,
        interactive=interactive,
        user_callback=user_callback,
    )


def get_restorer(
    filepath: str,
    mapping_store: MappingStore,
) -> BaseRestorer:
    """
    Get the appropriate restorer for a file.

    Args:
        filepath: Path to the file (used to determine extension)
        mapping_store: Mapping store with placeholder->original mappings

    Returns:
        Appropriate restorer instance

    Raises:
        ValueError: If file type is not supported
    """
    ext = os.path.splitext(filepath)[1].lower()

    if ext not in PROCESSOR_MAP:
        raise ValueError(
            f"Unsupported file type: {ext}. "
            f"Supported: {', '.join(SUPPORTED_EXTENSIONS)}"
        )

    _, restorer_class = PROCESSOR_MAP[ext]

    return restorer_class(mapping_store=mapping_store)


def get_processor_and_restorer(
    filepath: str,
    detector: PIIDetector,
    mapping_store: MappingStore,
    interactive: bool = True,
    user_callback: Optional[Callable[[PIIMatch], Optional[bool]]] = None,
) -> Tuple[BaseProcessor, BaseRestorer]:
    """
    Get both processor and restorer for a file.

    Args:
        filepath: Path to the file
        detector: PII detector instance
        mapping_store: Mapping store
        interactive: Whether to prompt for uncertain detections
        user_callback: Callback for uncertain detections

    Returns:
        Tuple of (processor, restorer)
    """
    ext = os.path.splitext(filepath)[1].lower()

    if ext not in PROCESSOR_MAP:
        raise ValueError(
            f"Unsupported file type: {ext}. "
            f"Supported: {', '.join(SUPPORTED_EXTENSIONS)}"
        )

    processor_class, restorer_class = PROCESSOR_MAP[ext]

    processor = processor_class(
        detector=detector,
        mapping_store=mapping_store,
        interactive=interactive,
        user_callback=user_callback,
    )

    restorer = restorer_class(mapping_store=mapping_store)

    return processor, restorer
