"""Document processors for various file formats."""

from .base import BaseProcessor, BaseRestorer, ProcessingResult
from .docx_processor import DocxProcessor, DocxRestorer
from .pdf_processor import PdfProcessor, PdfRestorer
from .text_processor import TextProcessor, TextRestorer
from .xlsx_processor import XlsxProcessor, XlsxRestorer
from .pptx_processor import PptxProcessor, PptxRestorer
from .factory import (
    get_processor,
    get_restorer,
    get_processor_and_restorer,
    get_supported_extensions,
    is_supported,
    SUPPORTED_EXTENSIONS,
)

__all__ = [
    # Base classes
    "BaseProcessor",
    "BaseRestorer",
    "ProcessingResult",
    # Processors
    "DocxProcessor",
    "PdfProcessor",
    "TextProcessor",
    "XlsxProcessor",
    "PptxProcessor",
    # Restorers
    "DocxRestorer",
    "PdfRestorer",
    "TextRestorer",
    "XlsxRestorer",
    "PptxRestorer",
    # Factory functions
    "get_processor",
    "get_restorer",
    "get_processor_and_restorer",
    "get_supported_extensions",
    "is_supported",
    "SUPPORTED_EXTENSIONS",
]
