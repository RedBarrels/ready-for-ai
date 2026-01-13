# Ready for AI

A Python tool for preparing documents for AI processing by redacting PII (Personally Identifiable Information) with encrypted, reversible mappings.

## The Problem

You want to use AI to analyze documents, but they contain sensitive information:
- Employee names, emails, phone numbers
- Client/company names
- Project names, internal Slack channels
- SSNs, credit cards, addresses

## The Solution

1. **Redact** your document → PII replaced with placeholders (John Doe, Example Corp)
2. **Send to AI** → AI works with safe placeholder data
3. **Restore AI's response** → Placeholders converted back to real values

Your sensitive data never leaves your machine!

## Supported Formats

- **Word** (.docx)
- **PDF** (.pdf) - Note: restored PDFs are text-only, original formatting is not preserved
- **Excel** (.xlsx, .xlsm)
- **PowerPoint** (.pptx)
- **Text/Markdown** (.txt, .md, .markdown)

## Installation

```bash
pip install -e .

# Download spaCy model (recommended for better name detection)
python -m spacy download en_core_web_sm
```

## Quick Start

### CLI Workflow

```bash
# Step 1: Redact document (creates redacted doc + encrypted mappings)
ready-for-ai redact document.docx --redact-all -p
# Enter password to encrypt mappings

# Step 2: Send redacted document to AI, get response
# AI sees: "Contact John Doe at person1@example.com about Example Corp"

# Step 3: Restore AI's response text
echo "Contact John Doe at person1@example.com" | ready-for-ai restore-text document_mappings.json -p
# Output: "Contact Jane Smith at jane.smith@acme.com"

# Or from file:
ready-for-ai restore-text document_mappings.json -p -i ai_response.txt -o restored_response.txt
```

### Web UI

```bash
# Launch browser-based interface (no password required, session-based)
ready-for-ai web
# Opens at http://localhost:5000
```

## Commands

### `redact` - Redact PII from documents

```bash
# Redact all detected PII (names, emails, companies, etc.)
ready-for-ai redact document.docx --redact-all -p

# Interactive mode - asks about uncertain detections (default)
ready-for-ai redact document.pdf -p

# Skip uncertain detections (only high-confidence matches)
ready-for-ai redact document.docx --no-interactive -p

# Faster processing (disable NLP-based detection)
ready-for-ai redact document.docx --redact-all --no-nlp -p

# Works with Excel and PowerPoint too
ready-for-ai redact spreadsheet.xlsx --redact-all -p
ready-for-ai redact presentation.pptx --redact-all -p
```

**Flags:**
- `-p, --password` - Prompt for password to encrypt mappings
- `--redact-all` - Auto-approve all detections without prompting
- `--no-interactive` - Skip uncertain detections entirely
- `--no-nlp` - Disable spaCy NLP for faster processing

### `restore-text` - Restore placeholders in any text

```bash
# From stdin (pipe AI response)
echo "John Doe works at Example Corp" | ready-for-ai restore-text mappings.json -p

# From file
ready-for-ai restore-text mappings.json -p -i ai_response.txt

# To file
ready-for-ai restore-text mappings.json -p -i ai_response.txt -o restored.txt
```

### `restore` - Restore a redacted document file

```bash
ready-for-ai restore document_redacted.docx document_mappings.json -p

# Delete mapping file after restoration
ready-for-ai restore document_redacted.docx document_mappings.json -p --delete-mapping
```

### `scan` - Preview what would be detected

```bash
ready-for-ai scan document.docx
```

### `web` - Launch web interface

```bash
ready-for-ai web
# Opens browser-based UI at http://localhost:5000
```

The web UI allows you to:
- Upload files or paste text directly
- Redact and download redacted documents
- Restore placeholder text using session mappings
- No password required (uses session-based encryption)

### Learning & Patterns

```bash
# View learned patterns statistics
ready-for-ai learn-stats

# Add custom regex pattern
ready-for-ai add-pattern "internal-id" "INT-\d{6}" -t project_name

# Export/import learned patterns
ready-for-ai learn-manage --export patterns.json
ready-for-ai learn-manage --import-file patterns.json

# Clear all learned patterns
ready-for-ai learn-manage --clear
```

## PII Types Detected

| Type | Example | Placeholder |
|------|---------|-------------|
| Person Name | John Smith | John Doe, Jane Smith, etc. |
| Email | john@company.com | person1@example.com |
| Phone | 555-123-4567 | 555-000-0001 |
| Company Name | Acme Inc | Example Corp, Sample LLC |
| Project Name | Project Phoenix | Project Alpha, etc. |
| Team Name | Engineering Team | Team Alpha, etc. |
| Slack Handle | @johnsmith | @user1 |
| Address | 123 Main St, NYC | [ADDRESS-1] |
| SSN | 123-45-6789 | XXX-XX-0001 |
| Credit Card | 4111-1111-1111-1111 | XXXX-XXXX-XXXX-0001 |
| IP Address | 192.168.1.1 | 192.0.2.1 |
| URL | https://internal.com/api | https://example.com/page1 |
| Date of Birth | 01/15/1990 | [DATE-1] |
| Custom | (user-defined) | [REDACTED-1] |

## How It Works

### Detection (Multi-Layer)

Detection combines multiple approaches with confidence scoring:

1. **Learned PII** - Previously confirmed patterns (highest priority)
2. **Regex Patterns** - Structured data (emails, phones, SSNs, credit cards, IPs, URLs)
3. **Custom Patterns** - User-defined regex via `add-pattern` command
4. **spaCy NLP** - Named Entity Recognition for names, organizations, locations
5. **Name Lists** - Common first/last name pattern matching

Matches with confidence >= 0.75 are auto-redacted. Lower confidence matches prompt for user confirmation in interactive mode.

### Consistent Mapping

Same PII always maps to same placeholder throughout the document:
- "John Smith" → "John Doe" everywhere
- Allows AI to understand relationships between entities

### Encrypted Storage

Mappings are protected with:
- **PBKDF2** key derivation (480,000 iterations) from your password
- **AES encryption** (Fernet) for original values
- **bcrypt hashing** for verification

### Learning System

The tool learns from your feedback:
- Confirmed PII patterns are remembered for future runs
- Safe (non-PII) values are excluded from future detections
- Patterns stored in `~/.ready_for_ai/learned_patterns.json`
- Export/import patterns across machines

## Security Notes

- **Password**: Choose a strong password - it encrypts all mappings
- **Mapping File**: Keep secure - needed to restore original values
- **Delete After Use**: Use `--delete-mapping` flag when done
- **PDF Limitation**: Restored PDFs are recreated as text-only documents; original formatting, images, and layout are not preserved

## Python API

```python
from ready_for_ai.detectors import PIIDetector
from ready_for_ai.storage import MappingStore
from ready_for_ai.processors import get_processor, get_supported_extensions

# Check supported formats
print(get_supported_extensions())  # ['.docx', '.pdf', '.xlsx', '.xlsm', '.pptx', '.txt', '.md', ...]

# Initialize
detector = PIIDetector(use_nlp=True)
mapping_store = MappingStore(password="your-secure-password")

# Redact document (works with any supported format)
processor = get_processor("input.docx", detector=detector, mapping_store=mapping_store)
result = processor.process("input.docx", "output_redacted.docx")

# Save mappings
mapping_store.save_to_file("mappings.json")

# Later: restore text
mapping_store = MappingStore.load_from_file("mappings.json", "your-secure-password")
restorations = mapping_store.get_all_restorations()

ai_response = "Contact John Doe at person1@example.com"
for placeholder, original in restorations.items():
    ai_response = ai_response.replace(placeholder, original)
print(ai_response)  # "Contact Jane Smith at jane.smith@acme.com"
```

## License

MIT
