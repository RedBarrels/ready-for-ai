"""Main PII detection engine combining patterns and NLP."""

import re
from typing import List, Dict, Set, Optional, Callable
from dataclasses import dataclass, field

from .patterns import (
    PatternMatcher,
    PIIMatch,
    PIIType,
    COMMON_FIRST_NAMES,
    COMMON_LAST_NAMES,
)


@dataclass
class DetectionResult:
    """Result of PII detection on a document."""
    matches: List[PIIMatch] = field(default_factory=list)
    uncertain: List[PIIMatch] = field(default_factory=list)  # Need user confirmation


class PIIDetector:
    """
    Main PII detection engine.
    Combines regex patterns, NLP (optional), and learned patterns.
    """

    # Confidence threshold for automatic detection vs asking user
    CONFIDENCE_THRESHOLD = 0.75

    def __init__(
        self,
        use_nlp: bool = True,
        learned_patterns: Optional[Dict[str, Set[str]]] = None,
        learned_safe: Optional[Set[str]] = None,
    ):
        """
        Initialize detector.

        Args:
            use_nlp: Whether to use spaCy NLP for entity detection
            learned_patterns: Dict mapping PII type to set of known PII values
            learned_safe: Set of values confirmed as NOT being PII
        """
        self.pattern_matcher = PatternMatcher()
        self.use_nlp = use_nlp
        self.nlp = None

        # Learned patterns from user feedback
        self.learned_pii: Dict[str, Set[str]] = learned_patterns or {}
        self.learned_safe: Set[str] = learned_safe or set()

        # Custom patterns added by user
        self.custom_patterns: List[tuple] = []  # (regex, pii_type, confidence)

        if use_nlp:
            self._init_nlp()

    def _init_nlp(self):
        """Initialize spaCy NLP model."""
        try:
            import spacy
            try:
                self.nlp = spacy.load("en_core_web_sm")
            except OSError:
                print("Downloading spaCy model...")
                from spacy.cli import download
                download("en_core_web_sm")
                self.nlp = spacy.load("en_core_web_sm")
        except ImportError:
            print("Warning: spaCy not installed. NLP detection disabled.")
            self.use_nlp = False

    def add_custom_pattern(
        self,
        pattern: str,
        pii_type: PIIType,
        confidence: float = 0.90
    ):
        """Add a custom regex pattern for detection."""
        self.custom_patterns.append((re.compile(pattern), pii_type, confidence))

    def detect(self, text: str) -> DetectionResult:
        """
        Detect PII in text.

        Returns DetectionResult with:
        - matches: High-confidence PII detections
        - uncertain: Lower-confidence detections needing user confirmation
        """
        result = DetectionResult()
        seen_spans: Set[tuple] = set()  # Track (start, end) to avoid duplicates

        # 1. Check learned PII patterns first (highest priority)
        for pii_type_str, values in self.learned_pii.items():
            pii_type = PIIType(pii_type_str) if pii_type_str in [t.value for t in PIIType] else PIIType.CUSTOM
            for value in values:
                for match in re.finditer(re.escape(value), text, re.IGNORECASE):
                    span = (match.start(), match.end())
                    if span not in seen_spans:
                        seen_spans.add(span)
                        result.matches.append(PIIMatch(
                            text=match.group(),
                            pii_type=pii_type,
                            start=match.start(),
                            end=match.end(),
                            confidence=1.0,  # User-confirmed
                            context=self.pattern_matcher._extract_context(
                                text, match.start(), match.end()
                            )
                        ))

        # 2. Apply regex patterns
        pattern_matches = self.pattern_matcher.find_pattern_matches(text)
        for match in pattern_matches:
            span = (match.start, match.end)
            if span in seen_spans:
                continue
            if match.text.lower() in self.learned_safe:
                continue

            seen_spans.add(span)
            if match.confidence >= self.CONFIDENCE_THRESHOLD:
                result.matches.append(match)
            else:
                result.uncertain.append(match)

        # 3. Apply custom patterns
        for regex, pii_type, confidence in self.custom_patterns:
            for match in regex.finditer(text):
                span = (match.start(), match.end())
                if span in seen_spans:
                    continue
                if match.group().lower() in self.learned_safe:
                    continue

                seen_spans.add(span)
                pii_match = PIIMatch(
                    text=match.group(),
                    pii_type=pii_type,
                    start=match.start(),
                    end=match.end(),
                    confidence=confidence,
                    context=self.pattern_matcher._extract_context(
                        text, match.start(), match.end()
                    )
                )
                if confidence >= self.CONFIDENCE_THRESHOLD:
                    result.matches.append(pii_match)
                else:
                    result.uncertain.append(pii_match)

        # 4. NLP-based detection
        if self.use_nlp and self.nlp:
            nlp_matches = self._detect_with_nlp(text, seen_spans)
            for match in nlp_matches:
                if match.text.lower() in self.learned_safe:
                    continue
                if match.confidence >= self.CONFIDENCE_THRESHOLD:
                    result.matches.append(match)
                else:
                    result.uncertain.append(match)

        # 5. Detect potential names using name lists
        name_matches = self._detect_names(text, seen_spans)
        for match in name_matches:
            if match.text.lower() in self.learned_safe:
                continue
            result.uncertain.append(match)

        # Remove overlapping matches (keep shorter/more specific ones)
        result.matches = self._remove_overlapping(result.matches)
        result.uncertain = self._remove_overlapping(result.uncertain)

        # Sort by position in text
        result.matches.sort(key=lambda m: m.start)
        result.uncertain.sort(key=lambda m: m.start)

        return result

    def _remove_overlapping(self, matches: List[PIIMatch]) -> List[PIIMatch]:
        """
        Remove overlapping matches, keeping non-overlapping ones.
        Prioritizes higher confidence and more specific PII types.
        Also deduplicates exact matches.
        """
        if not matches:
            return matches

        # Priority order for PII types (higher = more specific/important)
        type_priority = {
            PIIType.EMAIL: 10,
            PIIType.PHONE: 10,
            PIIType.SSN: 10,
            PIIType.CREDIT_CARD: 10,
            PIIType.IP_ADDRESS: 9,
            PIIType.URL: 9,
            PIIType.SLACK_HANDLE: 8,
            PIIType.PERSON_NAME: 7,
            PIIType.COMPANY_NAME: 6,
            PIIType.PROJECT_NAME: 5,
            PIIType.TEAM_NAME: 5,
            PIIType.ADDRESS: 4,
            PIIType.DATE_OF_BIRTH: 3,
            PIIType.CUSTOM: 2,
        }

        # Sort by: confidence (desc), type priority (desc), shorter length first
        sorted_matches = sorted(
            matches,
            key=lambda m: (-m.confidence, -type_priority.get(m.pii_type, 0), len(m.text))
        )

        result = []
        seen_texts = set()  # Track unique texts to avoid duplicates

        for match in sorted_matches:
            # Skip if we've already seen this exact text
            if match.text in seen_texts:
                continue

            # Check if this match overlaps with any already accepted match
            overlaps = False
            for accepted in result:
                # Check for overlap
                if not (match.end <= accepted.start or match.start >= accepted.end):
                    overlaps = True
                    break

            if not overlaps:
                result.append(match)
                seen_texts.add(match.text)

        return result

    def _detect_with_nlp(
        self,
        text: str,
        seen_spans: Set[tuple]
    ) -> List[PIIMatch]:
        """Use spaCy NER for entity detection."""
        matches = []
        doc = self.nlp(text)

        # Map spaCy entity types to our PII types
        entity_map = {
            'PERSON': (PIIType.PERSON_NAME, 0.90),
            'ORG': (PIIType.COMPANY_NAME, 0.85),
            'GPE': (PIIType.ADDRESS, 0.60),  # Geopolitical entity
            'LOC': (PIIType.ADDRESS, 0.60),
            'DATE': (PIIType.DATE_OF_BIRTH, 0.50),  # Low confidence, many dates aren't DOB
            'PRODUCT': (PIIType.PROJECT_NAME, 0.80),
            'WORK_OF_ART': (PIIType.PROJECT_NAME, 0.75),
        }

        # Words that are often misdetected by NLP
        false_positive_words = {
            # English
            'ip', 'ssn', 'api', 'url', 'email', 'phone', 'address', 'client',
            'contact', 'team', 'project', 'internal', 'slack', 'channel',
            'employee', 'corporate', 'card', 'best', 'regards', 'from', 'to',
            'cc', 'date', 'summary', 'executive', 'technical', 'details',
            'confidential', 'notes', 'information', 'members',
            # Ukrainian common words that might be misdetected
            'проект', 'команда', 'клієнт', 'контакт', 'адреса', 'телефон',
            'інформація', 'дата', 'деталі', 'учасники', 'працівник', 'відділ',
            'компанія', 'організація', 'договір', 'угода', 'документ', 'звіт',
            'замовник', 'виконавець', 'сторона', 'предмет', 'умови', 'стаття',
            'пункт', 'розділ', 'додаток', 'підпис', 'печатка', 'реквізити'
        }

        for ent in doc.ents:
            if ent.label_ not in entity_map:
                continue

            span = (ent.start_char, ent.end_char)
            if span in seen_spans:
                continue

            # Skip false positives - short generic words detected as ORG/PERSON
            ent_lower = ent.text.lower().strip()
            if ent_lower in false_positive_words:
                continue

            # Skip entities that contain technical patterns (IPs, etc)
            if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', ent.text):
                continue

            # Clean up entity text - NLP sometimes includes extra chars
            clean_text = ent.text.strip()

            # For PERSON entities, extract just the name part (stop at dash, newline, etc)
            if ent.label_ == 'PERSON':
                # Split on common separators and take first part
                # Supports both Latin and Cyrillic characters
                name_match = re.match(r'^([A-ZА-ЯҐЄІЇ][a-zа-яґєії\']+(?:\s+[A-ZА-ЯҐЄІЇ][a-zа-яґєії\']+)*)', clean_text)
                if name_match:
                    clean_text = name_match.group(1)
                # Skip if it's too long (likely a false positive)
                if len(clean_text.split()) > 3:
                    continue

            # For ORG, clean up multiline and filter bad detections
            if ent.label_ == 'ORG':
                # Take first line only
                clean_text = clean_text.split('\n')[0].strip()
                # Skip if starts with common document words
                if clean_text.lower().startswith(('project ', 'client ', 'internal ')):
                    # Try to extract company name after the keyword
                    parts = clean_text.split()
                    if len(parts) > 1:
                        potential_name = ' '.join(parts[1:])
                        # Only keep if it looks like a company name
                        if any(w in potential_name.lower() for w in ['inc', 'corp', 'llc', 'ltd', 'industries', 'tech', 'company']):
                            clean_text = potential_name
                        else:
                            continue
                    else:
                        continue

            # Skip if cleaned text is empty or too short
            if len(clean_text) < 2:
                continue

            pii_type, confidence = entity_map[ent.label_]

            # Recalculate span for cleaned text
            clean_start = text.find(clean_text, ent.start_char)
            if clean_start == -1:
                clean_start = ent.start_char
            clean_end = clean_start + len(clean_text)

            span = (clean_start, clean_end)
            if span in seen_spans:
                continue
            seen_spans.add(span)

            matches.append(PIIMatch(
                text=clean_text,
                pii_type=pii_type,
                start=clean_start,
                end=clean_end,
                confidence=confidence,
                context=self.pattern_matcher._extract_context(
                    text, clean_start, clean_end
                )
            ))

        return matches

    def _detect_names(
        self,
        text: str,
        seen_spans: Set[tuple]
    ) -> List[PIIMatch]:
        """Detect potential names using pattern matching."""
        matches = []

        # Pattern for two consecutive capitalized words (First Last name pattern)
        # This catches names regardless of whether they're in common name lists
        # Supports both Latin (A-Za-z) and Cyrillic (А-Яа-яґєіїҐЄІЇ) characters
        name_pattern = re.compile(r'\b([A-ZА-ЯҐЄІЇ][a-zа-яґєії\']+)\s+([A-ZА-ЯҐЄІЇ][a-zа-яґєії\']+)\b')

        for match in name_pattern.finditer(text):
            span = (match.start(), match.end())
            if span in seen_spans:
                continue

            first = match.group(1).lower()
            last = match.group(2).lower()

            # Check if matches known names for confidence scoring
            is_first_name = first in COMMON_FIRST_NAMES
            is_last_name = last in COMMON_LAST_NAMES

            # Higher confidence if matches common name lists
            if is_first_name and is_last_name:
                confidence = 0.70
            elif is_first_name or is_last_name:
                confidence = 0.60
            else:
                # Still detect as potential name, but lower confidence
                confidence = 0.50

            seen_spans.add(span)
            matches.append(PIIMatch(
                text=match.group(),
                pii_type=PIIType.PERSON_NAME,
                start=match.start(),
                end=match.end(),
                confidence=confidence,
                context=self.pattern_matcher._extract_context(
                    text, match.start(), match.end()
                )
            ))

        return matches

    def learn_pii(self, value: str, pii_type: PIIType):
        """Learn that a value is PII of a certain type."""
        type_key = pii_type.value
        if type_key not in self.learned_pii:
            self.learned_pii[type_key] = set()
        self.learned_pii[type_key].add(value)
        # Remove from safe list if present
        self.learned_safe.discard(value.lower())

    def learn_safe(self, value: str):
        """Learn that a value is NOT PII."""
        self.learned_safe.add(value.lower())
        # Remove from learned PII if present
        for values in self.learned_pii.values():
            values.discard(value)

    def get_learned_data(self) -> Dict:
        """Export learned patterns for persistence."""
        return {
            'pii': {k: list(v) for k, v in self.learned_pii.items()},
            'safe': list(self.learned_safe)
        }

    def load_learned_data(self, data: Dict):
        """Load previously learned patterns."""
        if 'pii' in data:
            self.learned_pii = {k: set(v) for k, v in data['pii'].items()}
        if 'safe' in data:
            self.learned_safe = set(data['safe'])
