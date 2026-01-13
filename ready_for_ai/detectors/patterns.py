"""Pattern matching for PII detection."""

import re
from dataclasses import dataclass
from typing import List, Tuple, Optional
from enum import Enum


class PIIType(Enum):
    """Types of PII that can be detected."""
    EMAIL = "email"
    PHONE = "phone"
    SLACK_HANDLE = "slack_handle"
    PERSON_NAME = "person_name"
    COMPANY_NAME = "company_name"
    PROJECT_NAME = "project_name"
    TEAM_NAME = "team_name"
    ADDRESS = "address"
    SSN = "ssn"
    CREDIT_CARD = "credit_card"
    IP_ADDRESS = "ip_address"
    URL = "url"
    DATE_OF_BIRTH = "date_of_birth"
    CUSTOM = "custom"


@dataclass
class PIIMatch:
    """Represents a detected PII match."""
    text: str
    pii_type: PIIType
    start: int
    end: int
    confidence: float  # 0.0 to 1.0
    context: str = ""  # Surrounding text for context


class PatternMatcher:
    """Regex-based pattern matching for common PII types."""

    # High-confidence patterns (regex with clear structure)
    PATTERNS = {
        PIIType.EMAIL: (
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            0.95
        ),
        PIIType.PHONE: (
            r'(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b',
            0.85
        ),
        PIIType.SLACK_HANDLE: (
            r'(?<![A-Za-z0-9._%+-])@[A-Za-z][A-Za-z0-9_-]{0,20}(?![A-Za-z0-9.])\b',
            0.80
        ),
        PIIType.SSN: (
            r'\b\d{3}[-.\s]?\d{2}[-.\s]?\d{4}\b',
            0.90
        ),
        PIIType.CREDIT_CARD: (
            r'\b(?:\d{4}[-.\s]?){3}\d{4}\b',
            0.85
        ),
        PIIType.IP_ADDRESS: (
            r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
            0.90
        ),
        PIIType.URL: (
            r'https?://[^\s<>"{}|\\^`\[\]]+',
            0.95
        ),
    }

    # Context keywords that suggest certain PII types
    CONTEXT_KEYWORDS = {
        PIIType.PERSON_NAME: [
            'mr', 'mrs', 'ms', 'dr', 'prof', 'dear', 'hi', 'hello',
            'regards', 'sincerely', 'from', 'to', 'cc', 'bcc',
            'employee', 'manager', 'director', 'ceo', 'cto', 'cfo'
        ],
        PIIType.COMPANY_NAME: [
            'inc', 'llc', 'ltd', 'corp', 'company', 'enterprise',
            'client', 'customer', 'partner', 'vendor', 'supplier'
        ],
        PIIType.PROJECT_NAME: [
            'project', 'initiative', 'program', 'campaign', 'sprint',
            'milestone', 'release', 'version', 'phase'
        ],
        PIIType.TEAM_NAME: [
            'team', 'squad', 'group', 'department', 'division',
            'unit', 'org', 'organization'
        ],
    }

    def __init__(self):
        self._compiled_patterns = {
            pii_type: re.compile(pattern, re.IGNORECASE)
            for pii_type, (pattern, _) in self.PATTERNS.items()
        }

    def find_pattern_matches(self, text: str) -> List[PIIMatch]:
        """Find all pattern-based PII matches in text."""
        matches = []

        for pii_type, regex in self._compiled_patterns.items():
            confidence = self.PATTERNS[pii_type][1]

            for match in regex.finditer(text):
                context = self._extract_context(text, match.start(), match.end())
                matches.append(PIIMatch(
                    text=match.group(),
                    pii_type=pii_type,
                    start=match.start(),
                    end=match.end(),
                    confidence=confidence,
                    context=context
                ))

        return matches

    def find_contextual_candidates(
        self,
        text: str,
        pii_type: PIIType
    ) -> List[Tuple[str, int, int, float]]:
        """
        Find potential PII based on context keywords.
        Returns list of (text, start, end, confidence) tuples.
        """
        candidates = []
        keywords = self.CONTEXT_KEYWORDS.get(pii_type, [])

        if not keywords:
            return candidates

        # Look for capitalized words/phrases near context keywords
        keyword_pattern = '|'.join(re.escape(k) for k in keywords)
        keyword_regex = re.compile(
            rf'\b({keyword_pattern})\b[:\s]+([A-Z][A-Za-z]+(?:\s+[A-Z][A-Za-z]+)*)',
            re.IGNORECASE
        )

        for match in keyword_regex.finditer(text):
            value = match.group(2)
            start = match.start(2)
            end = match.end(2)
            candidates.append((value, start, end, 0.60))  # Lower confidence for contextual

        return candidates

    def _extract_context(
        self,
        text: str,
        start: int,
        end: int,
        context_chars: int = 50
    ) -> str:
        """Extract surrounding context for a match."""
        ctx_start = max(0, start - context_chars)
        ctx_end = min(len(text), end + context_chars)

        context = text[ctx_start:ctx_end]
        if ctx_start > 0:
            context = "..." + context
        if ctx_end < len(text):
            context = context + "..."

        return context


# Common name lists for detection (can be extended)
COMMON_FIRST_NAMES = {
    'james', 'john', 'robert', 'michael', 'william', 'david', 'richard',
    'joseph', 'thomas', 'charles', 'mary', 'patricia', 'jennifer', 'linda',
    'elizabeth', 'barbara', 'susan', 'jessica', 'sarah', 'karen', 'nancy',
    'lisa', 'betty', 'margaret', 'sandra', 'ashley', 'dorothy', 'kimberly',
    'emily', 'donna', 'michelle', 'daniel', 'matthew', 'anthony', 'mark',
    'donald', 'steven', 'paul', 'andrew', 'joshua', 'kenneth', 'kevin',
    'brian', 'george', 'edward', 'ronald', 'timothy', 'jason', 'jeffrey',
    'ryan', 'jacob', 'gary', 'nicholas', 'eric', 'jonathan', 'stephen',
    'larry', 'justin', 'scott', 'brandon', 'benjamin', 'samuel', 'raymond',
    'gregory', 'frank', 'alexander', 'patrick', 'jack', 'dennis', 'jerry',
    # Add more as needed
}

COMMON_LAST_NAMES = {
    'smith', 'johnson', 'williams', 'brown', 'jones', 'garcia', 'miller',
    'davis', 'rodriguez', 'martinez', 'hernandez', 'lopez', 'gonzalez',
    'wilson', 'anderson', 'thomas', 'taylor', 'moore', 'jackson', 'martin',
    'lee', 'perez', 'thompson', 'white', 'harris', 'sanchez', 'clark',
    'ramirez', 'lewis', 'robinson', 'walker', 'young', 'allen', 'king',
    'wright', 'scott', 'torres', 'nguyen', 'hill', 'flores', 'green',
    'adams', 'nelson', 'baker', 'hall', 'rivera', 'campbell', 'mitchell',
    'carter', 'roberts', 'gomez', 'phillips', 'evans', 'turner', 'diaz',
    # Add more as needed
}
