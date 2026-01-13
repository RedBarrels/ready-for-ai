"""Encrypted storage for PII mappings using bcrypt and AES."""

import os
import json
import base64
import hashlib
import secrets
from typing import Dict, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime

import bcrypt
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


@dataclass
class PIIMapping:
    """A single PII value to placeholder mapping."""
    original_hash: str  # bcrypt hash of original value
    original_encrypted: str  # AES encrypted original value
    placeholder: str  # The replacement value (e.g., "John Doe")
    pii_type: str
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())


class MappingStore:
    """
    Secure storage for PII mappings.

    Uses bcrypt for hashing (to verify mappings) and AES for encryption
    (to allow restoration). The encryption key is derived from a user password
    or generated randomly for session-only use.
    """

    # Placeholder templates by PII type
    PLACEHOLDER_TEMPLATES = {
        'email': 'person{n}@example.com',
        'phone': '555-000-{n:04d}',
        'slack_handle': '@user{n}',
        'person_name': None,  # Uses name generator
        'company_name': None,  # Uses company generator
        'project_name': 'Project Alpha {n}',
        'team_name': 'Team {n}',
        'address': '{n} Example Street, Anytown, ST 12345',
        'ssn': 'XXX-XX-{n:04d}',
        'credit_card': 'XXXX-XXXX-XXXX-{n:04d}',
        'ip_address': '192.0.2.{n}',
        'url': 'https://example.com/page{n}',
        'date_of_birth': '1990-01-{n:02d}',
        'custom': '[REDACTED-{n}]',
    }

    # Placeholder names for person_name type
    PLACEHOLDER_NAMES = [
        'John Doe', 'Jane Smith', 'Bob Johnson', 'Alice Williams',
        'Charlie Brown', 'Diana Prince', 'Edward Norton', 'Fiona Green',
        'George Miller', 'Helen Davis', 'Ivan Petrov', 'Julia Roberts',
        'Kevin White', 'Laura Black', 'Michael Grey', 'Nancy Blue',
        'Oliver Stone', 'Patricia Gold', 'Quincy Silver', 'Rachel Bronze',
    ]

    # Placeholder company names
    PLACEHOLDER_COMPANIES = [
        'Example Corp', 'Acme Inc', 'Sample LLC', 'Demo Industries',
        'Test Company', 'Placeholder Ltd', 'Generic Solutions', 'Standard Co',
        'Universal Enterprises', 'Global Services', 'Alpha Technologies',
        'Beta Systems', 'Gamma Holdings', 'Delta Partners', 'Epsilon Group',
    ]

    def __init__(self, password: Optional[str] = None):
        """
        Initialize mapping store.

        Args:
            password: Optional password for encryption. If None, generates
                     a random key (session-only, mappings won't persist).
        """
        self.mappings: Dict[str, PIIMapping] = {}
        self._value_to_id: Dict[str, str] = {}  # Quick lookup by original value
        self._counters: Dict[str, int] = {}  # Counters for placeholder generation

        # Generate or derive encryption key
        if password:
            self._salt = os.urandom(16)
            self._key = self._derive_key(password, self._salt)
        else:
            self._salt = None
            self._key = Fernet.generate_key()

        self._fernet = Fernet(self._key)

    def _derive_key(self, password: str, salt: bytes) -> bytes:
        """Derive encryption key from password using PBKDF2."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=480000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key

    def _hash_value(self, value: str) -> str:
        """Create bcrypt hash of a value.

        Pre-hashes with SHA-256 to handle values longer than bcrypt's 72-byte limit.
        """
        # bcrypt has a 72-byte limit, so pre-hash long values with SHA-256
        value_bytes = value.encode()
        if len(value_bytes) > 72:
            value_bytes = hashlib.sha256(value_bytes).hexdigest().encode()
        return bcrypt.hashpw(value_bytes, bcrypt.gensalt()).decode()

    def _verify_hash(self, value: str, hashed: str) -> bool:
        """Verify a value against its bcrypt hash.

        Pre-hashes with SHA-256 to handle values longer than bcrypt's 72-byte limit.
        """
        value_bytes = value.encode()
        if len(value_bytes) > 72:
            value_bytes = hashlib.sha256(value_bytes).hexdigest().encode()
        return bcrypt.checkpw(value_bytes, hashed.encode())

    def _encrypt_value(self, value: str) -> str:
        """Encrypt a value using AES (Fernet)."""
        return self._fernet.encrypt(value.encode()).decode()

    def _decrypt_value(self, encrypted: str) -> str:
        """Decrypt a value using AES (Fernet)."""
        return self._fernet.decrypt(encrypted.encode()).decode()

    def _generate_placeholder(self, pii_type: str) -> str:
        """Generate a unique placeholder for a PII type."""
        # Get next counter for this type
        if pii_type not in self._counters:
            self._counters[pii_type] = 0
        n = self._counters[pii_type]
        self._counters[pii_type] += 1

        # Special handling for names and companies
        if pii_type == 'person_name':
            if n < len(self.PLACEHOLDER_NAMES):
                return self.PLACEHOLDER_NAMES[n]
            else:
                return f"Person {n + 1}"

        if pii_type == 'company_name':
            if n < len(self.PLACEHOLDER_COMPANIES):
                return self.PLACEHOLDER_COMPANIES[n]
            else:
                return f"Company {n + 1}"

        # Use template
        template = self.PLACEHOLDER_TEMPLATES.get(pii_type, '[REDACTED-{n}]')
        return template.format(n=n + 1)

    def add_mapping(
        self,
        original: str,
        pii_type: str,
        custom_placeholder: Optional[str] = None
    ) -> str:
        """
        Add a new PII mapping.

        Args:
            original: The original PII value
            pii_type: Type of PII (e.g., 'email', 'person_name')
            custom_placeholder: Optional custom placeholder to use

        Returns:
            The placeholder value to use in the document
        """
        # Check if we already have this value mapped
        lookup_key = f"{pii_type}:{original.lower()}"
        if lookup_key in self._value_to_id:
            mapping_id = self._value_to_id[lookup_key]
            return self.mappings[mapping_id].placeholder

        # Generate unique ID for this mapping
        mapping_id = secrets.token_hex(16)

        # Generate or use custom placeholder
        placeholder = custom_placeholder or self._generate_placeholder(pii_type)

        # Create mapping with hashed and encrypted original
        mapping = PIIMapping(
            original_hash=self._hash_value(original),
            original_encrypted=self._encrypt_value(original),
            placeholder=placeholder,
            pii_type=pii_type,
        )

        self.mappings[mapping_id] = mapping
        self._value_to_id[lookup_key] = mapping_id

        return placeholder

    def get_placeholder(self, original: str, pii_type: str) -> Optional[str]:
        """Get existing placeholder for a value, if any."""
        lookup_key = f"{pii_type}:{original.lower()}"
        if lookup_key in self._value_to_id:
            mapping_id = self._value_to_id[lookup_key]
            return self.mappings[mapping_id].placeholder
        return None

    def get_original(self, placeholder: str) -> Optional[Tuple[str, str]]:
        """
        Get original value for a placeholder.

        Returns:
            Tuple of (original_value, pii_type) or None if not found
        """
        for mapping in self.mappings.values():
            if mapping.placeholder == placeholder:
                original = self._decrypt_value(mapping.original_encrypted)
                return (original, mapping.pii_type)
        return None

    def get_all_restorations(self) -> Dict[str, str]:
        """
        Get all placeholder -> original mappings for restoration.

        Returns:
            Dict mapping placeholders to original values
        """
        return {
            mapping.placeholder: self._decrypt_value(mapping.original_encrypted)
            for mapping in self.mappings.values()
        }

    def export_encrypted(self) -> Dict:
        """
        Export mappings in encrypted format for storage.

        Note: Original values remain encrypted. Only metadata and
        placeholders are in plain text.
        """
        data = {
            'version': 1,
            'salt': base64.b64encode(self._salt).decode() if self._salt else None,
            'mappings': {},
            'counters': self._counters,
        }

        for mapping_id, mapping in self.mappings.items():
            data['mappings'][mapping_id] = {
                'original_hash': mapping.original_hash,
                'original_encrypted': mapping.original_encrypted,
                'placeholder': mapping.placeholder,
                'pii_type': mapping.pii_type,
                'created_at': mapping.created_at,
            }

        return data

    def save_to_file(self, filepath: str):
        """Save encrypted mappings to a file."""
        data = self.export_encrypted()
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)

    @classmethod
    def load_from_file(cls, filepath: str, password: str) -> 'MappingStore':
        """
        Load mappings from an encrypted file.

        Args:
            filepath: Path to the mapping file
            password: Password used when creating the mappings

        Returns:
            MappingStore instance with loaded mappings
        """
        with open(filepath, 'r') as f:
            data = json.load(f)

        if data.get('version') != 1:
            raise ValueError(f"Unsupported mapping file version: {data.get('version')}")

        # Create store with password and saved salt
        store = cls.__new__(cls)
        store.mappings = {}
        store._value_to_id = {}
        store._counters = data.get('counters', {})

        if data.get('salt'):
            store._salt = base64.b64decode(data['salt'])
            store._key = store._derive_key(password, store._salt)
        else:
            raise ValueError("Cannot load session-only mappings (no password was used)")

        store._fernet = Fernet(store._key)

        # Load mappings
        for mapping_id, mapping_data in data.get('mappings', {}).items():
            mapping = PIIMapping(
                original_hash=mapping_data['original_hash'],
                original_encrypted=mapping_data['original_encrypted'],
                placeholder=mapping_data['placeholder'],
                pii_type=mapping_data['pii_type'],
                created_at=mapping_data.get('created_at', ''),
            )
            store.mappings[mapping_id] = mapping

            # Rebuild value lookup (we can't recover original value without decryption)
            # This will be populated on first access

        return store

    def clear(self):
        """Clear all mappings (for cleanup after restoration)."""
        self.mappings.clear()
        self._value_to_id.clear()
        self._counters.clear()

    def stats(self) -> Dict:
        """Get statistics about stored mappings."""
        type_counts = {}
        for mapping in self.mappings.values():
            pii_type = mapping.pii_type
            type_counts[pii_type] = type_counts.get(pii_type, 0) + 1

        return {
            'total_mappings': len(self.mappings),
            'by_type': type_counts,
        }
