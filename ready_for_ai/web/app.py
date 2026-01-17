"""Flask web application for Ready for AI."""

import os
import uuid
import tempfile
import webbrowser
from datetime import datetime, timedelta
from threading import Timer
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field

from flask import Flask, render_template, request, jsonify, send_file
from flask_wtf.csrf import CSRFProtect, generate_csrf
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from ..detectors.pii_detector import PIIDetector, DetectionResult
from ..detectors.patterns import PIIMatch, PIIType
from ..storage.mapping_store import MappingStore
from ..storage.learning_store import LearningStore
from ..processors import (
    get_processor,
    get_restorer,
    is_supported,
    get_supported_extensions,
    TextProcessor,
    TextRestorer,
)


@dataclass
class UncertainMatch:
    """An uncertain PII match awaiting user decision."""
    index: int
    text: str
    pii_type: str
    confidence: float
    context: str
    start: int
    end: int


@dataclass
class Session:
    """A redaction session."""
    id: str
    mapping_store: MappingStore
    detector: PIIDetector
    original_text: Optional[str] = None
    original_filename: Optional[str] = None
    original_format: Optional[str] = None
    redacted_file_path: Optional[str] = None
    redacted_text: Optional[str] = None
    uncertain_matches: List[UncertainMatch] = field(default_factory=list)
    pending_uncertain_index: int = 0
    created_at: datetime = field(default_factory=datetime.utcnow)
    expires_at: datetime = field(default_factory=lambda: datetime.utcnow() + timedelta(hours=1))


# In-memory session storage
sessions: Dict[str, Session] = {}

# Initialize CSRF protection and rate limiter (will be initialized with app)
csrf = CSRFProtect()
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "100 per hour"],
    storage_uri="memory://",
)


def cleanup_expired_sessions():
    """Remove expired sessions."""
    now = datetime.utcnow()
    expired = [sid for sid, session in sessions.items() if session.expires_at < now]
    for sid in expired:
        session = sessions.pop(sid, None)
        if session and session.redacted_file_path:
            try:
                os.remove(session.redacted_file_path)
            except OSError:
                pass


def _validate_session_id(session_id: str) -> bool:
    """Validate that session_id is a valid UUID format."""
    try:
        uuid.UUID(session_id)
        return True
    except (ValueError, TypeError):
        return False


def create_app() -> Flask:
    """Create and configure the Flask application."""
    app = Flask(
        __name__,
        template_folder='templates',
        static_folder='static',
    )

    # Security configuration
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', os.urandom(24).hex())
    app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max upload
    app.config['WTF_CSRF_TIME_LIMIT'] = 3600  # 1 hour CSRF token validity

    # Initialize extensions
    csrf.init_app(app)
    limiter.init_app(app)

    # Initialize learning store
    learning_store = LearningStore()

    def get_detector() -> PIIDetector:
        """Get a fresh PII detector with learned patterns."""
        learned_data = learning_store.get_learned_data()
        return PIIDetector(
            use_nlp=True,
            learned_patterns={k: set(v) for k, v in learned_data['pii'].items()},
            learned_safe=set(learned_data['safe']),
        )

    @app.after_request
    def set_csrf_cookie(response):
        """Set CSRF token in cookie for JavaScript access."""
        response.set_cookie(
            'csrf_token',
            generate_csrf(),
            samesite='Strict',
            httponly=False,  # Needs to be accessible by JS
        )
        return response

    @app.route('/')
    def index():
        """Serve the main page."""
        cleanup_expired_sessions()
        return render_template('index.html')

    @app.route('/api/supported-formats')
    @limiter.limit("100 per minute")
    def supported_formats():
        """Get list of supported file formats."""
        return jsonify({
            'extensions': get_supported_extensions(),
        })

    @app.route('/api/redact', methods=['POST'])
    @limiter.limit("10 per minute")
    def redact():
        """Redact PII from text or file."""
        cleanup_expired_sessions()

        # Create new session
        session_id = str(uuid.uuid4())
        mapping_store = MappingStore(password=None)  # Session-only, no password
        detector = get_detector()

        try:
            # Check if file upload or text paste
            if 'file' in request.files and request.files['file'].filename:
                # File upload
                file = request.files['file']
                filename = file.filename
                ext = os.path.splitext(filename)[1].lower()

                if not is_supported(filename):
                    return jsonify({
                        'error': f'Unsupported file type: {ext}',
                        'supported': get_supported_extensions(),
                    }), 400

                # Save to temp file
                with tempfile.NamedTemporaryFile(delete=False, suffix=ext) as tmp:
                    file.save(tmp.name)
                    input_path = tmp.name

                # Read original text for uncertain detection
                original_text = None
                try:
                    with open(input_path, 'r', encoding='utf-8') as f:
                        original_text = f.read()
                except Exception:
                    pass

                # Detect PII first to get uncertain matches
                uncertain_matches = []
                if original_text:
                    detection_result = detector.detect(original_text)
                    for i, match in enumerate(detection_result.uncertain):
                        uncertain_matches.append(UncertainMatch(
                            index=i,
                            text=match.text,
                            pii_type=match.pii_type.value,
                            confidence=match.confidence,
                            context=match.context or "",
                            start=match.start,
                            end=match.end,
                        ))

                # Get processor
                processor = get_processor(
                    input_path,
                    detector=detector,
                    mapping_store=mapping_store,
                    interactive=False,
                )

                # Process file
                output_path = input_path.replace(ext, f'_redacted{ext}')
                result = processor.process(input_path, output_path)

                # Clean up input file
                os.remove(input_path)

                # Extract text for preview
                if hasattr(processor, 'extract_text'):
                    redacted_text = processor.extract_text(output_path)
                else:
                    redacted_text = None

                # Create session
                session = Session(
                    id=session_id,
                    mapping_store=mapping_store,
                    detector=detector,
                    original_text=original_text,
                    original_filename=filename,
                    original_format=ext,
                    redacted_file_path=output_path,
                    redacted_text=redacted_text,
                    uncertain_matches=uncertain_matches,
                )
                sessions[session_id] = session

                return jsonify({
                    'session_id': session_id,
                    'redacted_text': redacted_text,
                    'stats': {
                        'total_redactions': result.total_redactions,
                        'by_type': result.redactions_by_type,
                        'uncertain': result.uncertain_count,
                    },
                    'has_file': True,
                    'filename': filename.replace(ext, f'_redacted{ext}'),
                    'uncertain': [
                        {
                            'index': m.index,
                            'text': m.text,
                            'pii_type': m.pii_type,
                            'confidence': m.confidence,
                            'context': m.context,
                        }
                        for m in uncertain_matches
                    ],
                })

            elif request.is_json and 'text' in request.json:
                # Text paste
                text = request.json['text']

                if not text.strip():
                    return jsonify({'error': 'No text provided'}), 400

                # Detect PII first to get uncertain matches
                detection_result = detector.detect(text)
                uncertain_matches = []
                for i, match in enumerate(detection_result.uncertain):
                    uncertain_matches.append(UncertainMatch(
                        index=i,
                        text=match.text,
                        pii_type=match.pii_type.value,
                        confidence=match.confidence,
                        context=match.context or "",
                        start=match.start,
                        end=match.end,
                    ))

                # Use text processor
                processor = TextProcessor(
                    detector=detector,
                    mapping_store=mapping_store,
                    interactive=False,
                )

                redacted_text, stats = processor.process_string(text)

                # Create session
                session = Session(
                    id=session_id,
                    mapping_store=mapping_store,
                    detector=detector,
                    original_text=text,
                    original_filename=None,
                    original_format='.txt',
                    redacted_text=redacted_text,
                    uncertain_matches=uncertain_matches,
                )
                sessions[session_id] = session

                return jsonify({
                    'session_id': session_id,
                    'redacted_text': redacted_text,
                    'stats': {
                        'total_redactions': stats['redacted'],
                        'by_type': stats['by_type'],
                        'uncertain': stats['uncertain'],
                    },
                    'has_file': False,
                    'uncertain': [
                        {
                            'index': m.index,
                            'text': m.text,
                            'pii_type': m.pii_type,
                            'confidence': m.confidence,
                            'context': m.context,
                        }
                        for m in uncertain_matches
                    ],
                })

            else:
                return jsonify({'error': 'No file or text provided'}), 400

        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/confirm-uncertain', methods=['POST'])
    @limiter.limit("30 per minute")
    def confirm_uncertain():
        """Confirm or reject an uncertain PII detection."""
        if not request.is_json:
            return jsonify({'error': 'JSON required'}), 400

        session_id = request.json.get('session_id')
        match_index = request.json.get('match_index')
        decision = request.json.get('decision')  # 'yes', 'no', 'skip'
        pii_type_override = request.json.get('pii_type')  # Optional type override

        if not session_id or not _validate_session_id(session_id):
            return jsonify({'error': 'Invalid session_id'}), 400

        if match_index is None:
            return jsonify({'error': 'match_index required'}), 400

        if decision not in ('yes', 'no', 'skip'):
            return jsonify({'error': 'decision must be yes, no, or skip'}), 400

        session = sessions.get(session_id)
        if not session:
            return jsonify({'error': 'Session not found or expired'}), 404

        # Find the uncertain match
        match = None
        for m in session.uncertain_matches:
            if m.index == match_index:
                match = m
                break

        if not match:
            return jsonify({'error': 'Match not found'}), 404

        # Process decision
        redaction_added = False
        if decision == 'yes':
            # User confirmed it's PII - add to mapping and learn
            pii_type = pii_type_override or match.pii_type
            placeholder = session.mapping_store.add_mapping(match.text, pii_type)

            # Learn this as PII
            try:
                learning_store.learn_pii(match.text, pii_type)
            except Exception:
                pass

            # Update redacted text by replacing this match
            if session.redacted_text and session.original_text:
                # Re-process with the new mapping
                session.redacted_text = session.redacted_text  # Will be updated on next process
            redaction_added = True

        elif decision == 'no':
            # User confirmed it's NOT PII - learn as safe
            try:
                learning_store.learn_safe(match.text)
            except Exception:
                pass

        # Remove from pending list
        session.uncertain_matches = [m for m in session.uncertain_matches if m.index != match_index]

        return jsonify({
            'success': True,
            'redaction_added': redaction_added,
            'remaining': len(session.uncertain_matches),
            'remaining_matches': [
                {
                    'index': m.index,
                    'text': m.text,
                    'pii_type': m.pii_type,
                    'confidence': m.confidence,
                    'context': m.context,
                }
                for m in session.uncertain_matches
            ],
        })

    @app.route('/api/restore', methods=['POST'])
    @limiter.limit("20 per minute")
    def restore():
        """Restore placeholders in text."""
        if not request.is_json:
            return jsonify({'error': 'JSON required'}), 400

        session_id = request.json.get('session_id')
        text = request.json.get('text')

        if not session_id or not _validate_session_id(session_id):
            return jsonify({'error': 'Invalid session_id'}), 400

        if not text:
            return jsonify({'error': 'text required'}), 400

        session = sessions.get(session_id)
        if not session:
            return jsonify({'error': 'Session not found or expired'}), 404

        try:
            restorer = TextRestorer(session.mapping_store)
            restored_text, count = restorer.restore_string(text)

            return jsonify({
                'restored_text': restored_text,
                'restoration_count': count,
            })

        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/download/<session_id>')
    @limiter.limit("30 per minute")
    def download(session_id: str):
        """Download redacted file."""
        if not _validate_session_id(session_id):
            return jsonify({'error': 'Invalid session_id'}), 400

        session = sessions.get(session_id)
        if not session:
            return jsonify({'error': 'Session not found or expired'}), 404

        if not session.redacted_file_path or not os.path.exists(session.redacted_file_path):
            return jsonify({'error': 'No file available'}), 404

        filename = session.original_filename
        if filename:
            ext = os.path.splitext(filename)[1]
            download_name = filename.replace(ext, f'_redacted{ext}')
        else:
            download_name = 'redacted_document'

        return send_file(
            session.redacted_file_path,
            as_attachment=True,
            download_name=download_name,
        )

    @app.route('/api/session/<session_id>', methods=['DELETE', 'POST'])
    @limiter.limit("30 per minute")
    @csrf.exempt  # Exempt for sendBeacon which can't include CSRF token
    def delete_session(session_id: str):
        """Delete a session. Accepts both DELETE and POST for sendBeacon compatibility."""
        if not _validate_session_id(session_id):
            return jsonify({'error': 'Invalid session_id'}), 400

        session = sessions.pop(session_id, None)
        if session and session.redacted_file_path:
            try:
                os.remove(session.redacted_file_path)
            except OSError:
                pass

        return jsonify({'success': True})

    return app


def run_server(host: str = '127.0.0.1', port: int = 5000, open_browser: bool = True):
    """Run the Flask development server."""
    app = create_app()

    if open_browser:
        url = f'http://{host}:{port}'

        def open_browser_delayed():
            webbrowser.open(url)

        Timer(1.0, open_browser_delayed).start()

    print(f"\n  Ready for AI - Web Interface")
    print(f"  Running at: http://{host}:{port}")
    print(f"  Press Ctrl+C to quit\n")

    app.run(host=host, port=port, debug=False)
