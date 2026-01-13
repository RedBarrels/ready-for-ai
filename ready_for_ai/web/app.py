"""Flask web application for Ready for AI."""

import os
import uuid
import tempfile
import webbrowser
from datetime import datetime, timedelta
from threading import Timer
from typing import Dict, Optional
from dataclasses import dataclass, field

from flask import Flask, render_template, request, jsonify, send_file

from ..detectors.pii_detector import PIIDetector
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
class Session:
    """A redaction session."""
    id: str
    mapping_store: MappingStore
    original_filename: Optional[str] = None
    original_format: Optional[str] = None
    redacted_file_path: Optional[str] = None
    redacted_text: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.utcnow)
    expires_at: datetime = field(default_factory=lambda: datetime.utcnow() + timedelta(hours=1))


# In-memory session storage
sessions: Dict[str, Session] = {}


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


def create_app() -> Flask:
    """Create and configure the Flask application."""
    app = Flask(
        __name__,
        template_folder='templates',
        static_folder='static',
    )

    app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max upload

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

    @app.route('/')
    def index():
        """Serve the main page."""
        cleanup_expired_sessions()
        return render_template('index.html')

    @app.route('/api/supported-formats')
    def supported_formats():
        """Get list of supported file formats."""
        return jsonify({
            'extensions': get_supported_extensions(),
        })

    @app.route('/api/redact', methods=['POST'])
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
                    original_filename=filename,
                    original_format=ext,
                    redacted_file_path=output_path,
                    redacted_text=redacted_text,
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
                })

            elif request.is_json and 'text' in request.json:
                # Text paste
                text = request.json['text']

                if not text.strip():
                    return jsonify({'error': 'No text provided'}), 400

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
                    original_filename=None,
                    original_format='.txt',
                    redacted_text=redacted_text,
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
                })

            else:
                return jsonify({'error': 'No file or text provided'}), 400

        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/restore', methods=['POST'])
    def restore():
        """Restore placeholders in text."""
        if not request.is_json:
            return jsonify({'error': 'JSON required'}), 400

        session_id = request.json.get('session_id')
        text = request.json.get('text')

        if not session_id:
            return jsonify({'error': 'session_id required'}), 400

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
    def download(session_id: str):
        """Download redacted file."""
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

    @app.route('/api/session/<session_id>', methods=['DELETE'])
    def delete_session(session_id: str):
        """Delete a session."""
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
