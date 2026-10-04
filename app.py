"""Local-only Flask analysis and review API."""
from redaction import redact, InputError, RULES
import argparse
import json
import secrets
from pathlib import Path
from urllib.parse import urlsplit
from flask import Flask, jsonify, render_template, request, session, Response
from werkzeug.exceptions import HTTPException
import storage


def create_app(data_dir=None, testing=False, no_demo=False):
    app = Flask(__name__)
    root = Path(data_dir or Path(__file__).parent / 'instance')
    root.mkdir(parents=True, exist_ok=True)
    key_path = root / 'session.key'
    if not key_path.exists():
        try:
            with key_path.open('x') as handle:
                handle.write(secrets.token_hex(32))
            key_path.chmod(0o600)
        except FileExistsError:
            pass
    app.config.update(SECRET_KEY=key_path.read_text().strip(), TESTING=testing,
        SESSION_chhaya_session='chhaya_session', SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE='Strict', MAX_CONTENT_LENGTH=350000,
        TRUSTED_HOSTS=['localhost', '127.0.0.1'], DB=str(root / 'data.sqlite3'))
    storage.initialize(app.config['DB'])

    @app.before_request
    def protect():
        if request.method not in ('GET', 'HEAD', 'OPTIONS'):
            origin = request.headers.get('Origin')
            if origin and origin != request.host_url.rstrip('/'):
                return jsonify(error='Request origin is not allowed.'), 403
            expected = session.get('csrf')
            actual = request.headers.get('X-CSRF-Token')
            if not expected or not actual or not secrets.compare_digest(expected, actual):
                return jsonify(error='Refresh the page before submitting this request.'), 403

    @app.after_request
    def headers(response):
        response.headers['Cache-Control'] = 'no-store'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
        response.headers['Referrer-Policy'] = 'no-referrer'
        return response

    @app.errorhandler(HTTPException)
    def http_error(exc):
        return jsonify(error='Request could not be processed.', code=exc.code), exc.code

    @app.errorhandler(Exception)
    def internal_error(exc):
        # No request body, filenames or exception text are logged or returned.
        app.logger.error('Analysis request failed (%s).', type(exc).__name__)
        return jsonify(error='Analysis could not be saved. Try again with supported input.'), 500

    @app.get('/')
    def home():
        return render_template('index.html')

    @app.get('/api/health')
    def health():
        return jsonify(status='ok', app='Chhaya', offline=True)

    @app.get('/api/bootstrap')
    def bootstrap():
        if 'csrf' not in session:
            session['csrf'] = secrets.token_hex(24)
        return jsonify(csrf=session['csrf'], rules=RULES, demo_enabled=not no_demo)

    def input_text():
        if request.files:
            uploaded = request.files.get('file')
            if not uploaded:
                raise InputError('Choose a supported UTF-8 file.')
            try:
                text = uploaded.read().decode('utf-8')
            except UnicodeDecodeError:
                raise InputError('Files must use UTF-8 encoding.') from None
            return text, request.form.get('mode', 'text')
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            raise InputError('Provide a JSON object or UTF-8 upload.')
        return data.get('text'), data.get('mode', 'text')

    @app.get('/api/runs')
    def runs():
        return jsonify(runs=storage.history(app.config['DB']))

    @app.get('/api/runs/<run_id>')
    def run(run_id):
        item = storage.get(app.config['DB'], run_id)
        return (jsonify(item) if item else (jsonify(error='Run not found.'), 404))

    @app.get('/api/demo')
    def demo():
        if no_demo:
            return jsonify(error='Demo fixtures are disabled.'), 404
        return jsonify(text=(Path(__file__).parent / 'fixtures' / 'demo.txt').read_text(), mode='text')

    @app.post('/api/runs')
    def create_run():
        try:
            text, mode = input_text()
            result = redact(text, mode)
        except InputError as exc:
            return jsonify(error=str(exc)), 400
        return jsonify(storage.save(app.config['DB'], result)), 201

    @app.get('/api/runs/<run_id>/export')
    def export(run_id):
        item = storage.get(app.config['DB'], run_id)
        if not item:
            return jsonify(error='Run not found.'), 404
        suffix = 'jsonl' if item['mode'] == 'jsonl' else 'txt'
        response = Response(item['output'], mimetype='application/octet-stream')
        response.headers['Content-Disposition'] = f'attachment; filename="chhaya-{item["id"][:12]}.{suffix}"'
        return response

    return app

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Chhaya local security demo')
    parser.add_argument('--port', type=int, default=8114)
    parser.add_argument('--data-dir')
    parser.add_argument('--no-demo', action='store_true')
    args = parser.parse_args()
    create_app(args.data_dir, no_demo=args.no_demo).run(host='127.0.0.1', port=args.port, debug=False)
