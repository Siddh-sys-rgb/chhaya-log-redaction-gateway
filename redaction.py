"""Bounded, deterministic redaction. No raw text is retained by this module."""
import json
import re
from collections import Counter

MAX_CHARS = 80_000
MAX_LINES = 800
MAX_DEPTH = 12
RULES = {
    'email': 'Email-shaped strings with a supported domain are replaced.',
    'indian_phone': 'Standalone Indian mobile numbers with optional +91 and separators are replaced.',
    'credential': 'Values for explicit password, secret, token and API-key labels are replaced.',
    'bearer': 'Bearer authorization values are replaced.',
    'token': 'Recognized fictional/live-style token prefixes are replaced; unknown token formats need a labelled key.',
}
EMAIL = re.compile(r'(?<![\w.+-])[A-Za-z0-9.!#$%&\x27*+/=?^_`{|}~-]{1,64}@[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63}){1,4}(?![\w.-])')
PHONE = re.compile(r'(?<![\w.])(?:\+?91[ -]?)?[6-9](?:[ -]?\d){9}(?![\w.])')
CREDENTIAL = re.compile(r"""(?im)(\b(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret)\b["']?\s*[:=]\s*)(?:"(?:\\[^\n]|[^"\\\n])*(?:"|$)|'(?:\\[^\n]|[^'\\\n])*(?:'|$)|[^\s,;\}\]"']+)""")
BEARER = re.compile(r'(?i)(\bBearer\s+)[A-Za-z0-9._~+/-]+=*')
TOKEN = re.compile(r'(?<![A-Za-z0-9_])(?:sk_(?:test|live)_[A-Za-z0-9_-]{6,}|ghp_[A-Za-z0-9]{6,}|DEMO_[A-Z0-9_]{6,})(?![A-Za-z0-9_])')
SECRET_KEYS = re.compile(r'(?i)^(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|authorization)$')

class InputError(ValueError):
    pass

def validate(text):
    if not isinstance(text, str) or not text.strip():
        raise InputError('Provide non-empty UTF-8 text.')
    if len(text) > MAX_CHARS or len(text.splitlines()) > MAX_LINES:
        raise InputError('Input exceeds the 80,000-character or 800-line limit.')
    if '\x00' in text:
        raise InputError('NUL bytes are unsupported.')

def sanitize_string(text, counts):
    # Explicit labelled values first: an entire value is hidden even if it contains another pattern.
    def replace(rule, prefix=False):
        def sub(match):
            counts[rule] += 1
            return (match.group(1) if prefix else '') + '[REDACTED:' + rule.upper() + ']'
        return sub
    text = CREDENTIAL.sub(replace('credential', True), text)
    text = BEARER.sub(replace('bearer', True), text)
    text = TOKEN.sub(replace('token'), text)
    text = EMAIL.sub(replace('email'), text)
    return PHONE.sub(replace('indian_phone'), text)

def redact(text, mode='text'):
    validate(text)
    if mode not in ('text', 'jsonl'):
        raise InputError('Choose text or jsonl.')
    counts = Counter()
    if mode == 'text':
        output = sanitize_string(text, counts)
        lines = len(text.splitlines())
    else:
        def visit(value, depth=0):
            if depth > MAX_DEPTH:
                raise InputError('JSON nesting exceeds 12 levels.')
            if isinstance(value, dict):
                safe = {}
                for key, item in value.items():
                    clean_key = sanitize_string(key, counts)
                    if SECRET_KEYS.fullmatch(key):
                        counts['credential'] += 1
                        safe[clean_key] = '[REDACTED:CREDENTIAL]'
                    else:
                        safe[clean_key] = visit(item, depth + 1)
                return safe
            if isinstance(value, list):
                return [visit(item, depth + 1) for item in value]
            if isinstance(value, str):
                return sanitize_string(value, counts)
            if isinstance(value, int) and not isinstance(value, bool) and PHONE.fullmatch(str(value)):
                counts['indian_phone'] += 1
                return '[REDACTED:INDIAN_PHONE]'
            return value
        out = []
        for line in text.splitlines():
            if not line.strip():
                continue
            try:
                value = json.loads(line, parse_constant=lambda value: (_ for _ in ()).throw(ValueError()))
            except (ValueError, RecursionError):
                raise InputError('Each non-empty line must contain valid JSON.') from None
            out.append(json.dumps(visit(value), ensure_ascii=True, separators=(',', ':')))
        output = '\n'.join(out)
        lines = len(out)
    if len(output) > 160_000:
        raise InputError('Redacted output exceeds its size limit.')
    return {'output': output, 'mode': mode, 'line_count': lines, 'input_chars': len(text),
            'output_chars': len(output), 'counts': dict(sorted(counts.items())), 'matches': sum(counts.values())}
