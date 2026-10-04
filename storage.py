"""Persist only sanitized immutable artifacts. Raw input never reaches SQLite."""
import hashlib
import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path

def connect(path):
    db = sqlite3.connect(path, timeout=10)
    db.row_factory = sqlite3.Row
    return db

def initialize(path):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with connect(path) as db:
        db.execute('PRAGMA journal_mode=WAL')
        db.execute('CREATE TABLE IF NOT EXISTS runs (id TEXT PRIMARY KEY, created TEXT NOT NULL, artifact TEXT NOT NULL, output_sha256 TEXT NOT NULL)')

def save(path, result):
    item = dict(result, id=uuid.uuid4().hex, created=datetime.now(timezone.utc).isoformat(), output_sha256=hashlib.sha256(result['output'].encode()).hexdigest())
    with connect(path) as db:
        db.execute('INSERT INTO runs VALUES (?,?,?,?)', (item['id'], item['created'], json.dumps(item), item['output_sha256']))
    return item

def get(path, run_id):
    with connect(path) as db:
        row = db.execute('SELECT artifact FROM runs WHERE id=?', (run_id,)).fetchone()
    return json.loads(row['artifact']) if row else None

def history(path):
    with connect(path) as db:
        rows = db.execute('SELECT artifact FROM runs ORDER BY created DESC LIMIT 40').fetchall()
    return [{k: v for k, v in json.loads(row['artifact']).items() if k != 'output'} for row in rows]
