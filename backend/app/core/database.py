from contextlib import contextmanager
from pathlib import Path
import os
import sqlite3
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from .config import settings

DATABASE_URL = os.getenv("DATABASE_URL", settings.database_url)
SQLITE_DB_PATH = os.getenv("SQLITE_DB_PATH", settings.database_path)

_engine = None
_SessionLocal = None

def get_engine():
    global _engine
    if _engine is None:
        if DATABASE_URL.startswith("postgresql") or DATABASE_URL.startswith("postgres"):
            _engine = create_engine(DATABASE_URL, pool_pre_ping=True, pool_recycle=300)
        else:
            db_path = Path(SQLITE_DB_PATH)
            db_path.parent.mkdir(parents=True, exist_ok=True)
            _engine = create_engine(f"sqlite:///{db_path}", connect_args={"check_same_thread": False, "timeout": 15})
    return _engine

def get_session():
    global _SessionLocal
    if _SessionLocal is None:
        _SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=get_engine())
    return _SessionLocal()

@contextmanager
def db_connection():
    engine = get_engine()
    if engine.url.get_backend_name() == "postgresql":
        with engine.connect() as conn:
            yield conn
    else:
        db_path = Path(SQLITE_DB_PATH)
        db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(db_path, timeout=15)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        try:
            yield conn
        finally:
            conn.close()

def init_db():
    engine = get_engine()
    with engine.connect() as conn:
        if engine.url.get_backend_name() == "postgresql":
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS investigations (
                    id TEXT PRIMARY KEY, url TEXT NOT NULL, status TEXT, risk_score INTEGER,
                    classification TEXT, summary TEXT, report TEXT NOT NULL, created_at TEXT NOT NULL,
                    completed_at TEXT
                )
            """))
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS investigation_jobs (
                    id TEXT PRIMARY KEY, url TEXT NOT NULL, status TEXT NOT NULL, context TEXT NOT NULL,
                    error TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, completed_at TEXT
                )
            """))
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS evidence (
                    id TEXT PRIMARY KEY, investigation_id TEXT NOT NULL, category TEXT, title TEXT,
                    description TEXT, source TEXT, confidence REAL, severity TEXT, created_at TEXT
                )
            """))
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS features (
                    id SERIAL PRIMARY KEY, investigation_id TEXT NOT NULL,
                    feature_name TEXT, feature_value TEXT, source TEXT
                )
            """))
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS events (
                    id SERIAL PRIMARY KEY, investigation_id TEXT NOT NULL,
                    event_type TEXT, message TEXT, timestamp TEXT
                )
            """))
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS user_profile (
                    id INTEGER PRIMARY KEY, knowledge_level TEXT DEFAULT 'standard', created_at TEXT, updated_at TEXT
                )
            """))
            conn.execute(text("CREATE INDEX IF NOT EXISTS idx_investigations_created_at ON investigations(created_at DESC)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS idx_investigations_url_created_at ON investigations(url, created_at DESC)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS idx_jobs_status_updated_at ON investigation_jobs(status, updated_at DESC)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS idx_evidence_investigation_id ON evidence(investigation_id)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS idx_features_investigation_id ON features(investigation_id)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS idx_events_investigation_id ON events(investigation_id)"))
            conn.commit()
        else:
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS investigations (
                    id TEXT PRIMARY KEY, url TEXT NOT NULL, status TEXT, risk_score INTEGER,
                    classification TEXT, summary TEXT, report TEXT NOT NULL, created_at TEXT NOT NULL,
                    completed_at TEXT
                )
            """))
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS investigation_jobs (
                    id TEXT PRIMARY KEY, url TEXT NOT NULL, status TEXT NOT NULL, context TEXT NOT NULL,
                    error TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, completed_at TEXT
                )
            """))
            result = conn.execute(text("PRAGMA table_info(investigations)")).fetchall()
            columns = {row[1] for row in result}
            if "summary" not in columns:
                conn.execute(text("ALTER TABLE investigations ADD COLUMN summary TEXT"))
            if "report" not in columns:
                conn.execute(text("ALTER TABLE investigations ADD COLUMN report TEXT"))
            if "completed_at" not in columns:
                conn.execute(text("ALTER TABLE investigations ADD COLUMN completed_at TEXT"))
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS evidence (
                    id TEXT PRIMARY KEY, investigation_id TEXT NOT NULL, category TEXT, title TEXT,
                    description TEXT, source TEXT, confidence REAL, severity TEXT, created_at TEXT
                )
            """))
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS features (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, investigation_id TEXT NOT NULL,
                    feature_name TEXT, feature_value TEXT, source TEXT
                )
            """))
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, investigation_id TEXT NOT NULL,
                    event_type TEXT, message TEXT, timestamp TEXT
                )
            """))
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS user_profile (
                    id INTEGER PRIMARY KEY, knowledge_level TEXT DEFAULT 'standard', created_at TEXT, updated_at TEXT
                )
            """))
            conn.execute(text("CREATE INDEX IF NOT EXISTS idx_investigations_created_at ON investigations(created_at DESC)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS idx_investigations_url_created_at ON investigations(url, created_at DESC)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS idx_jobs_status_updated_at ON investigation_jobs(status, updated_at DESC)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS idx_evidence_investigation_id ON evidence(investigation_id)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS idx_features_investigation_id ON features(investigation_id)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS idx_events_investigation_id ON events(investigation_id)"))
            conn.commit()