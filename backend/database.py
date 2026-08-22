import os
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, declarative_base
from tenacity import retry, stop_after_attempt, wait_exponential

SQLALCHEMY_DATABASE_URL = os.environ.get(
    "DATABASE_URL", "postgresql://postgres:postgres@postgres:5432/sentinel_db"
)

# Hardened connection with pooling and pre-ping to handle dropped connections
engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    pool_size=20,
    max_overflow=10,
    pool_pre_ping=True
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

# Exponential backoff retry logic — only wraps the connection validation, NOT the generator
@retry(stop=stop_after_attempt(5), wait=wait_exponential(multiplier=1, min=2, max=10))
def _validate_connection():
    """Validates DB connectivity with retry/backoff on startup."""
    db = SessionLocal()
    try:
        db.execute(text("SELECT 1"))
    finally:
        db.close()

# FastAPI dependency — must be a plain generator (no @retry decorator)
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
