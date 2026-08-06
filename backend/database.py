from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

import os

# For local development. We will move this to a .env file later.
# Format: postgresql://user:password@localhost:5432/dbname
SQLALCHEMY_DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://postgres:postgres@localhost:5432/sentinel_db")

engine = create_engine(SQLALCHEMY_DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

# Dependency to get the database session for our API routes
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()