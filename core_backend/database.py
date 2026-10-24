from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
import os

def resolve_database_url(url: str) -> str:
    """Use psycopg2 when it is installed, otherwise the pure-Python pg8000 driver (e.g. Windows ARM64)."""
    scheme, sep, rest = url.partition("://")
    if sep and scheme in ("postgresql", "postgres"):
        try:
            import psycopg2  # noqa: F401
            return f"postgresql+psycopg2://{rest}"
        except ImportError:
            return f"postgresql+pg8000://{rest}"
    return url


DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL is not set. Configure it in the environment or core_backend/.env (see .env.example).")
DATABASE_URL = resolve_database_url(DATABASE_URL)

engine = create_engine(
    DATABASE_URL,
    echo=os.getenv("DEBUG", "False").lower() == "true",
    pool_pre_ping=True,
    pool_size=10,
    max_overflow=20
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Changes to tables that already exist; create_all() only creates missing tables.
MIGRATIONS = [
    """
    DO $$
    BEGIN
        IF EXISTS (
            SELECT 1 FROM information_schema.referential_constraints
            WHERE constraint_name = 'data_flows_created_by_fkey' AND delete_rule <> 'CASCADE'
        ) THEN
            ALTER TABLE data_flows DROP CONSTRAINT data_flows_created_by_fkey;
            ALTER TABLE data_flows ADD CONSTRAINT data_flows_created_by_fkey
                FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE CASCADE;
        END IF;
    END $$;
    """,
]


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    from .models import Base
    Base.metadata.create_all(bind=engine)
    if engine.dialect.name == "postgresql":
        with engine.begin() as conn:
            for statement in MIGRATIONS:
                conn.execute(text(statement))
