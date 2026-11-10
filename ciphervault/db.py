"""Database layer.

Supports SQLite (default, zero setup) and Microsoft SQL Server via pyodbc.
Both drivers use the `?` parameter style, so the same queries run on both;
only the DDL differs.

Connection strings (env var CIPHERVAULT_DB or --db):
  sqlite:///path/to/vault.db
  mssql://DRIVER={ODBC Driver 18 for SQL Server};SERVER=localhost,1433;DATABASE=ciphervault;UID=sa;PWD=...;TrustServerCertificate=yes
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

SQLITE_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    username        TEXT    NOT NULL UNIQUE,
    salt            BLOB    NOT NULL,
    kdf_iterations  INTEGER NOT NULL,
    verifier_nonce  BLOB    NOT NULL,
    verifier        BLOB    NOT NULL,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until    TEXT    NULL,
    created_at      TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS entries (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name        TEXT    NOT NULL,
    nonce       BLOB    NOT NULL,
    ciphertext  BLOB    NOT NULL,
    created_at  TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (user_id, name)
);
CREATE TABLE IF NOT EXISTS audit_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    username   TEXT NOT NULL,
    action     TEXT NOT NULL,
    success    INTEGER NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
"""

MSSQL_SCHEMA_PATH = Path(__file__).resolve().parent.parent / "sql" / "schema_mssql.sql"


class Database:
    def __init__(self, conn, dialect: str):
        self.conn = conn
        self.dialect = dialect

    # -- connection -----------------------------------------------------
    @classmethod
    def connect(cls, url: str) -> "Database":
        if url.startswith("sqlite:///"):
            path = url[len("sqlite:///"):] or ":memory:"
            conn = sqlite3.connect(path)
            conn.execute("PRAGMA foreign_keys = ON")
            return cls(conn, "sqlite")
        if url.startswith("mssql://"):
            import pyodbc  # optional dependency

            return cls(pyodbc.connect(url[len("mssql://"):], autocommit=False), "mssql")
        raise ValueError(f"unsupported database url: {url!r}")

    def init_schema(self) -> None:
        if self.dialect == "sqlite":
            self.conn.executescript(SQLITE_SCHEMA)
        else:
            cur = self.conn.cursor()
            for batch in MSSQL_SCHEMA_PATH.read_text().split("\nGO"):
                if batch.strip():
                    cur.execute(batch)
        self.conn.commit()

    # -- helpers --------------------------------------------------------
    def execute(self, sql: str, params: tuple = ()):
        cur = self.conn.cursor()
        cur.execute(sql, params)
        return cur

    def fetchone(self, sql: str, params: tuple = ()):
        return self.execute(sql, params).fetchone()

    def fetchall(self, sql: str, params: tuple = ()):
        return self.execute(sql, params).fetchall()

    def commit(self) -> None:
        self.conn.commit()

    def rollback(self) -> None:
        self.conn.rollback()

    def now_sql(self) -> str:
        return "CURRENT_TIMESTAMP" if self.dialect == "sqlite" else "SYSUTCDATETIME()"

    def close(self) -> None:
        self.conn.close()
