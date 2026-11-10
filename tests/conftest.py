"""Test fixtures.

By default tests run against in-memory SQLite. Set CIPHERVAULT_TEST_MSSQL to an
ODBC connection string to also run the whole suite against MS SQL Server
(CI does this with a SQL Server service container).
"""

import os

import pytest

from ciphervault.db import Database

# Low iteration count keeps the test suite fast; production uses 600,000.
FAST = 1_000

BACKENDS = ["sqlite"] + (["mssql"] if os.environ.get("CIPHERVAULT_TEST_MSSQL") else [])


@pytest.fixture(params=BACKENDS)
def db(request):
    if request.param == "sqlite":
        database = Database.connect("sqlite:///:memory:")
    else:
        database = Database.connect("mssql://" + os.environ["CIPHERVAULT_TEST_MSSQL"])
        for table in ("audit_log", "entries", "users"):
            database.execute(f"IF OBJECT_ID('dbo.{table}', 'U') IS NOT NULL DROP TABLE dbo.{table}")
        database.commit()
    database.init_schema()
    yield database
    database.close()
