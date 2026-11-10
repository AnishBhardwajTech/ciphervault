# CipherVault

An encryption and key-management vault written in Python. Secrets are encrypted with **AES-256-GCM** using keys derived from a master password with **PBKDF2-HMAC-SHA256** and a per-user random salt, and stored in **Microsoft SQL Server** (or SQLite for zero-setup local use).

![CI](https://github.com/AnishBhardwajTech/ciphervault/actions/workflows/ci.yml/badge.svg)

## Features

- **Password-derived keys**: PBKDF2-HMAC-SHA256, 600,000 iterations, 16-byte random salt per user
- **Authenticated encryption**: AES-256-GCM with a fresh 12-byte nonce per record, so tampering is detected
- **Master-password authentication** without storing the password or its hash (an encrypted verifier token is checked instead)
- **Brute-force protection**: account lockout for 15 minutes after 5 failed attempts
- **Audit log** of every registration, login and password change
- **Row binding**: each ciphertext is tied to its owner and entry name via AES-GCM associated data, so copying an encrypted row onto another entry fails to decrypt
- **Master password rotation** that re-encrypts every entry in a single transaction
- **Secure password generator** using Python's `secrets` module
- Multi-user, with each user's entries isolated

## Security design

```
master password ──► PBKDF2-HMAC-SHA256 (salt, 600k iters) ──► 256-bit key (memory only)
                                                                │
         ┌──────────────────────────────────────────────────────┤
         ▼                                                      ▼
 AES-GCM(key, "verifier")                         AES-GCM(key, entry JSON, aad = user_id:name)
 stored in users table                            stored in entries table (nonce + ciphertext)
 used to check the password at login
```

| Threat | Mitigation |
| --- | --- |
| Database dump is stolen | Only salts, nonces and ciphertext are stored; no password or hash |
| Offline password guessing | 600k PBKDF2 iterations make each guess expensive; unique salts block rainbow tables |
| Online password guessing | Lockout after 5 failures, all attempts audited |
| Ciphertext tampering or row swapping | AES-GCM authentication tag plus associated data |
| SQL injection | Every query is parameterised |

## Quick start (SQLite)

```bash
pip install -r requirements.txt
python -m ciphervault init              # create your vault
python -m ciphervault add github        # store a secret
python -m ciphervault add aws --generate
python -m ciphervault list
python -m ciphervault get github --show
python -m ciphervault passwd            # rotate master password
python -m ciphervault generate -n 24
```

## Running on MS SQL Server

With Docker:

```bash
docker compose up -d mssql
docker compose run --rm app init
docker compose run --rm app add github
```

Or point at any SQL Server (needs Microsoft ODBC Driver 18):

```bash
export CIPHERVAULT_DB='mssql://DRIVER={ODBC Driver 18 for SQL Server};SERVER=localhost,1433;DATABASE=master;UID=sa;PWD=...;TrustServerCertificate=yes'
python -m ciphervault init
```

The T-SQL schema is in [`sql/schema_mssql.sql`](sql/schema_mssql.sql) and is created automatically on first run.

## Tests

```bash
pip install -r requirements-dev.txt
pytest                                   # SQLite
CIPHERVAULT_TEST_MSSQL='DRIVER=...' pytest   # also runs every test against SQL Server
```

The suite covers key derivation, encryption round trips, tampering, wrong keys, lockout, audit logging, user isolation, row swapping and password rotation. GitHub Actions runs it on Python 3.11 to 3.13, against a real SQL Server 2022 service container, and builds the Docker image on every push.

## Project layout

```
ciphervault/
  crypto.py   PBKDF2 key derivation, AES-GCM, password generator
  vault.py    authentication, lockout, audit log, encrypted entries
  db.py       SQLite / MS SQL Server connection layer
  cli.py      command-line interface
sql/schema_mssql.sql
tests/
```
