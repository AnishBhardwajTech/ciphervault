-- CipherVault schema for Microsoft SQL Server.
-- Batches are separated by GO; db.py runs each one in turn.
IF OBJECT_ID('dbo.users', 'U') IS NULL
CREATE TABLE dbo.users (
    id              INT IDENTITY(1,1) PRIMARY KEY,
    username        NVARCHAR(100)  NOT NULL UNIQUE,
    salt            VARBINARY(32)  NOT NULL,
    kdf_iterations  INT            NOT NULL,
    verifier_nonce  VARBINARY(12)  NOT NULL,
    verifier        VARBINARY(128) NOT NULL,
    failed_attempts INT            NOT NULL DEFAULT 0,
    locked_until    DATETIME2      NULL,
    created_at      DATETIME2      NOT NULL DEFAULT SYSUTCDATETIME()
);
GO
IF OBJECT_ID('dbo.entries', 'U') IS NULL
CREATE TABLE dbo.entries (
    id          INT IDENTITY(1,1) PRIMARY KEY,
    user_id     INT            NOT NULL REFERENCES dbo.users(id) ON DELETE CASCADE,
    name        NVARCHAR(200)  NOT NULL,
    nonce       VARBINARY(12)  NOT NULL,
    ciphertext  VARBINARY(MAX) NOT NULL,
    created_at  DATETIME2      NOT NULL DEFAULT SYSUTCDATETIME(),
    updated_at  DATETIME2      NOT NULL DEFAULT SYSUTCDATETIME(),
    CONSTRAINT uq_entries_user_name UNIQUE (user_id, name)
);
GO
IF OBJECT_ID('dbo.audit_log', 'U') IS NULL
CREATE TABLE dbo.audit_log (
    id         INT IDENTITY(1,1) PRIMARY KEY,
    username   NVARCHAR(100) NOT NULL,
    action     NVARCHAR(50)  NOT NULL,
    success    BIT           NOT NULL,
    created_at DATETIME2     NOT NULL DEFAULT SYSUTCDATETIME()
);
GO
