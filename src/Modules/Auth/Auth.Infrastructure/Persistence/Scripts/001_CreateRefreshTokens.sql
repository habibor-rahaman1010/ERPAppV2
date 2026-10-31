-- Auth module: refresh token store (run once against the ERP database)
IF SCHEMA_ID('auth') IS NULL
    EXEC('CREATE SCHEMA auth');
GO

IF OBJECT_ID('auth.RefreshTokens', 'U') IS NULL
BEGIN
    CREATE TABLE auth.RefreshTokens (
        Id                  UNIQUEIDENTIFIER NOT NULL PRIMARY KEY,
        UserId              NVARCHAR(128)    NOT NULL,   -- tblUserControl.UserId
        TokenHash           NVARCHAR(64)     NOT NULL,   -- SHA-256 hex of the raw token; raw token is never stored
        TokenFamily         UNIQUEIDENTIFIER NOT NULL,   -- all rotations of one login share a family
        CreatedAtUtc        DATETIME2        NOT NULL,
        ExpiresAtUtc        DATETIME2        NOT NULL,
        CreatedByIp         NVARCHAR(45)     NULL,
        RevokedAtUtc        DATETIME2        NULL,
        RevokedReason       NVARCHAR(50)     NULL,
        ReplacedByTokenId   UNIQUEIDENTIFIER NULL
    );

    CREATE UNIQUE INDEX IX_RefreshTokens_TokenHash   ON auth.RefreshTokens(TokenHash);
    CREATE INDEX        IX_RefreshTokens_TokenFamily ON auth.RefreshTokens(TokenFamily);
    CREATE INDEX        IX_RefreshTokens_UserId      ON auth.RefreshTokens(UserId);
END
GO
