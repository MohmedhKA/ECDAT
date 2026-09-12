import pytest
from ecdat.models import XTier
from ecdat.schema_extractor.sql_parser import parse_sql_ddl_lifespan
from ecdat.schema_extractor.orm_parser import parse_orm_schema_lifespan

def test_sql_ddl_retention_comment_parsing():
    sql = """
    -- Table with explicit 7 year retention policy
    CREATE TABLE patient_records (
        id VARCHAR(64) PRIMARY KEY,
        encrypted_ssn BYTEA NOT NULL,
        data_payload JSONB
    ); -- retention: 7 years

    CREATE TABLE user_sessions (
        session_id VARCHAR(64) PRIMARY KEY,
        token_hash VARCHAR(128) NOT NULL,
        expires_at TIMESTAMP NOT NULL
    );
    """
    results = parse_sql_ddl_lifespan(sql, "test_schema.sql")
    assert "patient_records" in results
    tier, years, prov = results["patient_records"]
    assert tier == XTier.OPERATIONAL or tier == XTier.ARCHIVAL
    assert years == 7.0
    assert "sql_retention_comment" in prov

    assert "user_sessions" in results
    tier_s, years_s, prov_s = results["user_sessions"]
    assert tier_s == XTier.SHORT_TERM
    assert years_s == 1.0

def test_prisma_orm_schema_parsing():
    prisma = """
    model AuditLog {
        id        String   @id @default(uuid())
        action    String
        // retention: 10 years
        createdAt DateTime @default(now())
    }

    model CaptchaChallenge {
        id        String   @id
        token     String
        expiresAt DateTime
    }
    """
    results = parse_orm_schema_lifespan(prisma, "schema.prisma")
    assert "auditlog" in results
    tier, years, prov = results["auditlog"]
    assert tier == XTier.ARCHIVAL
    assert years == 10.0

    assert "captchachallenge" in results
    tier_c, years_c, prov_c = results["captchachallenge"]
    assert tier_c == XTier.SHORT_TERM
