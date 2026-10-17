"""
Safe SQL AST Validation and Query Governor Engine.
Prevents multi-statement SQL injection, DDL execution, catalog reconnaissance, and enforces query limits.
"""

import re
import sqlparse
import structlog
from sqlparse.sql import Statement

from src.core.config import settings
from src.core.exceptions import DatabaseSecurityError

logger = structlog.get_logger(__name__)

PROHIBITED_COMMAND_TYPES = {
    "DROP",
    "TRUNCATE",
    "ALTER",
    "CREATE",
    "GRANT",
    "REVOKE",
    "EXECUTE",
    "CALL"
}

DANGEROUS_INTERNAL_PROBES = [
    "pg_sleep",
    "pg_read_file",
    "pg_write_file",
    "pg_ls_dir",
    "copy_to_program",
    "pg_terminate_backend",
    "pg_class",
    "pg_proc",
    "pg_shadow",
    "pg_authid",
    "current_setting"
]


def strip_sql_comments(sql: str) -> str:
    """Removes single-line and multi-line SQL comments to prevent comment-based obfuscation."""
    # Remove block comments /* ... */
    no_block = re.sub(r'/\*.*?\*/', ' ', sql, flags=re.DOTALL)
    # Remove line comments -- ...
    no_line = re.sub(r'--.*$', ' ', no_block, flags=re.MULTILINE)
    return ' '.join(no_line.split())


def validate_read_only_sql(query: str) -> None:
    """
    Validates that a SQL string represents a single, valid, read-only SELECT statement.
    Validates table allowlists/denylists and detects catalog probes.
    Raises DatabaseSecurityError if violations are detected.
    """
    if not query or not query.strip():
        raise DatabaseSecurityError("SQL query string cannot be empty")

    cleaned_sql = strip_sql_comments(query.strip())

    parsed: list[Statement] = sqlparse.parse(cleaned_sql)
    if not parsed:
        raise DatabaseSecurityError("Unable to parse SQL statement")

    # 1. Statement chaining prevention (e.g., SELECT ...; DROP ...)
    meaningful_statements = [s for s in parsed if str(s).strip().strip(";")]
    if len(meaningful_statements) > 1:
        logger.warning("Security Block: Multi-statement query detected", query=query)
        raise DatabaseSecurityError(
            f"Multi-statement queries are prohibited. Found {len(meaningful_statements)} statements."
        )

    statement = meaningful_statements[0]
    statement_type = statement.get_type().upper()

    # 2. Statement type validation
    if statement_type != "SELECT":
        logger.warning(
            "Security Block: Non-SELECT statement submitted to read endpoint",
            type=statement_type,
            query=query
        )
        raise DatabaseSecurityError(
            f"Only SELECT statements are permitted on read-only endpoints. Received: {statement_type}"
        )

    # 3. Prohibited keyword check in token stream
    for token in statement.flatten():
        val = token.value.upper()
        if val in PROHIBITED_COMMAND_TYPES:
            logger.warning("Security Block: Prohibited keyword found in AST tokens", keyword=val)
            raise DatabaseSecurityError(f"Prohibited keyword '{val}' detected in query")

    # 4. Check for dangerous Postgres administrative functions & catalog probes
    query_lower = cleaned_sql.lower()
    for probe in DANGEROUS_INTERNAL_PROBES:
        if probe in query_lower:
            logger.warning("Security Block: Prohibited administrative or catalog probe", probe=probe)
            raise DatabaseSecurityError(f"Access to internal object or function '{probe}' is strictly prohibited")

    # 5. Table Denylist Enforcement (Sensitive tables like salaries, credentials, api_keys)
    for denied in settings.DENIED_TABLES:
        pattern = rf"\b{re.escape(denied.lower())}\b"
        if re.search(pattern, query_lower):
            logger.warning("Security Block: Access to denied sensitive table attempted", table=denied)
            raise DatabaseSecurityError(f"Access to sensitive table '{denied}' is restricted by enterprise policy")


def enforce_query_governor(query: str) -> str:
    """
    Query Governor: Ensures every SELECT query has a LIMIT clause to prevent
    unbounded table scans and memory exhaustion. Automatically appends LIMIT if absent.
    """
    cleaned_sql = query.strip().rstrip(";")
    query_lower = cleaned_sql.lower()

    # If query already specifies a LIMIT, keep it as long as it doesn't exceed maximum ceiling
    if re.search(r'\blimit\s+\d+\b', query_lower):
        match = re.search(r'\blimit\s+(\d+)\b', query_lower)
        if match:
            requested_limit = int(match.group(1))
            if requested_limit > settings.QUERY_MAX_ROWS:
                # Cap excessive limits to max allowed rows
                cleaned_sql = re.sub(
                    r'\blimit\s+\d+\b',
                    f"LIMIT {settings.QUERY_MAX_ROWS}",
                    cleaned_sql,
                    flags=re.IGNORECASE
                )
        return cleaned_sql

    # Otherwise append default limit
    return f"{cleaned_sql} LIMIT {settings.QUERY_DEFAULT_LIMIT}"
