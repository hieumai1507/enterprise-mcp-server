"""
Safe SQL AST Validation and Sanitization Engine.
Prevents multi-statement SQL injection, DDL execution, and syntax tampering.
"""


import sqlparse
import structlog
from sqlparse.sql import Statement

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


def validate_read_only_sql(query: str) -> None:
    """
    Validates that a SQL string represents a single, valid, read-only SELECT statement.
    Raises DatabaseSecurityError if violations are detected.
    """
    if not query or not query.strip():
        raise DatabaseSecurityError("SQL query string cannot be empty")

    parsed: list[Statement] = sqlparse.parse(query.strip())
    if not parsed:
        raise DatabaseSecurityError("Unable to parse SQL statement")

    # 1. Statement chaining prevention (e.g., SELECT ...; DROP ...)
    # Filter out empty statements (like trailing semicolons)
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

    # 4. Check for dangerous Postgres administrative functions
    dangerous_pg_functions = [
        "pg_sleep",
        "pg_read_file",
        "pg_write_file",
        "pg_ls_dir",
        "copy_to_program",
        "pg_terminate_backend"
    ]
    query_lower = query.lower()
    for func in dangerous_pg_functions:
        if func in query_lower:
            logger.warning("Security Block: Dangerous PostgreSQL internal function call", function=func)
            raise DatabaseSecurityError(f"Access to administrative function '{func}' is strictly prohibited")
