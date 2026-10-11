"""
Application Bootstrap and ASGI Entrypoint.
Enterprise PostgreSQL Model Context Protocol (MCP) Server.
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from src.audit.buffer import audit_buffer
from src.core.config import settings
from src.core.telemetry import configure_logging, logger
from src.db.session import db_manager
from src.mcp.transport.sse_endpoint import router as mcp_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifecycle manager for database pools and audit buffer background workers."""
    # 1. Initialize logging
    configure_logging()
    logger.info(
        "Starting Enterprise PostgreSQL MCP Server",
        version="1.0.0",
        environment=settings.ENVIRONMENT,
        oidc_issuer=settings.OIDC_ISSUER
    )

    # 2. Start isolated connection pools (No Token Passthrough)
    await db_manager.initialize()

    # 3. Start background audit buffer persistence worker
    await audit_buffer.start()

    yield

    # 4. Graceful shutdown
    logger.info("Initiating graceful shutdown sequence...")
    await audit_buffer.stop()
    await db_manager.close()
    logger.info("Enterprise PostgreSQL MCP Server stopped.")


app = FastAPI(
    title="Enterprise PostgreSQL MCP Server",
    version="1.0.0",
    description=(
        "Production-ready Model Context Protocol (MCP) server providing zero-trust "
        "relational data access to AI agents via OAuth 2.1, Tool-Level RBAC, and TypeSafe AI JEV Guardrails."
    ),
    lifespan=lifespan,
    docs_url="/docs" if settings.DEBUG or settings.ENVIRONMENT != "production" else None,
    redoc_url=None
)

# Cross-Origin Resource Sharing (CORS) Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount MCP Transports & Endpoints
app.include_router(mcp_router)


@app.get("/health", tags=["Health & Observability"])
async def health_check():
    """Liveness and readiness probe for Kubernetes / Docker orchestrators."""
    db_status = await db_manager.health_check()
    return {
        "status": "UP",
        "environment": settings.ENVIRONMENT,
        "database_pools": db_status,
        "audit_queue_size": audit_buffer.queue.qsize(),
        "guardrail_enabled": settings.JEV_ENABLED
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "src.main:app",
        host=settings.SERVER_HOST,
        port=settings.SERVER_PORT,
        reload=settings.DEBUG,
        workers=1
    )
