"""
SeceoKnight DLP - Main FastAPI Application
Enterprise-grade Data Loss Prevention Platform
"""

import logging
import sys
import asyncio
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI, Request, status, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from prometheus_client import make_asgi_app
import structlog

from app.core.config import settings
from app.core.logging import setup_logging
from app.core.database import init_databases, close_databases, Base
import app.core.database as _db
from app.core.cache import init_cache, close_cache
from app.core.opensearch import init_opensearch, close_opensearch
from app.middleware.rate_limit import RateLimitMiddleware
from app.middleware.request_id import RequestIDMiddleware
from app.middleware.security import SecurityHeadersMiddleware
from app.api.v1 import api_router

# Setup structured logging
setup_logging()
logger = structlog.get_logger()


async def _auto_init_schema_and_admin():
    """Create tables if missing and seed the default admin user on first boot.

    Safe to call from multiple uvicorn workers simultaneously — uses
    INSERT … ON CONFLICT to avoid duplicate-key errors from race conditions.
    """
    from sqlalchemy import text
    from app.core.security import get_password_hash

    # Import all models so Base.metadata knows about them
    import app.models.user  # noqa: F401
    import app.models.agent  # noqa: F401
    import app.models.policy  # noqa: F401
    import app.models.event  # noqa: F401
    import app.models.alert  # noqa: F401
    import app.models.google_drive  # noqa: F401
    import app.models.onedrive  # noqa: F401
    import app.models.classified_file  # noqa: F401

    try:
        # Check if tables already exist (avoid re-creating ENUM types which crashes asyncpg)
        async with _db.postgres_engine.connect() as conn:
            result = await conn.execute(
                text("SELECT EXISTS(SELECT 1 FROM information_schema.tables WHERE table_name='users')")
            )
            tables_exist = result.scalar()

        if not tables_exist:
            async with _db.postgres_engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
            logger.info("Database tables created")
        else:
            logger.info("Database tables already exist, skipping creation")

        # Sequences live in Alembic migrations, but fresh installs use
        # ``create_all`` and never run migrations — so without this the
        # ``agent_code_seq`` (added by migration 018) would never exist
        # on a clean box, _next_agent_code() would fail, and the UI would
        # fall back to the raw agent UUID instead of the "001/002/..."
        # display code. IF NOT EXISTS makes this safe to call on every
        # boot, including upgrades where Alembic already created it.
        async with _db.postgres_engine.begin() as conn:
            await conn.execute(
                text("CREATE SEQUENCE IF NOT EXISTS agent_code_seq START 1")
            )

        # Seed default admin if no users exist yet.
        # Uses ON CONFLICT to handle race conditions with multiple workers.
        async with _db.postgres_session_factory() as session:
            result = await session.execute(
                text("SELECT COUNT(*) FROM users")
            )
            user_count = result.scalar()
            if user_count == 0:
                # Fixed default password. Operators are expected to change it
                # after first login via Settings -> Profile -> Change Password.
                # Must meet the app's password policy (>=8 chars, letters+digits+symbol).
                admin_password = "Admin@1234"
                hashed = get_password_hash(admin_password)
                await session.execute(
                    text(
                        "INSERT INTO users (id, email, hashed_password, full_name, role, organization, "
                        "is_active, is_verified, must_change_password, created_at, updated_at) "
                        "VALUES (gen_random_uuid(), 'admin', :pw, 'Administrator', 'ADMIN', 'SeceoKnight', "
                        "TRUE, TRUE, FALSE, NOW(), NOW()) "
                        "ON CONFLICT (email) DO NOTHING"
                    ),
                    {"pw": hashed},
                )
                await session.commit()
                logger.warning(
                    "DEFAULT ADMIN CREATED — change this password after first login",
                    username="admin",
                    default_password=admin_password,
                    must_change_password=False,
                )
            else:
                logger.info("Users table already populated, skipping admin seed")
    except Exception as e:
        # Non-fatal: another worker may have already completed initialization
        logger.warning("Auto-init encountered an error (likely harmless race condition)", error=str(e))


async def _seed_default_roles():
    """Import default RBAC roles on first boot if the roles table is empty."""
    import json
    from pathlib import Path
    from sqlalchemy import text

    try:
        async with _db.postgres_session_factory() as session:
            result = await session.execute(text("SELECT COUNT(*) FROM roles"))
            role_count = result.scalar()

            if role_count > 0:
                logger.info("Roles table already populated, skipping seed", count=role_count)
                return

            roles_file = Path(__file__).parent.parent / "data" / "default_roles.json"
            if not roles_file.exists():
                logger.warning("Default roles file not found", path=str(roles_file))
                return

            roles_data = json.loads(roles_file.read_text())

            for role in roles_data:
                await session.execute(
                    text(
                        "INSERT INTO roles (id, name, permissions, created_at) "
                        "VALUES (gen_random_uuid(), :name, :permissions, NOW()) "
                        "ON CONFLICT (name) DO NOTHING"
                    ),
                    {
                        "name": role["name"],
                        "permissions": json.dumps(role["permissions"]),
                    },
                )

            await session.commit()
            logger.info("Default roles seeded", count=len(roles_data))

    except Exception as e:
        logger.warning("Default roles seed encountered an error", error=str(e))


async def _seed_default_labels():
    """Import default data labels on first boot if the data_labels table is empty."""
    import json
    from pathlib import Path
    from sqlalchemy import text

    try:
        async with _db.postgres_session_factory() as session:
            result = await session.execute(text("SELECT COUNT(*) FROM data_labels"))
            label_count = result.scalar()

            if label_count > 0:
                logger.info("Data labels table already populated, skipping seed", count=label_count)
                return

            labels_file = Path(__file__).parent.parent / "data" / "default_labels.json"
            if not labels_file.exists():
                logger.warning("Default labels file not found", path=str(labels_file))
                return

            labels_data = json.loads(labels_file.read_text())

            for label in labels_data:
                await session.execute(
                    text(
                        "INSERT INTO data_labels (id, name, severity, description, color, created_at, updated_at) "
                        "VALUES (gen_random_uuid(), :name, :severity, :description, :color, NOW(), NOW()) "
                        "ON CONFLICT (name) DO NOTHING"
                    ),
                    {
                        "name": label["name"],
                        "severity": label["severity"],
                        "description": label.get("description"),
                        "color": label.get("color"),
                    },
                )

            await session.commit()
            logger.info("Default data labels seeded", count=len(labels_data))

    except Exception as e:
        logger.warning("Default labels seed encountered an error", error=str(e))


async def _seed_default_rules():
    """Import default classification rules on first boot if the rules table is empty."""
    import json
    from pathlib import Path
    from sqlalchemy import text

    try:
        async with _db.postgres_session_factory() as session:
            result = await session.execute(text("SELECT COUNT(*) FROM rules"))
            rule_count = result.scalar()

            if rule_count > 0:
                logger.info("Rules table already populated, skipping default rules seed", count=rule_count)
                return

            # Load default rules from JSON
            rules_file = Path(__file__).parent.parent / "data" / "default_rules.json"
            if not rules_file.exists():
                logger.warning("Default rules file not found", path=str(rules_file))
                return

            rules_data = json.loads(rules_file.read_text())

            # Get admin user ID for created_by field
            result = await session.execute(text("SELECT id FROM users WHERE role = 'ADMIN' LIMIT 1"))
            admin_row = result.first()
            if not admin_row:
                logger.warning("No admin user found, skipping default rules seed")
                return
            admin_id = admin_row[0]

            # Build label name -> id lookup from data_labels table
            label_rows = await session.execute(text("SELECT id, name FROM data_labels"))
            label_map = {row[1]: row[0] for row in label_rows.fetchall()}

            for rule in rules_data:
                # Resolve label name to label_id
                label_name = rule.get("label")
                label_id = label_map.get(label_name) if label_name else None

                await session.execute(
                    text(
                        "INSERT INTO rules (id, name, description, enabled, type, pattern, regex_flags, "
                        "keywords, case_sensitive, threshold, weight, priority, label_id, "
                        "classification_labels, severity, "
                        "category, tags, created_by, created_at, updated_at, match_count) "
                        "VALUES (gen_random_uuid(), :name, :description, :enabled, :type, :pattern, "
                        ":regex_flags, :keywords, :case_sensitive, :threshold, :weight, :priority, :label_id, "
                        ":classification_labels, :severity, :category, :tags, :created_by, NOW(), NOW(), 0) "
                        "ON CONFLICT (name) DO NOTHING"
                    ),
                    {
                        "name": rule["name"],
                        "description": rule.get("description"),
                        "enabled": rule.get("enabled", True),
                        "type": rule["type"],
                        "pattern": rule.get("pattern"),
                        "regex_flags": json.dumps(rule["regex_flags"]) if rule.get("regex_flags") else None,
                        "keywords": json.dumps(rule["keywords"]) if rule.get("keywords") else None,
                        "case_sensitive": rule.get("case_sensitive", False),
                        "threshold": rule.get("threshold", 1),
                        "weight": rule.get("weight", 0.5),
                        "priority": rule.get("priority", 100),
                        "label_id": str(label_id) if label_id else None,
                        "classification_labels": json.dumps(rule["classification_labels"]) if rule.get("classification_labels") else None,
                        "severity": rule.get("severity", "medium"),
                        "category": rule.get("category"),
                        "tags": json.dumps(rule["tags"]) if rule.get("tags") else None,
                        "created_by": admin_id,
                    },
                )

            await session.commit()
            logger.info("Default classification rules seeded", count=len(rules_data))

    except Exception as e:
        logger.warning("Default rules seed encountered an error", error=str(e))


async def _seed_default_policies():
    """Import default blocking policies on first boot if the policies table is empty."""
    import json
    from pathlib import Path
    from sqlalchemy import text

    try:
        async with _db.postgres_session_factory() as session:
            result = await session.execute(text("SELECT COUNT(*) FROM policies"))
            policy_count = result.scalar()

            if policy_count > 0:
                logger.info("Policies table already populated, skipping default policies seed", count=policy_count)
                return

            policies_file = Path(__file__).parent.parent / "data" / "default_policies.json"
            if not policies_file.exists():
                logger.warning("Default policies file not found", path=str(policies_file))
                return

            policies_data = json.loads(policies_file.read_text())

            result = await session.execute(text("SELECT id FROM users WHERE role = 'ADMIN' LIMIT 1"))
            admin_row = result.first()
            if not admin_row:
                logger.warning("No admin user found, skipping default policies seed")
                return
            admin_id = admin_row[0]

            for policy in policies_data:
                await session.execute(
                    text(
                        "INSERT INTO policies (id, name, description, enabled, priority, type, severity, "
                        "config, conditions, actions, compliance_tags, agent_ids, created_by, created_at, updated_at) "
                        "VALUES (gen_random_uuid(), :name, :description, :enabled, :priority, :type, :severity, "
                        ":config, :conditions, :actions, :compliance_tags, :agent_ids, :created_by, NOW(), NOW()) "
                        "ON CONFLICT (name) DO NOTHING"
                    ),
                    {
                        "name": policy["name"],
                        "description": policy.get("description"),
                        "enabled": policy.get("enabled", True),
                        "priority": policy.get("priority", 100),
                        "type": policy.get("type"),
                        "severity": policy.get("severity", "medium"),
                        "config": json.dumps(policy.get("config", {})),
                        "conditions": json.dumps(policy["conditions"]),
                        "actions": json.dumps(policy["actions"]),
                        "compliance_tags": None,
                        "agent_ids": None,
                        "created_by": admin_id,
                    },
                )

            await session.commit()
            logger.info("Default blocking policies seeded", count=len(policies_data))

    except Exception as e:
        logger.warning("Default policies seed encountered an error", error=str(e))


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator:
    """
    Application lifespan manager for startup and shutdown events
    """
    # Startup
    logger.info("Starting SeceoKnight DLP Server", version=settings.VERSION)

    try:
        # Initialize databases
        await init_databases()
        logger.info("Databases initialized successfully")

        # Auto-create tables and seed default admin user on first boot
        await _auto_init_schema_and_admin()

        # Seed default RBAC roles on first boot
        await _seed_default_roles()

        # Seed default data labels on first boot
        await _seed_default_labels()

        # Seed default classification rules on first boot
        await _seed_default_rules()

        # Seed default blocking policies on first boot
        await _seed_default_policies()

        # Initialize cache
        await init_cache()
        logger.info("Cache initialized successfully")

        # Initialize OpenSearch
        await init_opensearch()
        logger.info("OpenSearch initialized successfully")

        # Additional startup tasks
        logger.info("Server startup complete",
                   environment=settings.ENVIRONMENT,
                   debug=settings.DEBUG,
                   port=settings.PORT)

        yield

    finally:
        # Shutdown
        logger.info("Shutting down SeceoKnight DLP Server")

        await close_opensearch()
        await close_cache()
        await close_databases()

        logger.info("Server shutdown complete")


# Create FastAPI application
app = FastAPI(
    title=settings.PROJECT_NAME,
    description=settings.PROJECT_DESCRIPTION,
    version=settings.VERSION,
    docs_url=f"{settings.API_V1_PREFIX}/docs",
    redoc_url=f"{settings.API_V1_PREFIX}/redoc",
    openapi_url=f"{settings.API_V1_PREFIX}/openapi.json",
    lifespan=lifespan,
)


# Middleware Configuration
# ========================

# Request ID tracking
app.add_middleware(RequestIDMiddleware)

# Security headers
app.add_middleware(SecurityHeadersMiddleware)

# Rate limiting
app.add_middleware(
    RateLimitMiddleware,
    max_requests=settings.RATE_LIMIT_REQUESTS,
    window_seconds=settings.RATE_LIMIT_WINDOW,
)

# CORS — reject wildcard origins in production.
_wildcard_cors = settings.CORS_ORIGINS == ["*"]
if _wildcard_cors and settings.ENVIRONMENT.lower() == "production":
    logger.error(
        "CORS_ORIGINS is set to ['*'] in production — this is insecure. "
        "Set CORS_ORIGINS to your dashboard URL(s) in .env."
    )
    raise SystemExit("Refusing to start with wildcard CORS in production.")

if _wildcard_cors:
    logger.warning("CORS_ORIGINS is ['*'] — acceptable for development only")

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=not _wildcard_cors,
    allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Request-ID", "X-Agent-Key"],
    expose_headers=["X-Request-ID"],
)

# Compression
app.add_middleware(GZipMiddleware, minimum_size=1000)

# Trusted hosts
if not settings.DEBUG:
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=settings.ALLOWED_HOSTS,
    )


# Exception Handlers
# ==================

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """
    Global exception handler for unhandled exceptions
    """
    logger.error(
        "Unhandled exception",
        exc_info=exc,
        path=request.url.path,
        method=request.method,
    )

    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": "Internal server error",
            "message": "An unexpected error occurred. Please contact support.",
            "request_id": request.state.request_id if hasattr(request.state, 'request_id') else None,
        },
    )


@app.exception_handler(ValueError)
async def value_error_handler(request: Request, exc: ValueError) -> JSONResponse:
    """
    Handler for validation errors
    """
    logger.warning(
        "Validation error",
        error=str(exc),
        path=request.url.path,
    )

    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={
            "error": "Validation error",
            "message": str(exc),
        },
    )


# API Routes
# ==========

@app.get("/", tags=["Root"])
async def root() -> dict:
    """
    Root endpoint - Health check
    """
    return {
        "service": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "status": "operational",
        "environment": settings.ENVIRONMENT,
    }


@app.get("/health", tags=["Health"])
async def health_check() -> dict:
    """
    Health check endpoint for load balancers and monitoring.
    Verifies connectivity to PostgreSQL, MongoDB, and Redis.
    Returns 503 if any critical dependency is unreachable.
    """
    from app.core.database import postgres_engine, mongodb_client
    from app.core.cache import redis_client
    from sqlalchemy import text

    checks = {"postgres": "fail", "mongodb": "fail", "redis": "fail"}

    try:
        if postgres_engine:
            async with postgres_engine.connect() as conn:
                await conn.execute(text("SELECT 1"))
            checks["postgres"] = "ok"
    except Exception:
        pass

    try:
        if mongodb_client:
            await mongodb_client.admin.command("ping")
            checks["mongodb"] = "ok"
    except Exception:
        pass

    try:
        if redis_client:
            await redis_client.ping()
            checks["redis"] = "ok"
    except Exception:
        pass

    all_ok = all(v == "ok" for v in checks.values())

    if not all_ok:
        from fastapi.responses import JSONResponse as _JSONResp
        return _JSONResp(
            status_code=503,
            content={
                "status": "unhealthy",
                "service": settings.PROJECT_NAME,
                "version": settings.VERSION,
                "checks": checks,
            },
        )

    return {
        "status": "healthy",
        "service": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "checks": checks,
    }


@app.get("/ready", tags=["Health"])
async def readiness_check() -> dict:
    """
    Readiness check endpoint for Kubernetes
    """
    from app.core.database import postgres_engine, mongodb_client
    from app.core.cache import redis_client
    from app.core.opensearch import opensearch_client
    from sqlalchemy import text

    services_status = {
        "database": "disconnected",
        "cache": "disconnected",
        "search": "unavailable"
    }

    try:
        # Check PostgreSQL connection
        if postgres_engine:
            async with postgres_engine.begin() as conn:
                await conn.execute(text("SELECT 1"))
            services_status["database"] = "connected"

        # Check MongoDB connection
        if mongodb_client:
            await mongodb_client.admin.command("ping")

        # Check Redis connection
        if redis_client:
            await redis_client.ping()
            services_status["cache"] = "connected"

        # Check OpenSearch connection (optional - not required for readiness)
        if opensearch_client:
            try:
                await opensearch_client.info()
                services_status["search"] = "connected"
            except Exception:
                services_status["search"] = "unavailable"
                logger.warning("OpenSearch unavailable during readiness check")

        # Server is ready if database and cache are connected
        # OpenSearch is optional
        is_ready = (services_status["database"] == "connected" and
                   services_status["cache"] == "connected")

        if not is_ready:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={
                    "status": "unready",
                    "services": services_status,
                },
            )

        return {
            "status": "ready",
            **services_status
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error("Readiness check failed", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "status": "unready",
                "error": str(e),
                "services": services_status
            },
        )


# Include API routers
app.include_router(api_router, prefix=settings.API_V1_PREFIX)


# Prometheus metrics endpoint
metrics_app = make_asgi_app()
app.mount("/metrics", metrics_app)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "app.main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.DEBUG,
        log_level="info",
        access_log=True,
    )
