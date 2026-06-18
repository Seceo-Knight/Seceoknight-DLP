"""
Import Default Rules
Loads default classification rules from JSON file into database
"""

import asyncio
import json
import sys
import os
from pathlib import Path
from uuid import uuid4

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from app.services.rule_service import RuleService
import structlog

logger = structlog.get_logger()


async def import_default_rules():
    """Import default rules from JSON file"""
    rules_file = Path(__file__).parent.parent / "data" / "default_rules.json"

    if not rules_file.exists():
        logger.error("Default rules file not found", path=str(rules_file))
        return

    # Load rules from JSON
    with open(rules_file, 'r') as f:
        rules_data = json.load(f)

    logger.info(f"Loading {len(rules_data)} default rules...")

    # Create database connection using environment variables
    postgres_host = os.getenv("POSTGRES_HOST", "postgres")
    postgres_port = os.getenv("POSTGRES_PORT", "5432")
    postgres_user = os.getenv("POSTGRES_USER", "dlp_user")
    postgres_password = os.getenv("POSTGRES_PASSWORD", "")
    postgres_db = os.getenv("POSTGRES_DB", "seceoknight_dlp")

    postgres_url = f"postgresql+asyncpg://{postgres_user}:{postgres_password}@{postgres_host}:{postgres_port}/{postgres_db}"
    engine = create_async_engine(postgres_url, echo=False)
    async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    # Import rules
    success_count = 0
    error_count = 0

    async with async_session() as session:
        service = RuleService(session)

        for rule_data in rules_data:
            try:
                # Check if rule already exists
                existing = await service.get_rule_by_name(rule_data['name'])
                if existing:
                    logger.info(f"Rule '{rule_data['name']}' already exists, skipping")
                    continue

                # Create rule with system UUID
                system_user_id = uuid4()  # In production, use actual system/admin user ID

                await service.create_rule(
                    name=rule_data['name'],
                    description=rule_data['description'],
                    type=rule_data['type'],
                    pattern=rule_data.get('pattern'),
                    regex_flags=rule_data.get('regex_flags'),
                    keywords=rule_data.get('keywords'),
                    case_sensitive=rule_data.get('case_sensitive', False),
                    dictionary_path=rule_data.get('dictionary_path'),
                    threshold=rule_data['threshold'],
                    weight=rule_data['weight'],
                    classification_labels=rule_data.get('classification_labels'),
                    severity=rule_data['severity'],
                    category=rule_data.get('category'),
                    tags=rule_data.get('tags'),
                    enabled=rule_data.get('enabled', True),
                    created_by=system_user_id,
                )

                logger.info(f"✓ Imported rule: {rule_data['name']}")
                success_count += 1

            except Exception as e:
                logger.error(f"✗ Failed to import rule '{rule_data['name']}': {str(e)}")
                error_count += 1

    logger.info(
        "Import complete",
        success=success_count,
        errors=error_count,
        total=len(rules_data)
    )


if __name__ == "__main__":
    asyncio.run(import_default_rules())
