.PHONY: help setup install test test-coverage lint format security-check clean docker-build docker-up docker-down

# Default target
help:
	@echo "CyberSentinel DLP - Development Commands"
	@echo ""
	@echo "Setup & Installation:"
	@echo "  make setup           - Complete development environment setup"
	@echo "  make install         - Install all dependencies"
	@echo "  make install-dev     - Install development dependencies"
	@echo ""
	@echo "Testing:"
	@echo "  make test            - Run all tests"
	@echo "  make test-backend    - Run backend tests only"
	@echo "  make test-coverage   - Run tests with coverage report"
	@echo "  make test-fast       - Run fast unit tests only"
	@echo ""
	@echo "Code Quality:"
	@echo "  make lint            - Run all linters"
	@echo "  make format          - Auto-format code with black/prettier"
	@echo "  make security-check  - Run security scanners"
	@echo "  make type-check      - Run type checkers"
	@echo ""
	@echo "Docker:"
	@echo "  make docker-build    - Build all Docker images"
	@echo "  make docker-up       - Start all services"
	@echo "  make docker-down     - Stop all services"
	@echo "  make docker-logs     - View service logs"
	@echo ""
	@echo "Database:"
	@echo "  make db-migrate      - Run database migrations"
	@echo "  make db-upgrade      - Upgrade database to latest"
	@echo "  make db-reset        - Reset database (WARNING: destroys data)"
	@echo ""
	@echo "Utilities:"
	@echo "  make clean           - Remove build artifacts"
	@echo "  make pre-commit      - Install pre-commit hooks"
	@echo ""

# Setup & Installation
setup: install pre-commit
	@echo "✅ Development environment setup complete!"

install: install-backend install-dashboard
	@echo "✅ All dependencies installed!"

install-backend:
	@echo "📦 Installing backend dependencies..."
	cd server && pip install -r requirements.txt

install-dashboard:
	@echo "📦 Installing dashboard dependencies..."
	cd dashboard && npm ci

install-dev: install-backend
	@echo "📦 Installing development tools..."
	pip install pytest pytest-cov pytest-asyncio black flake8 mypy bandit radon pre-commit

# Testing
test: test-backend test-dashboard
	@echo "✅ All tests passed!"

test-backend:
	@echo "🧪 Running backend tests..."
	cd server && pytest tests/ -v

test-dashboard:
	@echo "🧪 Running dashboard tests..."
	cd dashboard && npm run test

test-coverage:
	@echo "📊 Running tests with coverage..."
	cd server && pytest tests/ --cov=app --cov-report=term --cov-report=html
	@echo "📊 Coverage report generated at server/htmlcov/index.html"

test-fast:
	@echo "⚡ Running fast unit tests..."
	cd server && pytest tests/ -v -m "not slow"

# Code Quality
lint: lint-backend lint-dashboard
	@echo "✅ Linting complete!"

lint-backend:
	@echo "🔍 Linting backend..."
	cd server && flake8 app/ tests/ --max-line-length=120 --extend-ignore=E203,W503
	cd server && black --check app/ tests/

lint-dashboard:
	@echo "🔍 Linting dashboard..."
	cd dashboard && npm run lint

format: format-backend format-dashboard
	@echo "✨ Code formatted!"

format-backend:
	@echo "✨ Formatting backend code..."
	cd server && black app/ tests/
	cd server && isort app/ tests/

format-dashboard:
	@echo "✨ Formatting dashboard code..."
	cd dashboard && npm run format

security-check:
	@echo "🔒 Running security checks..."
	cd server && bandit -r app/ -f screen
	cd dashboard && npm audit

type-check:
	@echo "🔎 Running type checks..."
	cd server && mypy app/ --ignore-missing-imports
	cd dashboard && npx tsc --noEmit

# Docker
docker-build:
	@echo "🐳 Building Docker images..."
	docker-compose build

docker-up:
	@echo "🚀 Starting services..."
	docker-compose up -d
	@echo "✅ Services started!"
	@echo "   Dashboard: http://localhost:3000"
	@echo "   API: http://localhost:8000"
	@echo "   API Docs: http://localhost:8000/docs"

docker-down:
	@echo "🛑 Stopping services..."
	docker-compose down

docker-logs:
	docker-compose logs -f

docker-restart: docker-down docker-up
	@echo "🔄 Services restarted!"

docker-clean:
	@echo "🧹 Cleaning Docker resources..."
	docker-compose down -v
	docker system prune -f

# Database
db-migrate:
	@echo "📊 Running database migrations..."
	cd server && alembic revision --autogenerate -m "$(message)"

db-upgrade:
	@echo "📊 Upgrading database..."
	cd server && alembic upgrade head

db-downgrade:
	@echo "📊 Downgrading database..."
	cd server && alembic downgrade -1

db-reset:
	@echo "⚠️  WARNING: This will destroy all data!"
	@read -p "Are you sure? [y/N] " -n 1 -r; \
	echo; \
	if [[ $$REPLY =~ ^[Yy]$$ ]]; then \
		docker-compose down -v; \
		docker-compose up -d postgres redis opensearch; \
		sleep 10; \
		cd server && alembic upgrade head; \
		echo "✅ Database reset complete!"; \
	fi

# Pre-commit hooks
pre-commit:
	@echo "🪝 Installing pre-commit hooks..."
	pre-commit install
	pre-commit install --hook-type commit-msg
	@echo "✅ Pre-commit hooks installed!"

pre-commit-run:
	pre-commit run --all-files

# Utilities
clean: clean-backend clean-dashboard
	@echo "✅ Cleanup complete!"

clean-backend:
	@echo "🧹 Cleaning backend artifacts..."
	find server -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find server -type f -name "*.pyc" -delete 2>/dev/null || true
	find server -type f -name "*.pyo" -delete 2>/dev/null || true
	find server -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
	rm -rf server/.pytest_cache server/.mypy_cache server/htmlcov server/.coverage 2>/dev/null || true

clean-dashboard:
	@echo "🧹 Cleaning dashboard artifacts..."
	rm -rf dashboard/.next dashboard/node_modules/.cache 2>/dev/null || true

clean-all: clean docker-clean
	@echo "🧹 Deep cleaning..."
	rm -rf server/venv dashboard/node_modules

# CI/CD Simulation
ci-test: install-dev lint test-coverage security-check
	@echo "✅ CI checks passed!"

# Quick development workflow
dev: format lint test-fast
	@echo "✅ Quick dev checks passed!"

# Production checks
prod-check: lint test-coverage security-check type-check
	@echo "✅ Production checks passed!"
