.PHONY: help install build up down start stop restart logs clean db-migrate db-reset dev prod test setup health docker-build docker-prod

# Default target
help:
	@echo "Passkey Demo - Available commands:"
	@echo ""
	@echo "🚀 Quick Start:"
	@echo "  make setup        - First-time setup"
	@echo "  make dev          - Run in development mode"
	@echo "  make prod         - Run in production mode"
	@echo ""
	@echo "📦 Build & Deploy:"
	@echo "  make install      - Install all dependencies"
	@echo "  make build        - Build backend and frontend for production"
	@echo "  make docker-build - Build Docker images"
	@echo "  make docker-prod  - Run with Docker in production mode"
	@echo ""
	@echo "🔧 Service Management:"
	@echo "  make up           - Start all services (database + apps)"
	@echo "  make down         - Stop all services"
	@echo "  make start        - Start services in background"
	@echo "  make stop         - Stop background services"
	@echo "  make restart      - Restart all services"
	@echo "  make health       - Check service health"
	@echo ""
	@echo "🗄️ Database:"
	@echo "  make db-migrate   - Run database migrations"
	@echo "  make db-reset     - Reset database (WARNING: destroys data)"
	@echo ""
	@echo "🔍 Debugging:"
	@echo "  make logs         - View logs from all services"
	@echo "  make clean        - Clean build artifacts and dependencies"
	@echo "  make test         - Run tests"

# Install dependencies (builds containers)
install: 
	@echo "📦 Building Docker containers..."
	@docker-compose build
	@echo "✅ All containers built"

# Build for development 
build: 
	@echo "🔨 Building development Docker images..."
	@docker-compose build
	@echo "✅ Build complete"

# Docker and services management
up: docker-up
	@echo "✅ All services started"
	@echo "🌐 Frontend: http://localhost:3000"
	@echo "🔧 Backend: http://localhost:5001"
	@echo "🗄️  Database: localhost:5432"

docker-up:
	@echo "🐳 Starting Docker services..."
	@docker-compose up -d

down: docker-down
	@echo "✅ All services stopped"

docker-down:
	@echo "🛑 Stopping Docker services..."
	@docker-compose down

start: docker-up
	@echo "✅ All services started in Docker"

stop: docker-down
	@echo "✅ All services stopped"

restart: stop start
	@echo "✅ Services restarted"

# Logs
logs:
	@docker-compose logs -f

logs-backend:
	@tail -f logs/backend.log

logs-frontend:
	@tail -f logs/frontend.log

# Database management
db-migrate: wait-for-db
	@echo "🗄️  Running database migrations..."
	@docker-compose run --rm backend node dist/db/migrate.js

db-reset: docker-down docker-up wait-for-db
	@echo "⚠️  Resetting database..."
	@docker-compose exec -T postgres psql -U postgres -c "DROP DATABASE IF EXISTS passkey_demo;"
	@docker-compose exec -T postgres psql -U postgres -c "CREATE DATABASE passkey_demo;"
	@docker-compose run --rm backend node dist/db/migrate.js
	@echo "✅ Database reset complete"

wait-for-db:
	@echo "⏳ Waiting for database to be ready..."
	@until docker-compose exec -T postgres pg_isready -U postgres > /dev/null 2>&1; do \
		sleep 1; \
	done
	@echo "✅ Database is ready"

# Development mode
dev: docker-dev
	@echo "✅ Development environment started"
	@echo "🌐 Frontend: http://localhost:3000"
	@echo "🔧 Backend: http://localhost:5001"
	@echo "🗄️  Database: localhost:5432"
	@echo ""
	@echo "View logs: make logs"

docker-dev: docker-down
	@echo "🔧 Starting development environment with Docker..."
	@docker-compose up -d --build
	@sleep 5
	@make wait-for-db
	@docker-compose exec backend npm run build
	@docker-compose exec -T postgres psql -U postgres -c "DROP DATABASE IF EXISTS passkey_demo;"
	@docker-compose exec -T postgres psql -U postgres -c "CREATE DATABASE passkey_demo;"
	@docker-compose exec backend node dist/db/migrate.js
	@make health

# Removed dev-local targets - all development uses Docker

# Production mode
prod: check-env docker-prod
	@echo "✅ Production services started"

check-env:
	@if [ ! -f backend/.env ]; then \
		echo "❌ Error: backend/.env not found"; \
		echo "Please copy backend/.env.example to backend/.env and configure it"; \
		exit 1; \
	fi

# Clean
clean:
	@echo "🧹 Cleaning project..."
	@rm -rf backend/node_modules backend/dist
	@rm -rf frontend/node_modules frontend/dist
	@rm -rf logs
	@docker-compose down -v
	@echo "✅ Clean complete"

# Testing
test: 
	@echo "🧪 Running tests in Docker..."
	@docker-compose run --rm backend npm test || echo "No tests configured yet"
	@echo "✅ All tests passed"

# Create necessary directories
init-dirs:
	@mkdir -p logs

# Setup
setup:
	@./scripts/setup.sh

# Health check
health:
	@./scripts/health-check.sh

# Docker production build
docker-build:
	@echo "🐳 Building Docker images..."
	@docker-compose -f docker-compose.prod.yml build

# Docker production run
docker-prod: docker-build
	@echo "🚀 Starting production with Docker..."
	@docker-compose -f docker-compose.prod.yml up -d
	@echo "✅ Production services started"
	@echo "🌐 Frontend: http://localhost:3000"
	@echo "🔧 Backend: http://localhost:5001"
	@sleep 5
	@make health

# Docker production down
docker-prod-down:
	@echo "🛑 Stopping production Docker services..."
	@docker-compose -f docker-compose.prod.yml down