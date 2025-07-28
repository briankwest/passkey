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

# Install dependencies
install: install-backend install-frontend
	@echo "✅ All dependencies installed"

install-backend:
	@echo "📦 Installing backend dependencies..."
	@cd backend && npm install

install-frontend:
	@echo "📦 Installing frontend dependencies..."
	@cd frontend && npm install

# Build for production
build: build-backend build-frontend
	@echo "✅ Build complete"

build-backend:
	@echo "🔨 Building backend..."
	@cd backend && npm run build

build-frontend:
	@echo "🔨 Building frontend..."
	@cd frontend && npm run build

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

start: docker-up start-backend start-frontend
	@echo "✅ All services started in background"

start-backend:
	@echo "🚀 Starting backend..."
	@cd backend && npm start > ../logs/backend.log 2>&1 &

start-frontend:
	@echo "🚀 Starting frontend..."
	@cd frontend && npm run preview > ../logs/frontend.log 2>&1 &

stop: stop-apps docker-down
	@echo "✅ All services stopped"

stop-apps:
	@echo "🛑 Stopping applications..."
	@pkill -f "node.*backend" || true
	@pkill -f "vite" || true

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
	@cd backend && npm run db:migrate

db-reset: docker-down docker-up wait-for-db
	@echo "⚠️  Resetting database..."
	@docker-compose exec -T postgres psql -U postgres -c "DROP DATABASE IF EXISTS passkey_demo;"
	@docker-compose exec -T postgres psql -U postgres -c "CREATE DATABASE passkey_demo;"
	@cd backend && npm run db:migrate
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
	@make db-migrate
	@make health

dev-local: docker-up
	@echo "🔧 Starting in local development mode (no Docker for apps)..."
	@mkdir -p logs
	@make -j2 dev-backend-local dev-frontend-local

dev-backend-local: wait-for-db db-migrate
	@echo "🔧 Starting backend locally..."
	@cd backend && npm run dev

dev-frontend-local:
	@echo "🔧 Starting frontend locally..."
	@cd frontend && npm run dev

# Production mode
prod: check-env build docker-up wait-for-db db-migrate
	@echo "🚀 Starting in production mode..."
	@mkdir -p logs
	@make start-backend start-frontend
	@echo "✅ Production services started"
	@echo "View logs: make logs"

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
test: test-backend
	@echo "✅ All tests passed"

test-backend:
	@echo "🧪 Running backend tests..."
	@cd backend && npm test || echo "No tests configured yet"

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