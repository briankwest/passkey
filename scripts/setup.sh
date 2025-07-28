#!/bin/bash

echo "🚀 Passkey Demo Setup Script"
echo "============================"

# Check for required tools
check_command() {
    if ! command -v $1 &> /dev/null; then
        echo "❌ $1 is not installed. Please install it first."
        exit 1
    fi
}

echo "Checking prerequisites..."
check_command node
check_command npm
check_command docker
check_command docker-compose

# Check Node version
NODE_VERSION=$(node -v | cut -d'v' -f2 | cut -d'.' -f1)
if [ $NODE_VERSION -lt 18 ]; then
    echo "❌ Node.js version 18 or higher is required"
    exit 1
fi

echo "✅ All prerequisites met"

# Setup backend
echo ""
echo "Setting up backend..."
cd backend

if [ ! -f .env ]; then
    echo "Creating .env file from template..."
    cp .env.example .env
    echo "⚠️  Please edit backend/.env with your configuration"
fi

echo "Installing backend dependencies..."
npm install

# Setup frontend
echo ""
echo "Setting up frontend..."
cd ../frontend

echo "Installing frontend dependencies..."
npm install

cd ..

# Create necessary directories
echo ""
echo "Creating directories..."
mkdir -p logs

echo ""
echo "✅ Setup complete!"
echo ""
echo "Next steps:"
echo "1. Edit backend/.env if needed"
echo "2. Run 'make dev' to start in development mode"
echo "3. Visit http://localhost:3000"