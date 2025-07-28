#!/bin/bash

echo "🏥 Health Check"
echo "==============="

# Check database
echo -n "Database: "
if docker-compose exec -T postgres pg_isready -U postgres &> /dev/null; then
    echo "✅ Healthy"
else
    echo "❌ Not responding"
fi

# Check backend
echo -n "Backend: "
if curl -s http://localhost:5000/api/health > /dev/null; then
    echo "✅ Healthy"
else
    echo "❌ Not responding"
fi

# Check frontend
echo -n "Frontend: "
if curl -s http://localhost:3000 > /dev/null; then
    echo "✅ Healthy"
else
    echo "❌ Not responding"
fi