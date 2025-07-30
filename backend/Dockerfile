# Build stage
FROM node:20-alpine AS builder

WORKDIR /app

# Copy package files
COPY backend/package*.json ./
RUN npm install

# Copy source files
COPY backend/ .
RUN npm run build

# Production stage
FROM node:20-alpine

WORKDIR /app

# Install dumb-init for proper signal handling
RUN apk add --no-cache dumb-init

# Create non-root user
RUN addgroup -g 1001 -S nodejs
RUN adduser -S nodejs -u 1001

# Copy package files and install production dependencies
COPY --from=builder --chown=nodejs:nodejs /app/package*.json ./
RUN npm install --production

# Copy built application
COPY --from=builder --chown=nodejs:nodejs /app/dist ./dist

# Create database directory and copy schema
RUN mkdir -p ./database
COPY --chown=nodejs:nodejs database/schema.sql ./database/schema.sql

# Switch to non-root user
USER nodejs

EXPOSE 5000

# Use dumb-init to handle signals properly
ENTRYPOINT ["dumb-init", "--"]
CMD ["node", "dist/index.js"]