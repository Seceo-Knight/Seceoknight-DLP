# Server Module Documentation

## Overview

The FastAPI server is the core backend component of SeceoKnight DLP, providing RESTful APIs, authentication, business logic, and integration with databases and external systems.

## Architecture

```
┌─────────────────────────────────────────┐
│         FastAPI Application              │
├─────────────────────────────────────────┤
│  • API Endpoints (REST)                  │
│  • WebSocket (Real-time updates)         │
│  • Authentication (JWT + OAuth2)         │
│  • Rate Limiting & Security              │
│  • Logging & Monitoring                  │
└─────────────────────────────────────────┘
```

## Directory Structure

```
server/
├── app/
│   ├── main.py              # Application entry point
│   ├── core/                # Core functionality
│   │   ├── config.py        # Configuration management
│   │   ├── security.py      # Authentication & security
│   │   ├── database.py      # Database connections
│   │   ├── cache.py         # Redis cache
│   │   └── logging.py       # Structured logging
│   ├── api/                 # API endpoints
│   │   └── v1/              # API version 1
│   │       ├── auth.py      # Authentication endpoints
│   │       ├── events.py    # DLP events endpoints
│   │       ├── policies.py  # Policy management
│   │       ├── users.py     # User management
│   │       └── dashboard.py # Dashboard data
│   ├── models/              # Database models
│   │   ├── user.py          # User model
│   │   └── policy.py        # Policy model
│   ├── services/            # Business logic
│   ├── middleware/          # Custom middleware
│   │   ├── rate_limit.py    # Rate limiting
│   │   ├── request_id.py    # Request tracking
│   │   └── security.py      # Security headers
│   └── utils/               # Utility functions
├── tests/                   # Test suite
├── requirements.txt         # Python dependencies
├── Dockerfile              # Docker configuration
└── .env                    # Environment variables
```

## Installation

### Local Development

```bash
# Navigate to server directory
cd server

# Create virtual environment
python3.11 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Set up environment
cp ../config/env-templates/.env.server.example .env
# Edit .env with your configuration

# Run migrations
alembic upgrade head

# Start server
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

### Docker Deployment

```bash
# Build image
docker build -t seceoknight-server .

# Run container
docker run -d \
  -p 8000:8000 \
  --env-file .env \
  --name seceoknight-server \
  seceoknight-server
```

## Configuration

Environment variables in `.env`:

```bash
# Application
ENVIRONMENT=production
DEBUG=False
SECRET_KEY=<generate-strong-secret-32-chars>
HOST=0.0.0.0
PORT=8000

# PostgreSQL
POSTGRES_HOST=localhost
POSTGRES_PORT=5432
POSTGRES_USER=dlp_user
POSTGRES_PASSWORD=<secure-password>
POSTGRES_DB=seceoknight_dlp

# MongoDB
MONGODB_HOST=localhost
MONGODB_PORT=27017
MONGODB_USER=dlp_user
MONGODB_PASSWORD=<secure-password>
MONGODB_DB=seceoknight_dlp

# Redis
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=<secure-password>

# Security
CORS_ORIGINS=http://localhost:3000,http://<your-host-ip>:3000
RATE_LIMIT_REQUESTS=100
RATE_LIMIT_WINDOW=60
```

## API Endpoints

### Health & Status

- `GET /` - Root endpoint
- `GET /health` - Health check
- `GET /ready` - Readiness check
- `GET /metrics` - Prometheus metrics

### Authentication

- `POST /api/v1/auth/login` - User login
- `POST /api/v1/auth/register` - User registration
- `POST /api/v1/auth/refresh` - Refresh access token
- `POST /api/v1/auth/logout` - User logout

### Events

- `GET /api/v1/events` - List DLP events
- `GET /api/v1/events/{id}` - Get specific event
- `GET /api/v1/events/stats/summary` - Event statistics

### Policies

- `GET /api/v1/policies` - List policies
- `POST /api/v1/policies` - Create policy
- `PUT /api/v1/policies/{id}` - Update policy
- `DELETE /api/v1/policies/{id}` - Delete policy

### Users

- `GET /api/v1/users/me` - Current user profile
- `GET /api/v1/users` - List users (admin)
- `PUT /api/v1/users/{id}` - Update user (admin)

### Dashboard

- `GET /api/v1/dashboard/overview` - Dashboard statistics
- `GET /api/v1/dashboard/timeline` - Event timeline data

## API Documentation

Interactive API documentation is available at:

- **Swagger UI**: `https://YOUR_SERVER_IP/api/v1/docs`
- **ReDoc**: `https://YOUR_SERVER_IP/api/v1/redoc`

## Authentication

The server uses JWT (JSON Web Tokens) for authentication:

1. Login with credentials to get access and refresh tokens
2. Include access token in Authorization header: `Bearer <token>`
3. Refresh access token using refresh token when expired

Example:

```bash
# Login
curl -X POST https://YOUR_SERVER_IP/api/v1/auth/login \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin@seceoknight.local&password=ChangeMe123!"

# Use token
curl https://YOUR_SERVER_IP/api/v1/events \
  -H "Authorization: Bearer <access_token>"
```

## Security Features

- JWT-based authentication
- Rate limiting per IP
- CORS protection
- Security headers (HSTS, CSP, etc.)
- Input validation
- SQL injection prevention
- XSS protection

## Performance Optimization

### Scaling

```bash
# Increase workers
uvicorn app.main:app --workers 8

# Configure connection pools
POSTGRES_POOL_SIZE=50
MONGODB_MAX_POOL_SIZE=200
```

### Caching

Redis is used for:
- Session storage
- Rate limiting counters
- Policy cache
- API response cache

## Monitoring

### Health Checks

```bash
# Check health
curl https://YOUR_SERVER_IP/health

# Check readiness
curl https://YOUR_SERVER_IP/ready
```

### Metrics

Prometheus metrics available at `/metrics`:

- Request count and latency
- Database connection pool usage
- Cache hit/miss rates
- Error rates

### Logging

Structured JSON logs with:
- Request IDs for tracking
- User context
- Timestamp
- Log level
- Error details

View logs:
```bash
# Docker
docker logs -f seceoknight-server

# Local
tail -f server/logs/app.log
```

## Testing

```bash
# Run tests
pytest

# With coverage
pytest --cov=app tests/

# Specific test
pytest tests/test_auth.py
```

## Troubleshooting

### Server won't start

```bash
# Check port availability
lsof -i :8000

# Verify database connections
docker-compose ps
docker-compose logs postgres mongodb

# Check environment
cat .env
```

### Database connection errors

```bash
# Test PostgreSQL
docker-compose exec postgres psql -U dlp_user -d seceoknight_dlp

# Test MongoDB
docker-compose exec mongodb mongosh -u dlp_user -p
```

### Authentication issues

```bash
# Generate new secret key
openssl rand -hex 32

# Update in .env
SECRET_KEY=<new-secret>

# Restart server
docker-compose restart server
```

## Best Practices

1. **Use environment variables** for configuration
2. **Enable DEBUG=False** in production
3. **Set strong SECRET_KEY** (minimum 32 characters)
4. **Configure CORS** properly for your domain
5. **Monitor logs** regularly
6. **Set up alerts** for errors
7. **Backup database** regularly
8. **Update dependencies** regularly

## Support

For issues or questions:
- GitHub Issues: [Link]
- Email: support@seceoknight.local
- Documentation: [MASTER_DOCUMENTATION.md](../../MASTER_DOCUMENTATION.md)
