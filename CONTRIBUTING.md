# Contributing to SeceoKnight DLP

Thank you for your interest in contributing to SeceoKnight DLP! This document provides guidelines for contributing to the project.

## Code of Conduct

By participating in this project, you agree to abide by our Code of Conduct:
- Be respectful and inclusive
- Welcome newcomers and help them learn
- Focus on what is best for the community
- Show empathy towards other community members

## How to Contribute

### Reporting Bugs

Before creating bug reports, please check existing issues to avoid duplicates. When creating a bug report, include:

- **Clear title and description**
- **Steps to reproduce** the issue
- **Expected behavior** vs actual behavior
- **Environment details** (OS, Python version, etc.)
- **Screenshots or logs** if applicable

### Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. When creating an enhancement suggestion, include:

- **Clear title and description**
- **Use case** - why is this enhancement needed?
- **Proposed solution** - how should it work?
- **Alternative solutions** you've considered

### Pull Requests

1. **Fork the repository** and create your branch from `main`
2. **Make your changes** following our coding standards
3. **Add tests** for any new functionality
4. **Update documentation** if needed
5. **Ensure all tests pass** (`pytest server/tests/`)
6. **Commit with clear messages** following our commit conventions
7. **Open a pull request** with a clear description

## Development Setup

### Prerequisites

- Python 3.11+
- Node.js 18+
- Docker & Docker Compose
- PostgreSQL 15+
- MongoDB 7+
- Redis 7+

### Local Development

```bash
# Clone the repository
git clone https://github.com/seceoknight-06/seceoknight-dlp.git
cd seceoknight-dlp

# Backend setup
cd server
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt

# Frontend setup
cd ../dashboard
npm install

# Start services with Docker
docker-compose up -d
```

### Running Tests

```bash
# Backend tests
cd server
pytest tests/ -v

# Frontend tests
cd dashboard
npm test

# Coverage report
pytest tests/ --cov=app --cov-report=html
```

### Code Style

**Python:**
- Follow PEP 8
- Use Black for formatting: `black server/`
- Use flake8 for linting: `flake8 server/`
- Use type hints for all functions
- Maximum line length: 120 characters

**TypeScript/React:**
- Follow Airbnb style guide
- Use ESLint: `npm run lint`
- Use Prettier for formatting
- Functional components with hooks

**Git Commits:**
- Use imperative mood ("Add feature" not "Added feature")
- First line: brief summary (50 chars max)
- Blank line, then detailed description if needed
- Reference issues: "Fixes #123"

Example:
```
Add user authentication endpoint

- Implement JWT-based authentication
- Add password hashing with bcrypt
- Create user registration endpoint
- Add integration tests

Fixes #42
```

## Project Structure

```
seceoknight-dlp/
├── server/              # FastAPI backend
│   ├── app/
│   │   ├── api/         # API routes
│   │   ├── models/      # Database models
│   │   ├── services/    # Business logic
│   │   └── core/        # Core utilities
│   └── tests/           # Backend tests
├── dashboard/           # Next.js frontend
│   ├── src/
│   │   ├── app/         # Pages
│   │   ├── components/  # React components
│   │   └── lib/         # Utilities
│   └── tests/           # Frontend tests
├── agents/              # Endpoint agents
├── ml/                  # ML models
└── docs/                # Documentation
```

## Coding Guidelines

### Backend (FastAPI)

**API Endpoints:**
```python
from fastapi import APIRouter, Depends, HTTPException, status
from app.models.user import User
from app.services.user_service import UserService

router = APIRouter()

@router.get("/users/{user_id}", response_model=UserResponse)
async def get_user(
    user_id: str,
    service: UserService = Depends(),
    current_user: User = Depends(get_current_user)
) -> UserResponse:
    """
    Get user by ID.

    Args:
        user_id: UUID of the user
        service: User service dependency
        current_user: Authenticated user

    Returns:
        User details

    Raises:
        HTTPException: If user not found
    """
    user = await service.get_user(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return UserResponse.from_orm(user)
```

**Database Models:**
```python
from sqlalchemy import Column, String, DateTime
from sqlalchemy.dialects.postgresql import UUID
from app.core.database import Base
import uuid

class User(Base):
    __tablename__ = "users"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email = Column(String(255), unique=True, nullable=False, index=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
```

**Service Layer:**
```python
from typing import Optional, List
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.user import User

class UserService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def get_user(self, user_id: str) -> Optional[User]:
        """Fetch user by ID."""
        result = await self.db.execute(
            select(User).where(User.id == user_id)
        )
        return result.scalar_one_or_none()
```

### Frontend (Next.js/React)

**Components:**
```typescript
import { FC } from 'react';

interface UserCardProps {
  name: string;
  email: string;
  role: string;
}

export const UserCard: FC<UserCardProps> = ({ name, email, role }) => {
  return (
    <div className="bg-white rounded-lg shadow p-4">
      <h3 className="text-lg font-semibold">{name}</h3>
      <p className="text-gray-600">{email}</p>
      <span className="text-sm text-blue-600">{role}</span>
    </div>
  );
};
```

**API Calls:**
```typescript
import { apiClient } from '@/lib/api-client';
import { useQuery } from '@tanstack/react-query';

export const useUsers = () => {
  return useQuery({
    queryKey: ['users'],
    queryFn: async () => {
      const response = await apiClient.get('/users');
      return response.data;
    },
  });
};
```

## Testing Guidelines

### Unit Tests

```python
import pytest
from app.services.user_service import UserService
from app.models.user import User

@pytest.mark.asyncio
async def test_get_user_success(db_session):
    # Arrange
    service = UserService(db_session)
    user = User(email="test@example.com", full_name="Test User")
    db_session.add(user)
    await db_session.commit()

    # Act
    result = await service.get_user(user.id)

    # Assert
    assert result is not None
    assert result.email == "test@example.com"

@pytest.mark.asyncio
async def test_get_user_not_found(db_session):
    service = UserService(db_session)
    result = await service.get_user("non-existent-id")
    assert result is None
```

### Integration Tests

```python
from fastapi.testclient import TestClient

def test_create_user(client: TestClient, auth_headers):
    response = client.post(
        "/api/v1/users",
        headers=auth_headers,
        json={"email": "new@example.com", "full_name": "New User"}
    )
    assert response.status_code == 201
    data = response.json()
    assert data["email"] == "new@example.com"
```

## Documentation

- Update README.md for user-facing changes
- Add docstrings to all functions and classes
- Update API documentation (OpenAPI/Swagger)
- Create module-specific docs in `docs/` folder

## Security

- **Never commit secrets** (API keys, passwords, tokens)
- Use environment variables for configuration
- Sanitize user input
- Follow OWASP security guidelines
- Report security vulnerabilities privately

## Questions?

- Open an issue for questions
- Join discussions on GitHub
- Read the documentation in `docs/`

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

Thank you for contributing to SeceoKnight DLP! 🛡️
