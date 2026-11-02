from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field
from typing import Dict, List, Optional
import uuid

app = FastAPI(title="Expenses API")

security = HTTPBearer(auto_error=False)

TOKENS: Dict[str, str] = {
    "alice-token": "alice",
    "bob-token": "bob",
}

def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
) -> str:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
        )
    user = TOKENS.get(credentials.credentials)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
        )
    return user


class ExpenseCreate(BaseModel):
    amount: float = Field(..., gt=0)
    description: str
    category: str = "general"


class Expense(BaseModel):
    id: str
    amount: float
    description: str
    category: str = "general"
    owner: str
    user: str


expenses: Dict[str, dict] = {
    "exp-alice-1": {
        "id": "exp-alice-1",
        "amount": 25.5,
        "description": "Lunch",
        "category": "food",
        "owner": "alice",
        "user": "alice",
    },
    "exp-alice-2": {
        "id": "exp-alice-2",
        "amount": 60.0,
        "description": "Taxi",
        "category": "transport",
        "owner": "alice",
        "user": "alice",
    },
    "exp-bob-1": {
        "id": "exp-bob-1",
        "amount": 12.99,
        "description": "Coffee",
        "category": "food",
        "owner": "bob",
        "user": "bob",
    },
    "exp-bob-2": {
        "id": "exp-bob-2",
        "amount": 100.0,
        "description": "Books",
        "category": "education",
        "owner": "bob",
        "user": "bob",
    },
}
