from fastapi import FastAPI, Depends, HTTPException, Response, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
import uuid

app = FastAPI()

security = HTTPBearer(auto_error=False)

TOKENS = {
    "alice-token": "alice",
    "bob-token": "bob",
}

def get_current_user(credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)) -> str:
    if credentials is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing token")
    token = credentials.credentials
    if token not in TOKENS:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    return TOKENS[token]


class ExpenseCreate(BaseModel):
    amount: float = 0.0
    description: str = ""
    category: str = "general"
    title: Optional[str] = None

    class Config:
        extra = "allow"


class Expense(BaseModel):
    id: str
    owner: str
    amount: float = 0.0
    description: str = ""
    category: str = "general"
    title: Optional[str] = None

    class Config:
        extra = "allow"


expenses: Dict[str, Dict[str, Any]] = {
    "exp-alice-1": {"id": "exp-alice-1", "owner": "alice", "amount": 25.5, "description": "Lunch", "category": "food", "title": "Lunch"},
    "exp-alice-2": {"id": "exp-alice-2", "owner": "alice", "amount": 60.0, "description": "Groceries", "category": "food", "title": "Groceries"},
    "exp-bob-1": {"id": "exp-bob-1", "owner": "bob", "amount": 15.75, "description": "Taxi", "category": "transport", "title": "Taxi"},
    "exp-bob-2": {"id": "exp-bob-2", "owner": "bob", "amount": 120.0, "description": "Electricity bill", "category": "utilities", "title": "Electricity"},
}


def _dump(model: BaseModel) -> Dict[str, Any]:
    if hasattr(model, "model_dump"):
        return model.model_dump()
    return model.dict()


@app.get("/expenses", response_model=List[Expense])
def list_expenses(current_user: str = Depends(get_current_user)):
    return [e for e in expenses.values() if e.get("owner") == current_user]


@app.post("/expenses", response_model=Expense, status_code=201)
def create_expense(payload: ExpenseCreate, current_user: str = Depends(get_current_user)):
    data = _dump(payload)
    new_id = str(uuid.uuid4())
    expense: Dict[str, Any] = {**data, "id": new_id, "owner": current_user}
    expenses[new_id] = expense
    return expense


@app.get("/expenses/{expense_id}", response_model=Expense)
def get_expense(expense_id: str, current_user: str = Depends(get_current_user)):
    expense = expenses.get(expense_id)
    if expense is None:
        raise HTTPException(status_code=404, detail="Expense not found")
    if expense.get("owner") != current_user:
        raise HTTPException(status_code=403, detail="Forbidden")
    return expense


@app.delete("/expenses/{expense_id}", status_code=204)
def delete_expense(expense_id: str, current_user: str = Depends(get_current_user)):
    expense = expenses.get(expense_id)
    if expense is None:
        raise HTTPException(status_code=404, detail="Expense not found")
    if expense.get("owner") != current_user:
        raise HTTPException(status_code=403, detail="Forbidden")
    del expenses[expense_id]
    return Response(status_code=204)
