from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from typing import Dict, List, Optional
import uuid

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

security = HTTPBearer(auto_error=False)

TOKENS: Dict[str, str] = {
    "alice-token": "alice",
    "bob-token": "bob",
}

def get_current_user(credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)) -> str:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=401, detail="Not authenticated")
    token = credentials.credentials
    if token not in TOKENS:
        raise HTTPException(status_code=401, detail="Invalid token")
    return TOKENS[token]

class TicketCreate(BaseModel):
    title: str
    description: str = ""
    priority: str = "medium"

class Ticket(BaseModel):
    id: str
    title: str
    description: str
    status: str
    priority: str
    owner: str

tickets: Dict[str, Dict] = {
    "alice-ticket-1": {
        "id": "alice-ticket-1",
        "title": "Login issue",
        "description": "Cannot log in to account",
        "status": "open",
        "priority": "high",
        "owner": "alice",
    },
    "alice-ticket-2": {
        "id": "alice-ticket-2",
        "title": "Billing question",
        "description": "Charged twice this month",
        "status": "open",
        "priority": "medium",
        "owner": "alice",
    },
    "bob-ticket-1": {
        "id": "bob-ticket-1",
        "title": "Feature request",
        "description": "Add dark mode",
        "status": "open",
        "priority": "low",
        "owner": "bob",
    },
    "bob-ticket-2": {
        "id": "bob-ticket-2",
        "title": "Bug report",
        "description": "App crashes on upload",
        "status": "open",
        "priority": "high",
        "owner": "bob",
    },
}

@app.get("/tickets", response_model=List[Ticket])
def list_tickets(user: str = Depends(get_current_user)):
    return [t for t in tickets.values() if t["owner"] == user]

@app.post("/tickets", response_model=Ticket, status_code=201)
def create_ticket(payload: TicketCreate, user: str = Depends(get_current_user)):
    new_id = f"ticket-{uuid.uuid4().hex[:8]}"
    ticket = {
        "id": new_id,
        "title": payload.title,
        "description": payload.description,
        "status": "open",
        "priority": payload.priority,
        "owner": user,
    }
    tickets[new_id] = ticket
    return ticket

@app.get("/tickets/{ticket_id}", response_model=Ticket)
def get_ticket(ticket_id: str, user: str = Depends(get_current_user)):
    ticket = tickets.get(ticket_id)
    if ticket is None or ticket["owner"] != user:
        raise HTTPException(status_code=404, detail="Ticket not found")
    return ticket
