from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from typing import Dict, List
import uuid

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

security = HTTPBearer()

class Invoice(BaseModel):
    id: str
    owner: str
    amount: float
    description: str
    paid: bool = False

class InvoiceCreate(BaseModel):
    amount: float
    description: str = ""
    paid: bool = False

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> str:
    token = credentials.credentials
    if token == "alice-token":
        return "alice"
    if token == "bob-token":
        return "bob"
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

invoices: Dict[str, Invoice] = {
    "inv-alice-1": Invoice(id="inv-alice-1", owner="alice", amount=100.0, description="Alice invoice 1", paid=False),
    "inv-alice-2": Invoice(id="inv-alice-2", owner="alice", amount=250.5, description="Alice invoice 2", paid=True),
    "inv-bob-1": Invoice(id="inv-bob-1", owner="bob", amount=75.0, description="Bob invoice 1", paid=False),
    "inv-bob-2": Invoice(id="inv-bob-2", owner="bob", amount=320.0, description="Bob invoice 2", paid=False),
}

@app.get("/invoices", response_model=List[Invoice])
def list_invoices(user: str = Depends(get_current_user)):
    return [inv for inv in invoices.values() if inv.owner == user]

@app.get("/invoices/{invoice_id}", response_model=Invoice)
def get_invoice(invoice_id: str, user: str = Depends(get_current_user)):
    inv = invoices.get(invoice_id)
    if inv is None or inv.owner != user:
        raise HTTPException(status_code=404, detail="Invoice not found")
    return inv

@app.post("/invoices", response_model=Invoice, status_code=201)
def create_invoice(data: InvoiceCreate, user: str = Depends(get_current_user)):
    new_id = str(uuid.uuid4())
    inv = Invoice(id=new_id, owner=user, amount=data.amount, description=data.description, paid=data.paid)
    invoices[new_id] = inv
    return inv
