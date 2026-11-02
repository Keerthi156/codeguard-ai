from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from typing import Dict, List, Optional
import uuid

app = FastAPI()
security = HTTPBearer(auto_error=False)

TOKENS: Dict[str, str] = {
    "alice-token": "alice",
    "bob-token": "bob",
}

def get_current_user(creds: HTTPAuthorizationCredentials = Depends(security)) -> str:
    if creds is None or creds.scheme.lower() != "bearer":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing bearer token")
    user = TOKENS.get(creds.credentials)
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    return user

class ContactIn(BaseModel):
    name: str
    email: str
    phone: Optional[str] = None

class Contact(ContactIn):
    id: str
    owner: str

contacts: Dict[str, Dict] = {
    "alice-contact-1": {"id": "alice-contact-1", "owner": "alice", "name": "Alice Friend One", "email": "alice1@example.com", "phone": "111-111-1111"},
    "alice-contact-2": {"id": "alice-contact-2", "owner": "alice", "name": "Alice Friend Two", "email": "alice2@example.com", "phone": "222-222-2222"},
    "bob-contact-1": {"id": "bob-contact-1", "owner": "bob", "name": "Bob Friend One", "email": "bob1@example.com", "phone": "333-333-3333"},
    "bob-contact-2": {"id": "bob-contact-2", "owner": "bob", "name": "Bob Friend Two", "email": "bob2@example.com", "phone": "444-444-4444"},
}

@app.get("/contacts", response_model=List[Contact])
def list_contacts(user: str = Depends(get_current_user)):
    return [c for c in contacts.values() if c["owner"] == user]

@app.post("/contacts", response_model=Contact, status_code=201)
def create_contact(payload: ContactIn, user: str = Depends(get_current_user)):
    new_id = str(uuid.uuid4())
    item = {"id": new_id, "owner": user, "name": payload.name, "email": payload.email, "phone": payload.phone}
    contacts[new_id] = item
    return item

@app.delete("/contacts/{contact_id}")
def delete_contact(contact_id: str, user: str = Depends(get_current_user)):
    item = contacts.get(contact_id)
    if item is None or item["owner"] != user:
        raise HTTPException(status_code=404, detail="Contact not found")
    del contacts[contact_id]
    return {"id": contact_id, "deleted": True}
