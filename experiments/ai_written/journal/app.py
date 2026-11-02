from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel
from typing import Dict, List, Optional

app = FastAPI()

TOKENS: Dict[str, str] = {
    "alice-token": "alice",
    "bob-token": "bob",
}

def get_current_user(authorization: Optional[str] = Header(None)) -> str:
    if authorization is None or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")
    token = authorization[len("Bearer "):].strip()
    user = TOKENS.get(token)
    if user is None:
        raise HTTPException(status_code=401, detail="Invalid token")
    return user

class Entry(BaseModel):
    id: str
    owner: str
    title: str
    content: str

class EntryCreate(BaseModel):
    title: str
    content: str

entries: Dict[str, Dict] = {
    "alice-entry-1": {"id": "alice-entry-1", "owner": "alice", "title": "Alice Morning", "content": "Alice journal entry one"},
    "alice-entry-2": {"id": "alice-entry-2", "owner": "alice", "title": "Alice Evening", "content": "Alice journal entry two"},
    "bob-entry-1": {"id": "bob-entry-1", "owner": "bob", "title": "Bob Morning", "content": "Bob journal entry one"},
    "bob-entry-2": {"id": "bob-entry-2", "owner": "bob", "title": "Bob Evening", "content": "Bob journal entry two"},
}

_counter = 100

@app.get("/entries", response_model=List[Entry])
def list_entries(authorization: Optional[str] = Header(None)):
    user = get_current_user(authorization)
    return [e for e in entries.values() if e["owner"] == user]

@app.post("/entries", response_model=Entry, status_code=201)
def create_entry(payload: EntryCreate, authorization: Optional[str] = Header(None)):
    global _counter
    user = get_current_user(authorization)
    _counter += 1
    new_id = f"{user}-entry-{_counter}"
    entry = {"id": new_id, "owner": user, "title": payload.title, "content": payload.content}
    entries[new_id] = entry
    return entry

@app.get("/entries/{entry_id}", response_model=Entry)
def get_entry(entry_id: str, authorization: Optional[str] = Header(None)):
    user = get_current_user(authorization)
    entry = entries.get(entry_id)
    if entry is None or entry["owner"] != user:
        raise HTTPException(status_code=404, detail="Entry not found")
    return entry

@app.delete("/entries/{entry_id}")
def delete_entry(entry_id: str, authorization: Optional[str] = Header(None)):
    user = get_current_user(authorization)
    entry = entries.get(entry_id)
    if entry is None or entry["owner"] != user:
        raise HTTPException(status_code=404, detail="Entry not found")
    del entries[entry_id]
    return {"detail": "deleted"}
