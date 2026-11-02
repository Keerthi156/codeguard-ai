from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from typing import Dict, List, Optional

app = FastAPI(title="Notes API")
security = HTTPBearer()

TOKENS = {
    "alice-token": "alice",
    "bob-token": "bob",
}

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> str:
    token = credentials.credentials
    user = TOKENS.get(token)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing token",
        )
    return user

class Note(BaseModel):
    id: str
    owner: str
    title: str
    content: str = ""

class NoteCreate(BaseModel):
    title: str
    content: str = ""

notes_db: Dict[str, Dict] = {
    "note-alice-1": {"id": "note-alice-1", "owner": "alice", "title": "Alice Note 1", "content": "First note for alice"},
    "note-alice-2": {"id": "note-alice-2", "owner": "alice", "title": "Alice Note 2", "content": "Second note for alice"},
    "note-bob-1": {"id": "note-bob-1", "owner": "bob", "title": "Bob Note 1", "content": "First note for bob"},
    "note-bob-2": {"id": "note-bob-2", "owner": "bob", "title": "Bob Note 2", "content": "Second note for bob"},
}

@app.get("/notes", response_model=List[Note])
def list_notes(current_user: str = Depends(get_current_user)):
    return [n for n in notes_db.values() if n["owner"] == current_user]

@app.post("/notes", response_model=Note, status_code=status.HTTP_201_CREATED)
def create_note(payload: NoteCreate, current_user: str = Depends(get_current_user)):
    import uuid
    new_id = str(uuid.uuid4())
    note = {"id": new_id, "owner": current_user, "title": payload.title, "content": payload.content}
    notes_db[new_id] = note
    return note

@app.get("/notes/{note_id}", response_model=Note)
def get_note(note_id: str, current_user: str = Depends(get_current_user)):
    note = notes_db.get(note_id)
    if note is None or note["owner"] != current_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Note not found")
    return note

@app.delete("/notes/{note_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_note(note_id: str, current_user: str = Depends(get_current_user)):
    note = notes_db.get(note_id)
    if note is None or note["owner"] != current_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Note not found")
    del notes_db[note_id]
    return None
