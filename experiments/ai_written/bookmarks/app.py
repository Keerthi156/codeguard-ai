from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel
from typing import Dict, List
import uuid

app = FastAPI(title="Bookmarks API")

security = HTTPBearer()

TOKENS: Dict[str, str] = {
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

class Bookmark(BaseModel):
    id: str
    url: str
    title: str
    user: str

class BookmarkCreate(BaseModel):
    url: str
    title: str

bookmarks: Dict[str, Dict] = {
    "alice-bookmark-1": {"id": "alice-bookmark-1", "url": "https://example.com/alice1", "title": "Alice First", "user": "alice"},
    "alice-bookmark-2": {"id": "alice-bookmark-2", "url": "https://example.com/alice2", "title": "Alice Second", "user": "alice"},
    "bob-bookmark-1": {"id": "bob-bookmark-1", "url": "https://example.com/bob1", "title": "Bob First", "user": "bob"},
    "bob-bookmark-2": {"id": "bob-bookmark-2", "url": "https://example.com/bob2", "title": "Bob Second", "user": "bob"},
}

@app.get("/bookmarks", response_model=List[Bookmark])
def list_bookmarks(current_user: str = Depends(get_current_user)):
    return [b for b in bookmarks.values() if b["user"] == current_user]

@app.post("/bookmarks", response_model=Bookmark, status_code=status.HTTP_201_CREATED)
def create_bookmark(payload: BookmarkCreate, current_user: str = Depends(get_current_user)):
    new_id = str(uuid.uuid4())
    item = {"id": new_id, "url": payload.url, "title": payload.title, "user": current_user}
    bookmarks[new_id] = item
    return item

@app.delete("/bookmarks/{bookmark_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_bookmark(bookmark_id: str, current_user: str = Depends(get_current_user)):
    item = bookmarks.get(bookmark_id)
    if item is None or item["user"] != current_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Bookmark not found")
    del bookmarks[bookmark_id]
    return None
