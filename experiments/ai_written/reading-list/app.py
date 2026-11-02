from fastapi import FastAPI, Depends, HTTPException
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

def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
) -> str:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=401, detail="Not authenticated")
    user = TOKENS.get(credentials.credentials)
    if user is None:
        raise HTTPException(status_code=401, detail="Invalid token")
    return user


class ReadingItem(BaseModel):
    id: str
    owner: str
    title: str
    url: Optional[str] = None
    status: str = "to-read"


class CreateReadingItem(BaseModel):
    title: str
    url: Optional[str] = None


store: Dict[str, ReadingItem] = {
    "alice-1": ReadingItem(id="alice-1", owner="alice", title="Dune", url="https://example.com/dune", status="to-read"),
    "alice-2": ReadingItem(id="alice-2", owner="alice", title="Foundation", url="https://example.com/foundation", status="to-read"),
    "bob-1": ReadingItem(id="bob-1", owner="bob", title="Clean Code", url="https://example.com/clean-code", status="to-read"),
    "bob-2": ReadingItem(id="bob-2", owner="bob", title="Design Patterns", url="https://example.com/design-patterns", status="to-read"),
}


@app.get("/reading-list", response_model=List[ReadingItem])
def list_items(user: str = Depends(get_current_user)):
    return [item for item in store.values() if item.owner == user]


@app.post("/reading-list", response_model=ReadingItem, status_code=201)
def create_item(payload: CreateReadingItem, user: str = Depends(get_current_user)):
    new_id = str(uuid.uuid4())
    item = ReadingItem(id=new_id, owner=user, title=payload.title, url=payload.url, status="to-read")
    store[new_id] = item
    return item


@app.delete("/reading-list/{item_id}")
def delete_item(item_id: str, user: str = Depends(get_current_user)):
    item = store.get(item_id)
    if item is None or item.owner != user:
        raise HTTPException(status_code=404, detail="Item not found")
    del store[item_id]
    return {"detail": "deleted", "id": item_id}
