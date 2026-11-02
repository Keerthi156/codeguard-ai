from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from typing import Dict, List, Optional
import uuid

app = FastAPI(title="Tasks API")

security = HTTPBearer(auto_error=False)

TOKENS = {
    "alice-token": "alice",
    "bob-token": "bob",
}

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    token = credentials.credentials
    user = TOKENS.get(token)
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    return user

class TaskCreate(BaseModel):
    title: str
    description: Optional[str] = None

class TaskUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    completed: Optional[bool] = None

class Task(BaseModel):
    id: str
    title: str
    description: Optional[str] = None
    completed: bool = False
    owner: str

tasks_db: Dict[str, dict] = {
    "task-alice-1": {"id": "task-alice-1", "title": "Alice task 1", "description": "First task for alice", "completed": False, "owner": "alice"},
    "task-alice-2": {"id": "task-alice-2", "title": "Alice task 2", "description": "Second task for alice", "completed": False, "owner": "alice"},
    "task-bob-1": {"id": "task-bob-1", "title": "Bob task 1", "description": "First task for bob", "completed": False, "owner": "bob"},
    "task-bob-2": {"id": "task-bob-2", "title": "Bob task 2", "description": "Second task for bob", "completed": False, "owner": "bob"},
}

@app.get("/tasks", response_model=List[Task])
def list_tasks(current_user: str = Depends(get_current_user)):
    return [t for t in tasks_db.values() if t["owner"] == current_user]

@app.post("/tasks", response_model=Task, status_code=201)
def create_task(payload: TaskCreate, current_user: str = Depends(get_current_user)):
    new_id = str(uuid.uuid4())
    task = {"id": new_id, "title": payload.title, "description": payload.description, "completed": False, "owner": current_user}
    tasks_db[new_id] = task
    return task

@app.get("/tasks/{task_id}", response_model=Task)
def get_task(task_id: str, current_user: str = Depends(get_current_user)):
    task = tasks_db.get(task_id)
    if task is None or task["owner"] != current_user:
        raise HTTPException(status_code=404, detail="Task not found")
    return task

@app.delete("/tasks/{task_id}", status_code=204)
def delete_task(task_id: str, current_user: str = Depends(get_current_user)):
    task = tasks_db.get(task_id)
    if task is None or task["owner"] != current_user:
        raise HTTPException(status_code=404, detail="Task not found")
    del tasks_db[task_id]
    return None
