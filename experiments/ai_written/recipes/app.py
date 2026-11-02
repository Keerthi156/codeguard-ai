from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from typing import List, Dict, Optional
import uuid

app = FastAPI(title="Recipes API")

security = HTTPBearer(auto_error=False)

def get_current_user(credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)) -> str:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=401, detail="Not authenticated")
    token = credentials.credentials
    if token == "alice-token":
        return "alice"
    if token == "bob-token":
        return "bob"
    raise HTTPException(status_code=401, detail="Invalid token")

class RecipeCreate(BaseModel):
    title: str
    ingredients: List[str]
    instructions: str

class Recipe(RecipeCreate):
    id: str
    owner: str

recipes_db: Dict[str, dict] = {
    "alice-recipe-1": {
        "id": "alice-recipe-1",
        "title": "Alice Pancakes",
        "ingredients": ["flour", "milk", "egg"],
        "instructions": "Mix ingredients and fry on pan.",
        "owner": "alice",
    },
    "alice-recipe-2": {
        "id": "alice-recipe-2",
        "title": "Alice Salad",
        "ingredients": ["lettuce", "tomato", "olive oil"],
        "instructions": "Chop and mix all ingredients.",
        "owner": "alice",
    },
    "bob-recipe-1": {
        "id": "bob-recipe-1",
        "title": "Bob Omelette",
        "ingredients": ["egg", "cheese", "salt"],
        "instructions": "Beat eggs and cook with cheese.",
        "owner": "bob",
    },
    "bob-recipe-2": {
        "id": "bob-recipe-2",
        "title": "Bob Pasta",
        "ingredients": ["pasta", "tomato sauce", "basil"],
        "instructions": "Boil pasta and add sauce.",
        "owner": "bob",
    },
}

@app.get("/recipes")
def list_recipes(current_user: str = Depends(get_current_user)):
    return [r for r in recipes_db.values() if r["owner"] == current_user]

@app.post("/recipes", status_code=201)
def create_recipe(payload: RecipeCreate, current_user: str = Depends(get_current_user)):
    new_id = str(uuid.uuid4())
    recipe = {
        "id": new_id,
        "title": payload.title,
        "ingredients": payload.ingredients,
        "instructions": payload.instructions,
        "owner": current_user,
    }
    recipes_db[new_id] = recipe
    return recipe

@app.get("/recipes/{recipe_id}")
def get_recipe(recipe_id: str, current_user: str = Depends(get_current_user)):
    recipe = recipes_db.get(recipe_id)
    if recipe is None:
        raise HTTPException(status_code=404, detail="Recipe not found")
    if recipe["owner"] != current_user:
        raise HTTPException(status_code=403, detail="Not authorized")
    return recipe

@app.delete("/recipes/{recipe_id}")
def delete_recipe(recipe_id: str, current_user: str = Depends(get_current_user)):
    recipe = recipes_db.get(recipe_id)
    if recipe is None:
        raise HTTPException(status_code=404, detail="Recipe not found")
    if recipe["owner"] != current_user:
        raise HTTPException(status_code=403, detail="Not authorized")
    del recipes_db[recipe_id]
    return {"detail": "deleted"}
