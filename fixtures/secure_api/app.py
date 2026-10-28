# Enforces document ownership. For local testing only.
"""Documents API that accepts a valid bearer token and checks ownership.

A caller who does not own the document gets 404, the same response as a
missing document. Unknown tokens get 401. Bind to localhost only.

Users (Authorization: Bearer <token>):
    alice-token -> alice
    bob-token -> bob

Documents:
    101 owned by alice
    202 owned by bob

Start on a chosen port:

    uvicorn fixtures.secure_api.app:app --host 127.0.0.1 --port 8002
"""

from __future__ import annotations

import argparse
from typing import Annotated

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel

app = FastAPI(title="Secure documents API")

TOKENS: dict[str, str] = {
    "alice-token": "alice",
    "bob-token": "bob",
}


class Document(BaseModel):
    id: int
    owner: str
    title: str
    content: str


class DocumentUpdate(BaseModel):
    title: str
    content: str


DOCUMENTS: dict[int, Document] = {
    101: Document(id=101, owner="alice", title="Alice notes", content="alice-private"),
    202: Document(id=202, owner="bob", title="Bob notes", content="bob-private"),
}


def require_user(authorization: Annotated[str | None, Header()] = None) -> str:
    """Return the username for a known bearer token."""
    if authorization is None:
        raise HTTPException(status_code=401, detail="Unauthorized")
    scheme, separator, token = authorization.partition(" ")
    if separator != " " or scheme.lower() != "bearer":
        raise HTTPException(status_code=401, detail="Unauthorized")
    username = TOKENS.get(token.strip())
    if username is None:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return username


def _owned_document(document_id: int, user: str) -> Document:
    document = DOCUMENTS.get(document_id)
    if document is None or document.owner != user:
        raise HTTPException(status_code=404, detail="Document not found")
    return document


@app.get("/documents/{id}")
def get_document(id: int, user: Annotated[str, Depends(require_user)]) -> Document:
    """Return the document only when this user owns it."""
    return _owned_document(id, user)


@app.put("/documents/{id}")
def update_document(
    id: int,
    body: DocumentUpdate,
    user: Annotated[str, Depends(require_user)],
) -> Document:
    """Replace title and content only when this user owns the document."""
    document = _owned_document(id, user)
    updated = document.model_copy(update={"title": body.title, "content": body.content})
    DOCUMENTS[id] = updated
    return updated


def main() -> None:
    """Listen on 127.0.0.1. Pass --port to choose the port."""
    import uvicorn

    parser = argparse.ArgumentParser(description="Ownership-checked documents API. Local testing only.")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    uvicorn.run(app, host="127.0.0.1", port=args.port)


if __name__ == "__main__":
    main()
