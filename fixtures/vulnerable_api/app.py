# Intentionally vulnerable and for local testing only.
"""Documents API that accepts a valid bearer token and ignores ownership.

Any authenticated user can read or replace any document. This is a Broken
Object Level Authorization bug, and the app must stay on localhost.

Users (Authorization: Bearer <token>):
    alice-token -> alice
    bob-token -> bob

Documents:
    101 owned by alice
    202 owned by bob

Start on a chosen port:

    uvicorn fixtures.vulnerable_api.app:app --host 127.0.0.1 --port 8001
"""

from __future__ import annotations

import argparse
from typing import Annotated

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel

app = FastAPI(title="Vulnerable documents API")

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


def _existing_document(document_id: int) -> Document:
    document = DOCUMENTS.get(document_id)
    if document is None:
        raise HTTPException(status_code=404, detail="Document not found")
    return document


@app.get("/documents/{id}")
def get_document(id: int, _user: Annotated[str, Depends(require_user)]) -> Document:
    """Return the document when the token is valid. Ownership is not checked."""
    return _existing_document(id)


@app.put("/documents/{id}")
def update_document(
    id: int,
    body: DocumentUpdate,
    _user: Annotated[str, Depends(require_user)],
) -> Document:
    """Replace title and content when the token is valid. Ownership is not checked."""
    document = _existing_document(id)
    updated = document.model_copy(update={"title": body.title, "content": body.content})
    DOCUMENTS[id] = updated
    return updated


def main() -> None:
    """Listen on 127.0.0.1. Pass --port to choose the port."""
    import uvicorn

    parser = argparse.ArgumentParser(
        description="Intentionally vulnerable documents API. Local testing only."
    )
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    uvicorn.run(app, host="127.0.0.1", port=args.port)


if __name__ == "__main__":
    main()
