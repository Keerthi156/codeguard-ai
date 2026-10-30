# Intentionally vulnerable benchmark app. Local testing only. Not for production.
"""Documents API whose dependency authenticates and loads, then stops.

``authenticated_document`` is a ``Depends()`` dependency. It accepts a known
bearer token and returns the record. It does not compare the caller with the
owner, so any authenticated user can read or replace any document. Bind to
localhost only.

Users (Authorization: Bearer <token>):
    alice-token -> alice
    bob-token -> bob

Documents:
    101 owned by alice
    202 owned by bob

Start on a chosen port:

    uvicorn benchmarks.dependency_check.vulnerable.app:app --host 127.0.0.1 --port 8103
"""

from __future__ import annotations

import argparse
from typing import Annotated

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel

app = FastAPI(title="Benchmark dependency-check vulnerable")
PORT = 8103

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


def _seed() -> dict[int, Document]:
    return {
        101: Document(id=101, owner="alice", title="Alice notes", content="alice-private"),
        202: Document(id=202, owner="bob", title="Bob notes", content="bob-private"),
    }


DOCUMENTS: dict[int, Document] = _seed()


def reset() -> None:
    """Restore the in-memory documents."""
    DOCUMENTS.clear()
    DOCUMENTS.update(_seed())


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


def authenticated_document(id: int, _user: Annotated[str, Depends(require_user)]) -> Document:
    """Authenticate the caller and load the document. Ownership is not checked."""
    document = DOCUMENTS.get(id)
    if document is None:
        raise HTTPException(status_code=404, detail="Document not found")
    return document


@app.get("/documents/{id}")
def get_document(document: Annotated[Document, Depends(authenticated_document)]) -> Document:
    """Return the document produced by the dependency."""
    return document


@app.put("/documents/{id}")
def update_document(
    body: DocumentUpdate,
    document: Annotated[Document, Depends(authenticated_document)],
) -> Document:
    """Replace the document produced by the dependency."""
    updated = document.model_copy(update={"title": body.title, "content": body.content})
    DOCUMENTS[document.id] = updated
    return updated


def main() -> None:
    """Listen on 127.0.0.1. Pass --port to choose the port."""
    import uvicorn

    parser = argparse.ArgumentParser(description="Dependency-check vulnerable benchmark. Local testing only.")
    parser.add_argument("--port", type=int, default=PORT)
    args = parser.parse_args()
    uvicorn.run(app, host="127.0.0.1", port=args.port)


if __name__ == "__main__":
    main()
