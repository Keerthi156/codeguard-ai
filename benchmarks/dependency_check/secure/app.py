# Ownership-checked benchmark twin. Local testing only. Not for production.
"""Documents API whose dependency loads the document only for its owner.

``owned_document`` is a ``Depends()`` dependency. A caller who does not own
the document gets 404, the same response as a missing document. Unknown
tokens get 401. Bind to localhost only.

Users (Authorization: Bearer <token>):
    alice-token -> alice
    bob-token -> bob

Documents:
    101 owned by alice
    202 owned by bob

Start on a chosen port:

    uvicorn benchmarks.dependency_check.secure.app:app --host 127.0.0.1 --port 8104
"""

from __future__ import annotations

import argparse
from typing import Annotated

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel

app = FastAPI(title="Benchmark dependency-check secure")
PORT = 8104

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


def owned_document(id: int, user: Annotated[str, Depends(require_user)]) -> Document:
    """Load the document only when the authenticated user owns it."""
    document = DOCUMENTS.get(id)
    if document is None or document.owner != user:
        raise HTTPException(status_code=404, detail="Document not found")
    return document


@app.get("/documents/{id}")
def get_document(document: Annotated[Document, Depends(owned_document)]) -> Document:
    """Return the document produced by the ownership dependency."""
    return document


@app.put("/documents/{id}")
def update_document(
    body: DocumentUpdate,
    document: Annotated[Document, Depends(owned_document)],
) -> Document:
    """Replace the document produced by the ownership dependency."""
    updated = document.model_copy(update={"title": body.title, "content": body.content})
    DOCUMENTS[document.id] = updated
    return updated


def main() -> None:
    """Listen on 127.0.0.1. Pass --port to choose the port."""
    import uvicorn

    parser = argparse.ArgumentParser(description="Dependency-check secure benchmark. Local testing only.")
    parser.add_argument("--port", type=int, default=PORT)
    args = parser.parse_args()
    uvicorn.run(app, host="127.0.0.1", port=args.port)


if __name__ == "__main__":
    main()
