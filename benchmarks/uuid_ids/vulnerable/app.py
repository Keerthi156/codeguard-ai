# Intentionally vulnerable benchmark app. Local testing only. Not for production.
"""Documents API addressed by UUID strings. GET and DELETE ignore ownership.

A valid bearer token is enough to read or delete any document. Bind to
localhost only.

Users (Authorization: Bearer <token>):
    alice-token -> alice
    bob-token -> bob

Documents:
    11111111-1111-4111-8111-111111111111 owned by alice
    22222222-2222-4222-8222-222222222222 owned by bob

Start on a chosen port:

    uvicorn benchmarks.uuid_ids.vulnerable.app:app --host 127.0.0.1 --port 8105
"""

from __future__ import annotations

import argparse
from typing import Annotated

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel

app = FastAPI(title="Benchmark uuid-ids vulnerable")
PORT = 8105
ALICE_ID = "11111111-1111-4111-8111-111111111111"
BOB_ID = "22222222-2222-4222-8222-222222222222"

TOKENS: dict[str, str] = {
    "alice-token": "alice",
    "bob-token": "bob",
}


class Document(BaseModel):
    id: str
    owner: str
    title: str
    content: str


def _seed() -> dict[str, Document]:
    return {
        ALICE_ID: Document(id=ALICE_ID, owner="alice", title="Alice notes", content="alice-private"),
        BOB_ID: Document(id=BOB_ID, owner="bob", title="Bob notes", content="bob-private"),
    }


DOCUMENTS: dict[str, Document] = _seed()


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


def _existing_document(document_id: str) -> Document:
    document = DOCUMENTS.get(document_id)
    if document is None:
        raise HTTPException(status_code=404, detail="Document not found")
    return document


@app.get("/documents/{id}")
def get_document(id: str, _user: Annotated[str, Depends(require_user)]) -> Document:
    """Return the document when the token is valid. Ownership is not checked."""
    return _existing_document(id)


@app.delete("/documents/{id}")
def delete_document(id: str, _user: Annotated[str, Depends(require_user)]) -> dict[str, str]:
    """Delete the document when the token is valid. Ownership is not checked."""
    _existing_document(id)
    del DOCUMENTS[id]
    return {"id": id, "deleted": "true"}


def main() -> None:
    """Listen on 127.0.0.1. Pass --port to choose the port."""
    import uvicorn

    parser = argparse.ArgumentParser(description="UUID-id vulnerable benchmark. Local testing only.")
    parser.add_argument("--port", type=int, default=PORT)
    args = parser.parse_args()
    uvicorn.run(app, host="127.0.0.1", port=args.port)


if __name__ == "__main__":
    main()
