# Ownership-checked benchmark twin. Local testing only. Not for production.
"""Invoice items nested under a parent invoice. The parent owner is checked.

GET /invoices/{invoice_id}/items returns the child items only when the
caller owns the parent invoice. Anyone else gets 404, the same response as
a missing invoice. Unknown tokens get 401. Bind to localhost only.

Users (Authorization: Bearer <token>):
    alice-token -> alice
    bob-token -> bob

Invoices:
    inv-101 owned by alice
    inv-202 owned by bob

Start on a chosen port:

    uvicorn benchmarks.nested_resource.secure.app:app --host 127.0.0.1 --port 8108
"""

from __future__ import annotations

import argparse
from typing import Annotated

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel

app = FastAPI(title="Benchmark nested-resource secure")
PORT = 8108

TOKENS: dict[str, str] = {
    "alice-token": "alice",
    "bob-token": "bob",
}


class Item(BaseModel):
    sku: str
    note: str


class InvoiceItems(BaseModel):
    invoice_id: str
    owner: str
    items: list[Item]


def _seed_invoices() -> dict[str, str]:
    return {"inv-101": "alice", "inv-202": "bob"}


def _seed_items() -> dict[str, list[Item]]:
    return {
        "inv-101": [Item(sku="pen", note="alice-private")],
        "inv-202": [Item(sku="book", note="bob-private")],
    }


INVOICES: dict[str, str] = _seed_invoices()
ITEMS: dict[str, list[Item]] = _seed_items()


def reset() -> None:
    """Restore the in-memory invoices and items."""
    INVOICES.clear()
    INVOICES.update(_seed_invoices())
    ITEMS.clear()
    ITEMS.update(_seed_items())


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


@app.get("/invoices/{invoice_id}/items")
def list_items(invoice_id: str, user: Annotated[str, Depends(require_user)]) -> InvoiceItems:
    """Return items only when this user owns the parent invoice."""
    owner = INVOICES.get(invoice_id)
    if owner is None or owner != user:
        raise HTTPException(status_code=404, detail="Invoice not found")
    return InvoiceItems(invoice_id=invoice_id, owner=owner, items=list(ITEMS[invoice_id]))


def main() -> None:
    """Listen on 127.0.0.1. Pass --port to choose the port."""
    import uvicorn

    parser = argparse.ArgumentParser(description="Nested-resource secure benchmark. Local testing only.")
    parser.add_argument("--port", type=int, default=PORT)
    args = parser.parse_args()
    uvicorn.run(app, host="127.0.0.1", port=args.port)


if __name__ == "__main__":
    main()
