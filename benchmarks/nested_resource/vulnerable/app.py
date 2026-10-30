# Intentionally vulnerable benchmark app. Local testing only. Not for production.
"""Invoice items nested under a parent invoice, with no parent ownership check.

GET /invoices/{invoice_id}/items returns the child items when the bearer
token is valid and the invoice exists. The parent invoice owner is not
compared with the caller. Bind to localhost only.

Users (Authorization: Bearer <token>):
    alice-token -> alice
    bob-token -> bob

Invoices:
    inv-101 owned by alice
    inv-202 owned by bob

Start on a chosen port:

    uvicorn benchmarks.nested_resource.vulnerable.app:app --host 127.0.0.1 --port 8107
"""

from __future__ import annotations

import argparse
from typing import Annotated

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel

app = FastAPI(title="Benchmark nested-resource vulnerable")
PORT = 8107

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
def list_items(invoice_id: str, _user: Annotated[str, Depends(require_user)]) -> InvoiceItems:
    """Return items for an existing invoice. Parent ownership is not checked."""
    owner = INVOICES.get(invoice_id)
    if owner is None:
        raise HTTPException(status_code=404, detail="Invoice not found")
    return InvoiceItems(invoice_id=invoice_id, owner=owner, items=list(ITEMS[invoice_id]))


def main() -> None:
    """Listen on 127.0.0.1. Pass --port to choose the port."""
    import uvicorn

    parser = argparse.ArgumentParser(description="Nested-resource vulnerable benchmark. Local testing only.")
    parser.add_argument("--port", type=int, default=PORT)
    args = parser.parse_args()
    uvicorn.run(app, host="127.0.0.1", port=args.port)


if __name__ == "__main__":
    main()
