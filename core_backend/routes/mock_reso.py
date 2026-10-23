"""Mock RESO Web API (OData) server used for local development and testing."""

import re
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Header, HTTPException, Query

from ..ingestion import reso_api_token

router = APIRouter(prefix="/api/mock-reso/odata", tags=["mock-reso"])

MOCK_PROPERTIES: List[Dict[str, Any]] = [
    {"ListingKey": "RESO_2026_001", "ListPrice": 550000, "PropertyAddress": "123 Oak Street, San Francisco, CA",
     "BedroomsTotal": 3, "BathroomsTotalInteger": 2, "LivingArea": 2500, "YearBuilt": 1998,
     "ListAgentMlsId": "AG-1001", "StandardStatus": "Active", "ModificationTimestamp": "2026-10-22T09:00:00Z"},
    {"ListingKey": "RESO_2026_002", "ListPrice": 725000, "PropertyAddress": "456 Maple Avenue, San Francisco, CA",
     "BedroomsTotal": 4, "BathroomsTotalInteger": 3, "LivingArea": 3200, "YearBuilt": 2005,
     "ListAgentMlsId": "AG-1002", "StandardStatus": "Active", "ModificationTimestamp": "2026-10-22T08:30:00Z"},
    {"ListingKey": "RESO_2026_003", "ListPrice": 289000, "PropertyAddress": "9 Pine Court, Oakland, CA",
     "BedroomsTotal": 2, "BathroomsTotalInteger": 1, "LivingArea": 980, "YearBuilt": 1972,
     "ListAgentMlsId": "AG-1001", "StandardStatus": "Active", "ModificationTimestamp": "2026-10-21T17:10:00Z"},
    {"ListingKey": "RESO_2026_004", "ListPrice": 1450000, "PropertyAddress": "77 Bay View Drive, Sausalito, CA",
     "BedroomsTotal": 5, "BathroomsTotalInteger": 4, "LivingArea": 4100, "YearBuilt": 2015,
     "ListAgentMlsId": "AG-1003", "StandardStatus": "Pending", "ModificationTimestamp": "2026-10-20T12:00:00Z"},
    {"ListingKey": "RESO_2026_005", "ListPrice": 2350000, "PropertyAddress": "1 Summit Road, Palo Alto, CA",
     "BedroomsTotal": 6, "BathroomsTotalInteger": 5, "LivingArea": 5200, "YearBuilt": 2019,
     "ListAgentMlsId": "AG-1004", "StandardStatus": "Active", "ModificationTimestamp": "2026-10-19T08:45:00Z"},
    # Deliberately malformed: missing PropertyAddress and a non-integer bedroom count.
    {"ListingKey": "RESO_2026_006", "ListPrice": 610000, "BedroomsTotal": "three", "BathroomsTotalInteger": 2,
     "LivingArea": 1900, "YearBuilt": 1988, "ListAgentMlsId": "AG-1002", "StandardStatus": "Active",
     "ModificationTimestamp": "2026-10-22T07:15:00Z"},
]

RESOURCES: Dict[str, List[Dict[str, Any]]] = {
    "Property": MOCK_PROPERTIES,
    "Agent": [],
    "Office": [],
    "Contact": [],
}

_CONDITION = re.compile(r"^\s*(\w+)\s+(eq|ne|gt|ge|lt|le)\s+('(?:[^']|'')*'|-?\d+(?:\.\d+)?|true|false|null)\s*$")
_OPS = {
    "eq": lambda a, b: a == b,
    "ne": lambda a, b: a != b,
    "gt": lambda a, b: a is not None and a > b,
    "ge": lambda a, b: a is not None and a >= b,
    "lt": lambda a, b: a is not None and a < b,
    "le": lambda a, b: a is not None and a <= b,
}


def _parse_literal(raw: str) -> Any:
    if raw.startswith("'"):
        return raw[1:-1].replace("''", "'")
    if raw in ("true", "false"):
        return raw == "true"
    if raw == "null":
        return None
    return float(raw) if "." in raw else int(raw)


def parse_odata_filter(expression: str) -> List[tuple]:
    """Parse a subset of OData $filter: `Field op literal` clauses joined by `and`."""
    conditions = []
    for clause in re.split(r"\s+and\s+", expression.strip(), flags=re.IGNORECASE):
        match = _CONDITION.match(clause)
        if not match:
            raise ValueError(f"Unsupported $filter clause: {clause!r}")
        field, op, raw = match.groups()
        conditions.append((field, op, _parse_literal(raw)))
    return conditions


def apply_odata_filter(records: List[Dict[str, Any]], expression: Optional[str]) -> List[Dict[str, Any]]:
    if not expression:
        return list(records)
    conditions = parse_odata_filter(expression)
    result = []
    for record in records:
        try:
            if all(_OPS[op](record.get(field), value) for field, op, value in conditions):
                result.append(record)
        except TypeError:
            continue
    return result


@router.get("/{resource}")
async def query_resource(
    resource: str,
    authorization: Optional[str] = Header(None),
    filter_: Optional[str] = Query(None, alias="$filter"),
    select: Optional[str] = Query(None, alias="$select"),
    top: int = Query(100, alias="$top", ge=1, le=1000),
    skip: int = Query(0, alias="$skip", ge=0),
):
    if authorization != f"Bearer {reso_api_token()}":
        raise HTTPException(status_code=401, detail="Invalid RESO API token")

    if resource not in RESOURCES:
        raise HTTPException(status_code=404, detail=f"Unknown RESO resource: {resource}")

    try:
        records = apply_odata_filter(RESOURCES[resource], filter_)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    page = records[skip:skip + top]
    if select:
        fields = [f.strip() for f in select.split(",") if f.strip()]
        page = [{f: r[f] for f in fields if f in r} for r in page]

    return {
        "@odata.context": f"$metadata#{resource}",
        "@odata.count": len(records),
        "value": page,
    }
