"""
Milestone 2: Data Ingestion Engine with Schema Translation & Validation
Implements RESO Web API ingestion loops, dynamic schema translation, and token-bound filtering
"""

import math
import os
import httpx
from typing import Dict, Any, List, Optional
from datetime import datetime
from uuid import uuid4
import logging

logger = logging.getLogger(__name__)

# Real RESO feeds require vendor-issued credentials; by default we point at the
# bundled mock RESO OData server (routes/mock_reso.py).
DEFAULT_RESO_API_BASE_URL = "http://127.0.0.1:8000/api/mock-reso/odata"
DEFAULT_RESO_API_TOKEN = "mock-reso-token"


def reso_api_base_url() -> str:
    return os.getenv("RESO_API_BASE_URL", DEFAULT_RESO_API_BASE_URL).rstrip("/")


def reso_api_token() -> str:
    return os.getenv("RESO_API_TOKEN", DEFAULT_RESO_API_TOKEN)


def storable(value) -> bool:
    """PostgreSQL JSONB rejects NUL characters, and JSON has no NaN/Infinity."""
    if isinstance(value, str):
        return "\x00" not in value
    if isinstance(value, float):
        return math.isfinite(value)
    if isinstance(value, dict):
        return all(storable(k) and storable(v) for k, v in value.items())
    if isinstance(value, (list, tuple)):
        return all(storable(v) for v in value)
    return True


def safe_key(value):
    """A record identifier safe to put in logs and JSONB."""
    if value is None:
        return None
    return str(value).replace("\x00", "")[:200]


RESO_RESOURCES = {
    "Property": "/Property",
    "Agent": "/Agent",
    "Office": "/Office",
    "Contact": "/Contact",
}

class SchemaTranslator:
    """Dynamic schema translation module for converting between different data schemas"""

    def __init__(self):
        self.mappings: Dict[str, Dict[str, str]] = {}
        self._init_default_mappings()

    def _init_default_mappings(self):
        """Initialize default schema mappings"""
        # RESO to Internal Schema mapping
        self.mappings["reso_to_internal"] = {
            "ResourceName": "resource_type",
            "ListingKey": "listing_id",
            "ListPrice": "price",
            "PropertyAddress": "address",
            "BedroomsTotal": "bedrooms",
            "BathroomsTotalInteger": "bathrooms",
            "LivingArea": "square_feet",
            "YearBuilt": "year_built",
            "ListAgentMlsId": "agent_id",
            "ModificationTimestamp": "updated_at",
        }

        # Internal to CSV Schema mapping
        self.mappings["internal_to_csv"] = {
            "resource_type": "Resource Type",
            "listing_id": "Listing ID",
            "price": "Price",
            "address": "Address",
            "bedrooms": "Bedrooms",
            "bathrooms": "Bathrooms",
            "square_feet": "Square Feet",
            "year_built": "Year Built",
            "agent_id": "Agent ID",
            "updated_at": "Last Updated",
        }

    def translate_record(self, record: Dict[str, Any], source_schema: str, dest_schema: str) -> Dict[str, Any]:
        """
        Translate a single record from source schema to destination schema

        Args:
            record: The data record to translate
            source_schema: Source schema name (e.g., 'reso', 'internal')
            dest_schema: Destination schema name

        Returns:
            Translated record
        """
        mapping_key = f"{source_schema}_to_{dest_schema}"

        if mapping_key not in self.mappings:
            logger.warning(f"No mapping found for {mapping_key}, returning original record")
            return record

        mapping = self.mappings[mapping_key]
        translated = {}

        for source_field, dest_field in mapping.items():
            if source_field in record:
                value = record[source_field]
                # Apply transformations based on field type
                translated[dest_field] = self._transform_value(value, source_field)

        return translated

    def _transform_value(self, value: Any, field_name: str) -> Any:
        """Apply field-specific transformations"""
        if value is None:
            return None

        # Price normalization
        if "price" in field_name.lower() or "cost" in field_name.lower():
            try:
                return float(value)
            except (TypeError, ValueError):
                return value

        # Date normalization to ISO-8601 strings (JSON-storable)
        if "date" in field_name.lower() or "timestamp" in field_name.lower():
            try:
                return datetime.fromisoformat(str(value).replace("Z", "+00:00")).isoformat()
            except ValueError:
                return value

        return value

    def add_custom_mapping(self, source_schema: str, dest_schema: str, mapping: Dict[str, str]):
        """Add custom schema mapping"""
        mapping_key = f"{source_schema}_to_{dest_schema}"
        self.mappings[mapping_key] = mapping
        logger.info(f"Added custom mapping: {mapping_key}")


class PayloadValidator:
    """Validates data payloads against schemas with strict server-side filtering"""

    def __init__(self):
        self.schemas = {}
        self._init_default_schemas()

    def _init_default_schemas(self):
        """Initialize default schemas for validation"""
        self.schemas["reso_property"] = {
            "required": ["ListingKey", "PropertyAddress"],
            "types": {
                "ListingKey": str,
                "ListPrice": (int, float),
                "BedroomsTotal": int,
                "BathroomsTotalInteger": int,
            }
        }

        self.schemas["internal"] = {
            "required": ["listing_id", "address"],
            "types": {
                "listing_id": str,
                "price": (int, float),
                "bedrooms": int,
                "bathrooms": int,
            }
        }

    def validate_payload(self, payload: Dict[str, Any], schema_name: str) -> tuple[bool, List[str]]:
        """
        Validate payload against schema

        Args:
            payload: Data to validate
            schema_name: Schema to validate against

        Returns:
            Tuple of (is_valid, error_messages)
        """
        if schema_name not in self.schemas:
            return False, [f"Unknown schema: {schema_name}"]

        schema = self.schemas[schema_name]
        errors = []

        # Check required fields
        for required_field in schema.get("required", []):
            if required_field not in payload:
                errors.append(f"Missing required field: {required_field}")

        # Check field types
        for field_name, expected_type in schema.get("types", {}).items():
            if field_name in payload:
                value = payload[field_name]
                if value is not None and not isinstance(value, expected_type):
                    types = expected_type if isinstance(expected_type, tuple) else (expected_type,)
                    expected = " or ".join(t.__name__ for t in types)
                    errors.append(
                        f"Field {field_name} has invalid type: expected {expected}, got {type(value).__name__}"
                    )

        return len(errors) == 0, errors

    def add_custom_schema(self, schema_name: str, schema_def: Dict[str, Any]):
        """Add custom validation schema"""
        self.schemas[schema_name] = schema_def
        logger.info(f"Added custom schema: {schema_name}")


class RESODataIngestionEngine:
    """RESO Web API universal ingestion loop with token-bound filtering"""

    def __init__(
        self,
        auth_token: Optional[str] = None,
        base_url: Optional[str] = None,
        transport: Optional[httpx.AsyncBaseTransport] = None,
    ):
        self.auth_token = auth_token or reso_api_token()
        self.base_url = (base_url or reso_api_base_url()).rstrip("/")
        self.translator = SchemaTranslator()
        self.validator = PayloadValidator()
        self.client = httpx.AsyncClient(timeout=30.0, transport=transport)

    async def ingest_from_reso(
        self,
        resource_type: str,
        filters: Optional[str] = None,
        select_fields: Optional[List[str]] = None,
        top: int = 100,
        skip: int = 0
    ) -> List[Dict[str, Any]]:
        """
        Ingest data from RESO Web API with token-bound authorization

        Args:
            resource_type: RESO resource to query (Property, Agent, etc.)
            filters: OData filter conditions
            select_fields: Specific fields to select
            top: Number of records to fetch
            skip: Number of records to skip (pagination)

        Returns:
            List of ingested records
        """
        if resource_type not in RESO_RESOURCES:
            raise ValueError(f"Unknown RESO resource: {resource_type}")

        url = f"{self.base_url}{RESO_RESOURCES[resource_type]}"
        headers = {
            "Authorization": f"Bearer {self.auth_token}",
            "Accept": "application/json",
        }

        # Build query parameters
        params = {
            "$top": top,
            "$skip": skip,
        }

        if select_fields:
            params["$select"] = ",".join(select_fields)

        if filters:
            params["$filter"] = filters

        try:
            logger.info(f"Fetching RESO data: {resource_type} with filters: {filters}")
            response = await self.client.get(url, headers=headers, params=params)
            response.raise_for_status()

            data = response.json()
            records = data.get("value", [])

            logger.info(f"Successfully ingested {len(records)} records from RESO")
            return records

        except httpx.HTTPError as e:
            logger.error(f"RESO API error: {str(e)}")
            raise

    async def process_ingestion_batch(
        self,
        records: List[Dict[str, Any]],
        source_schema: str = "reso",
        dest_schema: str = "internal",
        validate: bool = True
    ) -> tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """
        Process a batch of ingested records with schema translation and validation

        Args:
            records: Records to process
            source_schema: Source schema name
            dest_schema: Destination schema name
            validate: Whether to validate records

        Returns:
            Tuple of (valid_records, failed_records)
        """
        valid_records = []
        failed_records = []

        for record in records:
            try:
                # Translate schema
                translated = self.translator.translate_record(record, source_schema, dest_schema)
                if not storable(translated):
                    failed_records.append({
                        "original": record,
                        "errors": ["Contains NUL characters or non-finite numbers, which can't be stored"],
                        "timestamp": datetime.utcnow().isoformat()
                    })
                    continue

                # Validate if requested
                if validate:
                    is_valid, errors = self.validator.validate_payload(translated, dest_schema)
                    if not is_valid:
                        failed_records.append({
                            "original": record,
                            "errors": errors,
                            "timestamp": datetime.utcnow().isoformat()
                        })
                        continue

                # Add metadata
                translated["_ingestion_id"] = str(uuid4())
                translated["_ingestion_timestamp"] = datetime.utcnow().isoformat()
                translated["_validation_status"] = "valid"

                valid_records.append(translated)

            except Exception as e:
                logger.error(f"Failed to process record: {str(e)}")
                failed_records.append({
                    "original": record,
                    "errors": [str(e)],
                    "timestamp": datetime.utcnow().isoformat()
                })

        logger.info(f"Batch processing complete: {len(valid_records)} valid, {len(failed_records)} failed")
        return valid_records, failed_records

    async def apply_token_bound_filters(
        self,
        records: List[Dict[str, Any]],
        user_id: str,
        filter_rules: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        """
        Apply token-bound filters to restrict data access by user

        Args:
            records: Records to filter
            user_id: User ID from JWT token
            filter_rules: Custom filter rules

        Returns:
            Filtered records
        """
        filtered = []

        for record in records:
            # Add user context to record
            record["_user_id"] = user_id
            record["_access_level"] = "user"

            # Apply custom filter rules
            if filter_rules:
                should_include = True
                for field, value in filter_rules.items():
                    if field in record and record[field] != value:
                        should_include = False
                        break

                if should_include:
                    filtered.append(record)
            else:
                filtered.append(record)

        logger.info(f"Applied token-bound filters: {len(filtered)} records from {len(records)}")
        return filtered

    async def close(self):
        """Close HTTP client"""
        await self.client.aclose()


# Global instances
schema_translator = SchemaTranslator()
payload_validator = PayloadValidator()
