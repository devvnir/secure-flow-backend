"""
Comprehensive tests for Milestone 2: Data Ingestion System
Tests RESO API ingestion, schema translation, validation, and filtering
"""

import pytest
import asyncio
from datetime import datetime
from uuid import uuid4

from ..ingestion import (
    SchemaTranslator,
    PayloadValidator,
    RESODataIngestionEngine,
)


class TestSchemaTranslator:
    """Test dynamic schema translation"""

    def setup_method(self):
        self.translator = SchemaTranslator()

    def test_default_mappings_exist(self):
        """Verify default mappings are initialized"""
        assert "reso_to_internal" in self.translator.mappings
        assert "internal_to_csv" in self.translator.mappings

    def test_translate_reso_to_internal(self):
        """Test RESO to Internal schema translation"""
        reso_record = {
            "ListingKey": "12345",
            "ListPrice": 500000,
            "PropertyAddress": "123 Main St",
            "BedroomsTotal": 3,
            "BathroomsTotalInteger": 2,
            "LivingArea": 2500,
        }

        translated = self.translator.translate_record(
            reso_record,
            "reso",
            "internal"
        )

        assert "listing_id" in translated
        assert translated["listing_id"] == "12345"
        assert "price" in translated
        assert translated["price"] == 500000
        assert "address" in translated
        assert translated["address"] == "123 Main St"
        assert "bedrooms" in translated
        assert translated["bedrooms"] == 3

    def test_translate_with_null_values(self):
        """Test translation handles null values properly"""
        record_with_nulls = {
            "ListingKey": "12345",
            "ListPrice": None,
            "PropertyAddress": "123 Main St",
        }

        translated = self.translator.translate_record(
            record_with_nulls,
            "reso",
            "internal"
        )

        assert translated.get("price") is None
        assert translated.get("listing_id") == "12345"

    def test_price_normalization(self):
        """Test price field normalization"""
        record = {
            "ListingKey": "123",
            "ListPrice": "500000.50",
        }

        translated = self.translator.translate_record(
            record,
            "reso",
            "internal"
        )

        assert isinstance(translated["price"], float)
        assert translated["price"] == 500000.50

    def test_add_custom_mapping(self):
        """Test adding custom schema mapping"""
        custom_mapping = {
            "CustomField1": "mapped_field1",
            "CustomField2": "mapped_field2",
        }

        self.translator.add_custom_mapping("custom_source", "custom_dest", custom_mapping)

        assert "custom_source_to_custom_dest" in self.translator.mappings
        assert self.translator.mappings["custom_source_to_custom_dest"] == custom_mapping


class TestPayloadValidator:
    """Test payload validation against schemas"""

    def setup_method(self):
        self.validator = PayloadValidator()

    def test_default_schemas_exist(self):
        """Verify default schemas are initialized"""
        assert "reso_property" in self.validator.schemas
        assert "internal" in self.validator.schemas

    def test_validate_valid_payload(self):
        """Test validation of valid payload"""
        payload = {
            "listing_id": "12345",
            "address": "123 Main St",
            "price": 500000,
            "bedrooms": 3,
            "bathrooms": 2,
        }

        is_valid, errors = self.validator.validate_payload(payload, "internal")

        assert is_valid is True
        assert len(errors) == 0

    def test_validate_missing_required_field(self):
        """Test validation fails when required field is missing"""
        payload = {
            "price": 500000,
            "bedrooms": 3,
        }

        is_valid, errors = self.validator.validate_payload(payload, "internal")

        assert is_valid is False
        assert any("listing_id" in error for error in errors)

    def test_validate_invalid_field_type(self):
        """Test validation fails when field has wrong type"""
        payload = {
            "listing_id": "12345",
            "address": "123 Main St",
            "price": "not_a_number",
        }

        is_valid, errors = self.validator.validate_payload(payload, "internal")

        assert is_valid is False
        assert any("price" in error for error in errors)

    def test_validate_null_values(self):
        """Test validation handles null values"""
        payload = {
            "listing_id": "12345",
            "address": "123 Main St",
            "price": None,
        }

        is_valid, errors = self.validator.validate_payload(payload, "internal")

        assert is_valid is True

    def test_add_custom_schema(self):
        """Test adding custom validation schema"""
        custom_schema = {
            "required": ["field1", "field2"],
            "types": {
                "field1": str,
                "field2": int,
            }
        }

        self.validator.add_custom_schema("custom_schema", custom_schema)

        assert "custom_schema" in self.validator.schemas

        # Test validation with custom schema
        payload = {"field1": "value", "field2": 42}
        is_valid, errors = self.validator.validate_payload(payload, "custom_schema")

        assert is_valid is True


class TestRESODataIngestionEngine:
    """Test RESO data ingestion engine"""

    def setup_method(self):
        self.engine = RESODataIngestionEngine(auth_token="test_token_12345")

    @pytest.mark.asyncio
    async def test_schema_translation_in_batch_processing(self):
        """Test schema translation during batch processing"""
        records = [
            {
                "ListingKey": "123",
                "PropertyAddress": "123 Main St",
                "ListPrice": 500000,
                "BedroomsTotal": 3,
            }
        ]

        valid_records, failed_records = await self.engine.process_ingestion_batch(
            records,
            source_schema="reso",
            dest_schema="internal",
            validate=False
        )

        assert len(valid_records) == 1
        assert len(failed_records) == 0
        assert valid_records[0]["listing_id"] == "123"
        assert "_ingestion_id" in valid_records[0]
        assert "_validation_status" in valid_records[0]

    @pytest.mark.asyncio
    async def test_batch_processing_with_validation(self):
        """Test batch processing with payload validation"""
        records = [
            {
                "listing_id": "123",
                "address": "123 Main St",
                "price": 500000,
            },
            {
                "listing_id": "456",
                # Missing address - should fail
                "price": 400000,
            }
        ]

        # First translate records
        translated_records = [
            self.engine.translator.translate_record(r, "internal", "internal")
            for r in records
        ]

        valid_records, failed_records = await self.engine.process_ingestion_batch(
            translated_records,
            source_schema="internal",
            dest_schema="internal",
            validate=True
        )

        assert len(valid_records) == 1
        assert len(failed_records) == 1

    @pytest.mark.asyncio
    async def test_token_bound_filtering(self):
        """Test token-bound user filtering"""
        records = [
            {"listing_id": "123", "address": "123 Main St"},
            {"listing_id": "456", "address": "456 Oak Ave"},
        ]

        user_id = "user_12345"
        filtered = await self.engine.apply_token_bound_filters(
            records,
            user_id=user_id,
            filter_rules=None
        )

        assert len(filtered) == 2
        for record in filtered:
            assert record["_user_id"] == user_id
            assert record["_access_level"] == "user"

    @pytest.mark.asyncio
    async def test_token_bound_filtering_with_rules(self):
        """Test token-bound filtering with custom rules"""
        records = [
            {"listing_id": "123", "status": "active"},
            {"listing_id": "456", "status": "inactive"},
            {"listing_id": "789", "status": "active"},
        ]

        filter_rules = {"status": "active"}
        filtered = await self.engine.apply_token_bound_filters(
            records,
            user_id="user_123",
            filter_rules=filter_rules
        )

        assert len(filtered) == 2
        assert all(r["status"] == "active" for r in filtered)


class TestDataIngestionPipeline:
    """Integration tests for complete ingestion pipeline"""

    @pytest.mark.asyncio
    async def test_complete_ingestion_pipeline(self):
        """Test complete pipeline: ingest → translate → validate → filter"""
        engine = RESODataIngestionEngine(auth_token="test_token")

        # Simulate RESO data
        reso_records = [
            {
                "ListingKey": "RESO123",
                "PropertyAddress": "123 Main St",
                "ListPrice": 500000,
                "BedroomsTotal": 3,
                "BathroomsTotalInteger": 2,
            }
        ]

        # Step 1: Process (translate + validate)
        valid_records, failed_records = await engine.process_ingestion_batch(
            reso_records,
            source_schema="reso",
            dest_schema="internal",
            validate=False
        )

        assert len(valid_records) == 1
        assert len(failed_records) == 0

        # Step 2: Apply token-bound filtering
        filtered = await engine.apply_token_bound_filters(
            valid_records,
            user_id="user_12345"
        )

        assert len(filtered) == 1
        assert filtered[0]["_user_id"] == "user_12345"
        assert filtered[0]["listing_id"] == "RESO123"
        assert filtered[0]["price"] == 500000

    def test_validation_error_handling(self):
        """Test error handling in validation"""
        validator = PayloadValidator()

        # Add strict schema
        strict_schema = {
            "required": ["id", "name", "value"],
            "types": {
                "id": str,
                "name": str,
                "value": int,
            }
        }
        validator.add_custom_schema("strict", strict_schema)

        # Test with invalid data
        payload = {"id": "123"}
        is_valid, errors = validator.validate_payload(payload, "strict")

        assert not is_valid
        assert len(errors) >= 2


# Test execution
if __name__ == "__main__":
    pytest.main([__file__, "-v"])
