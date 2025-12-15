from datetime import datetime
from sequence_rule_engine.engine.extractor import DottedPathExtractor
from sequence_rule_engine.engine.models import Event


class TestDottedPathExtractor:
    """Test the DottedPathExtractor class."""

    def test_extract_simple_field(self):
        """Test extracting a top-level field."""
        extractor = DottedPathExtractor()
        event = {"name": "test", "id": "123"}

        assert extractor.extract(event, "name") == "test"
        assert extractor.extract(event, "id") == "123"

    def test_extract_nested_field(self):
        """Test extracting nested fields with dot notation."""
        extractor = DottedPathExtractor()
        event = {"agent": {"id": "037", "name": "deb12"}}

        assert extractor.extract(event, "agent.id") == "037"
        assert extractor.extract(event, "agent.name") == "deb12"

    def test_extract_deeply_nested(self):
        """Test extracting deeply nested fields."""
        extractor = DottedPathExtractor()
        event = {"data": {"win": {"eventdata": {"status": "0x0", "user": "admin"}}}}

        assert extractor.extract(event, "data.win.eventdata.status") == "0x0"
        assert extractor.extract(event, "data.win.eventdata.user") == "admin"

    def test_extract_missing_field(self):
        """Test that missing fields return None by default."""
        extractor = DottedPathExtractor()
        event = {"name": "test"}

        assert extractor.extract(event, "missing") is None
        assert extractor.extract(event, "missing.nested") is None

    def test_extract_missing_field_with_default(self):
        """Test that missing fields return specified default."""
        extractor = DottedPathExtractor()
        event = {"name": "test"}

        assert extractor.extract(event, "missing", "default") == "default"
        assert extractor.extract(event, "missing", 0) == 0
        assert extractor.extract(event, "missing", []) == []

    def test_extract_partial_path_exists(self):
        """Test extraction when partial path exists but not full path."""
        extractor = DottedPathExtractor()
        event = {"agent": {"id": "037"}}

        assert extractor.extract(event, "agent.name") is None
        assert extractor.extract(event, "agent.name", "unknown") == "unknown"

    def test_extract_empty_path(self):
        """Test that empty path returns default."""
        extractor = DottedPathExtractor()
        event = {"name": "test"}

        assert extractor.extract(event, "") is None
        assert extractor.extract(event, "", "default") == "default"

    def test_extract_non_dict_value(self):
        """Test extraction when intermediate value is not a dict."""
        extractor = DottedPathExtractor()
        event = {"agent": "string_value"}

        assert extractor.extract(event, "agent.id") is None

    def test_extract_from_non_dict_event(self):
        """Test extraction from non-dict returns default."""
        extractor = DottedPathExtractor()

        assert extractor.extract(None, "path") is None
        assert extractor.extract("string", "path") is None
        assert extractor.extract([], "path") is None

    def test_extract_wazuh_alert_fields(self):
        """Test extraction from typical Wazuh alert structure."""
        extractor = DottedPathExtractor()
        event = {
            "timestamp": "2025-12-06T22:17:02.297+0700",
            "rule": {"level": 3, "description": "Auditbeat Integration", "id": "500111"},
            "agent": {"id": "037", "name": "deb12", "ip": "103.153.61.108"},
            "data": {"user": {"name": "root"}},
        }

        assert extractor.extract(event, "rule.id") == "500111"
        assert extractor.extract(event, "rule.level") == 3
        assert extractor.extract(event, "agent.name") == "deb12"
        assert extractor.extract(event, "data.user.name") == "root"

    def test_extract_multiple(self):
        """Test extracting multiple paths at once."""
        extractor = DottedPathExtractor()
        event = {"rule": {"id": "500111"}, "agent": {"name": "deb12"}, "missing": "value"}

        result = extractor.extract_multiple(event, ["rule.id", "agent.name", "nonexistent"])

        assert result["rule.id"] == "500111"
        assert result["agent.name"] == "deb12"
        assert result["nonexistent"] is None


class TestEventModel:
    """Test the Event model class."""

    def test_event_creation_with_fields(self):
        """Test creating an event with fields."""
        fields = {"name": "test", "value": 123}
        event = Event(fields=fields)

        assert event.fields == fields
        assert event.event_id is not None
        assert isinstance(event.timestamp, datetime)

    def test_event_creation_with_timestamp(self):
        """Test creating an event with explicit timestamp."""
        fields = {"name": "test"}
        timestamp = datetime(2025, 12, 6, 10, 30, 0)
        event = Event(fields=fields, timestamp=timestamp)

        assert event.timestamp == timestamp

    def test_event_creation_with_event_id(self):
        """Test creating an event with explicit event_id."""
        fields = {"name": "test"}
        event_id = "custom-id-123"
        event = Event(fields=fields, event_id=event_id)

        assert event.event_id == event_id

    def test_event_auto_generated_id(self):
        """Test that event_id is auto-generated as hash of fields."""
        fields = {"name": "test", "value": 123}
        event1 = Event(fields=fields)
        event2 = Event(fields=fields)

        assert event1.event_id == event2.event_id
        assert len(event1.event_id) == 64

    def test_event_different_fields_different_ids(self):
        """Test that different fields produce different event IDs."""
        event1 = Event(fields={"name": "test1"})
        event2 = Event(fields={"name": "test2"})

        assert event1.event_id != event2.event_id

    def test_event_get_simple_field(self):
        """Test Event.get() for simple fields."""
        event = Event(fields={"name": "test", "id": "123"})

        assert event.get("name") == "test"
        assert event.get("id") == "123"

    def test_event_get_nested_field(self):
        """Test Event.get() for nested fields."""
        event = Event(fields={"agent": {"id": "037", "name": "deb12"}})

        assert event.get("agent.id") == "037"
        assert event.get("agent.name") == "deb12"

    def test_event_get_deeply_nested(self):
        """Test Event.get() for deeply nested fields."""
        event = Event(fields={"data": {"win": {"eventdata": {"status": "0x0"}}}})

        assert event.get("data.win.eventdata.status") == "0x0"

    def test_event_get_missing_field(self):
        """Test Event.get() returns None for missing fields."""
        event = Event(fields={"name": "test"})

        assert event.get("missing") is None
        assert event.get("missing.nested") is None

    def test_event_get_with_default(self):
        """Test Event.get() with default value."""
        event = Event(fields={"name": "test"})

        assert event.get("missing", "default") == "default"
        assert event.get("missing", 0) == 0

    def test_event_get_empty_path(self):
        """Test Event.get() with empty path."""
        event = Event(fields={"name": "test"})

        assert event.get("") is None
        assert event.get("", "default") == "default"

    def test_event_repr(self):
        """Test Event string representation."""
        event = Event(fields={"name": "test"}, event_id="abcdef123456")
        repr_str = repr(event)

        assert "Event" in repr_str
        assert "abcdef12" in repr_str
        assert "timestamp" in repr_str

    def test_event_wazuh_structure(self):
        """Test Event with typical Wazuh alert structure."""
        fields = {
            "timestamp": "2025-12-06T22:17:02.297+0700",
            "rule": {"level": 3, "id": "500111"},
            "agent": {"id": "037", "name": "deb12"},
        }
        event = Event(fields=fields)

        assert event.get("rule.id") == "500111"
        assert event.get("rule.level") == 3
        assert event.get("agent.name") == "deb12"
