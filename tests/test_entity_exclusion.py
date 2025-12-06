"""Tests for entity exclusion functionality."""

from __future__ import annotations

from pathlib import Path
from typing import Dict

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from ueba.config import mapping_loader
from ueba.db.base import Base
from ueba.db.models import Entity, NormalizedEvent, RawAlert
from ueba.services.mapper.mapper import AlertMapper
from ueba.services.mapper.persistence import PersistenceManager
from ueba.services.mapper.utils import is_entity_excluded


@pytest.fixture()
def session_factory(tmp_path: Path):
    db_path = tmp_path / "exclusion_test.db"
    engine = create_engine(f"sqlite:///{db_path}", future=True)
    Base.metadata.create_all(bind=engine)
    SessionFactory = sessionmaker(bind=engine, autocommit=False, autoflush=False, future=True)
    try:
        yield SessionFactory
    finally:
        Base.metadata.drop_all(bind=engine)


@pytest.fixture()
def resolver_with_exclusions(tmp_path: Path):
    """Resolver with excluded entities configured."""
    mapping_file = tmp_path / "mapping.yml"
    mapping_file.write_text(
        """
        priority: global
        excluded_entities:
          - root
          - admin
          - system_*
          - service_*
        defaults:
          entity_id: agent.id
          entity_type: host
          severity: rule.level
          timestamp: "@timestamp"
          enrichment:
            agent_name: agent.name
        sources:
          wazuh:
            selectors:
              - name: user-based
                match:
                  group: authentication_failed
                fields:
                  entity_type: user
                  entity_id: data.srcuser
                  enrichment:
                    username: data.srcuser
        """,
        encoding="utf-8",
    )
    return mapping_loader.load([mapping_file])


def sample_alert(**overrides: Dict) -> Dict:
    """Create a sample alert for testing."""
    alert = {
        "id": "1670000000.1",
        "@timestamp": "2024-01-02T15:04:05Z",
        "agent": {"id": "001", "name": "host-1"},
        "rule": {
            "id": "9100",
            "level": 12,
            "description": "Test Rule",
            "groups": ["test_group"],
        },
        "data": {"srcuser": "alice", "severity": 9},
    }
    alert.update(overrides)
    return alert


# -------------------------------------------------------------------------
# Unit tests for is_entity_excluded function
# -------------------------------------------------------------------------


def test_is_entity_excluded_exact_match():
    """Test exact match exclusion."""
    patterns = ["root", "admin", "test"]
    assert is_entity_excluded("root", patterns) is True
    assert is_entity_excluded("admin", patterns) is True
    assert is_entity_excluded("test", patterns) is True


def test_is_entity_excluded_no_match():
    """Test entity that doesn't match any pattern."""
    patterns = ["root", "admin", "system_*"]
    assert is_entity_excluded("alice", patterns) is False
    assert is_entity_excluded("bob", patterns) is False
    assert is_entity_excluded("user123", patterns) is False


def test_is_entity_excluded_wildcard_match():
    """Test wildcard pattern matching."""
    patterns = ["system_*", "service_*", "*_temp"]

    # Should match system_*
    assert is_entity_excluded("system_account", patterns) is True
    assert is_entity_excluded("system_1", patterns) is True
    assert is_entity_excluded("system_", patterns) is True

    # Should match service_*
    assert is_entity_excluded("service_account", patterns) is True
    assert is_entity_excluded("service_1", patterns) is True

    # Should match *_temp
    assert is_entity_excluded("user_temp", patterns) is True
    assert is_entity_excluded("db_temp", patterns) is True

    # Should not match
    assert is_entity_excluded("systemaccount", patterns) is False  # no underscore
    assert is_entity_excluded("alice", patterns) is False


def test_is_entity_excluded_empty_patterns():
    """Test with empty pattern list."""
    assert is_entity_excluded("root", []) is False
    assert is_entity_excluded("anything", []) is False


def test_is_entity_excluded_empty_entity():
    """Test with empty entity value."""
    patterns = ["root", "admin"]
    assert is_entity_excluded("", patterns) is False
    assert is_entity_excluded(None, patterns) is False


def test_is_entity_excluded_case_sensitive():
    """Test that matching is case-sensitive."""
    patterns = ["root", "Admin"]
    assert is_entity_excluded("root", patterns) is True
    assert is_entity_excluded("Root", patterns) is False
    assert is_entity_excluded("Admin", patterns) is True
    assert is_entity_excluded("admin", patterns) is False


# -------------------------------------------------------------------------
# Integration tests with mapper
# -------------------------------------------------------------------------


def test_mapper_excludes_entity_exact_match(session_factory, resolver_with_exclusions):
    """Test mapper skips excluded entity (exact match)."""
    mapper = AlertMapper(resolver_with_exclusions)

    # Create alert with user entity = "root" (should be excluded)
    alert = sample_alert(
        rule={"id": "5501", "level": 5, "groups": ["authentication_failed"]},
        data={"srcuser": "root", "severity": 7},
    )

    with session_factory() as session:
        persistence = PersistenceManager(session)
        result = mapper.map_and_persist(alert, persistence, source="wazuh")
        session.commit()

        # Alert and event should be persisted
        assert result["status"] == "success"
        assert result["raw_alert_id"] is not None
        assert result["normalized_event_id"] is not None

        # But no entity should be created
        assert result["entity_id"] is None
        entities = session.execute(select(Entity)).scalars().all()
        assert len(entities) == 0

        # Raw alert and normalized event should have null entity_id
        raw_alert = session.execute(select(RawAlert)).scalar_one()
        assert raw_alert.entity_id is None

        normalized_event = session.execute(select(NormalizedEvent)).scalar_one()
        assert normalized_event.entity_id is None


def test_mapper_excludes_entity_wildcard_match(session_factory, resolver_with_exclusions):
    """Test mapper skips excluded entity (wildcard match)."""
    mapper = AlertMapper(resolver_with_exclusions)

    # Create alert with user entity = "system_user" (matches system_*)
    alert = sample_alert(
        rule={"id": "5501", "level": 5, "groups": ["authentication_failed"]},
        data={"srcuser": "system_user", "severity": 7},
    )

    with session_factory() as session:
        persistence = PersistenceManager(session)
        result = mapper.map_and_persist(alert, persistence, source="wazuh")
        session.commit()

        # Alert and event persisted, but no entity
        assert result["status"] == "success"
        assert result["entity_id"] is None
        entities = session.execute(select(Entity)).scalars().all()
        assert len(entities) == 0


def test_mapper_allows_non_excluded_entity(session_factory, resolver_with_exclusions):
    """Test mapper persists non-excluded entity."""
    mapper = AlertMapper(resolver_with_exclusions)

    # Create alert with user entity = "alice" (not excluded)
    alert = sample_alert(
        rule={"id": "5501", "level": 5, "groups": ["authentication_failed"]},
        data={"srcuser": "alice", "severity": 7},
    )

    with session_factory() as session:
        persistence = PersistenceManager(session)
        result = mapper.map_and_persist(alert, persistence, source="wazuh")
        session.commit()

        # Entity should be created
        assert result["status"] == "success"
        assert result["entity_id"] is not None

        entity = session.execute(select(Entity)).scalar_one()
        assert entity.entity_type == "user"
        assert entity.entity_value == "alice"


def test_mapper_multiple_alerts_with_exclusions(session_factory, resolver_with_exclusions):
    """Test mapper handles multiple alerts with mixed exclusions."""
    mapper = AlertMapper(resolver_with_exclusions)

    alerts = [
        # Should be excluded
        sample_alert(
            id="1",
            rule={"id": "5501", "level": 5, "groups": ["authentication_failed"]},
            data={"srcuser": "root", "severity": 7},
        ),
        # Should be excluded
        sample_alert(
            id="2",
            rule={"id": "5501", "level": 5, "groups": ["authentication_failed"]},
            data={"srcuser": "admin", "severity": 7},
        ),
        # Should be excluded
        sample_alert(
            id="3",
            rule={"id": "5501", "level": 5, "groups": ["authentication_failed"]},
            data={"srcuser": "service_account", "severity": 7},
        ),
        # Should NOT be excluded
        sample_alert(
            id="4",
            rule={"id": "5501", "level": 5, "groups": ["authentication_failed"]},
            data={"srcuser": "alice", "severity": 7},
        ),
        # Should NOT be excluded
        sample_alert(
            id="5",
            rule={"id": "5501", "level": 5, "groups": ["authentication_failed"]},
            data={"srcuser": "bob", "severity": 7},
        ),
    ]

    with session_factory() as session:
        persistence = PersistenceManager(session)
        for alert in alerts:
            mapper.map_and_persist(alert, persistence, source="wazuh")
        session.commit()

        # Should have 2 entities (alice and bob)
        entities = session.execute(select(Entity)).scalars().all()
        assert len(entities) == 2
        entity_values = {e.entity_value for e in entities}
        assert entity_values == {"alice", "bob"}

        # Should have 5 raw alerts
        raw_alerts = session.execute(select(RawAlert)).scalars().all()
        assert len(raw_alerts) == 5

        # Should have 5 normalized events
        normalized_events = session.execute(select(NormalizedEvent)).scalars().all()
        assert len(normalized_events) == 5


def test_mapping_resolver_loads_excluded_entities(resolver_with_exclusions):
    """Test that MappingResolver correctly loads excluded entities."""
    excluded = resolver_with_exclusions.get_excluded_entities()
    assert len(excluded) == 4
    assert "root" in excluded
    assert "admin" in excluded
    assert "system_*" in excluded
    assert "service_*" in excluded


def test_excluded_entities_with_no_config(tmp_path: Path):
    """Test mapping without excluded_entities config."""
    mapping_file = tmp_path / "mapping.yml"
    mapping_file.write_text(
        """
        priority: global
        defaults:
          entity_id: agent.id
          entity_type: host
          severity: rule.level
          timestamp: "@timestamp"
        """,
        encoding="utf-8",
    )
    resolver = mapping_loader.load([mapping_file])
    excluded = resolver.get_excluded_entities()
    assert excluded == []
