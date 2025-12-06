"""Tests for analyzer entity exclusion functionality."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from ueba.db.base import Base
from ueba.db.models import Entity, NormalizedEvent
from ueba.services.analyzer.repository import AnalyzerRepository


@pytest.fixture()
def session_factory(tmp_path: Path):
    db_path = tmp_path / "analyzer_exclusion.db"
    engine = create_engine(f"sqlite:///{db_path}", future=True)
    Base.metadata.create_all(bind=engine)
    SessionFactory = sessionmaker(bind=engine, autocommit=False, autoflush=False, future=True)
    try:
        yield SessionFactory
    finally:
        Base.metadata.drop_all(bind=engine)


def _create_entity(session, entity_type: str, value: str) -> Entity:
    entity = Entity(entity_type=entity_type, entity_value=value)
    session.add(entity)
    session.commit()
    return entity


def _add_event(session, entity_id: int, ts: datetime, event_type: str, severity: int) -> None:
    session.add(
        NormalizedEvent(
            entity_id=entity_id,
            event_type=event_type,
            observed_at=ts,
            normalized_payload={"severity": severity},
        )
    )


def test_analyzer_repository_excludes_entities_exact_match(session_factory):
    """Test that AnalyzerRepository filters out excluded entities (exact match)."""
    base_time = datetime(2024, 1, 1, 8, 0, 0, tzinfo=timezone.utc)

    with session_factory() as session:
        # Create entities
        root_entity = _create_entity(session, "user", "root")
        admin_entity = _create_entity(session, "user", "admin")
        alice_entity = _create_entity(session, "user", "alice")

        # Add events for all entities
        _add_event(session, root_entity.id, base_time, "login", 5)
        _add_event(session, admin_entity.id, base_time, "login", 6)
        _add_event(session, alice_entity.id, base_time, "login", 7)
        session.commit()

        # Capture IDs before session closes
        alice_id = alice_entity.id

    # Create repository with excluded entities
    with session_factory() as session:
        repository = AnalyzerRepository(session, excluded_entities=["root", "admin"])
        windows = repository.fetch_entity_event_windows(
            since=base_time,
            until=base_time + timedelta(days=1),
        )

    # Should only have window for alice
    assert len(windows) == 1
    assert windows[0].entity_id == alice_id


def test_analyzer_repository_excludes_entities_wildcard_match(session_factory):
    """Test that AnalyzerRepository filters out excluded entities (wildcard match)."""
    base_time = datetime(2024, 1, 1, 8, 0, 0, tzinfo=timezone.utc)

    with session_factory() as session:
        # Create entities
        system_user = _create_entity(session, "user", "system_account")
        service_user = _create_entity(session, "user", "service_db")
        normal_user = _create_entity(session, "user", "alice")

        # Add events
        _add_event(session, system_user.id, base_time, "login", 5)
        _add_event(session, service_user.id, base_time, "login", 6)
        _add_event(session, normal_user.id, base_time, "login", 7)
        session.commit()

        # Capture ID before session closes
        normal_user_id = normal_user.id

    with session_factory() as session:
        repository = AnalyzerRepository(session, excluded_entities=["system_*", "service_*"])
        windows = repository.fetch_entity_event_windows(
            since=base_time,
            until=base_time + timedelta(days=1),
        )

    # Should only have window for alice
    assert len(windows) == 1
    assert windows[0].entity_id == normal_user_id


def test_analyzer_repository_no_exclusions(session_factory):
    """Test that repository works normally with no exclusions."""
    base_time = datetime(2024, 1, 1, 8, 0, 0, tzinfo=timezone.utc)

    with session_factory() as session:
        user1 = _create_entity(session, "user", "alice")
        user2 = _create_entity(session, "user", "bob")

        _add_event(session, user1.id, base_time, "login", 5)
        _add_event(session, user2.id, base_time, "login", 6)
        session.commit()

    with session_factory() as session:
        repository = AnalyzerRepository(session, excluded_entities=[])
        windows = repository.fetch_entity_event_windows(
            since=base_time,
            until=base_time + timedelta(days=1),
        )

    # Should have windows for both users
    assert len(windows) == 2


def test_analyzer_service_skips_excluded_entities(session_factory):
    """Test that AnalyzerService doesn't create risk history for excluded entities.

    Note: This test validates the exclusion logic at the repository level.
    Full service integration test is skipped due to SQLite lacking stddev_pop function.
    """
    base_time = datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc)

    with session_factory() as session:
        # Create entities
        root_entity = _create_entity(session, "user", "root")
        alice_entity = _create_entity(session, "user", "alice")

        # Add events
        _add_event(session, root_entity.id, base_time + timedelta(hours=1), "auth", 5)
        _add_event(session, alice_entity.id, base_time + timedelta(hours=2), "auth", 7)
        session.commit()

        alice_id = alice_entity.id

    # Test repository exclusion logic directly
    with session_factory() as session:
        repository = AnalyzerRepository(session, excluded_entities=["root", "admin"])
        windows = repository.fetch_entity_event_windows(
            since=base_time,
            until=base_time + timedelta(days=1),
        )

    # Should only have window for alice
    assert len(windows) == 1
    assert windows[0].entity_id == alice_id


def test_analyzer_repository_with_multiple_entities(session_factory):
    """Test analyzer repository with mixed excluded and non-excluded entities."""
    base_time = datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc)

    with session_factory() as session:
        entities = [
            _create_entity(session, "user", "root"),  # excluded
            _create_entity(session, "user", "admin"),  # excluded
            _create_entity(session, "user", "system_test"),  # excluded (wildcard)
            _create_entity(session, "user", "alice"),  # not excluded
            _create_entity(session, "user", "bob"),  # not excluded
        ]

        # Add events for all
        for i, entity in enumerate(entities):
            _add_event(session, entity.id, base_time, "event", 5 + i)
        session.commit()

        # Capture IDs before session closes
        alice_id = entities[3].id
        bob_id = entities[4].id

    with session_factory() as session:
        repository = AnalyzerRepository(
            session,
            excluded_entities=["root", "admin", "system_*"],
        )
        windows = repository.fetch_entity_event_windows(
            since=base_time,
            until=base_time + timedelta(days=1),
        )

    # Should only get alice and bob
    assert len(windows) == 2
    entity_ids = {w.entity_id for w in windows}
    assert entity_ids == {alice_id, bob_id}
