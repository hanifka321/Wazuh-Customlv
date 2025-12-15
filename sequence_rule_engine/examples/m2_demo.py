#!/usr/bin/env python3
"""
Milestone 2 Demo: JSONL Parser & Field Extractor

This script demonstrates the core functionality of the sequence rule engine:
- Parsing JSONL formatted Wazuh alerts
- Extracting fields using dotted path notation
- Filtering events using where expressions
- Simulating basic sequence detection
"""

from sequence_rule_engine.engine.parser import parse_jsonl
from sequence_rule_engine.engine.models import Event
from sequence_rule_engine.engine.extractor import DottedPathExtractor
from sequence_rule_engine.engine.where_parser import WhereExpressionParser


def demo_parser():
    """Demonstrate JSONL parsing with comments and empty lines."""
    print("=" * 70)
    print("DEMO 1: JSONL Parser")
    print("=" * 70)

    jsonl = """# Sample Wazuh SSH Authentication Events
{"timestamp":"2025-12-06T22:17:00","rule":{"id":"5710","description":"SSH authentication failed"},"agent":{"name":"server1"},"data":{"srcip":"192.168.1.100","dstuser":"admin"}}

{"timestamp":"2025-12-06T22:17:05","rule":{"id":"5710","description":"SSH authentication failed"},"agent":{"name":"server1"},"data":{"srcip":"192.168.1.100","dstuser":"admin"}}

# Multiple failed attempts
{"timestamp":"2025-12-06T22:17:10","rule":{"id":"5710","description":"SSH authentication failed"},"agent":{"name":"server1"},"data":{"srcip":"192.168.1.100","dstuser":"admin"}}

# Finally successful
{"timestamp":"2025-12-06T22:17:15","rule":{"id":"5715","description":"SSH authentication success"},"agent":{"name":"server1"},"data":{"srcip":"192.168.1.100","dstuser":"admin"}}
"""

    events = parse_jsonl(jsonl)
    print(f"\nParsed {len(events)} events from JSONL (comments and empty lines skipped)")

    for i, event in enumerate(events, 1):
        print(f"  Event {i}: rule.id={event['rule']['id']}, timestamp={event['timestamp']}")

    print("\n✓ Parser successfully handles comments, empty lines, and nested JSON\n")


def demo_extractor():
    """Demonstrate field extraction with dotted paths."""
    print("=" * 70)
    print("DEMO 2: Field Extractor")
    print("=" * 70)

    event = {
        "timestamp": "2025-12-06T22:17:02.297+0700",
        "rule": {"level": 5, "id": "5710"},
        "agent": {"id": "037", "name": "deb12", "ip": "103.153.61.108"},
        "data": {"win": {"eventdata": {"status": "0x0", "user": "Administrator"}}},
    }

    extractor = DottedPathExtractor()

    print("\nExtracting fields from nested structure:")
    print(f"  rule.id: {extractor.extract(event, 'rule.id')}")
    print(f"  rule.level: {extractor.extract(event, 'rule.level')}")
    print(f"  agent.name: {extractor.extract(event, 'agent.name')}")
    print(f"  agent.ip: {extractor.extract(event, 'agent.ip')}")
    print(f"  data.win.eventdata.status: {extractor.extract(event, 'data.win.eventdata.status')}")
    print(f"  data.win.eventdata.user: {extractor.extract(event, 'data.win.eventdata.user')}")

    print("\nHandling missing fields:")
    print(f"  missing.field: {extractor.extract(event, 'missing.field')}")
    print(f"  missing.field (with default): {extractor.extract(event, 'missing.field', 'N/A')}")

    print("\n✓ Extractor handles nested paths and missing fields gracefully\n")


def demo_event_model():
    """Demonstrate Event model with auto-generated IDs."""
    print("=" * 70)
    print("DEMO 3: Event Model")
    print("=" * 70)

    fields1 = {"rule": {"id": "5710"}, "agent": {"name": "server1"}}
    fields2 = {"rule": {"id": "5715"}, "agent": {"name": "server1"}}

    event1 = Event(fields=fields1)
    event2 = Event(fields=fields2)

    print(f"\nEvent 1: {event1}")
    print(f"  ID: {event1.event_id[:16]}...")
    print(f"  rule.id: {event1.get('rule.id')}")
    print(f"  agent.name: {event1.get('agent.name')}")

    print(f"\nEvent 2: {event2}")
    print(f"  ID: {event2.event_id[:16]}...")
    print(f"  rule.id: {event2.get('rule.id')}")

    print("\n✓ Event model provides auto-generated IDs and convenient field access\n")


def demo_where_expressions():
    """Demonstrate where expression parsing and evaluation."""
    print("=" * 70)
    print("DEMO 4: Where Expression Parser")
    print("=" * 70)

    events = [
        {"rule": {"id": "5710", "level": 5}, "agent": {"name": "server1"}},
        {"rule": {"id": "5715", "level": 3}, "agent": {"name": "server1"}},
        {"rule": {"id": "5710", "level": 5}, "agent": {"name": "server2"}},
        {"rule": {"id": "60104", "level": 5}, "agent": {"name": "win-server"}},
    ]

    parser = WhereExpressionParser()

    print("\nEquality operator (==):")
    pred = parser.parse('rule.id == "5710"')
    matched = [e for e in events if pred(e)]
    print(f"  rule.id == '5710': {len(matched)} matches")

    print("\nList membership (in):")
    pred = parser.parse('rule.id in ["5710", "5715"]')
    matched = [e for e in events if pred(e)]
    print(f"  rule.id in ['5710', '5715']: {len(matched)} matches")

    print("\nContains operator:")
    pred = parser.parse('contains(agent.name, "server")')
    matched = [e for e in events if pred(e)]
    print(f"  contains(agent.name, 'server'): {len(matched)} matches")

    print("\nComplex expression:")
    pred = parser.parse("rule.level in [5, 7, 9]")
    matched = [e for e in events if pred(e)]
    print(f"  rule.level in [5, 7, 9]: {len(matched)} matches")

    print("\n✓ Where expressions compile to fast callable predicates\n")


def demo_sequence_detection():
    """Demonstrate basic sequence detection workflow."""
    print("=" * 70)
    print("DEMO 5: Sequence Detection Simulation")
    print("=" * 70)

    jsonl = """{"timestamp":"2025-12-06T22:17:00","rule":{"id":"5710"},"data":{"srcip":"192.168.1.100"}}
{"timestamp":"2025-12-06T22:17:05","rule":{"id":"5710"},"data":{"srcip":"192.168.1.100"}}
{"timestamp":"2025-12-06T22:17:10","rule":{"id":"5710"},"data":{"srcip":"192.168.1.100"}}
{"timestamp":"2025-12-06T22:17:15","rule":{"id":"5715"},"data":{"srcip":"192.168.1.100"}}
{"timestamp":"2025-12-06T22:18:00","rule":{"id":"5710"},"data":{"srcip":"10.0.0.50"}}"""

    events = parse_jsonl(jsonl)
    parser = WhereExpressionParser()
    extractor = DottedPathExtractor()

    failed_login = parser.parse('rule.id == "5710"')
    success_login = parser.parse('rule.id == "5715"')

    grouped = {}
    for event in events:
        srcip = extractor.extract(event, "data.srcip")
        if srcip not in grouped:
            grouped[srcip] = {"failed": [], "success": []}

        if failed_login(event):
            grouped[srcip]["failed"].append(event)
        elif success_login(event):
            grouped[srcip]["success"].append(event)

    print("\nDetecting SSH brute force sequences (3+ failed, then 1+ success):")

    for srcip, group in grouped.items():
        failed_count = len(group["failed"])
        success_count = len(group["success"])

        print(f"\n  Source IP: {srcip}")
        print(f"    Failed logins: {failed_count}")
        print(f"    Successful logins: {success_count}")

        if failed_count >= 3 and success_count >= 1:
            print("    ⚠️  ALERT: Brute force sequence detected!")
        else:
            print("    ✓ No sequence detected")

    print("\n✓ Successfully grouped events and detected sequences\n")


def main():
    """Run all demos."""
    print("\n")
    print("╔════════════════════════════════════════════════════════════════════╗")
    print("║  Wazuh Sequence Rule Engine - Milestone 2 Demo                    ║")
    print("║  JSONL Parser & Field Extractor                                   ║")
    print("╚════════════════════════════════════════════════════════════════════╝")
    print()

    demo_parser()
    demo_extractor()
    demo_event_model()
    demo_where_expressions()
    demo_sequence_detection()

    print("=" * 70)
    print("Demo Complete!")
    print("=" * 70)
    print("\nAll components are working correctly and ready for Milestone 3.")
    print("Next steps: Implement sequence matching engine with time windows.\n")


if __name__ == "__main__":
    main()
