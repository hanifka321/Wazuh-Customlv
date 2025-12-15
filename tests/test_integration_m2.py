from sequence_rule_engine.engine.parser import parse_jsonl
from sequence_rule_engine.engine.models import Event
from sequence_rule_engine.engine.extractor import DottedPathExtractor
from sequence_rule_engine.engine.where_parser import WhereExpressionParser


class TestIntegrationM2:
    """Integration tests for Milestone 2 components working together."""

    def test_parse_and_extract_wazuh_alerts(self):
        """Test parsing JSONL and extracting fields from Wazuh alerts."""
        jsonl = """{"timestamp":"2025-12-06T22:17:02.307+0700","rule":{"level":5,"description":"syslog: User authentication failure.","id":"2501"},"agent":{"id":"037","name":"deb12","ip":"103.153.61.108"},"data":{"srcip":"103.204.167.14","dstuser":"root"}}
{"timestamp":"2025-12-06T22:17:02.317+0700","rule":{"level":5,"description":"PAM: User login failed.","id":"5503"},"agent":{"id":"037","name":"deb12","ip":"103.153.61.108"},"data":{"srcip":"103.204.167.14","dstuser":"root"}}
{"timestamp":"2025-12-06T22:17:02.583+0700","rule":{"level":5,"description":"Windows audit failure event","id":"60104"},"agent":{"id":"020","name":"test","ip":"172.16.17.205"}}"""

        events = parse_jsonl(jsonl)
        extractor = DottedPathExtractor()

        assert len(events) == 3

        assert extractor.extract(events[0], "rule.id") == "2501"
        assert extractor.extract(events[0], "agent.name") == "deb12"
        assert extractor.extract(events[0], "data.srcip") == "103.204.167.14"

        assert extractor.extract(events[1], "rule.id") == "5503"
        assert extractor.extract(events[1], "data.dstuser") == "root"

        assert extractor.extract(events[2], "rule.id") == "60104"
        assert extractor.extract(events[2], "agent.name") == "test"

    def test_parse_and_create_event_objects(self):
        """Test parsing JSONL and creating Event objects."""
        jsonl = """{"timestamp":"2025-12-06T22:17:00","rule":{"id":"5710"},"agent":{"name":"server1"},"user":{"name":"admin"}}
{"timestamp":"2025-12-06T22:18:00","rule":{"id":"5715"},"agent":{"name":"server1"},"user":{"name":"admin"}}"""

        parsed_events = parse_jsonl(jsonl)
        event_objects = [Event(fields=e) for e in parsed_events]

        assert len(event_objects) == 2

        assert event_objects[0].get("rule.id") == "5710"
        assert event_objects[0].get("user.name") == "admin"

        assert event_objects[1].get("rule.id") == "5715"
        assert event_objects[1].get("agent.name") == "server1"

        assert event_objects[0].event_id != event_objects[1].event_id

    def test_parse_and_filter_with_where_expressions(self):
        """Test parsing events and filtering with where expressions."""
        jsonl = """{"rule":{"id":"5710"},"agent":{"name":"server1"}}
{"rule":{"id":"5715"},"agent":{"name":"server1"}}
{"rule":{"id":"5720"},"agent":{"name":"server2"}}
{"rule":{"id":"5710"},"agent":{"name":"server2"}}"""

        events = parse_jsonl(jsonl)
        parser = WhereExpressionParser()

        failed_login_pred = parser.parse('rule.id == "5710"')
        success_login_pred = parser.parse('rule.id == "5715"')
        server1_pred = parser.parse('agent.name == "server1"')

        failed_logins = [e for e in events if failed_login_pred(e)]
        success_logins = [e for e in events if success_login_pred(e)]
        server1_events = [e for e in events if server1_pred(e)]

        assert len(failed_logins) == 2
        assert len(success_logins) == 1
        assert len(server1_events) == 2

    def test_sequence_detection_simulation(self):
        """Test simulating sequence detection: failed login followed by success."""
        jsonl = """{"timestamp":"2025-12-06T22:17:00","rule":{"id":"5710"},"agent":{"name":"server1"},"data":{"srcip":"192.168.1.100"}}
{"timestamp":"2025-12-06T22:17:05","rule":{"id":"5710"},"agent":{"name":"server1"},"data":{"srcip":"192.168.1.100"}}
{"timestamp":"2025-12-06T22:17:10","rule":{"id":"5710"},"agent":{"name":"server1"},"data":{"srcip":"192.168.1.100"}}
{"timestamp":"2025-12-06T22:17:15","rule":{"id":"5715"},"agent":{"name":"server1"},"data":{"srcip":"192.168.1.100"}}"""

        events = parse_jsonl(jsonl)
        parser = WhereExpressionParser()

        failed_login = parser.parse('rule.id == "5710"')
        success_login = parser.parse('rule.id == "5715"')

        failed_events = [e for e in events if failed_login(e)]
        success_events = [e for e in events if success_login(e)]

        assert len(failed_events) == 3
        assert len(success_events) == 1

        if len(failed_events) >= 3 and len(success_events) >= 1:
            detected_sequence = True
        else:
            detected_sequence = False

        assert detected_sequence is True

    def test_complex_where_expressions_on_wazuh_data(self):
        """Test complex where expressions on Wazuh alert data."""
        jsonl = """{"rule":{"id":"5710","level":5},"agent":{"name":"deb12"},"data":{"srcip":"192.168.1.100","dstuser":"admin"}}
{"rule":{"id":"5715","level":3},"agent":{"name":"deb12"},"data":{"srcip":"192.168.1.100","dstuser":"admin"}}
{"rule":{"id":"5710","level":5},"agent":{"name":"ubuntu01"},"data":{"srcip":"10.0.0.50","dstuser":"root"}}
{"rule":{"id":"60104","level":5},"agent":{"name":"win-server"},"data":{"status":"failure"}}"""

        events = parse_jsonl(jsonl)
        parser = WhereExpressionParser()

        high_level_pred = parser.parse("rule.level in [5, 7, 9]")
        ssh_rules_pred = parser.parse('rule.id in ["5710", "5715"]')
        contains_admin_pred = parser.parse('contains(data.dstuser, "admin")')

        high_level = [e for e in events if high_level_pred(e)]
        ssh_events = [e for e in events if ssh_rules_pred(e)]
        admin_events = [e for e in events if contains_admin_pred(e)]

        assert len(high_level) == 3
        assert len(ssh_events) == 3
        assert len(admin_events) == 2

    def test_event_grouping_by_field(self):
        """Test grouping events by field for sequence detection."""
        jsonl = """{"rule":{"id":"5710"},"data":{"srcip":"192.168.1.100"}}
{"rule":{"id":"5710"},"data":{"srcip":"192.168.1.101"}}
{"rule":{"id":"5715"},"data":{"srcip":"192.168.1.100"}}
{"rule":{"id":"5715"},"data":{"srcip":"192.168.1.101"}}"""

        events = parse_jsonl(jsonl)
        extractor = DottedPathExtractor()

        grouped = {}
        for event in events:
            srcip = extractor.extract(event, "data.srcip")
            if srcip not in grouped:
                grouped[srcip] = []
            grouped[srcip].append(event)

        assert len(grouped) == 2
        assert len(grouped["192.168.1.100"]) == 2
        assert len(grouped["192.168.1.101"]) == 2

    def test_handle_missing_fields_gracefully(self):
        """Test that missing fields are handled gracefully across components."""
        jsonl = """{"rule":{"id":"5710"},"agent":{"name":"server1"}}
{"rule":{"id":"5715"}}
{"agent":{"name":"server2"}}"""

        events = parse_jsonl(jsonl)
        parser = WhereExpressionParser()
        extractor = DottedPathExtractor()

        rule_pred = parser.parse('rule.id == "5710"')
        matched = [e for e in events if rule_pred(e)]

        assert len(matched) == 1

        for event in events:
            rule_id = extractor.extract(event, "rule.id", "unknown")
            agent_name = extractor.extract(event, "agent.name", "unknown")

            assert rule_id is not None
            assert agent_name is not None

    def test_end_to_end_with_comments_and_empty_lines(self):
        """Test complete workflow with comments and empty lines in JSONL."""
        jsonl = """# This is a sample JSONL file with Wazuh alerts
# Rule 5710: SSH authentication failed

{"rule":{"id":"5710"},"agent":{"name":"server1"},"timestamp":"2025-12-06T22:17:00"}

# Rule 5715: SSH authentication success
{"rule":{"id":"5715"},"agent":{"name":"server1"},"timestamp":"2025-12-06T22:17:15"}

# End of file"""

        events = parse_jsonl(jsonl)
        event_objects = [Event(fields=e) for e in events]
        parser = WhereExpressionParser()

        assert len(event_objects) == 2

        failed_pred = parser.parse('rule.id == "5710"')
        success_pred = parser.parse('rule.id == "5715"')

        assert failed_pred(events[0]) is True
        assert success_pred(events[1]) is True

        assert event_objects[0].get("timestamp") == "2025-12-06T22:17:00"
        assert event_objects[1].get("timestamp") == "2025-12-06T22:17:15"

    def test_real_wazuh_structure_extraction(self):
        """Test with realistic Wazuh alert structure from the sample file."""
        jsonl = '{"timestamp":"2025-12-06T22:17:02.297+0700","rule":{"level":3,"description":"Auditbeat Integration","id":"500111","firedtimes":654,"mail":false,"groups":["auditbeat","syscall","process","network","auditbeat"]},"agent":{"id":"037","name":"deb12","ip":"103.153.61.108"},"manager":{"name":"svr9-wzh"},"id":"1765034222.627780672","data":{"@timestamp":"2025-12-06T15:17:01.278Z","user":{"audit":{"id":"0","name":"root"}}},"location":"/var/log/auditbeat/auditbeat-20251206-27.ndjson"}'

        events = parse_jsonl(jsonl)
        extractor = DottedPathExtractor()
        parser = WhereExpressionParser()

        assert len(events) == 1
        event = events[0]

        assert extractor.extract(event, "rule.id") == "500111"
        assert extractor.extract(event, "rule.level") == 3
        assert extractor.extract(event, "agent.name") == "deb12"
        assert extractor.extract(event, "agent.ip") == "103.153.61.108"
        assert extractor.extract(event, "manager.name") == "svr9-wzh"
        assert extractor.extract(event, "data.user.audit.name") == "root"

        rule_pred = parser.parse('rule.id == "500111"')
        level_pred = parser.parse("rule.level == 3")
        user_pred = parser.parse('contains(data.user.audit.name, "root")')

        assert rule_pred(event) is True
        assert level_pred(event) is True
        assert user_pred(event) is True
