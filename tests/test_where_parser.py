import pytest
from sequence_rule_engine.engine.where_parser import WhereExpressionParser


class TestWhereExpressionParser:
    """Test the WhereExpressionParser class."""

    def test_parse_equality_string(self):
        """Test parsing == operator with string value."""
        parser = WhereExpressionParser()
        predicate = parser.parse('rule.id == "60122"')

        assert predicate({"rule": {"id": "60122"}}) is True
        assert predicate({"rule": {"id": "60123"}}) is False
        assert predicate({"rule": {}}) is False

    def test_parse_equality_number(self):
        """Test parsing == operator with numeric value."""
        parser = WhereExpressionParser()
        predicate = parser.parse("rule.level == 5")

        assert predicate({"rule": {"level": 5}}) is True
        assert predicate({"rule": {"level": 3}}) is False
        assert predicate({"rule": {"level": "5"}}) is False

    def test_parse_inequality_string(self):
        """Test parsing != operator with string value."""
        parser = WhereExpressionParser()
        predicate = parser.parse('status != "success"')

        assert predicate({"status": "failure"}) is True
        assert predicate({"status": "success"}) is False
        assert predicate({}) is True

    def test_parse_inequality_number(self):
        """Test parsing != operator with numeric value."""
        parser = WhereExpressionParser()
        predicate = parser.parse("count != 0")

        assert predicate({"count": 5}) is True
        assert predicate({"count": 0}) is False

    def test_parse_in_operator_strings(self):
        """Test parsing 'in' operator with string list."""
        parser = WhereExpressionParser()
        predicate = parser.parse('rule.id in ["5710", "5715", "5720"]')

        assert predicate({"rule": {"id": "5710"}}) is True
        assert predicate({"rule": {"id": "5715"}}) is True
        assert predicate({"rule": {"id": "5720"}}) is True
        assert predicate({"rule": {"id": "5725"}}) is False
        assert predicate({"rule": {}}) is False

    def test_parse_in_operator_numbers(self):
        """Test parsing 'in' operator with numeric list."""
        parser = WhereExpressionParser()
        predicate = parser.parse("level in [3, 5, 7]")

        assert predicate({"level": 3}) is True
        assert predicate({"level": 5}) is True
        assert predicate({"level": 4}) is False

    def test_parse_in_operator_mixed(self):
        """Test parsing 'in' operator with mixed types."""
        parser = WhereExpressionParser()
        predicate = parser.parse('value in ["string", 123, true]')

        assert predicate({"value": "string"}) is True
        assert predicate({"value": 123}) is True
        assert predicate({"value": True}) is True
        assert predicate({"value": False}) is False

    def test_parse_contains_function(self):
        """Test parsing contains() function."""
        parser = WhereExpressionParser()
        predicate = parser.parse('contains(message, "error")')

        assert predicate({"message": "An error occurred"}) is True
        assert predicate({"message": "Everything is fine"}) is False
        assert predicate({"message": "ERROR in caps"}) is False
        assert predicate({}) is False

    def test_parse_contains_nested_field(self):
        """Test contains() with nested field path."""
        parser = WhereExpressionParser()
        predicate = parser.parse('contains(data.user.name, "admin")')

        assert predicate({"data": {"user": {"name": "administrator"}}}) is True
        assert predicate({"data": {"user": {"name": "user123"}}}) is False

    def test_parse_contains_non_string(self):
        """Test contains() converts non-string to string."""
        parser = WhereExpressionParser()
        predicate = parser.parse('contains(status, "200")')

        assert predicate({"status": 200}) is True
        assert predicate({"status": "200 OK"}) is True
        assert predicate({"status": 404}) is False

    def test_parse_regex_function(self):
        """Test parsing regex() function."""
        parser = WhereExpressionParser()
        predicate = parser.parse('regex(user.name, "^admin.*")')

        assert predicate({"user": {"name": "admin"}}) is True
        assert predicate({"user": {"name": "administrator"}}) is True
        assert predicate({"user": {"name": "user"}}) is False
        assert predicate({"user": {}}) is False

    def test_parse_regex_complex_pattern(self):
        """Test regex() with complex pattern."""
        parser = WhereExpressionParser()
        predicate = parser.parse('regex(ip, "\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}")')

        assert predicate({"ip": "192.168.1.1"}) is True
        assert predicate({"ip": "10.0.0.1"}) is True
        assert predicate({"ip": "not.an.ip"}) is False

    def test_parse_regex_invalid_pattern(self):
        """Test that invalid regex pattern raises ValueError."""
        parser = WhereExpressionParser()

        with pytest.raises(ValueError) as exc_info:
            parser.parse('regex(field, "(?P<invalid")')

        assert "Invalid regex pattern" in str(exc_info.value)

    def test_parse_nested_field_paths(self):
        """Test parsing with deeply nested field paths."""
        parser = WhereExpressionParser()
        predicate = parser.parse('data.win.eventdata.status == "0x0"')

        event = {"data": {"win": {"eventdata": {"status": "0x0"}}}}
        assert predicate(event) is True

    def test_parse_wazuh_rule_id(self):
        """Test parsing typical Wazuh rule.id expression."""
        parser = WhereExpressionParser()
        predicate = parser.parse('rule.id == "5710"')

        wazuh_event = {"rule": {"id": "5710", "description": "SSH authentication failed"}}
        assert predicate(wazuh_event) is True

    def test_parse_wazuh_agent_name(self):
        """Test parsing Wazuh agent.name expression."""
        parser = WhereExpressionParser()
        predicate = parser.parse('agent.name == "deb12"')

        wazuh_event = {"agent": {"id": "037", "name": "deb12"}}
        assert predicate(wazuh_event) is True

    def test_parse_empty_expression(self):
        """Test that empty expression raises ValueError."""
        parser = WhereExpressionParser()

        with pytest.raises(ValueError) as exc_info:
            parser.parse("")

        assert "Empty where expression" in str(exc_info.value)

    def test_parse_whitespace_expression(self):
        """Test that whitespace-only expression raises ValueError."""
        parser = WhereExpressionParser()

        with pytest.raises(ValueError) as exc_info:
            parser.parse("   ")

        assert "Empty where expression" in str(exc_info.value)

    def test_parse_unsupported_operator(self):
        """Test that unsupported operator raises ValueError."""
        parser = WhereExpressionParser()

        with pytest.raises(ValueError) as exc_info:
            parser.parse("field > 10")

        assert "Unsupported expression syntax" in str(exc_info.value)

    def test_parse_invalid_equality_syntax(self):
        """Test that invalid == syntax raises ValueError."""
        parser = WhereExpressionParser()

        with pytest.raises(ValueError) as exc_info:
            parser.parse("field ==")

        assert "Invalid == expression" in str(exc_info.value)

    def test_parse_invalid_in_syntax(self):
        """Test that invalid 'in' syntax raises ValueError."""
        parser = WhereExpressionParser()

        with pytest.raises(ValueError) as exc_info:
            parser.parse("field in")

        assert "Unsupported expression syntax" in str(exc_info.value)

    def test_parse_invalid_contains_syntax(self):
        """Test that invalid contains syntax raises ValueError."""
        parser = WhereExpressionParser()

        with pytest.raises(ValueError) as exc_info:
            parser.parse("contains(field)")

        assert "Invalid contains expression" in str(exc_info.value)

    def test_parse_value_types(self):
        """Test parsing various value types."""
        parser = WhereExpressionParser()

        pred_str = parser.parse('field == "string"')
        assert pred_str({"field": "string"}) is True

        pred_int = parser.parse("field == 123")
        assert pred_int({"field": 123}) is True

        pred_float = parser.parse("field == 45.67")
        assert pred_float({"field": 45.67}) is True

        pred_bool_true = parser.parse("field == true")
        assert pred_bool_true({"field": True}) is True

        pred_bool_false = parser.parse("field == false")
        assert pred_bool_false({"field": False}) is True

        pred_null = parser.parse("field == null")
        assert pred_null({"field": None}) is True

    def test_parse_single_quotes(self):
        """Test parsing with single-quoted strings."""
        parser = WhereExpressionParser()
        predicate = parser.parse("rule.id == '5710'")

        assert predicate({"rule": {"id": "5710"}}) is True

    def test_parse_in_with_spaces(self):
        """Test 'in' operator handles various spacing."""
        parser = WhereExpressionParser()

        pred1 = parser.parse('field in["a", "b"]')
        pred2 = parser.parse('field in ["a", "b"]')
        pred3 = parser.parse('field in  [  "a" ,  "b"  ]')

        event = {"field": "a"}
        assert pred1(event) is True
        assert pred2(event) is True
        assert pred3(event) is True

    def test_parse_sequential_rules(self):
        """Test parsing multiple rules for sequence detection."""
        parser = WhereExpressionParser()

        failed_login = parser.parse('rule.id == "5710"')
        success_login = parser.parse('rule.id == "5715"')

        event1 = {"rule": {"id": "5710"}}
        event2 = {"rule": {"id": "5715"}}

        assert failed_login(event1) is True
        assert failed_login(event2) is False
        assert success_login(event1) is False
        assert success_login(event2) is True
