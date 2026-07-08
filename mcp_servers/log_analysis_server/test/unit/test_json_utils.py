"""Unit tests for shared JSON extraction utilities."""

import json

import pytest

from mcp_servers.log_analysis_server.services.json_utils import extract_json_object


def test_extract_json_direct():
    raw = '{"mongo_filter": {"source_ip": "10.0.0.1"}}'
    result = extract_json_object(raw)
    assert result["mongo_filter"]["source_ip"] == "10.0.0.1"


def test_extract_json_fenced_block():
    raw = '```json\n{"mongo_filter": {"source_ip": "10.0.0.1"}}\n```'
    result = extract_json_object(raw)
    assert result["mongo_filter"]["source_ip"] == "10.0.0.1"


def test_extract_json_substring_braces():
    raw = 'Some preamble {"mongo_filter": {"source_ip": "10.0.0.1"}} some suffix'
    result = extract_json_object(raw)
    assert result["mongo_filter"]["source_ip"] == "10.0.0.1"


def test_extract_json_empty_string_strict_raises():
    with pytest.raises(json.JSONDecodeError):
        extract_json_object("", strict=True)


def test_extract_json_empty_string_lenient_returns_empty():
    assert extract_json_object("", strict=False) == {}


def test_extract_json_invalid_strict_raises():
    with pytest.raises(json.JSONDecodeError):
        extract_json_object("not json at all !!!", strict=True)


def test_extract_json_invalid_lenient_returns_empty():
    assert extract_json_object("not json at all !!!", strict=False) == {}


def test_extract_json_non_dict_lenient_returns_empty():
    assert extract_json_object('[{"key": "val"}]', strict=False) == {}


def test_extract_json_non_dict_strict_raises():
    with pytest.raises(json.JSONDecodeError):
        extract_json_object("[1, 2, 3]", strict=True)
