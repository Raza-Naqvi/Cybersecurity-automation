from security_toolkit.json_paths import lookup_dotted_path


def test_lookup_dotted_path_resolves_nested_field():
    assert lookup_dotted_path({"data": {"token": "abc"}}, "data.token") == "abc"


def test_lookup_dotted_path_returns_none_when_missing():
    assert lookup_dotted_path({"data": {}}, "data.token") is None


def test_lookup_dotted_path_returns_none_when_intermediate_not_a_dict():
    assert lookup_dotted_path({"data": "not-a-dict"}, "data.token") is None


def test_lookup_dotted_path_single_level():
    assert lookup_dotted_path({"token": "abc"}, "token") == "abc"
