import pytest

from security_toolkit.recon.html_forms import (
    FormParsingError,
    extract_inputs,
    find_form_action,
    find_form_with_password_field,
)


def test_find_form_with_password_field_skips_forms_without_one():
    html = """
    <form action="/search"><input type="text" name="q"></form>
    <form action="/login"><input type="email" name="email"><input type="password" name="password"></form>
    """
    form = find_form_with_password_field(html)
    assert "password" in form
    assert "/login" in form


def test_find_form_with_password_field_raises_when_none_found():
    with pytest.raises(FormParsingError):
        find_form_with_password_field("<form><input type='text' name='q'></form>")


def test_extract_inputs_reads_name_type_value():
    form_html = '<form><input type="hidden" name="_token" value="abc123"><input type="email" name="email"></form>'
    inputs = extract_inputs(form_html)
    by_name = {i["name"]: i for i in inputs}
    assert by_name["_token"]["type"] == "hidden"
    assert by_name["_token"]["value"] == "abc123"
    assert by_name["email"]["type"] == "email"
    assert by_name["email"]["value"] == ""


def test_find_form_action_returns_action_attribute():
    form_html = '<form action="/register" method="post"></form>'
    assert find_form_action(form_html, "https://x.test/register") == "/register"


def test_find_form_action_falls_back_when_missing():
    form_html = "<form method='post'></form>"
    assert find_form_action(form_html, "https://x.test/register") == "https://x.test/register"
