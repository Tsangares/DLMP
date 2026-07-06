"""Tests for the DLMP "permanent redirect" feature (see TODO.md).

Covers:
  * the pure `validate_redirect_url()` validation function (scheme
    allowlist, credential/whitespace rejection) — no Flask/DB needed.
  * the public page view (`GET /<key>`), which should 302 a visitor to
    the stored redirect URL but never redirect the page's own owner.
  * the admin flow for setting/clearing the redirect via the test
    client, backed by an in-memory mongomock database (see
    conftest.py — this suite never touches a real MongoDB instance).
"""
import io

import pytest

from conftest import main


# ---------------------------------------------------------------------
# Pure validation logic
# ---------------------------------------------------------------------

@pytest.mark.parametrize("url", [
    "https://example.com",
    "http://example.com",
    "https://example.com/some/path?x=1",
    "https://sub.example.co.uk/page",
    "https://example.com:8080/path",
])
def test_validate_redirect_url_accepts_valid_urls(url):
    assert main.validate_redirect_url(url) is True


@pytest.mark.parametrize("url", [
    "javascript:alert(1)",
    "javascript:alert(document.cookie)",
    "JaVaScRiPt:alert(1)",
    "data:text/html,<script>alert(1)</script>",
    "file:///etc/passwd",
    "ftp://example.com/file",
    "vbscript:msgbox(1)",
])
def test_validate_redirect_url_rejects_dangerous_schemes(url):
    assert main.validate_redirect_url(url) is False


@pytest.mark.parametrize("url", [
    "example.com",           # no scheme at all
    "//evil.com",             # protocol-relative, no scheme
    "https://",               # scheme but no host
    "https:///path",          # scheme, empty host, path only
    "",
    None,
])
def test_validate_redirect_url_rejects_missing_scheme_or_host(url):
    assert main.validate_redirect_url(url) is False


@pytest.mark.parametrize("url", [
    "https://example.com/ path",
    "https://exa mple.com",
    "https://example.com\t/path",
    "https://example.com\n",
    " https://example.com",
    "https://example.com ",
])
def test_validate_redirect_url_rejects_whitespace(url):
    assert main.validate_redirect_url(url) is False


@pytest.mark.parametrize("url", [
    "https://user:pass@evil.com",
    "https://trusted.com@evil.com",  # classic "looks like trusted.com" trick
    "http://admin:hunter2@example.com/",
])
def test_validate_redirect_url_rejects_embedded_credentials(url):
    assert main.validate_redirect_url(url) is False


def test_validate_redirect_url_rejects_non_string():
    assert main.validate_redirect_url(12345) is False
    assert main.validate_redirect_url(["https://example.com"]) is False


# ---------------------------------------------------------------------
# Route-level behavior (Flask test client + in-memory mongomock db)
# ---------------------------------------------------------------------

KEY = "abcdef12345"  # 11 chars, matches VALID_HASH_LEN


def _make_account(db, key=KEY, name="Test User", redirect=None):
    doc = {"key": key, "name": name, "blurb": ""}
    if redirect is not None:
        doc["redirect"] = redirect
    db.users.insert_one(doc)
    return doc


def _login_as(client, key):
    with client.session_transaction() as sess:
        sess["_user_id"] = key


def _post_admin(client, key, **form_fields):
    data = {"image": (io.BytesIO(b""), "")}
    data.update(form_fields)
    return client.post(f"/{key}/admin", data=data, content_type="multipart/form-data")


def test_visitor_is_redirected_when_redirect_set(client, in_memory_mongo):
    _make_account(in_memory_mongo, redirect="https://destination.example.com/page")
    resp = client.get(f"/{KEY}", follow_redirects=False)
    assert resp.status_code == 302
    assert resp.headers["Location"] == "https://destination.example.com/page"


def test_visitor_not_redirected_when_no_redirect_set(client, in_memory_mongo):
    _make_account(in_memory_mongo, redirect=None)
    resp = client.get(f"/{KEY}", follow_redirects=False)
    assert resp.status_code == 200


def test_owner_is_not_redirected_and_sees_escape_hatch(client, in_memory_mongo):
    _make_account(in_memory_mongo, redirect="https://destination.example.com/page")
    _login_as(client, KEY)
    resp = client.get(f"/{KEY}", follow_redirects=False)
    # The owner must still be able to reach their own page (not bounced
    # away) so they have a path back to /admin to remove the redirect.
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "destination.example.com" in body
    assert f"/{KEY}/admin" in body


def test_malformed_stored_redirect_is_not_followed(client, in_memory_mongo):
    # Defense in depth: even if a bad value somehow ends up in the DB
    # (e.g. from data inserted before this validation existed), the
    # public view must not redirect to it.
    _make_account(in_memory_mongo, redirect="javascript:alert(1)")
    resp = client.get(f"/{KEY}", follow_redirects=False)
    assert resp.status_code == 200


def test_admin_can_set_a_valid_redirect(client, in_memory_mongo):
    _make_account(in_memory_mongo, redirect=None)
    _login_as(client, KEY)
    resp = _post_admin(client, KEY, set_redirect="Confirm Redirect", redirect="https://newsite.example.com")
    assert resp.status_code == 200
    account = in_memory_mongo.users.find_one({"key": KEY})
    assert account["redirect"] == "https://newsite.example.com"
    assert "Saved!" in resp.get_data(as_text=True)


def test_admin_set_redirect_rejects_javascript_scheme(client, in_memory_mongo):
    _make_account(in_memory_mongo, redirect=None)
    _login_as(client, KEY)
    resp = _post_admin(client, KEY, set_redirect="Confirm Redirect", redirect="javascript:alert(1)")
    assert resp.status_code == 200
    account = in_memory_mongo.users.find_one({"key": KEY})
    assert "redirect" not in account or not account.get("redirect")
    assert "malformed" in resp.get_data(as_text=True)


def test_admin_set_redirect_rejects_data_scheme(client, in_memory_mongo):
    _make_account(in_memory_mongo, redirect=None)
    _login_as(client, KEY)
    resp = _post_admin(
        client, KEY, set_redirect="Confirm Redirect",
        redirect="data:text/html,<script>alert(1)</script>",
    )
    assert resp.status_code == 200
    account = in_memory_mongo.users.find_one({"key": KEY})
    assert "redirect" not in account or not account.get("redirect")
    assert "malformed" in resp.get_data(as_text=True)


def test_admin_can_remove_an_existing_redirect(client, in_memory_mongo):
    _make_account(in_memory_mongo, redirect="https://oldsite.example.com")
    _login_as(client, KEY)
    resp = _post_admin(client, KEY, del_redirect="Confirm Redirect")
    assert resp.status_code == 200
    account = in_memory_mongo.users.find_one({"key": KEY})
    assert "redirect" not in account or not account.get("redirect")
    # Visitor should now see the normal page, not a redirect.
    client2 = client
    with client2.session_transaction() as sess:
        sess.pop("_user_id", None)
    resp2 = client2.get(f"/{KEY}", follow_redirects=False)
    assert resp2.status_code == 200
