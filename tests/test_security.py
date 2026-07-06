"""Security regression tests for DLMP.

Recovered from mat's disconnected git history (commit 8853a7a, where this
file existed but this repo never picked it up - see the merge commit that
dropped it) and adapted to this repo's conftest.py / mongomock test
harness (the original used a session-scoped Flask test client backed by
whatever MONGO_URI was configured; this version follows test_redirect.py's
pattern of the `client`/`in_memory_mongo` fixtures instead, so it never
touches a real database).

Tested vulnerabilities (all fixed alongside this test file):
    1. Open redirect via /unauthorized?next= (meta-refresh injection)
    2. javascript:/data: href XSS via the add-link endpoint
    3. Open redirect via request.referrer on /notify
"""
import pytest

from conftest import main


KEY = "abcdef12345"  # 11 chars, matches VALID_HASH_LEN


def _make_account(db, key=KEY, name="Test User", public=False):
    doc = {"key": key, "name": name, "blurb": ""}
    if public:
        doc["public"] = True
    db.users.insert_one(doc)
    return doc


def _login_as(client, key):
    with client.session_transaction() as sess:
        sess["_user_id"] = key


def _stored_links(db, key=KEY):
    return list(db.content.find({"key": key, "type": "link"}))


# ---------------------------------------------------------------------
# 1. Open redirect: /unauthorized?next=
# ---------------------------------------------------------------------

class TestOpenRedirectUnauthorized:

    def test_relative_path_passes_through(self, client):
        """A safe relative path should still appear in the response."""
        r = client.get(f'/unauthorized?next=/{KEY}')
        assert r.status_code == 200
        assert f'/{KEY}'.encode() in r.data

    def test_external_url_is_blocked(self, client):
        """External URL must NOT be injected into the meta-refresh tag."""
        r = client.get('/unauthorized?next=https://evil.com')
        assert r.status_code == 200
        assert b'evil.com' not in r.data, (
            'VULNERABLE: external URL reflected into meta-refresh - open redirect'
        )

    def test_protocol_relative_is_blocked(self, client):
        """Protocol-relative URL (//evil.com) must be blocked."""
        r = client.get('/unauthorized?next=//evil.com')
        assert r.status_code == 200
        assert b'evil.com' not in r.data, (
            'VULNERABLE: protocol-relative URL reflected into meta-refresh - open redirect'
        )

    def test_backslash_variant_is_blocked(self, client):
        """"/\\evil.com" starts with a single "/" but some browsers treat
        "\\" as "/", making it behave like a protocol-relative URL."""
        r = client.get('/unauthorized?next=/\\evil.com')
        assert r.status_code == 200
        assert b'evil.com' not in r.data

    def test_missing_next_defaults_safely(self, client):
        r = client.get('/unauthorized')
        assert r.status_code == 200
        assert b'url=/' in r.data


# ---------------------------------------------------------------------
# 2. javascript:/data: href XSS via add-link
# ---------------------------------------------------------------------

class TestJavascriptLinks:

    def test_https_link_is_accepted(self, client, in_memory_mongo):
        """A normal https link should be stored without issue."""
        _make_account(in_memory_mongo)
        _login_as(client, KEY)
        client.post(f'/{KEY}/admin/add/link', data={
            'title': 'Safe', 'link': 'https://example.com', 'action': 'open',
        }, follow_redirects=False)
        stored = _stored_links(in_memory_mongo)
        assert any('example.com' in (i.get('link') or '') for i in stored)

    def test_javascript_link_blocked_from_owner(self, client, in_memory_mongo):
        """Owner must not be able to store a javascript: link."""
        _make_account(in_memory_mongo)
        _login_as(client, KEY)
        client.post(f'/{KEY}/admin/add/link', data={
            'title': 'XSS', 'link': 'javascript:alert(document.cookie)', 'action': 'open',
        }, follow_redirects=False)
        for item in _stored_links(in_memory_mongo):
            assert 'javascript:' not in (item.get('link') or '').lower(), (
                'VULNERABLE: javascript: link stored in DB via owner'
            )

    def test_javascript_link_blocked_from_public_visitor(self, client, in_memory_mongo):
        """Anonymous visitor on a public page must not store a javascript: link."""
        _make_account(in_memory_mongo, public=True)
        client.post(f'/{KEY}/admin/add/link', data={
            'title': 'XSS anon', 'link': 'javascript:alert(1)', 'action': 'open',
        }, follow_redirects=False)
        for item in _stored_links(in_memory_mongo):
            assert 'javascript:' not in (item.get('link') or '').lower(), (
                'VULNERABLE: javascript: link stored in DB via anonymous public visitor'
            )

    def test_data_uri_link_blocked(self, client, in_memory_mongo):
        """data: URI links must also be rejected."""
        _make_account(in_memory_mongo)
        _login_as(client, KEY)
        client.post(f'/{KEY}/admin/add/link', data={
            'title': 'data', 'link': 'data:text/html,<script>alert(1)</script>', 'action': 'open',
        }, follow_redirects=False)
        for item in _stored_links(in_memory_mongo):
            assert not (item.get('link') or '').lower().startswith('data:'), (
                'VULNERABLE: data: URI stored in DB'
            )

    def test_bare_domain_link_still_accepted(self, client, in_memory_mongo):
        """Backwards compatibility: a scheme-less bare domain (the old
        style predating any scheme validation) must still be accepted -
        User.fix_link() normalizes it to a protocol-relative href, and it
        can never execute script."""
        _make_account(in_memory_mongo)
        _login_as(client, KEY)
        client.post(f'/{KEY}/admin/add/link', data={
            'title': 'Bare', 'link': 'example.com/page', 'action': 'open',
        }, follow_redirects=False)
        stored = _stored_links(in_memory_mongo)
        assert any('example.com' in (i.get('link') or '') for i in stored)

    def test_javascript_link_neutralized_at_render(self, client, in_memory_mongo):
        """Defense in depth: a dangerous link already in storage (e.g.
        from before this validation existed) must never render as a live
        href on the account page."""
        _make_account(in_memory_mongo)
        in_memory_mongo.content.insert_one({
            'key': KEY, 'type': 'link', 'title': 'Legacy XSS',
            'link': 'javascript:alert(1)', 'action': 'open',
        })
        resp = client.get(f'/{KEY}')
        assert resp.status_code == 200
        assert b'href="javascript:alert(1)"' not in resp.data


# ---------------------------------------------------------------------
# 3. Open redirect: request.referrer on /notify
# ---------------------------------------------------------------------

class TestOpenRedirectReferrer:

    def test_external_referrer_not_followed(self, client, in_memory_mongo):
        """Notify must not redirect to an external Referer header."""
        _make_account(in_memory_mongo)
        _login_as(client, KEY)
        r = client.post(
            f'/{KEY}/notify',
            data={'notify_text': 'test'},
            headers={'Referer': 'https://evil.com/phishing'},
            follow_redirects=False,
        )
        location = r.headers.get('Location', '')
        assert 'evil.com' not in location, (
            'VULNERABLE: /notify redirects to external Referer header'
        )

    def test_same_origin_referrer_is_ok(self, client, in_memory_mongo):
        """A same-origin Referer should be followed."""
        _make_account(in_memory_mongo)
        _login_as(client, KEY)
        r = client.post(
            f'/{KEY}/notify',
            data={'notify_text': 'test'},
            headers={'Referer': f'http://localhost/{KEY}'},
            follow_redirects=False,
        )
        location = r.headers.get('Location', '')
        assert 'evil.com' not in location
        assert location == f'http://localhost/{KEY}'

    def test_missing_referrer_falls_back(self, client, in_memory_mongo):
        """No Referer header should fall back to a safe default, not crash."""
        _make_account(in_memory_mongo)
        _login_as(client, KEY)
        r = client.post(
            f'/{KEY}/notify',
            data={'notify_text': 'test'},
            follow_redirects=False,
        )
        # 400 if no message, 302 if message sent (no subscribers is fine)
        assert r.status_code in (302, 400)


# ---------------------------------------------------------------------
# Pure validation helpers
# ---------------------------------------------------------------------

@pytest.mark.parametrize("link", [
    "https://example.com",
    "http://example.com/page",
    "example.com",
    "example.com/page",
])
def test_is_link_scheme_safe_accepts(link):
    assert main.is_link_scheme_safe(link) is True


@pytest.mark.parametrize("link", [
    "javascript:alert(1)",
    "JaVaScRiPt:alert(1)",
    "data:text/html,<script>alert(1)</script>",
    "vbscript:msgbox(1)",
    "file:///etc/passwd",
    "https://user:pass@evil.com",
    "https://example.com\t",
])
def test_is_link_scheme_safe_rejects(link):
    assert main.is_link_scheme_safe(link) is False


@pytest.mark.parametrize("path", [
    "/abc",
    "/abc/def?x=1",
])
def test_is_safe_relative_redirect_accepts(path):
    assert main.is_safe_relative_redirect(path) is True


@pytest.mark.parametrize("path", [
    "https://evil.com",
    "//evil.com",
    "/\\evil.com",
    "javascript:alert(1)",
    "",
    None,
    "no-leading-slash",
])
def test_is_safe_relative_redirect_rejects(path):
    assert main.is_safe_relative_redirect(path) is False
