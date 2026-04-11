"""
Security regression tests for DLMP.

Run BEFORE fixes — some tests will FAIL (proving the vulnerability exists):
    pytest tests/test_security.py -v

Run AFTER fixes — all tests should PASS:
    pytest tests/test_security.py -v

Tested vulnerabilities:
    1. Open redirect via /unauthorized?next= (meta-refresh injection)
    2. javascript: href XSS via add-link endpoint
    3. Open redirect via request.referrer on /notify
"""
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv
load_dotenv(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), '.env'))

import pytest
from src.main import app, unique_hash, mongo

# Deterministic test identity — never matches a real key in prod
_TEST_PASSKEY = 'dlmp_automated_test_xK9mZ2pQ_do_not_use'


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(scope='session')
def tkey():
    """Derive a valid 11-char key from the test passkey."""
    return unique_hash(_TEST_PASSKEY)[:11]


@pytest.fixture(scope='session')
def owner(tkey):
    """Authenticated owner client with a named, public test page."""
    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = False
    c = app.test_client()
    # Login (creates the user document if not exists)
    c.post(f'/{tkey}', data={'passkey': _TEST_PASSKEY}, follow_redirects=False)
    # Set a name — required for make_public to work
    c.post(f'/{tkey}/admin', data={
        'name': 'Security Test Page',
        'blurb': 'automated test',
        'login': 'submit',
    }, follow_redirects=False)
    # Make the page public so anon-visitor link tests work
    c.get(f'/{tkey}/admin/make/public', follow_redirects=False)
    yield c
    # Teardown
    with app.app_context():
        mongo.db.users.delete_one({'key': tkey})
        mongo.db.content.delete_many({'key': tkey})


@pytest.fixture(scope='session')
def anon():
    """Unauthenticated client."""
    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = False
    return app.test_client()


# ── 1. Open redirect: /unauthorized?next= ────────────────────────────────────

class TestOpenRedirectUnauthorized:

    def test_relative_path_passes_through(self, anon, tkey):
        """A safe relative path should still appear in the response."""
        r = anon.get(f'/unauthorized?next=/{tkey}')
        assert r.status_code == 200
        assert f'/{tkey}'.encode() in r.data

    def test_external_url_is_blocked(self, anon):
        """External URL must NOT be injected into the meta-refresh tag."""
        r = anon.get('/unauthorized?next=https://evil.com')
        assert r.status_code == 200
        assert b'evil.com' not in r.data, (
            'VULNERABLE: external URL reflected into meta-refresh — open redirect'
        )

    def test_protocol_relative_is_blocked(self, anon):
        """Protocol-relative URL (//evil.com) must be blocked."""
        r = anon.get('/unauthorized?next=//evil.com')
        assert r.status_code == 200
        assert b'evil.com' not in r.data, (
            'VULNERABLE: protocol-relative URL reflected into meta-refresh — open redirect'
        )


# ── 2. javascript: href XSS via add-link ─────────────────────────────────────

class TestJavascriptLinks:

    def _stored_links(self, tkey):
        with app.app_context():
            return list(mongo.db.content.find({'key': tkey, 'type': 'link'}))

    def _cleanup(self, tkey):
        with app.app_context():
            mongo.db.content.delete_many({'key': tkey, 'type': 'link'})

    def test_https_link_is_accepted(self, owner, tkey):
        """A normal https link should be stored without issue."""
        owner.post(f'/{tkey}/admin/add/link', data={
            'title': 'Safe', 'link': 'https://example.com', 'action': 'open',
        }, follow_redirects=False)
        stored = self._stored_links(tkey)
        assert any('example.com' in (i.get('link') or '') for i in stored)
        self._cleanup(tkey)

    def test_javascript_link_blocked_from_owner(self, owner, tkey):
        """Owner must not be able to store a javascript: link."""
        owner.post(f'/{tkey}/admin/add/link', data={
            'title': 'XSS', 'link': 'javascript:alert(document.cookie)', 'action': 'open',
        }, follow_redirects=False)
        for item in self._stored_links(tkey):
            assert 'javascript:' not in (item.get('link') or '').lower(), (
                'VULNERABLE: javascript: link stored in DB via owner'
            )
        self._cleanup(tkey)

    def test_javascript_link_blocked_from_public_visitor(self, anon, tkey):
        """Anonymous visitor on a public page must not store a javascript: link."""
        anon.post(f'/{tkey}/admin/add/link', data={
            'title': 'XSS anon', 'link': 'javascript:alert(1)', 'action': 'open',
        }, follow_redirects=False)
        for item in self._stored_links(tkey):
            assert 'javascript:' not in (item.get('link') or '').lower(), (
                'VULNERABLE: javascript: link stored in DB via anonymous public visitor'
            )
        self._cleanup(tkey)

    def test_data_uri_link_blocked(self, owner, tkey):
        """data: URI links must also be rejected."""
        owner.post(f'/{tkey}/admin/add/link', data={
            'title': 'data', 'link': 'data:text/html,<script>alert(1)</script>', 'action': 'open',
        }, follow_redirects=False)
        for item in self._stored_links(tkey):
            assert not (item.get('link') or '').lower().startswith('data:'), (
                'VULNERABLE: data: URI stored in DB'
            )
        self._cleanup(tkey)


# ── 3. Open redirect: request.referrer on /notify ────────────────────────────

class TestOpenRedirectReferrer:

    def test_external_referrer_not_followed(self, owner, tkey):
        """Notify must not redirect to an external Referer header."""
        r = owner.post(
            f'/{tkey}/notify',
            data={'notify_text': 'test'},
            headers={'Referer': 'https://evil.com/phishing'},
            follow_redirects=False,
        )
        location = r.headers.get('Location', '')
        assert 'evil.com' not in location, (
            'VULNERABLE: /notify redirects to external Referer header'
        )

    def test_same_origin_referrer_is_ok(self, owner, tkey):
        """A same-origin Referer should not cause issues."""
        r = owner.post(
            f'/{tkey}/notify',
            data={'notify_text': 'test'},
            headers={'Referer': f'http://localhost/{tkey}'},
            follow_redirects=False,
        )
        location = r.headers.get('Location', '')
        assert 'evil.com' not in location

    def test_missing_referrer_falls_back(self, owner, tkey):
        """No Referer header should fall back to the default redirect."""
        r = owner.post(
            f'/{tkey}/notify',
            data={'notify_text': 'test'},
            follow_redirects=False,
        )
        # 400 if no message, 302 if message sent (no subscribers is fine)
        assert r.status_code in (302, 400)
