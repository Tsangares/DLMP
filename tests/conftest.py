"""Shared pytest fixtures for the DLMP test suite.

These tests must never touch a real MongoDB instance (dev or prod). To
guarantee that:

* We run with a fake ``MONGO_URI`` and fake ``secret``/``salt`` values,
  set as environment variables *before* ``src.main`` is imported.
* We change into an empty scratch directory first so ``src/main.py``'s
  relative ``dlmp_cred/cred.json`` lookup (which would otherwise take
  priority over env vars and load real credentials) can't find anything.
* Route-level tests that need a database swap ``mongo.db`` for an
  in-memory ``mongomock`` database, so nothing is ever sent over the
  network.

A few third-party packages used by ``src/main.py`` (``vonage``, ``sinch``,
``pillow_heif``) are unrelated to the redirect feature and don't have
wheels available for the Python version in this sandbox, so they're
stubbed out here purely so the module can be imported.
"""
import os
import sys
import types

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _stub_module(name, **attrs):
    if name in sys.modules:
        return
    mod = types.ModuleType(name)
    for key, value in attrs.items():
        setattr(mod, key, value)
    sys.modules[name] = mod


# Stub optional/unavailable third-party deps unrelated to the redirect
# feature (SMS providers, HEIC image support) so `src.main` can be
# imported without them installed.
_stub_module("vonage", Auth=object, Vonage=object)
_stub_module("vonage_sms", SmsMessage=object)
_stub_module("sinch", SinchClient=object)
_stub_module("pillow_heif", register_heif_opener=lambda: None)

# Fake, obviously-non-production credentials. Set before import since
# src/main.py reads these at module load time.
os.environ.setdefault("secret", "test-secret-key-not-real")
os.environ.setdefault("salt", "test-salt-not-real")
os.environ.setdefault("MONGO_URI", "mongodb://127.0.0.1:27017/dlmp_test")

# src/main.py resolves a handful of paths (the font, dlmp_cred/cred.json)
# relative to the process CWD, matching how it's actually deployed
# (`gunicorn src.main:app` run from the repo root). Run from the repo
# root so those resolve, but make sure the *real* credentials file can
# never be read: it takes priority over the env vars set above, and it
# contains a real (if unreachable-in-this-sandbox) Mongo URI. We only
# special-case that one path; everything else behaves normally.
os.chdir(REPO_ROOT)
_real_exists = os.path.exists


def _guarded_exists(path):
    if path == "dlmp_cred/cred.json":
        return False
    return _real_exists(path)


# `src/static` is a symlink checked into git that points at an
# absolute, production-only path (/var/www/dlmp/static) — see
# `git ls-files -s src/static`. It doesn't resolve in a local sandbox,
# which would otherwise crash the unrelated module-level badge-font
# loading in src/main.py (`ImageFont.truetype("src/static/...")`).
# Patch just that call for the duration of the import; it's not used by
# any of the redirect code paths under test.
from PIL import ImageFont as _ImageFont

_real_truetype = _ImageFont.truetype


def _guarded_truetype(font, *args, **kwargs):
    if isinstance(font, str) and font.startswith("src/static/"):
        return _ImageFont.load_default()
    return _real_truetype(font, *args, **kwargs)


os.path.exists = _guarded_exists
_ImageFont.truetype = _guarded_truetype

# src/main.py also wires Flask-Limiter's rate-limit counter storage to
# the same MONGO_URI (`Limiter(..., storage_uri=MONGO_URI, ...)`).
# Unlike flask_pymongo's client, Limiter's Mongo storage backend hits
# the network on every single request (not lazily), which would make
# every route test block for ~30s and then fail on a connection
# refusal. Force it to use Limiter's built-in in-memory storage instead
# — this only affects rate-limit counters, not app data.
import flask_limiter

_real_limiter_init = flask_limiter.Limiter.__init__


def _memory_storage_limiter_init(self, *args, **kwargs):
    kwargs["storage_uri"] = "memory://"
    return _real_limiter_init(self, *args, **kwargs)


flask_limiter.Limiter.__init__ = _memory_storage_limiter_init
try:
    sys.path.insert(0, REPO_ROOT)
    import src.main as main  # noqa: E402  (import must happen after stubbing/env setup above)
finally:
    os.path.exists = _real_exists
    _ImageFont.truetype = _real_truetype
    flask_limiter.Limiter.__init__ = _real_limiter_init

try:
    import mongomock
except ImportError:
    mongomock = None


@pytest.fixture(autouse=True)
def in_memory_mongo(monkeypatch):
    """Point src.main's `mongo.db` at a fresh in-memory mongomock database.

    This guarantees tests never open a socket to any real MongoDB
    instance (dev or prod), while still exercising the real route code
    paths that read/write `mongo.db.users`, etc.
    """
    if mongomock is None:
        pytest.skip("mongomock is not installed")
    fake_client = mongomock.MongoClient()
    fake_db = fake_client["dlmp_test"]
    monkeypatch.setattr(main.mongo, "db", fake_db, raising=False)
    return fake_db


@pytest.fixture
def app():
    main.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
    return main.app


@pytest.fixture
def client(app):
    return app.test_client()
