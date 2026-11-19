"""Security helpers for the user-facing site (passwords, rate limits, reset links)."""
import logging
import re
import secrets

from django.conf import settings
from django.contrib.auth.hashers import check_password, is_password_usable, make_password
from django.core import signing
from django.core.cache import cache
from django.utils.crypto import salted_hmac

logger = logging.getLogger(__name__)

_SPECIAL = r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?]'


# ── Password strength / verification ────────────────────────────────────────

def password_error(password):
    """Return a human-readable error if the password is too weak, else None."""
    if len(password) < 8:
        return 'Password must be at least 8 characters long.'
    if not re.search(r'[A-Z]', password):
        return 'Password must contain at least one uppercase letter.'
    if not re.search(r'[a-z]', password):
        return 'Password must contain at least one lowercase letter.'
    if not re.search(r'[0-9]', password):
        return 'Password must contain at least one number.'
    if not re.search(_SPECIAL, password):
        return 'Password must contain at least one special character.'
    if ' ' in password:
        return 'Password must not contain spaces.'
    return None


_dummy_hash = None


def verify_password(raw, stored):
    """Check a raw password against a stored hash.

    Blank / unusable stored passwords (e.g. Google-only accounts) never match.
    A throw-away hash is checked in those cases (and for unknown emails, where
    callers pass stored=None) so response time does not reveal whether an
    account exists.
    """
    global _dummy_hash
    if not raw or not stored or not is_password_usable(stored):
        if _dummy_hash is None:
            _dummy_hash = make_password(secrets.token_urlsafe(16))
        check_password(raw or 'x', _dummy_hash)
        return False
    return check_password(raw, stored)


def generate_otp():
    """Cryptographically secure 6-digit code (random.randint is not)."""
    return f"{secrets.randbelow(900000) + 100000}"


# ── Rate limiting (uses the project's cache; see CACHES in settings.py) ─────

LOGIN_LIMIT, LOGIN_WINDOW = 5, 5 * 60          # 5 failures / 5 minutes
RESET_LIMIT, RESET_WINDOW = 3, 60 * 60         # 3 reset emails / hour


def _key(scope, request, ident):
    ip = request.META.get('REMOTE_ADDR', 'unknown')
    return f"rl:{scope}:{ip}:{(ident or '').strip().lower()}"


def is_rate_limited(scope, request, ident, limit):
    try:
        return cache.get(_key(scope, request, ident), 0) >= limit
    except Exception:  # cache outage must not take login down
        logger.exception('rate-limit cache read failed')
        return False


def record_attempt(scope, request, ident, window):
    key = _key(scope, request, ident)
    try:
        cache.add(key, 0, window)   # starts the window only once
        cache.incr(key)
    except Exception:
        logger.exception('rate-limit cache write failed')


def clear_attempts(scope, request, ident):
    try:
        cache.delete(_key(scope, request, ident))
    except Exception:
        logger.exception('rate-limit cache delete failed')


# ── Signed, expiring, single-use password-reset links ───────────────────────

RESET_SALT = 'user.password-reset.v1'


def _fingerprint(u):
    # Changes whenever the password hash or email changes => token is single-use.
    return salted_hmac(RESET_SALT, f"{u.pk}|{u.email}|{u.password}").hexdigest()[:32]


def make_reset_token(u):
    return signing.dumps({'uid': u.pk, 'fp': _fingerprint(u)}, salt=RESET_SALT)


def user_from_reset_token(token):
    """Return the user a valid reset token belongs to, or None.

    None is returned for tampered, expired (settings.PASSWORD_RESET_TIMEOUT),
    already-used or otherwise invalid tokens.
    """
    from .models import user
    try:
        data = signing.loads(token, salt=RESET_SALT, max_age=settings.PASSWORD_RESET_TIMEOUT)
        u = user.objects.filter(pk=data['uid']).first()
    except (signing.BadSignature, KeyError, TypeError, ValueError):
        return None
    if u is None or not secrets.compare_digest(data.get('fp', ''), _fingerprint(u)):
        return None
    return u
