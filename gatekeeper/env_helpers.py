import os
from django.core.exceptions import ImproperlyConfigured

PLACEHOLDER_SECRET_BLOCKLIST = {
    "change-me",
    "some-key",
    "dev_jwt_signing_key",
    "smoketest-jwt-key-change-in-production",
}


def get_env_var(var_name):
    try:
        return os.environ[var_name]
    except KeyError:
        raise ImproperlyConfigured(f'"{var_name}" was not set as an env variable.')


def get_secret_env_var(var_name):
    """Like get_env_var, but additionally rejects known placeholder values.

    Use this for secrets that must never be left at their sample/dev default
    (e.g. DJANGO_SECRET_KEY, JWT_SIGNING_KEY) so a forgotten `change-me` in
    .env fails fast at startup instead of silently running insecurely.
    """
    value = get_env_var(var_name)
    if value.strip().lower() in PLACEHOLDER_SECRET_BLOCKLIST:
        raise ImproperlyConfigured(
            f'"{var_name}" is set to a placeholder secret ("{value}"). '
            "Set it to a real, unique value before starting the service."
        )
    return value
