from django.conf import settings

DEFAULTS = {
    # Superusers bypass all OPA checks (including the default-deny for
    # models without a PolicySetBinding).
    "DJANGO_OPA_SUPERUSER_BYPASS": True,
    # Maximum number of rows django_opa_query returns to a policy.
    "DJANGO_OPA_QUERY_LIMIT": 1000,
    # Dotted path of the backend class used by module-level helpers
    # (managers, engine) when no OpaPermissionBackend instance is found in
    # AUTHENTICATION_BACKENDS. Subclass it to customize behaviour.
    "DJANGO_OPA_BACKEND": "django_opa_permissions.backends.OpaPermissionBackend",
}


def get_setting(name):
    return getattr(settings, name, DEFAULTS[name])
