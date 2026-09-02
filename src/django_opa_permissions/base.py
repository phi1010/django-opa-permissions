"""Configurable base class for this app's models.

``DJANGO_OPA_MODEL_BASE`` names an abstract model class (dotted path) that
``Policy``, ``PolicySet`` and ``PolicySetBinding`` inherit from. The default,
:class:`OpaModelBase`, provides the UUID primary key and timestamps. Because
the base is resolved when models are created (import time), the setting must
be in place before Django loads this app — and since it changes the concrete
schema, choose it before generating/applying migrations (with a custom base,
ship your own migrations via ``MIGRATION_MODULES``).
"""
from __future__ import annotations

import uuid

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.db import models
from django.utils.module_loading import import_string


class OpaModelBase(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True


def get_model_base() -> type[models.Model]:
    path = getattr(
        settings, "DJANGO_OPA_MODEL_BASE", "django_opa_permissions.base.OpaModelBase"
    )
    base = import_string(path)
    if not issubclass(base, models.Model) or not base._meta.abstract:
        raise ImproperlyConfigured(
            f"DJANGO_OPA_MODEL_BASE ({path!r}) must be an abstract model class"
        )
    return base
