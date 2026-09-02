"""Custom OPA builtins giving policies read access to Django data.

Policies never receive full serialized objects in the input document; they
fetch what they need:

    obj := django_opa_fetch(input.app_label, input.model, input.object.id)
    old := django_opa_fetch_old(input.app_label, input.model, input.object.id)
    rows := django_opa_query("auth", "user", {"is_active": true})

All builtins use ``_base_manager`` so they never route through a
permission-filtering manager (no recursion) and always see unfiltered data.

During a save/create check the caller registers the not-yet-persisted
instance (and optionally a pre-write snapshot) in a thread-local registry via
``pending_objects``; ``django_opa_fetch`` then returns the *changed* state for
that pk while ``django_opa_fetch_old`` returns the persisted/pre-transaction
state.
"""
from __future__ import annotations

import datetime
import decimal
import threading
import uuid
from contextlib import contextmanager

from django.apps import apps

from .conf import get_setting

_TLS = threading.local()


def _pending() -> dict:
    if not hasattr(_TLS, "pending"):
        _TLS.pending = {}  # (app_label, model, str(pk)) -> {"new": dict|None, "old": dict|None}
    return _TLS.pending


def _key(app_label: str, model: str, pk) -> tuple:
    return (str(app_label), str(model).lower(), str(pk))


@contextmanager
def pending_objects(instance=None, *, old=None, key=None):
    """Register the changed (unsaved) ``instance`` and/or ``old`` snapshot for
    the duration of a permission check. Exception-safe: entries never leak.

    ``old`` may be a model instance (serialized here) or an already-serialized
    dict. For creations pass only ``instance``; pk may be preassigned or None
    (a None pk is registered under the key "None" and additionally exposed to
    ``django_opa_fetch`` when queried with a null pk).
    """
    if key is None:
        meta = type(instance if instance is not None else old)._meta
        pk = instance.pk if instance is not None else old.pk
        key = _key(meta.app_label, meta.model_name, pk)
    entry = {
        "new": serialize_instance(instance) if instance is not None else None,
        "old": serialize_instance(old) if old is not None and not isinstance(old, dict) else old,
    }
    reg = _pending()
    previous = reg.get(key)
    reg[key] = entry
    try:
        yield
    finally:
        if previous is None:
            reg.pop(key, None)
        else:
            reg[key] = previous


def serialize_instance(instance) -> dict:
    """JSON-compatible dict of an instance's concrete columns.

    FKs appear as ``<name>_id``; UUID/Decimal become strings, dates/datetimes
    ISO strings, files their storage name.
    """
    out = {}
    for field in instance._meta.concrete_fields:
        value = getattr(instance, field.attname)
        out[field.attname] = _to_json(value)
    if "id" not in out:
        out["id"] = _to_json(instance.pk)
    return out


def _to_json(value):
    if isinstance(value, (uuid.UUID, decimal.Decimal)):
        return str(value)
    if isinstance(value, (datetime.datetime, datetime.date, datetime.time)):
        return value.isoformat()
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    if hasattr(value, "name") and hasattr(value, "storage"):  # FieldFile
        return value.name or None
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, (list, dict)):
        return value
    return str(value)


def _get_model(app_label, model):
    try:
        return apps.get_model(str(app_label), str(model))
    except (LookupError, ValueError):
        return None


def django_opa_fetch(app_label, model, pk):
    """Fetch one object as JSON by app label, model name and pk.

    Returns the registered *changed* (unsaved) state when a save/create check
    is in progress for that object; otherwise reads the database. Returns
    null/None for unknown models, malformed pks, or missing rows.
    """
    entry = _pending().get(_key(app_label, model, pk))
    if entry and entry["new"] is not None:
        return entry["new"]
    model_cls = _get_model(app_label, model)
    if model_cls is None:
        return None
    try:
        instance = model_cls._base_manager.get(pk=pk)
    except Exception:
        return None
    return serialize_instance(instance)


def django_opa_fetch_old(app_label, model, pk):
    """Fetch the persisted / pre-transaction state of an object as JSON.

    Returns the registered pre-write snapshot when a save check is in
    progress; otherwise reads the database (which inside an uncommitted
    check equals the pre-transaction state as long as the caller evaluates
    permissions before writing).
    """
    entry = _pending().get(_key(app_label, model, pk))
    if entry and entry["old"] is not None:
        return entry["old"]
    if entry and entry["new"] is not None and entry["old"] is None:
        # A registered creation has no old state.
        return None
    model_cls = _get_model(app_label, model)
    if model_cls is None:
        return None
    try:
        instance = model_cls._base_manager.get(pk=pk)
    except Exception:
        return None
    return serialize_instance(instance)


def django_opa_query(app_label, model, filters):
    """Run a filtered ORM query and return a list of JSON objects.

    ``filters`` maps validated field paths (``__``-separated exact/relation
    lookups only — no arbitrary lookup suffixes) to constants. The result is
    capped at DJANGO_OPA_QUERY_LIMIT rows.
    """
    model_cls = _get_model(app_label, model)
    if model_cls is None:
        return None
    if not isinstance(filters, dict):
        return None
    kwargs = {}
    for path, value in filters.items():
        lookup = _validate_query_path(model_cls, str(path))
        if lookup is None:
            return None
        kwargs[lookup] = value
    limit = get_setting("DJANGO_OPA_QUERY_LIMIT")
    qs = model_cls._base_manager.filter(**kwargs)[:limit]
    return [serialize_instance(obj) for obj in qs]


def _validate_query_path(model_cls, path: str) -> str | None:
    """Whitelist a ``__``-separated field path: every segment must be a real
    field; intermediate segments must be relations. Returns the exact-match
    lookup or None if invalid."""
    segments = path.split("__")
    current = model_cls
    for i, seg in enumerate(segments):
        last = i == len(segments) - 1
        if seg in ("pk", "id") and last:
            return path
        try:
            field = current._meta.get_field(seg)
        except Exception:
            if last and seg.endswith("_id"):
                try:
                    fk = current._meta.get_field(seg[:-3])
                except Exception:
                    return None
                if fk.is_relation:
                    return path
            return None
        if last:
            if field.is_relation and not field.concrete:
                return None
        else:
            if not field.is_relation:
                return None
            current = field.related_model
    return path


DEFAULT_BUILTINS = {
    "django_opa_fetch": django_opa_fetch,
    "django_opa_fetch_old": django_opa_fetch_old,
    "django_opa_query": django_opa_query,
}
