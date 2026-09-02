"""Authentication backend delegating object permissions to OPA policies.

The backend is deliberately decomposed into many small instance methods so a
derived class can change one aspect of the behaviour without forking:

- ``get_builtins`` / ``register_builtins``     add or replace policy builtins
- ``serialize_user``                           enrich the ``input.user`` doc
- ``build_input`` / ``extend_input``           add context to the input
- ``parse_perm`` / ``codename_to_action``      change permission-name mapping
- ``is_bypass``                                sudo modes / superuser bypass
- ``get_binding`` / ``get_session``            policy lookup strategy
- ``evaluate_allow`` / ``filter_result``       post-process decisions
- ``on_deny``                                  audit/log denials
- ``compile_browse_q``                         queryset pre-filter strategy

Module-level helpers (managers, admin) route through the *active backend
instance* returned by :func:`get_backend`, so subclass behaviour applies
everywhere, not only to ``user.has_perm``.
"""
from __future__ import annotations

import logging
from functools import lru_cache

from django.contrib.auth.backends import BaseBackend
from django.contrib.contenttypes.models import ContentType
from django.db.models import Q
from django.utils.module_loading import import_string

from . import engine as engine_mod
from .builtins import DEFAULT_BUILTINS, _to_json, pending_objects
from .conf import get_setting
from .ucast import UcastError, compile_ucast_to_q

logger = logging.getLogger(__name__)

BROWSE_ACTION = "browse"


class OpaPermissionBackend(BaseBackend):
    # ── builtins ─────────────────────────────────────────────────────────
    def get_builtins(self) -> dict:
        """Name → callable map registered on every engine. Override to add
        custom builtins (they must be registered before policies compile)."""
        return dict(DEFAULT_BUILTINS)

    def register_builtins(self, opa_engine) -> None:
        for name, fn in self.get_builtins().items():
            opa_engine.register_function(name, fn)

    # ── input document ───────────────────────────────────────────────────
    def serialize_user(self, user) -> dict:
        if user is None or getattr(user, "is_anonymous", False):
            return {"id": None, "username": "", "is_superuser": False,
                    "is_active": False, "is_authenticated": False}
        return {
            "id": _to_json(user.pk),  # int pks stay ints, UUIDs become strings
            "username": getattr(user, "username", ""),
            "is_superuser": bool(getattr(user, "is_superuser", False)),
            "is_active": bool(getattr(user, "is_active", False)),
            "is_authenticated": True,
        }

    def build_input(self, user, action, app_label, model_name, obj_pk=None) -> dict:
        doc = {
            "user": self.serialize_user(user),
            "app_label": app_label,
            "model": model_name,
            "action": action,
        }
        if obj_pk is not None:
            doc["object"] = {"id": _to_json(obj_pk)}
        return self.extend_input(doc, user=user, action=action,
                                 app_label=app_label, model_name=model_name,
                                 obj_pk=obj_pk)

    def extend_input(self, input_doc: dict, **context) -> dict:
        """Hook: add request/tenant/session context to the input document."""
        return input_doc

    # ── permission-name mapping ──────────────────────────────────────────
    def parse_perm(self, perm: str):
        """``"app_label.codename"`` → (app_label, action, model_name) or None."""
        if "." not in perm:
            return None
        app_label, codename = perm.split(".", 1)
        parsed = self.codename_to_action(codename)
        if parsed is None:
            return None
        action, model_name = parsed
        return app_label, action, model_name

    def codename_to_action(self, codename: str):
        """``"view_book"`` → ("view", "book"). Override for custom schemes."""
        if "_" not in codename:
            return None
        action, model_name = codename.split("_", 1)
        return action, model_name

    # ── bypass / policy lookup ───────────────────────────────────────────
    def is_bypass(self, user) -> bool:
        """True when the user skips policy evaluation entirely (allowed).
        Override e.g. to require an active sudo session on top."""
        return bool(
            get_setting("DJANGO_OPA_SUPERUSER_BYPASS")
            and getattr(user, "is_superuser", False)
            and getattr(user, "is_active", False)
        )

    def get_binding(self, content_type):
        from .models import PolicySetBinding

        return (
            PolicySetBinding.objects.select_related("policy_set")
            .filter(content_type=content_type)
            .first()
        )

    def get_session(self, content_type):
        binding = self.get_binding(content_type)
        if binding is None:
            return None
        try:
            return engine_mod.get_session_for_policy_set(
                binding.policy_set, self.register_builtins
            )
        except Exception:
            # a non-compiling policyset must deny, not raise into has_perm
            logger.exception("Building the OPA session failed; denying")
            return None

    # ── evaluation ───────────────────────────────────────────────────────
    def evaluate_allow(self, session, input_doc) -> bool:
        try:
            result = session.eval_document(engine_mod.ALLOW_RULE, input_doc)
        except Exception:
            logger.exception("OPA evaluation failed; denying")
            return False
        return self.filter_result(result, input_doc) is True

    def filter_result(self, result, input_doc):
        """Hook: post-process the raw ``allow`` document value."""
        return result

    def on_deny(self, user, action, content_type, obj_pk, reason: str) -> None:
        """Hook: called on every denial with a machine-readable reason."""
        logger.debug(
            "OPA deny: user=%s action=%s ct=%s pk=%s (%s)",
            getattr(user, "pk", None), action, content_type, obj_pk, reason,
        )

    def check_permission(self, user, action, model_cls, obj=None, *, obj_pk=None,
                         old=None) -> bool:
        """Authoritative check for one action on one model (or instance).

        ``obj`` may be an unsaved/modified instance: it is exposed to
        ``django_opa_fetch`` as the changed state for the duration of the
        check, and ``old`` (instance or dict) as the pre-write snapshot for
        ``django_opa_fetch_old``.
        """
        if self.is_bypass(user):
            return True
        ct = ContentType.objects.get_for_model(model_cls, for_concrete_model=False)
        session = self.get_session(ct)
        if session is None:
            self.on_deny(user, action, ct, obj_pk, "no_binding_or_policies")
            return False
        if obj is not None and obj_pk is None:
            obj_pk = obj.pk
        input_doc = self.build_input(user, action, ct.app_label, ct.model, obj_pk)
        if obj is not None:
            with pending_objects(obj, old=old):
                allowed = self.evaluate_allow(session, input_doc)
        else:
            allowed = self.evaluate_allow(session, input_doc)
        if not allowed:
            self.on_deny(user, action, ct, obj_pk, "policy")
        return allowed

    # ── browse partial evaluation ────────────────────────────────────────
    def compile_browse_q(self, user, model_cls, action: str = BROWSE_ACTION) -> Q:
        """Queryset pre-filter for the browse permission via OPA partial
        evaluation of ``data.policies.filter``. Deny-by-default: no binding,
        no filter rule, an untranslatable residual, or a compiler error all
        yield a match-nothing Q (the error is logged)."""
        if self.is_bypass(user):
            return Q()
        deny = Q(pk__in=[])
        ct = ContentType.objects.get_for_model(model_cls, for_concrete_model=False)
        session = self.get_session(ct)
        if session is None:
            return deny
        if not session.defines_rule("filter"):
            return deny
        input_doc = self.build_input(user, action, ct.app_label, ct.model)
        try:
            ucast = session.compile_filters(engine_mod.FILTER_RULE, input_doc)
        except Exception:
            logger.exception("OPA partial evaluation failed; denying browse")
            return deny
        if ucast is None:
            return deny
        try:
            return compile_ucast_to_q(model_cls, ucast)
        except UcastError:
            logger.exception("UCAST compilation failed; denying browse")
            return deny

    # ── Django auth backend API ──────────────────────────────────────────
    def authenticate(self, request, **credentials):
        return None  # authorization-only backend

    def has_perm(self, user_obj, perm, obj=None):
        parsed = self.parse_perm(perm)
        if parsed is None:
            return False
        app_label, action, model_name = parsed
        if self.is_bypass(user_obj):
            return True
        try:
            ct = ContentType.objects.get(app_label=app_label, model=model_name)
        except ContentType.DoesNotExist:
            return False
        model_cls = ct.model_class()
        if model_cls is None:
            return False
        if obj is not None:
            if not isinstance(obj, model_cls):
                return False
            return self.check_permission(user_obj, action, model_cls, obj=obj)
        if action == BROWSE_ACTION or action == "add" or action == "create":
            # model-level checks: browse ("may list at all") and creation
            return self.check_permission(user_obj, action, model_cls)
        return False

    def has_module_perms(self, user_obj, app_label):
        if self.is_bypass(user_obj):
            return True
        from .models import PolicySetBinding

        return PolicySetBinding.objects.filter(
            content_type__app_label=app_label
        ).exists()


@lru_cache(maxsize=1)
def _default_backend():
    return import_string(get_setting("DJANGO_OPA_BACKEND"))()


def get_backend() -> OpaPermissionBackend:
    """The active OpaPermissionBackend instance: the first one configured in
    AUTHENTICATION_BACKENDS, else an instance of DJANGO_OPA_BACKEND."""
    from django.contrib.auth import get_backends

    for backend in get_backends():
        if isinstance(backend, OpaPermissionBackend):
            return backend
    return _default_backend()
