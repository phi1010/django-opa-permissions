"""QuerySet/manager and base model for OPA-permissioned models."""
from __future__ import annotations

from django.db import models

from .backends import BROWSE_ACTION, get_backend


class OpaQuerySet(models.QuerySet):
    def for_user(self, user, action: str = BROWSE_ACTION):
        """Pre-filter via OPA partial evaluation of the ``filter`` rule.

        This is the fast, SQL-level pass. It composes with ``select_related``
        and any further queryset methods. It is authoritative only when the
        policy's ``filter`` rule exactly mirrors ``allow``; a ``filter`` rule
        may deliberately overapproximate — then run
        :meth:`allowed_for_user` (or per-object checks) on the candidates.
        """
        return self.filter(get_backend().compile_browse_q(user, self.model, action))

    def allowed_for_user(self, user, action: str = BROWSE_ACTION):
        """Two-pass browse: SQL pre-filter, then the authoritative full OPA
        evaluation (object pk included in the input) per candidate. Returns a
        queryset restricted to the allowed pks."""
        backend = get_backend()
        candidates = self.for_user(user, action)
        allowed = [
            obj.pk
            for obj in candidates
            if backend.check_permission(user, action, self.model, obj_pk=obj.pk)
        ]
        return self.filter(pk__in=allowed)


class OpaManager(models.Manager.from_queryset(OpaQuerySet)):
    """Non-auto-filtering manager exposing ``for_user``/``allowed_for_user``."""


class OpaPermissionedModel(models.Model):
    objects = OpaManager()

    class Meta:
        abstract = True

    def user_can(self, user, action: str, *, old=None) -> bool:
        """Authoritative OPA check for ``action`` on this instance. For save
        checks, call on the MODIFIED (unsaved) instance and pass ``old`` (the
        persisted snapshot) so policies can compare both states."""
        return get_backend().check_permission(
            user, action, type(self), obj=self, old=old
        )
