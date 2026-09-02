"""OPA engine sessions per policyset, with caching and cache invalidation.

An engine (``opa_bindings.OpaEngine``) is built per PolicySet from its
policies' Rego sources, with the Django builtins registered BEFORE any policy
is added (a hard requirement of the bindings). Sessions are cached per thread
keyed by policyset pk; every access re-reads the policy sources and compares
a sha256 hash, so edits — in this or any other process — take effect on the
next check. Model signals additionally bump a process-wide generation counter
so unrelated threads also rebuild promptly.
"""
from __future__ import annotations

import hashlib
import itertools
import logging
import re
import threading

import opa_bindings
from django.db.models.signals import post_delete, post_save
from django.dispatch import receiver

logger = logging.getLogger(__name__)

ALLOW_RULE = "policies.allow"
FILTER_RULE = "data.policies.filter"
PACKAGE_RE = re.compile(r"^\s*package\s+policies\s*$", re.MULTILINE)

_generation = itertools.count()
_current_generation = next(_generation)
_TLS = threading.local()


class RegoSession:
    """One compiled OPA engine over an ordered list of (filename, source)."""

    def __init__(self, sources, register_builtins):
        self.sources = list(sources)
        self._engine = opa_bindings.OpaEngine()
        self._engine.print_handler = lambda message, location: None
        register_builtins(self._engine)
        for filename, source in self.sources:
            self._engine.add_policy(filename, source)

    @property
    def engine(self):
        return self._engine

    def eval_document(self, path, input_doc, *, coverage=False):
        """Evaluate ``data.<path>``; returns None when undefined."""
        try:
            return self._engine.eval_document(path, input_doc, coverage=coverage)
        except opa_bindings.OpaUndefinedError:
            return None

    def compile_filters(self, rule_path, input_doc, *, unknowns=("input.object",)):
        """Partial evaluation to a UCAST condition dict.

        Returns ``{}`` for "always", ``None`` for "never", or the condition.
        """
        result = self._engine.compile_filters(
            rule_path, input_doc, unknowns=list(unknowns), target="ucast", dialect=""
        )
        return (result or {}).get("query")

    def defines_rule(self, name: str) -> bool:
        pattern = re.compile(rf"^\s*(default\s+)?{re.escape(name)}\b", re.MULTILINE)
        return any(pattern.search(source) for _, source in self.sources)


def sources_for_policy_set(policy_set) -> list[tuple[str, str]]:
    return [
        (policy.filename(), policy.source)
        for policy in policy_set.policies.order_by("sort_order", "name")
    ]


def _sources_hash(sources) -> str:
    h = hashlib.sha256()
    for filename, source in sources:
        h.update(filename.encode())
        h.update(b"\0")
        h.update(source.encode())
        h.update(b"\0")
    return h.hexdigest()


def get_session_for_policy_set(policy_set, register_builtins) -> RegoSession | None:
    """Cached session for a policyset; None when the set has no policies."""
    sources = sources_for_policy_set(policy_set)
    if not sources:
        return None
    key = str(policy_set.pk)
    digest = _sources_hash(sources)
    cache = getattr(_TLS, "sessions", None)
    if cache is None:
        cache = _TLS.sessions = {}
    cached = cache.get(key)
    if cached and cached[0] == digest and cached[1] == _current_generation:
        return cached[2]
    session = RegoSession(sources, register_builtins)
    if cached:
        try:
            cached[2].engine.close()
        except Exception:  # pragma: no cover
            pass
    cache[key] = (digest, _current_generation, session)
    return session


def clear_engine_cache():
    """Invalidate cached sessions in ALL threads (via the generation counter)
    and drop the current thread's immediately."""
    global _current_generation
    _current_generation = next(_generation)
    _TLS.sessions = {}


def _connect_signals():
    from .models import Policy, PolicySet, PolicySetBinding

    for model in (Policy, PolicySet, PolicySetBinding):
        post_save.connect(_on_policy_change, sender=model, weak=False)
        post_delete.connect(_on_policy_change, sender=model, weak=False)


def _on_policy_change(sender, **kwargs):
    clear_engine_cache()


def validate_policy_source(filename: str, source: str) -> str | None:
    """Compile-check one policy source; returns an error message or None."""
    if not PACKAGE_RE.search(source or ""):
        return "Policy must declare `package policies`."
    from .backends import get_backend

    try:
        engine = opa_bindings.OpaEngine()
        engine.print_handler = lambda message, location: None
        # the ACTIVE backend's builtins, so policies using subclass-provided
        # builtins validate too
        get_backend().register_builtins(engine)
        engine.add_policy(filename, source)
    except opa_bindings.OpaError as exc:
        return f"Policy does not compile: {exc}"
    finally:
        try:
            engine.close()
        except Exception:
            pass
    return None


try:  # app registry may not be ready at import time in edge cases
    _connect_signals()
except Exception:  # pragma: no cover
    pass
