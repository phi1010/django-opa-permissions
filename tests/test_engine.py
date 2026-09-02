import pytest
from django.contrib.contenttypes.models import ContentType

from django_opa_permissions.backends import get_backend
from django_opa_permissions.engine import validate_policy_source
from django_opa_permissions.models import Policy
from library.models import Book

pytestmark = pytest.mark.django_db

ALLOW_ACTIVE = "package policies\nimport rego.v1\nallow if { input.user.is_active }"


def test_policy_edit_invalidates_cache(make_policy, alice):
    policy = make_policy(ALLOW_ACTIVE)
    book = Book.objects.create(title="b", owner=alice)
    assert alice.has_perm("library.view_book", book)
    policy.source = 'package policies\nimport rego.v1\nallow if { false }'
    policy.save()
    assert not alice.has_perm("library.view_book", book)


def test_undefined_allow_denies(make_policy, alice):
    make_policy('package policies\nimport rego.v1\nallow if { input.user.username == "x" }')
    book = Book.objects.create(title="b", owner=alice)
    assert not alice.has_perm("library.view_book", book)


def test_empty_policy_set_denies(make_policy, alice):
    policy = make_policy(ALLOW_ACTIVE)
    book = Book.objects.create(title="b", owner=alice)
    Policy.objects.all().delete()
    assert not alice.has_perm("library.view_book", book)


def test_prints_captured(make_policy, alice):
    make_policy(
        'package policies\nimport rego.v1\nallow if { print("hello", input.user.username) }'
    )
    backend = get_backend()
    ct = ContentType.objects.get_for_model(Book)
    session = backend.get_session(ct)
    doc = backend.build_input(alice, "view", "library", "book", 1)
    session.eval_document("policies.allow", doc, coverage=True)
    assert any("hello" in message for message, _ in session.engine.last_prints)
    assert session.engine.last_coverage["files"]


def test_validate_policy_source():
    assert validate_policy_source("f.rego", "package other\n") is not None
    assert validate_policy_source("f.rego", "package policies\nallow if {") is not None
    assert validate_policy_source("f.rego", ALLOW_ACTIVE) is None


def test_defines_rule(make_policy, alice):
    make_policy(ALLOW_ACTIVE + "\nfilter if { input.object.published == true }")
    backend = get_backend()
    session = backend.get_session(ContentType.objects.get_for_model(Book))
    assert session.defines_rule("filter")
    assert session.defines_rule("allow")
    assert not session.defines_rule("nope")


class CustomBuiltinBackend:
    pass


def test_validate_uses_subclass_builtins(settings):
    """Policies calling subclass-provided builtins must validate (clean())."""
    from django_opa_permissions.backends import OpaPermissionBackend, _default_backend

    class B(OpaPermissionBackend):
        def get_builtins(self):
            builtins = super().get_builtins()
            builtins["magic_number"] = lambda: 7
            return builtins

    import tests.test_engine as me

    me.CustomBuiltinBackend = B
    settings.AUTHENTICATION_BACKENDS = ["django.contrib.auth.backends.ModelBackend"]
    settings.DJANGO_OPA_BACKEND = "tests.test_engine.CustomBuiltinBackend"
    _default_backend.cache_clear()
    try:
        src = "package policies\nimport rego.v1\nallow if { magic_number() == 7 }"
        assert validate_policy_source("f.rego", src) is None
    finally:
        _default_backend.cache_clear()


def test_broken_policyset_denies_instead_of_raising(make_policy, alice, monkeypatch):
    """A policy that fails to compile at session-build time denies cleanly."""
    policy = make_policy(ALLOW_ACTIVE)
    # bypass model validation to store a source using an unknown builtin
    Policy.objects.filter(pk=policy.pk).update(
        source="package policies\nimport rego.v1\nallow if { no_such_builtin() }"
    )
    from django_opa_permissions.engine import clear_engine_cache

    clear_engine_cache()
    book = Book.objects.create(title="b", owner=alice)
    assert not alice.has_perm("library.view_book", book)
