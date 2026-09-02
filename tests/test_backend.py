import pytest
from django.contrib.auth.models import AnonymousUser

from django_opa_permissions.backends import OpaPermissionBackend, get_backend
from library.models import Book

pytestmark = pytest.mark.django_db

OWNER_POLICY = """
package policies
import rego.v1

allow if {
    obj := django_opa_fetch(input.app_label, input.model, input.object.id)
    obj.owner_id == input.user.id
}

allow if {
    input.action == "browse"
    not input.object
    input.user.is_active
}

allow if {
    input.action == "add"
    input.user.is_authenticated
}
"""


def test_has_perm_object(make_policy, alice, bob):
    make_policy(OWNER_POLICY)
    book = Book.objects.create(title="b", owner=alice)
    assert alice.has_perm("library.view_book", book)
    assert alice.has_perm("library.change_book", book)
    assert not bob.has_perm("library.view_book", book)


def test_model_level_perms(make_policy, alice):
    make_policy(OWNER_POLICY)
    assert alice.has_perm("library.browse_book")
    assert alice.has_perm("library.add_book")
    # object-level action without an object is denied
    assert not alice.has_perm("library.view_book")


def test_no_binding_denies(alice, db):
    book = Book.objects.create(title="b", owner=alice)
    assert not alice.has_perm("library.view_book", book)


def test_superuser_bypass(admin_user, alice, db):
    book = Book.objects.create(title="b", owner=alice)
    assert admin_user.has_perm("library.view_book", book)
    assert admin_user.has_perm("library.browse_book")


def test_anonymous_denied(make_policy, alice):
    make_policy(OWNER_POLICY)
    book = Book.objects.create(title="b", owner=alice)
    anon = AnonymousUser()
    backend = get_backend()
    assert not backend.has_perm(anon, "library.view_book", book)
    assert not backend.has_perm(anon, "library.browse_book")


def test_wrong_model_instance(make_policy, alice):
    make_policy(OWNER_POLICY)
    backend = get_backend()
    assert not backend.has_perm(alice, "library.view_book", alice)  # not a Book


def test_malformed_perm(alice):
    backend = get_backend()
    assert not backend.has_perm(alice, "nodots", None)
    assert not backend.has_perm(alice, "library.nounderscore", None)


def test_subclass_hooks(make_policy, alice):
    """extend_input and get_builtins are honoured by the evaluation path."""
    make_policy(
        """
package policies
import rego.v1
allow if {
    input.tenant == "acme"
    custom_answer() == 42
}
"""
    )

    class MyBackend(OpaPermissionBackend):
        def extend_input(self, input_doc, **context):
            input_doc["tenant"] = "acme"
            return input_doc

        def get_builtins(self):
            builtins = super().get_builtins()
            builtins["custom_answer"] = lambda: 42
            return builtins

    book = Book.objects.create(title="b", owner=alice)
    assert MyBackend().check_permission(alice, "view", Book, obj=book)
    assert not OpaPermissionBackend().check_permission(alice, "view", Book, obj=book)


def test_filter_result_hook(make_policy, alice):
    make_policy(OWNER_POLICY)
    book = Book.objects.create(title="b", owner=alice)

    class DenyAll(OpaPermissionBackend):
        def filter_result(self, result, input_doc):
            return False

    assert not DenyAll().check_permission(alice, "view", Book, obj=book)
