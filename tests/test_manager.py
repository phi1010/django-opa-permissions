import pytest

from django_opa_permissions.backends import get_backend
from library.models import Book

pytestmark = pytest.mark.django_db

POLICY = """
package policies
import rego.v1

allow if {
    obj := django_opa_fetch(input.app_label, input.model, input.object.id)
    obj.owner_id == input.user.id
}

allow if {
    input.action in {"view", "browse"}
    obj := django_opa_fetch(input.app_label, input.model, input.object.id)
    obj.published == true
}

# overapproximating prefilter: also lists unpublished books with "leak" title
filter if { input.object.published == true }
filter if { input.object.owner_id == input.user.id }
filter if { input.object.title == "leak" }
"""


def test_for_user_prefilter(make_policy, alice, bob):
    make_policy(POLICY)
    Book.objects.create(title="mine", owner=alice)
    Book.objects.create(title="pub", owner=bob, published=True)
    Book.objects.create(title="hidden", owner=bob)
    assert set(Book.objects.for_user(alice).values_list("title", flat=True)) == {
        "mine", "pub"}


def test_allowed_for_user_second_pass(make_policy, alice, bob):
    """The prefilter overapproximates ("leak"); the authoritative second pass
    (browse WITH the object pk) removes it."""
    make_policy(POLICY)
    Book.objects.create(title="pub", owner=bob, published=True)
    Book.objects.create(title="leak", owner=bob)
    assert set(Book.objects.for_user(alice).values_list("title", flat=True)) == {
        "pub", "leak"}
    assert set(
        Book.objects.allowed_for_user(alice, "browse").values_list("title", flat=True)
    ) == {"pub"}


def test_no_filter_rule_denies(make_policy, alice):
    make_policy("package policies\nimport rego.v1\nallow if { input.user.is_active }")
    Book.objects.create(title="b", owner=alice)
    assert Book.objects.for_user(alice).count() == 0


def test_never_filter(make_policy, alice):
    make_policy(
        'package policies\nimport rego.v1\nfilter if { input.user.username == "nobody" }'
    )
    Book.objects.create(title="b", owner=alice)
    assert Book.objects.for_user(alice).count() == 0


def test_always_filter(make_policy, alice):
    make_policy("package policies\nimport rego.v1\nfilter if { input.user.is_active }")
    Book.objects.create(title="b", owner=alice)
    assert Book.objects.for_user(alice).count() == 1


def test_superuser_sees_all(make_policy, admin_user, alice):
    make_policy(POLICY)
    Book.objects.create(title="b", owner=alice)
    assert Book.objects.for_user(admin_user).count() == 1


def test_user_can_save_check_with_old(make_policy, alice, bob):
    make_policy(
        """
package policies
import rego.v1

allow if {
    input.action == "change"
    old := django_opa_fetch_old(input.app_label, input.model, input.object.id)
    new := django_opa_fetch(input.app_label, input.model, input.object.id)
    old.owner_id == input.user.id
    new.owner_id == old.owner_id
}
"""
    )
    book = Book.objects.create(title="b", owner=alice)
    old = Book.objects.get(pk=book.pk)
    book.title = "renamed"
    assert book.user_can(alice, "change", old=old)
    book.owner = bob  # ownership theft
    assert not book.user_can(alice, "change", old=old)
    assert not book.user_can(bob, "change", old=old)


def test_pending_registry_is_exception_safe(make_policy, alice):
    from django_opa_permissions.builtins import _pending, pending_objects

    book = Book.objects.create(title="b", owner=alice)
    with pytest.raises(RuntimeError):
        with pending_objects(book):
            assert _pending()
            raise RuntimeError
    assert not _pending()
