import pytest

from django_opa_permissions.builtins import (
    django_opa_fetch,
    django_opa_fetch_old,
    django_opa_query,
    pending_objects,
    serialize_instance,
)
from library.models import Book, Membership, Team

pytestmark = pytest.mark.django_db


def test_fetch(alice):
    book = Book.objects.create(title="b", owner=alice, published=True)
    doc = django_opa_fetch("library", "book", book.pk)
    assert doc["title"] == "b"
    assert doc["owner_id"] == alice.pk
    assert doc["published"] is True
    assert doc["team_id"] is None


def test_fetch_bad_input():
    assert django_opa_fetch("nope", "nope", 1) is None
    assert django_opa_fetch("library", "book", 999999) is None
    assert django_opa_fetch("library", "book", "not-a-pk") is None


def test_fetch_pending_new_and_old(alice, bob):
    book = Book.objects.create(title="old-title", owner=alice)
    old = Book.objects.get(pk=book.pk)
    book.title = "new-title"
    book.owner = bob
    with pending_objects(book, old=old):
        assert django_opa_fetch("library", "book", book.pk)["title"] == "new-title"
        assert django_opa_fetch("library", "book", book.pk)["owner_id"] == bob.pk
        assert django_opa_fetch_old("library", "book", book.pk)["title"] == "old-title"
        assert django_opa_fetch_old("library", "book", book.pk)["owner_id"] == alice.pk
    # registry cleaned up: DB state again
    assert django_opa_fetch("library", "book", book.pk)["title"] == "old-title"


def test_fetch_old_for_creation_is_none(alice):
    book = Book(title="new", owner=alice)
    book.pk = 424242
    with pending_objects(book):
        assert django_opa_fetch("library", "book", 424242)["title"] == "new"
        assert django_opa_fetch_old("library", "book", 424242) is None


def test_query(alice, bob):
    team = Team.objects.create(name="t")
    Membership.objects.create(team=team, user=alice, role="admin")
    Membership.objects.create(team=team, user=bob, role="member")
    rows = django_opa_query("library", "membership", {"team_id": team.pk, "role": "admin"})
    assert len(rows) == 1
    assert rows[0]["user_id"] == alice.pk
    # relation path
    rows = django_opa_query("library", "membership", {"user__username": "bob"})
    assert len(rows) == 1


def test_query_rejects_bad_paths(alice):
    assert django_opa_query("library", "book", {"title__icontains": "x"}) is None
    assert django_opa_query("library", "book", {"nosuch": 1}) is None
    assert django_opa_query("library", "book", "not-a-dict") is None


def test_query_limit(alice, settings):
    settings.DJANGO_OPA_QUERY_LIMIT = 2
    for i in range(3):
        Book.objects.create(title=f"b{i}", owner=alice)
    assert len(django_opa_query("library", "book", {})) == 2


def test_serialize_types(alice):
    from django_opa_permissions.models import PolicySet

    ps = PolicySet.objects.create(name="s")
    doc = serialize_instance(ps)
    assert doc["id"] == str(ps.pk)  # UUID → str
    assert isinstance(doc["created_at"], str)
