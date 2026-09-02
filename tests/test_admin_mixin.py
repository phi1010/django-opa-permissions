"""OpaModelAdminMixin: changelist visibility and prefiltered listing."""
import pytest
from django.urls import reverse

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
    input.action == "browse"
    not input.object
    input.user.is_active
}

filter if { input.object.owner_id == input.user.id }
"""


@pytest.fixture
def staff_bob(bob):
    bob.is_staff = True
    bob.save()
    return bob


def test_changelist_accessible_via_browse(make_policy, client, staff_bob, alice):
    make_policy(POLICY)
    Book.objects.create(title="bobs", owner=staff_bob)
    Book.objects.create(title="alices", owner=alice)
    client.force_login(staff_bob)
    response = client.get(reverse("admin:library_book_changelist"))
    assert response.status_code == 200
    content = response.content.decode()
    # prefiltered: only bob's book is listed
    assert "bobs" in content
    assert "alices" not in content


def test_admin_index_shows_book_link(make_policy, client, staff_bob):
    make_policy(POLICY)
    client.force_login(staff_bob)
    response = client.get(reverse("admin:index"))
    assert reverse("admin:library_book_changelist").encode() in response.content


def test_object_pages_respect_object_permission(make_policy, client, staff_bob, alice):
    make_policy(POLICY)
    own = Book.objects.create(title="bobs", owner=staff_bob)
    foreign = Book.objects.create(title="alices", owner=alice)
    client.force_login(staff_bob)
    assert client.get(
        reverse("admin:library_book_change", args=[own.pk])).status_code == 200
    assert client.get(
        reverse("admin:library_book_change", args=[foreign.pk])).status_code == 302


def test_changelist_denied_without_browse(make_policy, client, staff_bob):
    make_policy(
        'package policies\nimport rego.v1\nallow if { input.action == "view" }')
    client.force_login(staff_bob)
    response = client.get(reverse("admin:library_book_changelist"))
    assert response.status_code == 403
