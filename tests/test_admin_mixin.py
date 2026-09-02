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


def test_bob_can_list_policies_when_bound(make_policy, client, staff_bob):
    """Binding a policyset to the Policy model itself makes the app's own
    admins listable via OPA."""
    from django_opa_permissions.models import Policy

    make_policy(
        "package policies\nimport rego.v1\n"
        "allow if { input.user.is_active }\n"
        "filter if { input.user.is_active }",
        model=Policy,
        name="meta",
    )
    client.force_login(staff_bob)
    response = client.get(reverse("admin:django_opa_permissions_policy_changelist"))
    assert response.status_code == 200
    assert b"meta" in response.content


def test_policy_changelist_denied_without_binding(client, staff_bob, db):
    client.force_login(staff_bob)
    response = client.get(reverse("admin:django_opa_permissions_policy_changelist"))
    assert response.status_code == 403


def test_django_perms_fallback(make_policy, client, staff_bob, alice):
    """Classic Django model perms still grant full, unfiltered access."""
    from django.contrib.auth.models import Permission

    make_policy(POLICY)  # OPA prefilter would hide alice's book from bob
    Book.objects.create(title="bobs", owner=staff_bob)
    Book.objects.create(title="alices", owner=alice)
    staff_bob.user_permissions.add(
        Permission.objects.get(codename="view_book"))
    staff_bob = type(staff_bob).objects.get(pk=staff_bob.pk)  # clear perm cache
    client.force_login(staff_bob)
    content = client.get(reverse("admin:library_book_changelist")).content.decode()
    assert "bobs" in content and "alices" in content


def test_admin_base_setting_validation():
    from django.core.exceptions import ImproperlyConfigured
    from django.test import override_settings

    from django_opa_permissions.admin import get_admin_base

    with override_settings(DJANGO_OPA_ADMIN_BASE="library.admin.BookAdmin"):
        assert get_admin_base().__name__ == "BookAdmin"
    with override_settings(DJANGO_OPA_ADMIN_BASE="library.models.Book"):
        with pytest.raises(ImproperlyConfigured):
            get_admin_base()
