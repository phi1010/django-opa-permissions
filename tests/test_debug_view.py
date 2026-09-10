import pytest
from django.contrib.auth.models import User
from django.urls import reverse

from django_opa_permissions.models import Policy
from library.models import Book

pytestmark = pytest.mark.django_db

POLICY = """
package policies
import rego.v1

allow if {
    print("evaluating for", input.user.username)
    obj := django_opa_fetch(input.app_label, input.model, input.object.id)
    obj.owner_id == input.user.id
}

filter if { input.object.published == true }
filter if { input.object.owner_id == input.user.id }
"""


@pytest.fixture
def logged_in_admin(client, admin_user):
    client.force_login(admin_user)
    return admin_user


def _debug_url(policy):
    return reverse("admin:django_opa_permissions_policy_debug", args=[policy.pk])


def test_debug_view_renders_form(make_policy, logged_in_admin, client):
    policy = make_policy(POLICY)
    response = client.get(_debug_url(policy))
    assert response.status_code == 200
    assert b"Evaluate" in response.content


def test_debug_view_evaluates(make_policy, logged_in_admin, client, alice):
    from django.contrib.contenttypes.models import ContentType

    policy = make_policy(POLICY)
    book = Book.objects.create(title="b", owner=alice)
    ct = ContentType.objects.get_for_model(Book)
    response = client.post(_debug_url(policy), {
        "user": alice.pk,
        "content_type": ct.pk,
        "action": "view",
        "object_pk": str(book.pk),
    })
    assert response.status_code == 200
    content = response.content.decode()
    assert "allow = True" in content
    assert "evaluating for" in content          # print shown inline
    assert "opa-line covered" in content        # coverage highlighting
    assert "conditional" in content             # prefilter status
    assert "included" in content                # object included by prefilter
    assert "trace" not in content.lower()


def test_debug_view_prefilter_never(make_policy, logged_in_admin, client, alice):
    from django.contrib.contenttypes.models import ContentType

    policy = make_policy(
        'package policies\nimport rego.v1\nfilter if { input.user.username == "x" }')
    ct = ContentType.objects.get_for_model(Book)
    response = client.post(_debug_url(policy), {
        "user": alice.pk, "content_type": ct.pk, "action": "browse",
        "object_pk": "",
    })
    assert b"never" in response.content


def test_debug_view_requires_staff(make_policy, client, alice):
    policy = make_policy(POLICY)
    client.force_login(alice)
    response = client.get(_debug_url(policy))
    # non-staff users are bounced by the admin site
    assert response.status_code in (302, 403)


def test_debug_view_requires_change_permission(make_policy, client, alice):
    """Staff users without the change-policy permission get PermissionDenied."""
    from django.contrib.auth.models import Permission

    policy = make_policy(POLICY)
    alice.is_staff = True
    alice.save()
    alice.user_permissions.add(
        Permission.objects.get(codename="view_policy"))  # view is not enough
    alice = type(alice).objects.get(pk=alice.pk)  # clear perm cache
    client.force_login(alice)
    response = client.get(_debug_url(policy))
    assert response.status_code == 403


def test_debug_view_allows_django_change_permission(make_policy, client, alice):
    """The classic ``change_policy`` permission unlocks the debugger too."""
    from django.contrib.auth.models import Permission

    policy = make_policy(POLICY)
    alice.is_staff = True
    alice.save()
    alice.user_permissions.add(
        Permission.objects.get(codename="change_policy"))
    alice = type(alice).objects.get(pk=alice.pk)  # clear perm cache
    client.force_login(alice)
    response = client.get(_debug_url(policy))
    assert response.status_code == 200
    assert b"Evaluate" in response.content


def test_debug_view_opa_change_permission(make_policy, client, alice):
    """An OPA policy bound to Policy granting change on that policy unlocks
    the debugger for a non-superuser."""
    from django_opa_permissions.models import Policy

    policy = make_policy(POLICY)
    make_policy(
        "package policies\nimport rego.v1\n"
        'allow if { input.action == "change" }',
        model=Policy,
        name="meta",
    )
    alice.is_staff = True
    alice.save()
    client.force_login(alice)
    response = client.get(_debug_url(policy))
    assert response.status_code == 200
    assert b"Evaluate" in response.content


def test_user_dropdown_filtered(make_policy, client, alice, bob, admin_user):
    """When the user model is OPA-bound, non-superusers only see users the
    browse prefilter yields (plus themselves)."""
    make_policy(POLICY)  # bind Book
    user_policy = make_policy(
        "package policies\nimport rego.v1\n"
        "allow if { input.user.is_active }\n"
        "filter if { input.object.username == input.user.username }",
        model=User,
        name="users",
    )
    make_policy(  # grant alice change on the policy to open the debugger
        "package policies\nimport rego.v1\n"
        "allow if { input.action == \"change\" }",
        model=Policy,
        name="meta",
    )
    alice.is_staff = True
    alice.save()
    client.force_login(alice)
    policy = user_policy
    response = client.get(_debug_url(policy))
    content = response.content.decode()
    assert "alice" in content
    assert ">bob<" not in content


def test_change_form_debug_link(make_policy, logged_in_admin, client, alice):
    make_policy(POLICY)
    book = Book.objects.create(title="b", owner=alice)
    response = client.get(
        reverse("admin:library_book_change", args=[book.pk]))
    assert b"Debug policy" in response.content
    assert f"object_pk={book.pk}".encode() in response.content
