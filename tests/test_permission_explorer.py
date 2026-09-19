import pytest
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from django.urls import reverse

from django_opa_permissions.models import Policy
from library.models import Book

pytestmark = pytest.mark.django_db

POLICY = """
package policies
import rego.v1

allow if { input.action == "browse"; input.user.username == "alice" }
allow if {
    obj := django_opa_fetch(input.app_label, input.model, input.object.id)
    obj.owner_id == input.user.id
}
filter if { input.object.owner_id == input.user.id }
"""

URL = reverse("admin:django_opa_permissions_permission_explorer")


@pytest.fixture
def logged_in_admin(client, admin_user):
    client.force_login(admin_user)
    return admin_user


def test_renders_forms_and_permission_choices(make_policy, logged_in_admin, client):
    make_policy(POLICY)
    response = client.get(URL)
    assert response.status_code == 200
    content = response.content.decode()
    assert "library.browse_book" in content
    assert "library.view_book" in content
    assert "library.change_book" in content
    assert "Check users" in content and "Check permissions" in content


def test_changelist_links_to_explorer(make_policy, logged_in_admin, client):
    make_policy(POLICY)
    response = client.get(reverse("admin:django_opa_permissions_policy_changelist"))
    assert URL.encode() in response.content


def test_who_can_lists_users(make_policy, logged_in_admin, client, alice, bob):
    make_policy(POLICY)
    book = Book.objects.create(title="b", owner=alice)
    response = client.post(URL, {"mode": "who", "permission": "library.view_book",
                                 "object_pk": str(book.pk)})
    content = response.content.decode()
    rows = content.split("<tbody>")[1].split("</tbody>")[0].split("<tr>")[1:]
    by_user = {r.split("<td>")[1].split("</td>")[0]: r for r in rows}
    assert "opa-yes" in by_user["alice"]
    assert "opa-no" in by_user["bob"]
    assert "opa-no" in by_user["anonymous"]
    assert "superuser bypass" in by_user["root"]
    assert "allowed for 2 of 4 users" in content


def test_who_can_browse_shows_prefilter_counts(make_policy, logged_in_admin, client,
                                               alice, bob):
    make_policy(POLICY)
    Book.objects.create(title="a", owner=alice)
    Book.objects.create(title="b", owner=bob)
    response = client.post(URL, {"mode": "who", "permission": "library.browse_book",
                                 "object_pk": ""})
    assert "1 of 2 objects pass the prefilter" in response.content.decode()


def test_what_can_lists_permissions(make_policy, logged_in_admin, client, alice):
    make_policy(POLICY)
    book = Book.objects.create(title="b", owner=alice)
    ct = ContentType.objects.get_for_model(Book)
    response = client.post(URL, {"mode": "what", "user": alice.pk,
                                 "content_type": ct.pk, "object_pk": str(book.pk)})
    content = response.content.decode()
    assert "library.view_book" in content and "library.delete_book" in content
    # every mapped permission row is allowed (owner) → 5 yes: browse + 4 defaults
    assert content.count('<span class="opa-yes">') == 5
    assert '<span class="opa-no">' not in content


def test_what_can_all_models_and_unmapped_codename(make_policy, logged_in_admin,
                                                   client, alice):
    make_policy(POLICY)
    ct = ContentType.objects.get_for_model(Book)
    Permission.objects.create(content_type=ct, codename="publish", name="Can publish")
    response = client.post(URL, {"mode": "what", "user": alice.pk,
                                 "content_type": "", "object_pk": ""})
    content = response.content.decode()
    assert "library.publish" in content
    assert "not mapped to an action" in content
    assert "library.book" in content


def test_object_pk_requires_model(make_policy, logged_in_admin, client, alice):
    make_policy(POLICY)
    response = client.post(URL, {"mode": "what", "user": alice.pk,
                                 "content_type": "", "object_pk": "1"})
    assert b"Pick a model to check an object." in response.content


def test_requires_change_permission(make_policy, client, alice):
    make_policy(POLICY)
    alice.is_staff = True
    alice.save()
    alice.user_permissions.add(Permission.objects.get(codename="view_policy"))
    alice = type(alice).objects.get(pk=alice.pk)
    client.force_login(alice)
    assert client.get(URL).status_code == 403


def test_only_debuggable_models_offered(make_policy, client, alice):
    """A staff user who may change only some policies sees only the models
    governed by those policies."""
    from django.contrib.auth.models import User

    make_policy(POLICY)  # Book, policy "test"
    make_policy("package policies\nimport rego.v1\nallow if { true }",
                model=User, name="users")
    make_policy(  # alice may change the Book policy, but not "users"/"meta"
        "package policies\nimport rego.v1\n"
        'allow if { input.action == "browse" }\n'
        "allow if {\n"
        '  input.action == "change"\n'
        "  obj := django_opa_fetch(input.app_label, input.model, input.object.id)\n"
        '  obj.name == "test"\n'
        "}",
        model=Policy, name="meta")
    alice.is_staff = True
    alice.save()
    client.force_login(alice)
    response = client.get(URL)
    assert response.status_code == 200
    content = response.content.decode()
    assert "library.browse_book" in content
    assert "auth.browse_user" not in content
    assert "django_opa_permissions.browse_policy" not in content


def test_change_form_links_to_explorer(make_policy, logged_in_admin, client, alice):
    make_policy(POLICY)
    book = Book.objects.create(title="b", owner=alice)
    ct = ContentType.objects.get_for_model(Book)
    response = client.get(reverse("admin:library_book_change", args=[book.pk]))
    content = response.content.decode()
    assert "Permission explorer" in content
    link = (f"{URL}?mode=who&amp;permission=library.view_book&amp;object_pk={book.pk}"
            f"&amp;content_type={ct.pk}&amp;user={logged_in_admin.pk}")
    assert link in content
    # following the link evaluates "who can" immediately and prefills "what can"
    response = client.get(URL, {"mode": "who", "permission": "library.view_book",
                                "object_pk": str(book.pk), "content_type": ct.pk,
                                "user": logged_in_admin.pk})
    content = response.content.decode()
    assert "allowed for" in content
    assert f'<option value="{logged_in_admin.pk}" selected>' in content
    assert f'<option value="{ct.pk}" selected>' in content
    assert content.count(f'value="{book.pk}"') >= 2  # object pk in both forms
