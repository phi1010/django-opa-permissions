# django-opa-permissions

Object-level Django permissions backed by [OPA](https://www.openpolicyagent.org/)
(Rego) policies stored in the database, evaluated in-process via
[`opa-golib-python-bindings`](https://github.com/phi1010/opa-golib-python-bindings) —
no OPA server needed.

## Features

- **Policies as DB objects** — `Policy` (UUID pk, Rego source) grouped into a
  `PolicySet` via FK; a `PolicySetBinding` maps a Django model (ContentType) to
  the policyset governing it. Unbound models deny everything (superusers excepted).
- **Auth backend** — `OpaPermissionBackend` implements
  `user.has_perm("app.view_book", obj)` so Django and DRF
  (`DjangoObjectPermissions`) work out of the box. Designed for subclassing:
  many small hook methods (`extend_input`, `get_builtins`, `is_bypass`,
  `filter_result`, …).
- **Minimal input document** — policies receive only the user pk, app label,
  model name, action, and (except for browse/create) the object pk. Data is
  fetched from inside the policy via custom builtins (`django_opa_fetch`,
  `django_opa_fetch_old`, `django_opa_query`) — ORM-backed, no SQL.
- **Browse partial evaluation** — `Model.objects.for_user(user)` compiles the
  policy's `filter` rule with the object left unknown (OPA partial evaluation →
  UCAST → Django `Q`/`Exists`), filtering listings in SQL; relation traversal
  and `$some`/`$all`/`$none` quantifiers are supported. The authoritative
  full check (with the object pk) runs in `allowed_for_user` / `has_perm`.
- **Admin policy debugger** — evaluate a policyset as any (visible) user
  against any bound model/object: `print()` output inline next to the policy
  line, per-line coverage highlighting, the full output document as a tree,
  and the residual browse prefilter. No trace logs.

## Install

```
pip install django-opa-permissions
```

```python
INSTALLED_APPS = [..., "django_opa_permissions"]
AUTHENTICATION_BACKENDS = [
    "django.contrib.auth.backends.ModelBackend",
    "django_opa_permissions.backends.OpaPermissionBackend",
]
```

## Quick start

```python
from django_opa_permissions.managers import OpaPermissionedModel

class Book(OpaPermissionedModel):
    title = models.CharField(max_length=300)
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    published = models.BooleanField(default=False)
```

Create a `PolicySet`, add a `Policy`, and bind it to the `Book` content type
(all in the admin). Every policy must declare `package policies`; the entry
points are `allow` (full evaluation) and `filter` (browse partial evaluation):

```rego
package policies

import rego.v1

# Owners may do anything with their own books.
allow if {
    obj := django_opa_fetch(input.app_label, input.model, input.object.id)
    obj.owner_id == input.user.id
}

# Anyone may view or browse published books.
allow if {
    input.action in {"view", "browse"}
    obj := django_opa_fetch(input.app_label, input.model, input.object.id)
    obj.published == true
}

# Browse prefilter: the object is UNKNOWN here — reference its columns via
# input.object; this compiles to SQL through the ORM.
filter if {
    input.object.published == true
}

filter if {
    input.object.owner_id == to_number(input.user.id)
}
```

```python
Book.objects.for_user(user)          # SQL prefilter (partial evaluation)
Book.objects.allowed_for_user(user)  # prefilter + authoritative per-object pass
user.has_perm("library.view_book", book)
book.user_can(user, "change")        # or "delete", custom actions, ...
modified.user_can(user, "change", old=snapshot)  # policies may fetch both states
```

See `docs/` for the input schema, builtins, filter-rule grammar (relation
paths and quantifiers), and subclassing the backend; `example_project/` is a
runnable sqlite demo (`python manage.py migrate && python manage.py
load_example_policies && python manage.py runserver`).

## License

MIT
