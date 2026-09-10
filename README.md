# django-opa-permissions

Object-level Django permissions backed by [OPA](https://www.openpolicyagent.org/)
(Rego) policies stored in the database, evaluated in-process via
[`opa-golib-python-bindings`](https://github.com/phi1010/opa-golib-python-bindings) —
no OPA server needed.

## Features

- **Policies as DB objects** — `Policy` (UUID pk, Rego source) grouped into
  `PolicySet`s via an ordered membership (a policy may belong to several
  sets); a `PolicySetBinding` maps a Django model (ContentType) to
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
- **Admin integration** — `OpaModelAdminMixin` wires a `ModelAdmin` to OPA:
  the changelist is gated by the `browse` permission and filtered with the
  browse prefilter; object pages check `view`/`change`/`delete` per object.
  Classic Django model permissions remain a fallback (see
  [Security notes](#security-notes)).
- **Admin policy debugger** — evaluate a policyset as any (visible) user
  against any bound model/object: `print()` output inline next to the policy
  line, per-line coverage highlighting, the full output document as a tree,
  and the residual browse prefilter. No trace logs. Requires the change
  permission on the policy (see [Security notes](#security-notes)).

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
runnable sqlite demo:

```
cd example_project
python manage.py migrate
python manage.py load_example_policies
python manage.py create_demo_users   # alice/alice-password, bob/bob-password,
                                     # admin/admin-password (superuser)
python manage.py runserver
```

## Security notes

Read this before rolling out in a hostile environment. The design trades a
few guarantees for admin ergonomics; every point below is deliberate and
configurable.

- **Admin falls back to classic Django permissions.** With
  `OpaModelAdminMixin`, every OPA decision is OR-ed with the classic ModelAdmin
  check: a user holding a traditional Django model permission (e.g.
  `view_book` via groups + `ModelBackend`) gets **full, unfiltered** access to
  that model in the admin — OPA row-level denies do not apply to them. This
  keeps stock Django workflows working, but it means your Django groups must
  not hold permissions on OPA-governed models if you want OPA to be the sole
  authority. Audit `django.contrib.auth.models.Permission` assignments on
  bound models accordingly.
- **Policy authors can read your whole database.** The builtins
  (`django_opa_fetch`, `django_opa_fetch_old`, `django_opa_query`) serialize
  every concrete column of any model — including sensitive ones such as
  `User.password` (the hash), tokens or secrets stored on rows — and they use
  `_base_manager`, bypassing any permission-filtering manager. Anyone who can
  create or edit a `Policy` (and anyone able to open the policy debugger)
  can therefore read data your application policies are meant to protect.
  Treat policy authorship as a highly privileged role; if you need redaction,
  override `serialize_instance` / `get_builtins` in a backend subclass to
  strip sensitive fields.
- **Superusers bypass OPA by default.** `DJANGO_OPA_SUPERUSER_BYPASS` (default
  `True`) lets superusers skip all policy checks, including the default-deny
  for unbound models. Set it to `False` in settings if superusers must be
  policy-governed too.
- **The full OPA builtin surface is available to policies.** Beyond the
  Django builtins, policies run on the embedded OPA engine
  (`opa-golib-python-bindings`), so whatever builtins that engine exposes —
  potentially including `http.send`, `net.*`, `opa.runtime` and
  `crypto.*` — is callable from a policy. A policy author can make network
  requests or read runtime configuration from inside your request path.
  Verify the engine's capabilities for your deployment (e.g. via a
  capabilities file) and restrict who may author policies.

## License

MIT
