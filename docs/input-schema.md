# Policy input document

Every evaluation receives a deliberately **minimal** input document — policies
fetch any additional data via the [builtins](builtins.md):

```json
{
  "user": {
    "id": 7,
    "username": "alice",
    "is_superuser": false,
    "is_active": true,
    "is_authenticated": true
  },
  "app_label": "library",
  "model": "book",
  "action": "view",
  "object": {"id": 3}
}
```

- `user.id` is the user's pk in its native JSON type (int pks stay numbers,
  UUID pks become strings). Anonymous users get
  `{"id": null, "is_authenticated": false, ...}`.
- `action` is derived from the Django permission codename: `view_book` →
  `view` on model `book`. `view`, `add`, `change`, `delete` and the
  pseudo-action `browse` are conventional; any custom `<action>_<model>`
  codename works.
- `object.id` (the object's pk) is present for object-level checks — including
  the **second pass** of a browse check — and absent for `add`/model-level
  `browse` and for the browse **partial-evaluation** pass, where the object is
  the unknown.

## Entry points

Policies must declare `package policies`. Two rules are evaluated:

- `allow` — boolean, the authoritative decision. Multiple `allow` rules
  (across all policies of the set) OR together.
- `filter` — evaluated only by **partial evaluation** for queryset
  pre-filtering; see [filter-rules.md](filter-rules.md).

Undefined `allow`, a missing binding, or any evaluation error ⇒ **deny**.
Superusers bypass everything (`DJANGO_OPA_SUPERUSER_BYPASS`, default on).

## Extending the input

Subclass the backend and override `extend_input` (see
[backend-hooks.md](backend-hooks.md)) to add tenant/request/session context.
