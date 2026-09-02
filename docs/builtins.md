# Django data builtins

Instead of serializing objects into the input document, policies pull data on
demand through custom OPA builtins (registered on every engine before policies
compile). All of them read through `_base_manager`, never through a
permission-filtering manager — a policy can therefore never recurse into
another permission check via these builtins.

## `django_opa_fetch(app_label, model, pk) -> object | null`

Returns one object as JSON: every concrete column, FKs as `<name>_id`,
UUID/Decimal as strings, dates as ISO strings. `null` for unknown
models/rows/malformed pks.

During a **save/create check** (`instance.user_can(user, "change", old=...)`
or `backend.check_permission(..., obj=modified_instance, old=snapshot)`), the
*modified, not-yet-persisted* state is returned for that object's pk.

## `django_opa_fetch_old(app_label, model, pk) -> object | null`

The persisted / pre-transaction state. During a save check this is the `old`
snapshot registered by the caller; for a creation it is `null`; otherwise it
reads the database.

```rego
allow if {
    input.action == "change"
    old := django_opa_fetch_old(input.app_label, input.model, input.object.id)
    new := django_opa_fetch(input.app_label, input.model, input.object.id)
    old.owner_id == input.user.id
    new.owner_id == old.owner_id   # may not reassign ownership
}
```

## `django_opa_query(app_label, model, filters) -> [object] | null`

ORM query with a validated filter dict: keys are `__`-separated **exact**
field paths (relations allowed, e.g. `"user__username"`), no lookup suffixes
like `__icontains`. Results are capped at `DJANGO_OPA_QUERY_LIMIT`
(default 1000). Invalid model/paths return `null` (which fails the rule).

```rego
rows := django_opa_query("library", "membership",
                         {"team_id": obj.team_id, "user_id": input.user.id})
count(rows) > 0
```

## Adding your own

Override `OpaPermissionBackend.get_builtins()`:

```python
class MyBackend(OpaPermissionBackend):
    def get_builtins(self):
        builtins = super().get_builtins()
        builtins["my_lookup"] = my_callable  # JSON-compatible args/return
        return builtins
```
