# Customizing the backend

`OpaPermissionBackend` is decomposed into small instance methods; subclass it,
point `AUTHENTICATION_BACKENDS` (or the `DJANGO_OPA_BACKEND` setting, used by
managers/admin when no instance is in `AUTHENTICATION_BACKENDS`) at your
class, and every code path — `has_perm`, `for_user`, the admin debugger —
uses your behaviour.

| Hook | Purpose |
|---|---|
| `get_builtins()` | add/replace policy builtins |
| `serialize_user(user)` | shape of `input.user` (add groups, roles, …) |
| `build_input(...)` / `extend_input(doc, **ctx)` | add context to the input document |
| `parse_perm(perm)` / `codename_to_action(codename)` | permission-string mapping |
| `is_bypass(user)` | superuser bypass / sudo mode |
| `get_binding(ct)` / `get_session(ct)` | policy lookup strategy |
| `evaluate_allow(session, doc)` / `filter_result(result, doc)` | decision post-processing |
| `on_deny(user, action, ct, pk, reason)` | audit logging |
| `compile_browse_q(user, model)` | queryset pre-filter strategy |

## Examples

Sudo mode (superusers must explicitly elevate per session):

```python
class SudoBackend(OpaPermissionBackend):
    def is_bypass(self, user):
        return super().is_bypass(user) and getattr(user, "_sudo_active", False)
```

Tenant context + tenant-scoped builtin:

```python
class TenantBackend(OpaPermissionBackend):
    def extend_input(self, doc, **ctx):
        doc["tenant"] = get_current_tenant_id()
        return doc

    def get_builtins(self):
        b = super().get_builtins()
        b["tenant_settings"] = lambda: get_current_tenant_settings()
        return b
```

Audit denials:

```python
class AuditBackend(OpaPermissionBackend):
    def on_deny(self, user, action, ct, pk, reason):
        audit_log.warning("deny %s %s on %s:%s (%s)", user, action, ct, pk, reason)
```

## Caveat: one backend class per process

Compiled OPA engines are cached per policyset (per thread), not per backend
class — the first backend to build a session determines which builtins the
engine has. Run one `OpaPermissionBackend` (sub)class per process; don't mix
backends with different builtin sets in the same process.
