# Custom model base class

`DJANGO_OPA_MODEL_BASE` (dotted path, default
`django_opa_permissions.base.OpaModelBase`) names the **abstract** model class
that `Policy`, `PolicySet` and `PolicySetBinding` inherit from. The default
base provides the UUID primary key plus `created_at`/`updated_at`.

```python
# settings.py
DJANGO_OPA_MODEL_BASE = "myproject.core.models.TenantAwareBase"
```

```python
class TenantAwareBase(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant = models.ForeignKey("core.Tenant", on_delete=models.CASCADE)

    class Meta:
        abstract = True
```

Rules:

- The base **must be abstract**; anything else raises `ImproperlyConfigured`
  at startup.
- The base is resolved when the app's models are created, so the setting must
  exist before Django loads `django_opa_permissions` — it cannot be changed
  at runtime or per-test.
- The base defines the concrete schema: **choose it before migrating**. The
  shipped `0001_initial` matches the default base; with a custom base,
  generate and ship your own migrations instead:

  ```python
  MIGRATION_MODULES = {"django_opa_permissions": "myproject.opa_migrations"}
  ```

  then run `manage.py makemigrations django_opa_permissions`.
- If your base replaces the primary key (e.g. an int pk), everything still
  works — policy filenames and cache keys use `pk` generically.

# Custom admin base class

`DJANGO_OPA_ADMIN_BASE` (dotted path, default
`django.contrib.admin.ModelAdmin`) names the `ModelAdmin` subclass that this
app's own admins (`PolicyAdmin`, `PolicySetAdmin`, `PolicySetBindingAdmin`)
inherit from — use it to apply project-wide admin conventions to the policy
management screens. Must be a `ModelAdmin` subclass (else
`ImproperlyConfigured`); resolved at admin import, so set it before startup.
