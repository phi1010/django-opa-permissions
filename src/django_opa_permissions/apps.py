from django.apps import AppConfig


class DjangoOpaPermissionsConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "django_opa_permissions"
    verbose_name = "OPA permissions"

    def ready(self):
        from . import engine  # noqa: F401  (connects cache-invalidation signals)
