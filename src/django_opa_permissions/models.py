import uuid

from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import ValidationError
from django.db import models

REQUIRED_PACKAGE = "policies"


class PolicySet(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=200, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name


class Policy(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=200)
    source = models.TextField(help_text="Rego source; must declare `package policies`.")
    policy_set = models.ForeignKey(
        PolicySet, related_name="policies", on_delete=models.CASCADE
    )
    sort_order = models.IntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["sort_order", "name"]
        verbose_name_plural = "policies"

    def __str__(self):
        return self.name

    def clean(self):
        from .engine import validate_policy_source

        error = validate_policy_source(self.filename(), self.source)
        if error:
            raise ValidationError({"source": error})

    def filename(self):
        return f"policy_{self.pk}.rego"


class PolicySetBinding(models.Model):
    """Maps a Django model (via ContentType) to the PolicySet governing it.

    A model without a binding denies every permission (superusers excepted).
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    content_type = models.OneToOneField(
        ContentType, on_delete=models.CASCADE, related_name="opa_policy_binding"
    )
    policy_set = models.ForeignKey(
        PolicySet, related_name="bindings", on_delete=models.CASCADE
    )

    def __str__(self):
        return f"{self.content_type} → {self.policy_set}"
