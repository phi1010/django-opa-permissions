from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import ValidationError
from django.db import models

from .base import get_model_base

REQUIRED_PACKAGE = "policies"

ModelBase = get_model_base()


class Policy(ModelBase):
    name = models.CharField(max_length=200, unique=True)
    source = models.TextField(help_text="Rego source; must declare `package policies`.")

    class Meta:
        ordering = ["name"]
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


class PolicySet(ModelBase):
    name = models.CharField(max_length=200, unique=True)
    policies = models.ManyToManyField(
        Policy, through="PolicySetMembership", related_name="policy_sets", blank=True
    )

    def __str__(self):
        return self.name

    def ordered_policies(self):
        return [
            m.policy
            for m in self.memberships.select_related("policy").order_by(
                "sort_order", "policy__name"
            )
        ]


class PolicySetMembership(ModelBase):
    """A policy's membership in a policyset, with per-set ordering.

    A policy may belong to any number of sets."""

    policy = models.ForeignKey(
        Policy, related_name="memberships", on_delete=models.CASCADE
    )
    policy_set = models.ForeignKey(
        PolicySet, related_name="memberships", on_delete=models.CASCADE
    )
    sort_order = models.IntegerField(default=0)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["policy", "policy_set"], name="unique_policy_per_set"
            )
        ]
        ordering = ["sort_order"]

    def __str__(self):
        return f"{self.policy} in {self.policy_set}"


class PolicySetBinding(ModelBase):
    """Maps a Django model (via ContentType) to the PolicySet governing it.

    A model without a binding denies every permission (superusers excepted).
    """

    content_type = models.OneToOneField(
        ContentType, on_delete=models.CASCADE, related_name="opa_policy_binding"
    )
    policy_set = models.ForeignKey(
        PolicySet, related_name="bindings", on_delete=models.CASCADE
    )

    def __str__(self):
        return f"{self.content_type} → {self.policy_set}"
