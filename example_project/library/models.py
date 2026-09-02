from django.conf import settings
from django.db import models

from django_opa_permissions.managers import OpaPermissionedModel


class Team(models.Model):
    name = models.CharField(max_length=200)
    members = models.ManyToManyField(settings.AUTH_USER_MODEL, related_name="teams",
                                     blank=True)

    def __str__(self):
        return self.name


class Membership(models.Model):
    """Explicit role-carrying membership (reverse-FK quantifier example)."""

    team = models.ForeignKey(Team, related_name="memberships",
                             on_delete=models.CASCADE)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, related_name="memberships",
                             on_delete=models.CASCADE)
    role = models.CharField(max_length=50, default="member")

    def __str__(self):
        return f"{self.user} in {self.team} as {self.role}"


class Book(OpaPermissionedModel):
    title = models.CharField(max_length=300)
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, related_name="books",
                              on_delete=models.CASCADE)
    team = models.ForeignKey(Team, related_name="books", null=True, blank=True,
                             on_delete=models.SET_NULL)
    published = models.BooleanField(default=False)

    def __str__(self):
        return self.title
