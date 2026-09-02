from importlib.resources import files

from django.contrib.contenttypes.models import ContentType
from django.core.management.base import BaseCommand

from django_opa_permissions.models import (
    Policy,
    PolicySet,
    PolicySetBinding,
    PolicySetMembership,
)
from library.models import Book


class Command(BaseCommand):
    help = "Load the shipped example policies and bind them to library.Book."

    def handle(self, *args, **options):
        source = (
            files("django_opa_permissions") / "policies/examples/library.rego"
        ).read_text()
        policy_set, _ = PolicySet.objects.get_or_create(name="library-example")
        policy, _ = Policy.objects.update_or_create(
            name="library", defaults={"source": source}
        )
        PolicySetMembership.objects.get_or_create(
            policy=policy, policy_set=policy_set, defaults={"sort_order": 0}
        )
        ct = ContentType.objects.get_for_model(Book)
        PolicySetBinding.objects.update_or_create(
            content_type=ct, defaults={"policy_set": policy_set}
        )
        self.stdout.write(self.style.SUCCESS("Example policies loaded and bound."))
