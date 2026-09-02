import pytest
from django.contrib.auth.models import User
from django.contrib.contenttypes.models import ContentType

from django_opa_permissions.engine import clear_engine_cache
from django_opa_permissions.models import Policy, PolicySet, PolicySetBinding
from library.models import Book


@pytest.fixture(autouse=True)
def _fresh_engine_cache():
    clear_engine_cache()
    yield
    clear_engine_cache()


@pytest.fixture
def make_policy(db):
    """Create a policyset with one policy bound to a model (default Book)."""

    def _make(source, model=Book, name="test"):
        policy_set = PolicySet.objects.create(name=f"set-{name}")
        policy = Policy.objects.create(
            policy_set=policy_set, name=name, source=source
        )
        ct = ContentType.objects.get_for_model(model)
        PolicySetBinding.objects.update_or_create(
            content_type=ct, defaults={"policy_set": policy_set}
        )
        return policy

    return _make


@pytest.fixture
def alice(db):
    return User.objects.create_user("alice")


@pytest.fixture
def bob(db):
    return User.objects.create_user("bob")


@pytest.fixture
def admin_user(db):
    return User.objects.create_superuser("root")
