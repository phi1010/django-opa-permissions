from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand

DEMO_USERS = [
    # (username, password, is_superuser)
    ("alice", "alice-password", False),
    ("bob", "bob-password", False),
    ("admin", "admin-password", True),
]


class Command(BaseCommand):
    help = "Create the demo users alice, bob and admin with known passwords."

    def handle(self, *args, **options):
        User = get_user_model()
        for username, password, is_superuser in DEMO_USERS:
            user, _ = User.objects.get_or_create(username=username)
            user.set_password(password)
            user.is_staff = True  # all may open the admin (incl. the debugger)
            user.is_superuser = is_superuser
            user.is_active = True
            user.save()
            self.stdout.write(
                self.style.SUCCESS(f"{username} (password: {password})")
            )
