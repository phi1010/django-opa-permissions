from django.contrib import admin

from django_opa_permissions.admin import OpaDebugAdminMixin, OpaModelAdminMixin

from .models import Book, Membership, Team


@admin.register(Book)
class BookAdmin(OpaModelAdminMixin, OpaDebugAdminMixin, admin.ModelAdmin):
    list_display = ("title", "owner", "team", "published")


admin.site.register(Team)
admin.site.register(Membership)
