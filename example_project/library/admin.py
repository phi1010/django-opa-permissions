from django.contrib import admin

from django_opa_permissions.admin import OpaDebugAdminMixin

from .models import Book, Membership, Team


@admin.register(Book)
class BookAdmin(OpaDebugAdminMixin, admin.ModelAdmin):
    list_display = ("title", "owner", "team", "published")


admin.site.register(Team)
admin.site.register(Membership)
