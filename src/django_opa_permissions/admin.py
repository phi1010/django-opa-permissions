"""Admin for policies, policysets, bindings — and the policy debugger.

The debugger evaluates a policyset against a chosen user/model/action/object
and renders, per policy source line: coverage highlighting and the output of
``print()`` calls inline next to their line. The full ``data.policies``
document is shown as a tree. Trace logs are deliberately NOT collected.
"""
from __future__ import annotations

import json

from django import forms
from django.contrib import admin
from django.contrib.auth import get_user_model
from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import PermissionDenied
from django.db.models import Q
from django.shortcuts import get_object_or_404, render
from django.urls import path, reverse
from django.utils.html import format_html

from . import engine as engine_mod
from .backends import get_backend
from .models import Policy, PolicySet, PolicySetBinding, PolicySetMembership


class PolicySetMembershipInline(admin.TabularInline):
    model = PolicySetMembership
    fields = ("policy", "sort_order")
    extra = 0


@admin.register(PolicySet)
class PolicySetAdmin(admin.ModelAdmin):
    list_display = ("name", "created_at", "updated_at")
    inlines = [PolicySetMembershipInline]


@admin.register(PolicySetBinding)
class PolicySetBindingAdmin(admin.ModelAdmin):
    list_display = ("content_type", "policy_set")
    list_select_related = ("content_type", "policy_set")


class PolicyDebugForm(forms.Form):
    user = forms.ModelChoiceField(queryset=None, required=False,
                                  help_text="Evaluate as this user (empty = anonymous).")
    content_type = forms.ModelChoiceField(queryset=None, label="Model")
    action = forms.CharField(initial="view")
    object_pk = forms.CharField(required=False, label="Object pk")

    def __init__(self, *args, request_user=None, **kwargs):
        super().__init__(*args, **kwargs)
        users = get_user_model()._default_manager.all()
        # Show only users the calling user is allowed to see: if the user
        # model is OPA-bound, apply the browse prefilter; superusers see all.
        if not getattr(request_user, "is_superuser", False):
            user_ct = ContentType.objects.get_for_model(get_user_model())
            if PolicySetBinding.objects.filter(content_type=user_ct).exists():
                users = users.filter(
                    get_backend().compile_browse_q(request_user, get_user_model())
                    | Q(pk=request_user.pk)
                )
        self.fields["user"].queryset = users.order_by("username")
        self.fields["content_type"].queryset = ContentType.objects.filter(
            pk__in=PolicySetBinding.objects.values("content_type")
        ).order_by("app_label", "model")


def _flatten_coverage(coverage, filename):
    """Row-range coverage of one file → (covered_lines, not_covered_lines)."""
    covered, not_covered = set(), set()
    info = ((coverage or {}).get("files") or {}).get(filename) or {}
    for key, bucket in (("covered", covered), ("not_covered", not_covered)):
        for span in info.get(key) or []:
            start = span.get("start", {}).get("row")
            end = span.get("end", {}).get("row", start)
            if start:
                bucket.update(range(start, (end or start) + 1))
    return covered, not_covered - covered


def _prints_by_line(prints, filename):
    """last_prints entries for one file, grouped by line number."""
    out: dict[int, list[str]] = {}
    for message, location in prints or []:
        fname, _, line = (location or "").rpartition(":")
        if fname == filename and line.isdigit():
            out.setdefault(int(line), []).append(message)
    return out


def _annotate_policy(policy, prints, coverage):
    filename = policy.filename()
    covered, not_covered = _flatten_coverage(coverage, filename)
    per_line = _prints_by_line(prints, filename)
    lines = []
    for number, text in enumerate(policy.source.splitlines(), start=1):
        state = "covered" if number in covered else (
            "not-covered" if number in not_covered else "neutral")
        lines.append({
            "number": number,
            "text": text,
            "state": state,
            "prints": per_line.get(number, []),
        })
    return {"policy": policy, "lines": lines}


@admin.register(Policy)
class PolicyAdmin(admin.ModelAdmin):
    list_display = ("name", "sets", "debug_link")
    list_filter = ("policy_sets",)

    @admin.display(description="policy sets")
    def sets(self, obj):
        return ", ".join(str(s) for s in obj.policy_sets.all()) or "—"

    @admin.display(description="debug")
    def debug_link(self, obj):
        url = reverse("admin:django_opa_permissions_policy_debug", args=[obj.pk])
        return format_html('<a href="{}">Debug</a>', url)

    def get_urls(self):
        urls = super().get_urls()
        custom = [
            path(
                "debug/<uuid:pk>/",
                self.admin_site.admin_view(self.debug_view),
                name="django_opa_permissions_policy_debug",
            ),
        ]
        return custom + urls

    def debug_view(self, request, pk):
        if not request.user.is_staff:
            raise PermissionDenied
        policy = get_object_or_404(Policy, pk=pk)
        data = request.POST if request.method == "POST" else (
            request.GET if request.GET else None)
        form = PolicyDebugForm(data, request_user=request.user)
        context = {
            **self.admin_site.each_context(request),
            "title": f"Debug policy “{policy.name}”",
            "policy": policy,
            "form": form,
            "result": None,
        }
        if data is not None and form.is_valid():
            context["result"] = self._evaluate(request, form)
        return render(request, "django_opa_permissions/policy_debug.html", context)

    def _evaluate(self, request, form):
        backend = get_backend()
        target_user = form.cleaned_data["user"]
        ct = form.cleaned_data["content_type"]
        action = form.cleaned_data["action"].strip()
        obj_pk = form.cleaned_data["object_pk"].strip() or None
        session = backend.get_session(ct)
        if session is None:
            return {"error": "This model has no policyset binding or the set has no policies."}
        input_doc = backend.build_input(target_user, action, ct.app_label, ct.model, obj_pk)
        result = {
            "input_json": json.dumps(input_doc, indent=2),
            "policies": [],
            "error": None,
        }
        # 1. allow, with coverage + prints (snapshotted immediately: the
        #    next eval overwrites both engine attributes)
        try:
            allow = session.eval_document(engine_mod.ALLOW_RULE, input_doc, coverage=True)
        except Exception as exc:
            result["error"] = str(exc)
            allow = None
        prints = list(session.engine.last_prints or [])
        coverage = session.engine.last_coverage
        result["allow"] = allow
        result["prints"] = [f"{loc}: {msg}" for msg, loc in prints]
        result["policies"] = [
            _annotate_policy(m.policy, prints, coverage)
            for m in PolicySetMembership.objects.filter(
                policy_set__bindings__content_type=ct
            ).select_related("policy").order_by("sort_order", "policy__name")
        ]
        # 2. full document tree
        try:
            tree = session.eval_document("policies", input_doc)
        except Exception as exc:
            tree = {"error": str(exc)}
        result["tree_json"] = json.dumps(tree, indent=2, default=str)
        # 3. browse prefilter
        result["prefilter"] = self._prefilter(backend, session, ct, target_user, obj_pk)
        return result

    def _prefilter(self, backend, session, ct, target_user, obj_pk):
        from .ucast import UcastError, compile_ucast_to_q

        model_cls = ct.model_class()
        if not session.defines_rule("filter"):
            return {"status": "no_rule"}
        input_doc = backend.build_input(target_user, "browse", ct.app_label, ct.model)
        try:
            ucast = session.compile_filters(engine_mod.FILTER_RULE, input_doc)
        except Exception as exc:
            return {"status": "error", "detail": str(exc)}
        if ucast is None:
            return {"status": "never"}
        if ucast == {}:
            return {"status": "always"}
        out = {"status": "conditional", "ucast_json": json.dumps(ucast, indent=2)}
        try:
            q = compile_ucast_to_q(model_cls, ucast)
        except UcastError as exc:
            out["status"] = "error"
            out["detail"] = f"UCAST → ORM compilation failed: {exc}"
            return out
        if obj_pk:
            try:
                out["object_included"] = model_cls._base_manager.filter(
                    pk=obj_pk).filter(q).exists()
            except Exception as exc:
                out["object_included_error"] = str(exc)
        return out


class OpaDebugAdminMixin:
    """Add to a ModelAdmin to get a "Debug policy" link on every change form,
    pointing at the policy debugger with model, object pk, action and the
    current user prefilled."""

    change_form_template = "django_opa_permissions/change_form_with_debug.html"

    def render_change_form(self, request, context, add=False, change=False,
                           form_url="", obj=None):
        if obj is not None:
            ct = ContentType.objects.get_for_model(obj, for_concrete_model=False)
            binding = (
                PolicySetBinding.objects.select_related("policy_set")
                .filter(content_type=ct)
                .first()
            )
            ordered = binding.policy_set.ordered_policies() if binding else []
            first = ordered[0] if ordered else None
            if first:
                url = reverse("admin:django_opa_permissions_policy_debug",
                              args=[first.pk])
                context["opa_debug_url"] = (
                    f"{url}?content_type={ct.pk}&object_pk={obj.pk}"
                    f"&action=view&user={request.user.pk}"
                )
        response = super().render_change_form(request, context, add=add,
                                              change=change, form_url=form_url,
                                              obj=obj)
        return response
