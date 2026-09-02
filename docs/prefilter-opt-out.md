# Opting out of (or fully into) prefiltering

`Model.objects.for_user(user)` partially evaluates `data.policies.filter`.
The result has four regimes — pick the one you want deliberately:

| You write | Residual | `for_user` result |
|---|---|---|
| no `filter` rule at all | — | **empty queryset** (deny) |
| `filter` rule that can never hold | never | empty queryset |
| `filter` rule with unknown-object conditions | conditional | SQL-filtered rows |
| `filter` rule already true from known input | always | **all rows** |

## Hide a model completely at prefiltering

Do nothing: a policyset **without a `filter` rule denies browse listings** for
every non-superuser, even when `allow` would grant per-object access. The same
holds for a model with no `PolicySetBinding` at all.

To hide conditionally (e.g. only guests), make the rule unsatisfiable for
those users from *known* input alone — the object is irrelevant:

```rego
# Listings only for authenticated users; everyone else gets an empty list.
filter if {
    input.user.is_authenticated
    input.object.published == true
}
```

For an unauthenticated user no rule body can hold ⇒ residual "never" ⇒ empty
queryset. Note this hides rows from listings only; `allow` still governs
direct object access.

## Opt out of prefiltering (let everything through)

Sometimes the browse decision can't be expressed as a translatable SQL
condition (it needs a builtin, or complex logic). Then make the prefilter a
no-op and rely on the authoritative second pass:

```rego
# Prefilter opt-out: pass every row; allowed_for_user()/allow decides.
filter if {
    input.user.is_active
}
```

The body only uses known input, so partial evaluation reduces it to "always"
and `for_user` returns the unfiltered queryset. **You must then use
`Model.objects.allowed_for_user(user)`** (or check `allow` per object) —
`for_user` alone would show everything to every active user.

You can mix regimes per user class:

```rego
# Staff skip the SQL filter (second pass still applies)…
filter if {
    input.user.is_staff
}

# …everyone else is filtered in SQL.
filter if {
    input.object.published == true
}
```

## Opting out in Python instead of Rego

- Simply don't call `for_user`/`allowed_for_user` for that model — plain
  `Model.objects.all()` is never filtered; prefiltering is opt-in per query.
- To change the *policy-independent* defaults (e.g. treat "no filter rule" as
  allow-all instead of deny, or skip prefiltering for certain models
  globally), override the backend hook:

```python
class MyBackend(OpaPermissionBackend):
    def compile_browse_q(self, user, model_cls, action="browse"):
        if model_cls in PREFILTER_EXEMPT_MODELS:
            return Q()          # opt out: match everything
        if model_cls in HIDDEN_IN_LISTINGS:
            return Q(pk__in=[])  # hide completely
        return super().compile_browse_q(user, model_cls, action)
```

The hook is used by `for_user`, `allowed_for_user`, and the admin debugger's
user dropdown alike.

## Safety rule of thumb

A `filter` rule may **overapproximate** browse `allow` (show too much to the
SQL pass — the second pass removes the rest) but must never underapproximate,
or listings will silently hide objects the user is allowed to see. "Opt out"
(always) is the maximal safe overapproximation; "hide" (never/no rule) is a
deliberate underapproximation — use it only where hiding is the intent.
