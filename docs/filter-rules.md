# Browse filter rules (partial evaluation)

`Model.objects.for_user(user)` asks OPA to **partially evaluate**
`data.policies.filter` with `input.object` unknown. The residual condition
(UCAST) is compiled into a Django `Q` (`Exists`/`OuterRef` subqueries for
quantifiers) and applied in SQL — it composes with `select_related`,
`annotate`, ordering and further filters.

Deny-by-default: no binding, no `filter` rule, an unsatisfiable residual, or
an untranslatable one all yield an empty queryset (errors are logged).

## Referencing the unknown object

Because partial-evaluation unknowns must be exactly two path segments
(`input.object.<field>`), relation traversal is encoded **inside the field
name** (percent-encode names containing `/`, `:` or `$`):

| Rego reference | Meaning |
|---|---|
| `input.object.published` | column of the filtered model |
| `input.object.owner_id` | FK id column |
| `input.object["owner/username"]` | path through to-one relations (`owner__username`) |
| `input.object["$root/<path>"]` | explicit root form of the above |

## Quantifiers over to-many relations

```rego
filter if {
    input.object["$root/$some:team/$bind"] == "t"       # bind team as t
    input.object["t/$some:memberships/$bind"] == "m"    # bind membership as m
    input.object["m/user_id"] == input.user.id
    input.object["m/role"] == "admin"
}
```

- `$some` — at least one related row satisfies the body (EXISTS)
- `$all` — every related row does (NOT EXISTS violation; vacuously true when
  the relation is empty)
- `$none` — no related row does (NOT EXISTS)

Relations may be reverse FKs, forward/reverse M2M, or to-one relations (a
0/1-element domain). Aliases are lexically scoped; a Boolean subtree may
reference several scopes at once (e.g. `input.object.published == true` OR-ed
with a predicate on `m`). Alias names shadow same-named root relations across
the condition — use short distinctive aliases (`t`, `m1`).

Both conjuncts of a bound predicate must sit in the same rule body as the
`$bind` (one `and`); duplicate aliases in a scope, unbound aliases and
cyclic binds are rejected.

## Constraints

- Comparisons must be `<unknown field> <op> <constant>` after substitution of
  known input; supported operators: `eq ne lt lte gt gte in nin contains
  startswith endswith`. (`contains` is case-sensitive on PostgreSQL but
  case-insensitive on sqlite — sqlite's `LIKE` is case-insensitive for ASCII.)
- `ne`/`nin` on a NULL column are **false**; `x == null` compiles to
  `IS NULL`, `x != null` to `IS NOT NULL`.
- No `print()` in filter rules, no `default filter := ...`.
- The prefilter runs with the `browse` action and no `object` in the input.

## Two-pass browse

`for_user` is only the SQL pre-filter. The authoritative decision is the full
evaluation of `allow` **with** the object pk:

- `Model.objects.allowed_for_user(user)` runs both passes;
- write the `filter` rule as a superset (overapproximation) of browse `allow`
  when exact translation is impossible — never a subset, or listings will
  silently hide permitted objects.

Note: the admin policy debugger's user dropdown is also restricted with this
prefilter — an overapproximating `filter` rule on the user model can therefore
show usernames there that the full policy would hide.

See [prefilter-opt-out.md](prefilter-opt-out.md) for opting out of
prefiltering (pass all rows to the second pass) or hiding a model completely
from listings.
