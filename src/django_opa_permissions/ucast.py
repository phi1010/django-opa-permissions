"""UCAST → Django ORM compiler for arbitrary Django models.

OPA partial evaluation (``OpaEngine.compile_filters(..., target="ucast")``)
leaves ``input.object`` unknown; policies reference synthetic field names that
encode column access, relation traversal and quantification:

    input.object.published                       column of the filtered model
    input.object["owner/team_id"]                path through to-one relations
    input.object["$root/$some:members/$bind"] == "m1"   bind m1 existentially
    input.object["m1/role"]                      column of the bound entity
    <alias>/$all:<relation>/$bind                universal over a relation
    <alias>/$none:<relation>/$bind               negated existential

Bare two-segment fields (``object.<path>``) are treated as ``$root/<path>``.
Relation/column names containing structural characters must be percent-encoded
(decoded with ``urllib.parse.unquote``).

The UCAST condition object is parsed into a binding-aware relational AST
(explicit ``EntityRef`` on every predicate, lexical scopes, quantifiers as
first-class nodes — Boolean subtrees may reference multiple scopes at once)
and compiled into a single ``Q`` using ``Exists``/``OuterRef`` subqueries.

Model mapping:

- a predicate path ``a/b/c`` on an entity resolves against that entity's model
  ``_meta``: intermediate segments must be to-one forward relations, the final
  segment a concrete column (an FK name resolves to its id column); it becomes
  the Django lookup ``a__b__c``;
- a quantifier relation resolves to a reverse FK, forward/reverse M2M, or a
  to-one relation of the parent model; candidates are built as a SINGLE-arm
  correlated subquery per relation. M2M candidates go through the through
  model (one extra subquery level) rather than OR-ing arms into one subquery:
  PostgreSQL 18 (observed on 18.6) returns wrong results when an EXISTS whose
  subquery contains an OR of a correlated join arm and an IN-subquery arm is
  itself OR-ed with another such EXISTS; single-arm subqueries plan correctly.

NULL semantics: ``ne``/``nin`` on a NULL column are FALSE (SQL semantics);
``eq None`` maps to ``isnull=True`` and ``ne None`` to ``isnull=False``.

Synthetic field strings are an input language: every segment is validated
against model metadata; nothing is concatenated into lookups unvalidated.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Literal
from urllib.parse import unquote

from django.db.models import Exists, ForeignKey, OneToOneField, OuterRef, Q
from django.db.models.fields.related import ManyToManyField
from django.db.models.fields.reverse_related import (
    ManyToManyRel,
    ManyToOneRel,
    OneToOneRel,
)


class UcastError(ValueError):
    """Malformed or unsupported UCAST input (validation is whitelist-based)."""


# ─── Relational AST ──────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Const:
    value: bool


@dataclass(frozen=True)
class EntityRef:
    name: str  # "$root" or a bound alias


@dataclass(frozen=True)
class AttributePredicate:
    entity: EntityRef
    key: str  # slash-separated column path, segments already unquoted
    operator: str
    value: Any


@dataclass(frozen=True)
class And:
    children: tuple["Expr", ...]


@dataclass(frozen=True)
class Or:
    children: tuple["Expr", ...]


@dataclass(frozen=True)
class Not:
    child: "Expr"


@dataclass(frozen=True)
class Quantifier:
    quantifier: Literal["some", "all", "none"]
    alias: str
    parent: EntityRef
    relation: str
    body: "Expr"


# Parse-stage-only leaf: a `$bind` condition before scopes are built.
@dataclass(frozen=True)
class _Bind:
    parent: str
    quantifier: str
    relation: str
    alias: str


Expr = Any  # union of the dataclasses above

_ALIAS_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]*$")
_SEGMENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_QUANTIFIERS = ("some", "all", "none")
_OPERATORS = (
    "eq", "ne", "lt", "lte", "gt", "gte", "in", "nin",
    "contains", "startswith", "endswith",
)
_FIELD_PREFIX = "object."


# ─── UCAST parsing ───────────────────────────────────────────────────────────

def _parse_alias(name: str, *, what: str) -> str:
    if name == "$root":
        return name
    if not _ALIAS_RE.match(name):
        raise UcastError(f"invalid {what} {name!r}")
    return name


def _collect_aliases(node: Any, out: set[str]) -> None:
    """Pre-pass: collect every alias name introduced by a ``$bind`` anywhere
    in the UCAST tree, so field parsing can distinguish an alias prefix from
    the first segment of a root column path. Consequence (documented): alias
    names shadow same-named root relations across the whole condition — use
    distinctive alias names such as ``m1``."""
    if not isinstance(node, dict):
        return
    if node.get("type") == "field":
        f = node.get("field", "")
        if isinstance(f, str) and f.startswith(_FIELD_PREFIX):
            parts = f[len(_FIELD_PREFIX):].split("/")
            if len(parts) == 3 and parts[2] == "$bind" and isinstance(node.get("value"), str):
                out.add(node["value"])
        return
    if node.get("type") == "compound" and isinstance(node.get("value"), list):
        for child in node["value"]:
            _collect_aliases(child, out)


def _parse_field(field: str, operator: str, value: Any, aliases: frozenset[str]) -> Expr:
    if not field.startswith(_FIELD_PREFIX):
        raise UcastError(f"unsupported UCAST field {field!r} (expected 'object.…')")
    path = field[len(_FIELD_PREFIX):]
    parts = path.split("/")
    if len(parts) >= 3 and parts[-1] == "$bind":
        if len(parts) != 3:
            raise UcastError(f"unsupported binding path {field!r}")
        parent = _parse_alias(parts[0], what="binding parent")
        seg = parts[1]
        if not seg.startswith("$") or ":" not in seg:
            raise UcastError(f"malformed quantifier segment {seg!r} in {field!r}")
        quant, _, relation = seg[1:].partition(":")
        if quant not in _QUANTIFIERS:
            raise UcastError(f"unsupported quantifier {quant!r} in {field!r}")
        relation = unquote(relation)
        if not relation:
            raise UcastError(f"empty relation name in {field!r}")
        if operator != "eq" or not isinstance(value, str):
            raise UcastError(f"$bind requires 'eq' with a string alias ({field!r})")
        alias = _parse_alias(value, what="bound alias")
        if alias == "$root":
            raise UcastError("cannot rebind $root")
        return _Bind(parent=parent, quantifier=quant, relation=relation, alias=alias)
    # `object.<path>` is shorthand for `$root/<path>` unless the first
    # segment is `$root` or a `$bind`-introduced alias (see _collect_aliases).
    if len(parts) >= 2 and (parts[0] == "$root" or parts[0] in aliases):
        entity = _parse_alias(parts[0], what="entity reference")
        key_parts = parts[1:]
    else:
        entity = "$root"
        key_parts = parts
    key_parts = [unquote(p) for p in key_parts]
    if not key_parts or any(not p or p.startswith("$") for p in key_parts):
        raise UcastError(f"invalid column path in {field!r}")
    if operator not in _OPERATORS:
        raise UcastError(f"unsupported operator {operator!r}")
    return AttributePredicate(EntityRef(entity), "/".join(key_parts), operator, value)


def parse_ucast(node: Any, aliases: frozenset[str] | None = None) -> Expr:
    """Parse a UCAST condition object into the raw expression tree
    (Boolean structure preserved; `$bind`s still inline as _Bind leaves)."""
    if aliases is None:
        found: set[str] = set()
        _collect_aliases(node, found)
        aliases = frozenset(found)
    if not isinstance(node, dict):
        raise UcastError(f"UCAST node must be an object, got {type(node).__name__}")
    ntype = node.get("type")
    if ntype == "field":
        return _parse_field(node.get("field", ""), node.get("operator", ""), node.get("value"), aliases)
    if ntype == "compound":
        op = node.get("operator")
        values = node.get("value")
        if not isinstance(values, list):
            raise UcastError("compound node without a value list")
        children = tuple(parse_ucast(v, aliases) for v in values)
        if op == "and":
            return And(children)
        if op == "or":
            return Or(children)
        if op == "not":
            if len(children) != 1:
                raise UcastError("'not' requires exactly one child")
            return Not(children[0])
        raise UcastError(f"unsupported compound operator {op!r}")
    raise UcastError(f"unsupported UCAST node type {ntype!r}")


# ─── Scope building (lexical binding environments) ───────────────────────────

def _free_aliases(expr: Expr, locally_bound: frozenset[str]) -> frozenset[str]:
    """Aliases referenced by ``expr`` that are not bound within it."""
    if isinstance(expr, AttributePredicate):
        name = expr.entity.name
        return frozenset() if (name == "$root" or name in locally_bound) else frozenset({name})
    if isinstance(expr, _Bind):
        p = expr.parent
        return frozenset() if (p == "$root" or p in locally_bound) else frozenset({p})
    if isinstance(expr, Not):
        return _free_aliases(expr.child, locally_bound)
    if isinstance(expr, Or):
        out: frozenset[str] = frozenset()
        for c in expr.children:
            out |= _free_aliases(c, locally_bound)
        return out
    if isinstance(expr, And):
        inner = locally_bound | {b.alias for b in expr.children if isinstance(b, _Bind)}
        out = frozenset()
        for c in expr.children:
            out |= _free_aliases(c, inner)
        return out
    if isinstance(expr, (Const, Quantifier)):
        return frozenset()
    raise UcastError(f"unexpected AST node {expr!r}")


def _order_binds(binds: list[_Bind], bound: frozenset[str]) -> list[_Bind]:
    """Topological order (parents before dependents); rejects duplicate
    aliases in one lexical scope, unbound parents, and symbolic cycles."""
    aliases = [b.alias for b in binds]
    if len(set(aliases)) != len(aliases):
        raise UcastError("duplicate binding alias in the same scope")
    dup = set(aliases) & bound
    if dup:
        raise UcastError(f"binding alias shadows an outer binding: {sorted(dup)}")
    by_alias = {b.alias: b for b in binds}
    ordered: list[_Bind] = []
    resolved = set(bound) | {"$root"}
    pending = list(binds)
    while pending:
        progress = [b for b in pending if b.parent in resolved]
        if not progress:
            unresolved_parents = {b.parent for b in pending} - set(by_alias)
            if unresolved_parents - resolved:
                raise UcastError(f"unbound binding parent(s): {sorted(unresolved_parents - resolved)}")
            raise UcastError("cyclic symbolic binding graph")
        for b in progress:
            ordered.append(b)
            resolved.add(b.alias)
            pending.remove(b)
    return ordered


def build_scoped(expr: Expr, bound: frozenset[str] = frozenset()) -> Expr:
    """Turn the raw parse tree into a quantifier-scoped AST.

    In every ``And``, ``$bind`` leaves become nested ``Quantifier`` nodes (in
    dependency order); each remaining conjunct is placed at the shallowest
    quantifier level that binds all aliases it references, so predicates
    independent of a quantifier never fall inside it (this keeps ``$all``
    vacuous-truth semantics correct) while cross-scope Boolean subtrees are
    placed inside the innermost scope they need.
    """
    if isinstance(expr, (Const, AttributePredicate)):
        if isinstance(expr, AttributePredicate):
            name = expr.entity.name
            if name != "$root" and name not in bound:
                raise UcastError(f"unbound alias {name!r}")
        return expr
    if isinstance(expr, _Bind):
        # A bind outside an And still opens a scope — with an empty body.
        return build_scoped(And((expr,)), bound)
    if isinstance(expr, Not):
        return Not(build_scoped(expr.child, bound))
    if isinstance(expr, Or):
        return Or(tuple(build_scoped(c, bound) for c in expr.children))
    if isinstance(expr, And):
        binds = [c for c in expr.children if isinstance(c, _Bind)]
        rest = [c for c in expr.children if not isinstance(c, _Bind)]
        if not binds:
            return And(tuple(build_scoped(c, bound) for c in rest))
        chain = _order_binds(binds, bound)
        chain_aliases = [b.alias for b in chain]

        # index in chain = how deep an expression must be placed; -1 = outside
        def depth_of(c: Expr) -> int:
            free = _free_aliases(c, frozenset())
            idxs = [chain_aliases.index(a) for a in free if a in chain_aliases]
            return max(idxs) if idxs else -1

        levels: dict[int, list[Expr]] = {i: [] for i in range(-1, len(chain))}
        for c in rest:
            levels[depth_of(c)].append(c)
        # build inside-out
        body: Expr | None = None
        for i in range(len(chain) - 1, -1, -1):
            visible = bound | set(chain_aliases[: i + 1])
            conj = [build_scoped(c, visible) for c in levels[i]]
            if body is not None:
                conj.append(body)
            b = chain[i]
            body = Quantifier(
                quantifier=b.quantifier,  # type: ignore[arg-type]
                alias=b.alias,
                parent=EntityRef(b.parent),
                relation=b.relation,
                body=conj[0] if len(conj) == 1 else And(tuple(conj)) if conj else Const(True),
            )
        outer = [build_scoped(c, bound) for c in levels[-1]] + [body]
        return outer[0] if len(outer) == 1 else And(tuple(outer))
    raise UcastError(f"unexpected AST node {expr!r}")


# ─── Django compilation ──────────────────────────────────────────────────────

_ORDER_OPS = {"lt", "lte", "gt", "gte"}
_STRING_OPS = {"contains", "startswith", "endswith"}


def _ref(levels: int, field: str = "pk"):
    """OuterRef chained ``levels`` subquery levels up (levels >= 1)."""
    ref = OuterRef(field)
    for _ in range(levels - 1):
        ref = OuterRef(ref)
    return ref


def _false_q() -> Q:
    return Q(pk__in=[])


def _or_q(qs: list[Q]) -> Q:
    if not qs:
        return _false_q()
    out = qs[0]
    for q in qs[1:]:
        out = out | q
    return out


def _resolve_column_path(model, key: str) -> str:
    """Validate a slash path against model metadata and return the Django
    ``__`` lookup path. Intermediate segments must be to-one forward
    relations; the final segment must be a concrete column, ``pk``/``id``,
    or an FK name (resolved to its id column)."""
    segments = key.split("/")
    lookup_parts: list[str] = []
    current = model
    for i, seg in enumerate(segments):
        last = i == len(segments) - 1
        if not _SEGMENT_RE.match(seg) and seg != "pk":
            raise UcastError(f"invalid column segment {seg!r} in {key!r}")
        if seg in ("pk", "id"):
            if not last:
                raise UcastError(f"{seg!r} must be the last segment in {key!r}")
            lookup_parts.append("pk")
            break
        try:
            field = current._meta.get_field(seg)
        except Exception:
            # allow `<fk>_id` naming for FK columns
            if last and seg.endswith("_id"):
                try:
                    field = current._meta.get_field(seg[:-3])
                except Exception:
                    field = None
                if isinstance(field, (ForeignKey, OneToOneField)):
                    lookup_parts.append(field.attname)
                    break
            raise UcastError(
                f"unknown field {seg!r} on {current._meta.label} in {key!r}"
            )
        if last:
            if isinstance(field, (ForeignKey, OneToOneField)):
                lookup_parts.append(field.attname)  # compare by id
            elif getattr(field, "concrete", False) and not field.many_to_many:
                lookup_parts.append(field.name)
            else:
                raise UcastError(
                    f"field {seg!r} on {current._meta.label} is not a comparable column"
                )
        else:
            if isinstance(field, (ForeignKey, OneToOneField)):
                lookup_parts.append(field.name)
                current = field.related_model
            else:
                raise UcastError(
                    f"segment {seg!r} on {current._meta.label} is not a to-one relation"
                )
    return "__".join(lookup_parts)


def _predicate_q(model, key: str, operator: str, value: Any) -> Q:
    """Q over ``model`` rows for one predicate (no entity resolution)."""
    lookup = _resolve_column_path(model, key)
    if operator == "eq":
        if value is None:
            return Q(**{f"{lookup}__isnull": True})
        return Q(**{f"{lookup}__exact": value})
    if operator == "ne":
        if value is None:
            return Q(**{f"{lookup}__isnull": False})
        # Pinned semantics: ne on a NULL column is FALSE. Django's negation
        # matches NULL rows (Python-like), so require non-null explicitly.
        return Q(**{f"{lookup}__isnull": False}) & ~Q(**{f"{lookup}__exact": value})
    if operator in _ORDER_OPS:
        if value is None:
            raise UcastError(f"{operator} requires a non-null constant")
        return Q(**{f"{lookup}__{operator}": value})
    if operator in _STRING_OPS:
        if not isinstance(value, str):
            raise UcastError(f"{operator} requires a string constant")
        return Q(**{f"{lookup}__{operator}": value})
    if operator == "in":
        if not isinstance(value, (list, tuple)):
            raise UcastError("'in' requires a list constant")
        return Q(**{f"{lookup}__in": list(value)})
    if operator == "nin":
        if not isinstance(value, (list, tuple)):
            raise UcastError("'nin' requires a list constant")
        return Q(**{f"{lookup}__isnull": False}) & ~Q(**{f"{lookup}__in": list(value)})
    raise UcastError(f"unsupported operator {operator!r}")


class _Compiler:
    """env maps alias → (subquery depth, model class) of the alias's row.

    Depth 0 is the outer queryset being filtered ($root). Each quantifier body
    compiles at depth+1. A correlated subquery referencing an alias bound at
    depth b from inside a subquery opened at depth d uses (d + 1 - b) chained
    OuterRefs.
    """

    def __init__(self, root_model):
        self.root_model = root_model

    def compile(self, expr: Expr, env: dict[str, tuple[int, type]], depth: int) -> Q:
        if isinstance(expr, Const):
            return Q() if expr.value else _false_q()
        if isinstance(expr, And):
            out = Q()
            for c in expr.children:
                out = out & self.compile(c, env, depth)
            return out
        if isinstance(expr, Or):
            if not expr.children:
                return _false_q()
            return _or_q([self.compile(c, env, depth) for c in expr.children])
        if isinstance(expr, Not):
            return ~self.compile(expr.child, env, depth)
        if isinstance(expr, AttributePredicate):
            return self._compile_predicate(expr, env, depth)
        if isinstance(expr, Quantifier):
            return self._compile_quantifier(expr, env, depth)
        raise UcastError(f"unexpected AST node {expr!r}")

    def _binding(self, entity: EntityRef, env) -> tuple[int, type]:
        if entity.name == "$root":
            return 0, self.root_model
        if entity.name in env:
            return env[entity.name]
        raise UcastError(f"unbound alias {entity.name!r}")

    def _compile_predicate(self, p: AttributePredicate, env, depth: int) -> Q:
        bound_at, model = self._binding(p.entity, env)
        if bound_at == depth:
            # Predicate on the row of the current (sub)queryset: plain lookup.
            return _predicate_q(model, p.key, p.operator, p.value)
        # Reference to an outer scope's row: correlated EXISTS over that row.
        levels = depth + 1 - bound_at
        sub = model._base_manager.filter(pk=_ref(levels)).filter(
            _predicate_q(model, p.key, p.operator, p.value)
        )
        return Q(Exists(sub))

    def _candidate_queryset(self, quant: Quantifier, env, depth: int):
        """Single-arm correlated candidates queryset for the relation (see
        module docstring for why arms are never OR-ed together)."""
        parent_depth, parent_model = self._binding(quant.parent, env)
        # the candidates subquery itself sits at depth + 1
        parent_levels = depth + 1 - parent_depth
        try:
            field = parent_model._meta.get_field(quant.relation)
        except Exception:
            raise UcastError(
                f"unknown relation {quant.relation!r} on {parent_model._meta.label}"
            )
        if isinstance(field, ManyToOneRel) and not isinstance(field, OneToOneRel):
            # reverse FK: child rows pointing at the parent
            child = field.related_model
            return child._base_manager.filter(
                **{field.field.attname: _ref(parent_levels)}
            ), field.related_model
        if isinstance(field, OneToOneRel):
            child = field.related_model
            return child._base_manager.filter(
                **{field.field.attname: _ref(parent_levels)}
            ), field.related_model
        if isinstance(field, ManyToManyField):
            through = field.remote_field.through
            src = field.m2m_field_name()      # FK on through → parent model
            tgt = field.m2m_reverse_field_name()  # FK on through → related
            # the through subquery inside pk__in sits one level deeper
            link = through._base_manager.filter(
                **{f"{src}__pk": _ref(parent_levels + 1)}
            ).values(f"{tgt}__pk")
            rel = field.remote_field.model
            return rel._base_manager.filter(pk__in=link), rel
        if isinstance(field, ManyToManyRel):
            m2m = field.field  # the forward M2M on the related model
            through = m2m.remote_field.through
            src = m2m.m2m_reverse_field_name()  # FK on through → parent side
            tgt = m2m.m2m_field_name()          # FK on through → related side
            link = through._base_manager.filter(
                **{f"{src}__pk": _ref(parent_levels + 1)}
            ).values(f"{tgt}__pk")
            rel = field.related_model
            return rel._base_manager.filter(pk__in=link), rel
        if isinstance(field, (ForeignKey, OneToOneField)):
            # to-one relation used as a (0/1)-element quantifier domain
            rel = field.related_model
            return rel._base_manager.filter(
                pk=_ref(parent_levels, field.attname)
            ), rel
        raise UcastError(
            f"field {quant.relation!r} on {parent_model._meta.label} "
            f"is not a traversable relation"
        )

    def _compile_quantifier(self, quant: Quantifier, env, depth: int) -> Q:
        candidates, rel_model = self._candidate_queryset(quant, env, depth)
        inner_env = {**env, quant.alias: (depth + 1, rel_model)}
        body = self.compile(quant.body, inner_env, depth + 1)
        if quant.quantifier == "some":
            return Q(Exists(candidates.filter(body)))
        if quant.quantifier == "none":
            return ~Q(Exists(candidates.filter(body)))
        if quant.quantifier == "all":
            return ~Q(Exists(candidates.filter(~body)))
        raise UcastError(f"unsupported quantifier {quant.quantifier!r}")


def compile_ucast_to_q(model, ucast: Any) -> Q:
    """Full pipeline: UCAST condition object → ``Q`` over ``model`` rows
    (the row is ``$root``).

    An empty condition object means "always satisfied" and returns a
    match-everything ``Q()``. ``None`` (never satisfiable) is the CALLER's
    responsibility — this function only accepts a condition object.
    """
    if ucast == {} or ucast is True:
        return Q()
    expr = build_scoped(parse_ucast(ucast))
    return _Compiler(model).compile(expr, {}, 0)
