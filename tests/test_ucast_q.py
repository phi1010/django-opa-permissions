"""UCAST → Q compiler tests, including the handoff doc's integration cases
ported onto the library models (Book $root, team → memberships quantifiers)."""
import pytest
from django.contrib.auth.models import User

from django_opa_permissions.ucast import UcastError, compile_ucast_to_q
from library.models import Book, Membership, Team

pytestmark = pytest.mark.django_db


def field(name, operator, value):
    return {"type": "field", "field": name, "operator": operator, "value": value}


def compound(op, *children):
    return {"type": "compound", "operator": op, "value": list(children)}


def bind(parent, quant, relation, alias):
    return field(f"object.{parent}/${quant}:{relation}/$bind", "eq", alias)


def books(ucast):
    return set(
        Book.objects.filter(compile_ucast_to_q(Book, ucast)).values_list(
            "title", flat=True
        )
    )


@pytest.fixture
def data(db):
    alice = User.objects.create_user("alice")
    bob = User.objects.create_user("bob")
    sales = Team.objects.create(name="sales")
    eng = Team.objects.create(name="eng")
    Membership.objects.create(team=sales, user=alice, role="admin")
    Membership.objects.create(team=sales, user=bob, role="member")
    Membership.objects.create(team=eng, user=bob, role="admin")
    Book.objects.create(title="pub", owner=alice, published=True)
    Book.objects.create(title="priv", owner=alice, published=False)
    Book.objects.create(title="sales-book", owner=bob, team=sales)
    Book.objects.create(title="eng-book", owner=alice, team=eng)
    return {"alice": alice, "bob": bob, "sales": sales, "eng": eng}


def test_flat_column(data):
    assert books(field("object.published", "eq", True)) == {"pub"}


def test_relation_path(data):
    assert books(field("object.owner/username", "eq", "bob")) == {"sales-book"}


def test_fk_id_column(data):
    alice = data["alice"]
    assert books(field("object.owner_id", "eq", alice.pk)) == {
        "pub", "priv", "eng-book"}
    assert books(field("object.owner/id", "eq", alice.pk)) == {
        "pub", "priv", "eng-book"}


def test_operators(data):
    assert books(field("object.title", "startswith", "sales")) == {"sales-book"}
    assert books(field("object.title", "in", ["pub", "priv"])) == {"pub", "priv"}
    assert books(field("object.title", "nin", ["pub", "priv"])) == {
        "sales-book", "eng-book"}


def test_ne_on_null_is_false(data):
    # priv/pub have team=None: `team_id ne X` must NOT match NULL rows
    sales_id = data["sales"].pk
    assert books(field("object.team_id", "ne", sales_id)) == {"eng-book"}


def test_eq_null_maps_to_isnull(data):
    assert books(field("object.team_id", "eq", None)) == {"pub", "priv"}
    assert books(field("object.team_id", "ne", None)) == {"sales-book", "eng-book"}


def test_boolean_structure(data):
    ucast = compound(
        "or",
        field("object.published", "eq", True),
        compound("not", field("object.team_id", "eq", None)),
    )
    assert books(ucast) == {"pub", "sales-book", "eng-book"}


def test_correlated_some(data):
    # SOME membership of the book's team: role == admin AND user == alice
    alice = data["alice"]
    ucast = compound(
        "and",
        bind("$root", "some", "team", "t"),
        bind("t", "some", "memberships", "m"),
        field("object.m/role", "eq", "admin"),
        field("object.m/user_id", "eq", alice.pk),
    )
    assert books(ucast) == {"sales-book"}


def test_correlation_same_row(data):
    # bob is member(sales) and admin(eng): no single membership row is
    # both admin AND in sales for alice? construct: role=admin AND user=bob
    # must only match eng-book (bob is only 'member' in sales).
    bob = data["bob"]
    ucast = compound(
        "and",
        bind("$root", "some", "team", "t"),
        bind("t", "some", "memberships", "m"),
        field("object.m/role", "eq", "admin"),
        field("object.m/user_id", "eq", bob.pk),
    )
    assert books(ucast) == {"eng-book"}


def test_all_and_vacuous_truth(data):
    # ALL memberships of the team are admins. sales has a non-admin → excluded;
    # eng all-admin → included. Books without a team: the to-one quantifier
    # domain is empty → vacuously true.
    ucast = compound(
        "and",
        bind("$root", "all", "team", "t"),
        bind("t", "all", "memberships", "m"),
        field("object.m/role", "eq", "admin"),
    )
    assert books(ucast) == {"pub", "priv", "eng-book"}


def test_none(data):
    # NONE membership with role member → excludes sales-book
    ucast = compound(
        "and",
        bind("$root", "some", "team", "t"),
        bind("t", "none", "memberships", "m"),
        field("object.m/role", "eq", "member"),
    )
    assert books(ucast) == {"eng-book"}


def test_cross_scope_or(data):
    # published OR (some team membership by alice) — OR references $root and m
    alice = data["alice"]
    ucast = compound(
        "and",
        bind("$root", "some", "team", "t"),
        bind("t", "some", "memberships", "m"),
        compound(
            "or",
            field("object.published", "eq", True),
            field("object.m/user_id", "eq", alice.pk),
        ),
    )
    assert books(ucast) == {"sales-book"}


def test_alias_reuse_in_or_branches(data):
    ucast = compound(
        "or",
        compound(
            "and",
            bind("$root", "some", "team", "t"),
            field("object.t/name", "eq", "sales"),
        ),
        compound(
            "and",
            bind("$root", "some", "team", "t"),
            field("object.t/name", "eq", "eng"),
        ),
    )
    assert books(ucast) == {"sales-book", "eng-book"}


def test_m2m_quantifier(data):
    data["sales"].members.add(data["alice"])
    ucast = compound(
        "and",
        bind("$root", "some", "team", "t"),
        bind("t", "some", "members", "u"),
        field("object.u/username", "eq", "alice"),
    )
    assert books(ucast) == {"sales-book"}


def test_always_and_shapes():
    assert str(compile_ucast_to_q(Book, {})) == str(
        compile_ucast_to_q(Book, True))


@pytest.mark.parametrize(
    "bad",
    [
        field("object.nosuchfield", "eq", 1),
        field("object.owner/nosuch", "eq", 1),
        field("object.title", "regex", "x"),
        field("attrs.title", "eq", "x"),
        compound(
            "and",
            bind("$root", "some", "team", "t"),
            bind("$root", "some", "team", "t"),  # duplicate alias
        ),
        field("object.ghost/active", "eq", True),  # multi-segment unknown root path
        compound(  # symbolic cycle
            "and",
            bind("m2", "some", "team", "m1"),
            bind("m1", "some", "team", "m2"),
        ),
    ],
)
def test_rejections(db, bad):
    with pytest.raises(UcastError):
        compile_ucast_to_q(Book, bad)


def test_select_related_composes(data):
    q = compile_ucast_to_q(Book, field("object.published", "eq", True))
    qs = Book.objects.select_related("owner", "team").filter(q)
    assert [b.owner.username for b in qs] == ["alice"]
