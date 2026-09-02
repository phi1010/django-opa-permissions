package policies

import rego.v1

# ── Full-evaluation rules (data.policies.allow) ──────────────────────────────
# Input: {user: {id, username, is_superuser, ...}, app_label, model, action,
#         object: {id}}   (object omitted for create and the browse prefilter)
# Fetch data with the builtins; never rely on it being passed in.

# Owners may do anything with their own books.
allow if {
	obj := django_opa_fetch(input.app_label, input.model, input.object.id)
	obj.owner_id == input.user.id
}

# Anyone authenticated may view or browse published books.
allow if {
	input.action in {"view", "browse"}
	input.user.is_authenticated
	obj := django_opa_fetch(input.app_label, input.model, input.object.id)
	obj.published == true
}

# Model-level browse ("may list at all"): any active user.
allow if {
	input.action == "browse"
	not input.object
	input.user.is_active
}

# Any active user may create books — but only as themselves…
allow if {
	input.action == "add"
	input.user.is_active
}

# …and a save may not steal ownership: compare old and changed state.
allow if {
	input.action == "change"
	old := django_opa_fetch_old(input.app_label, input.model, input.object.id)
	new := django_opa_fetch(input.app_label, input.model, input.object.id)
	old.owner_id == input.user.id
	new.owner_id == old.owner_id
}

# Team admins may change team books (ORM query from the policy).
allow if {
	input.action in {"view", "change"}
	obj := django_opa_fetch(input.app_label, input.model, input.object.id)
	obj.team_id != null
	rows := django_opa_query("library", "membership", {
		"team_id": obj.team_id,
		"user_id": input.user.id,
		"role": "admin",
	})
	count(rows) > 0
}

# ── Browse prefilter (data.policies.filter) ──────────────────────────────────
# The object is UNKNOWN: reference its columns via input.object; this is
# compiled to SQL through the ORM. No print(), keep rules simple.

# Published books are listed for everyone.
filter if {
	input.object.published == true
}

# Own books are listed.
filter if {
	input.object["owner/id"] == input.user.id
}

# Books of teams where the user is an admin (quantifier over the reverse-FK
# relation team → memberships).
filter if {
	input.object["$root/$some:team/$bind"] == "t"
	input.object["t/$some:memberships/$bind"] == "m"
	input.object["m/user_id"] == input.user.id
	input.object["m/role"] == "admin"
}
