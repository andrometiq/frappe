# Copyright (c) 2026, Frappe Technologies and contributors
# License: MIT. See LICENSE

import base64
import hashlib
import json
import secrets
from ipaddress import ip_address
from urllib.parse import urlsplit

import frappe
from frappe import _
from frappe.auth import get_login_attempt_tracker
from frappe.model.document import Document
from frappe.rate_limiter import rate_limit
from frappe.twofactor import should_run_2fa
from frappe.utils import cint, escape_html, format_datetime, now_datetime
from frappe.utils.password import check_password


class UserPasskey(Document):
	# begin: auto-generated types
	# This code is auto-generated. Do not modify anything in this block.

	from typing import TYPE_CHECKING

	if TYPE_CHECKING:
		from frappe.types import DF

		backed_up: DF.Check
		backup_eligible: DF.Check
		credential_id: DF.LongText | None
		credential_id_hash: DF.Data | None
		label: DF.Data
		last_used_at: DF.Datetime | None
		public_key: DF.LongText | None
		sign_count: DF.Int
		transports: DF.Data | None
		user: DF.Link
		user_handle: DF.Data | None
	# end: auto-generated types

	def validate(self):
		if not isinstance(self.label, str) or not 1 <= len(self.label.strip()) <= 140:
			frappe.throw(_("Passkey labels must contain between 1 and 140 characters."))
		self.label = self.label.strip()
		if not 0 <= self.sign_count <= 2**32 - 1:
			_fail("register")
		if not self.is_new():
			for field in (
				"user",
				"credential_id",
				"credential_id_hash",
				"public_key",
				"user_handle",
				"backup_eligible",
			):
				if self.has_value_changed(field):
					frappe.throw(_("Passkey credentials cannot be changed."))


def has_permission(doc, user=None):
	user = user or frappe.session.user
	return doc.user == user or "System Manager" in frappe.get_roles(user)


def get_permission_query_conditions(user=None):
	user = user or frappe.session.user
	if "System Manager" in frappe.get_roles(user):
		return ""
	return f"`tabUser Passkey`.`user` = {frappe.db.escape(user)}"


def get_relying_party():
	# Read the configured public URL directly: get_url() can append backend ports or infer the scheme.
	configured = frappe.conf.host_name or frappe.conf.hostname
	if not configured:
		return None
	try:
		url = urlsplit(configured)
		host = url.hostname
		port = url.port
	except ValueError:
		return None
	if not host or url.username or url.password:
		return None
	try:
		ip_address(host)
	except ValueError:
		pass
	else:
		return None
	is_loopback = host == "localhost" or host.endswith(".localhost")
	if url.scheme != "https" and not (url.scheme == "http" and is_loopback):
		return None
	authority = host
	if port and port != (443 if url.scheme == "https" else 80):
		authority += f":{port}"
	return {"origin": f"{url.scheme}://{authority}", "rp_id": host}


def _fail(kind):
	message = (
		_("Couldn't sign you in with this passkey. Use your password instead.")
		if kind == "login"
		else _("Couldn't add this passkey. Please try again.")
	)
	frappe.throw(message, frappe.AuthenticationError if kind == "login" else frappe.ValidationError)


def _policy(kind):
	policy = get_relying_party()
	if not frappe.get_system_settings("login_with_passkey") or not policy:
		_fail(kind)
	if not frappe.request or frappe.request.headers.get("Origin") != policy["origin"]:
		_fail(kind)
	return policy


def _registration_user():
	user = frappe.session.user
	if user == "Guest" or frappe.session.data.get("impersonated_by"):
		_fail("register")
	if should_run_2fa(user):
		frappe.throw(_("Passkeys can't be added while two-factor authentication applies to your account"))
	return user


def _check_password(user, password):
	trackers = [get_login_attempt_tracker(user), get_login_attempt_tracker(frappe.local.request_ip)]
	try:
		check_password(user, password, delete_tracker_cache=False)
	except frappe.AuthenticationError:
		for tracker in trackers:
			tracker.add_failure_attempt()
		_fail("register")
	for tracker in trackers:
		tracker.add_success_attempt()


def _cookie_name(policy):
	return "__Host-passkey_state" if policy["origin"].startswith("https://") else "passkey_state"


def _set_cookie(value, max_age, policy):
	# CookieManager's generic deletion omits Secure, which __Host- cookies require.
	frappe.local.cookie_manager.set_cookie(
		_cookie_name(policy),
		value,
		httponly=True,
		samesite="Strict",
		secure=policy["origin"].startswith("https://"),
		max_age=max_age,
	)


def _store_state(kind, options, policy, **values):
	state_id = frappe.generate_hash(length=32)
	state = {"kind": kind, "challenge": options["challenge"], **policy, **values}
	# make_key scopes raw JSON to this site; GETDEL must consume it atomically.
	frappe.cache.set(  # nosemgrep: frappe-cache-breaks-multitenancy
		frappe.cache.make_key(f"passkey:{state_id}"), json.dumps(state), ex=300
	)
	_set_cookie(state_id, 300, policy)
	return options


def _consume_state(kind):
	policy = _policy(kind)
	state_id = frappe.request.cookies.get(_cookie_name(policy))
	_set_cookie("", 0, policy)
	if not state_id or len(state_id) != 32:
		_fail(kind)
	raw = frappe.cache.getdel(frappe.cache.make_key(f"passkey:{state_id}"))
	if not raw:
		_fail(kind)
	state = json.loads(raw)
	if state["kind"] != kind or any(state[key] != value for key, value in policy.items()):
		_fail(kind)
	return state


def _credentials(user):
	if not frappe.db.get_value("User", user, "name", for_update=True):
		_fail("register")
	return frappe.db.get_values(
		"User Passkey",
		{"user": user},
		["credential_id", "user_handle"],
		as_dict=True,
		order_by="creation asc, name asc",
		for_update=True,
	)


def _parse(credential, kind):
	from webauthn.helpers import parse_authentication_credential_json, parse_registration_credential_json

	parsed = (
		parse_authentication_credential_json(credential)
		if kind == "login"
		else parse_registration_credential_json(credential)
	)
	client_data = json.loads(parsed.response.client_data_json)
	# py_webauthn 2.8 does not enforce crossOrigin or topOrigin.
	if not isinstance(client_data, dict) or client_data.get("crossOrigin") or "topOrigin" in client_data:
		_fail(kind)
	return parsed


@frappe.whitelist(methods=["POST"])
@rate_limit(limit=10, seconds=3600, user_based=True)
def begin_registration(password: str) -> dict:
	from webauthn import generate_registration_options, options_to_json
	from webauthn.helpers import base64url_to_bytes
	from webauthn.helpers.structs import (
		AuthenticatorSelectionCriteria,
		PublicKeyCredentialDescriptor,
		ResidentKeyRequirement,
		UserVerificationRequirement,
	)

	policy = _policy("register")
	user = _registration_user()
	_check_password(user, password)
	credentials = _credentials(user)
	handle = (
		credentials[0].user_handle
		if credentials
		else base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()
	)
	options = generate_registration_options(
		rp_id=policy["rp_id"],
		rp_name=frappe.get_system_settings("app_name") or _("Frappe"),
		user_name=user,
		user_id=base64url_to_bytes(handle),
		authenticator_selection=AuthenticatorSelectionCriteria(
			resident_key=ResidentKeyRequirement.REQUIRED,
			user_verification=UserVerificationRequirement.REQUIRED,
		),
		exclude_credentials=[
			PublicKeyCredentialDescriptor(id=base64url_to_bytes(row.credential_id)) for row in credentials
		],
	)
	return _store_state(
		"register",
		json.loads(options_to_json(options)),
		policy,
		user=user,
		sid=frappe.session.sid,
		user_handle=handle,
	)


@frappe.whitelist(methods=["POST"])
@rate_limit(limit=10, seconds=3600, user_based=True)
def verify_registration(credential: str, password: str, label: str | None = None) -> dict:
	from webauthn import verify_registration_response
	from webauthn.helpers import (
		base64url_to_bytes,
		bytes_to_base64url,
		decode_credential_public_key,
		decoded_public_key_to_cryptography,
	)
	from webauthn.helpers.exceptions import WebAuthnException

	user = _registration_user()
	state = _consume_state("register")
	if state["user"] != user or state["sid"] != frappe.session.sid:
		_fail("register")
	_check_password(user, password)
	credentials = _credentials(user)
	if credentials and credentials[0].user_handle != state["user_handle"]:
		frappe.throw(_("Please try again"))
	try:
		parsed = _parse(credential, "register")
		result = verify_registration_response(
			credential=parsed,
			expected_challenge=base64url_to_bytes(state["challenge"]),
			expected_origin=state["origin"],
			expected_rp_id=state["rp_id"],
			require_user_verification=True,
		)
		# None attestation does not make py_webauthn validate the public key coordinates.
		decoded_public_key_to_cryptography(decode_credential_public_key(result.credential_public_key))
	except (WebAuthnException, ValueError, TypeError, KeyError, IndexError):
		_fail("register")
	digest = hashlib.sha256(result.credential_id).hexdigest()
	if (
		len(result.credential_id) > 1023
		or not 0 <= result.sign_count <= 2**32 - 1
		or frappe.db.exists("User Passkey", {"credential_id_hash": digest})
	):
		_fail("register")
	doc = frappe.get_doc(
		{
			"doctype": "User Passkey",
			"user": user,
			"label": label if label is not None else _("Passkey"),
			"credential_id": bytes_to_base64url(result.credential_id),
			"credential_id_hash": digest,
			"public_key": bytes_to_base64url(result.credential_public_key),
			"user_handle": state["user_handle"],
			"sign_count": result.sign_count,
			"backup_eligible": result.credential_device_type.value == "multi_device",
			"backed_up": result.credential_backed_up,
			"transports": ",".join(dict.fromkeys(t.value for t in parsed.response.transports or [])),
		}
	)
	try:
		# Only a server-verified credential may bypass the DocType's create restriction.
		doc.insert(ignore_permissions=True)
	except (frappe.UniqueValidationError, frappe.DuplicateEntryError):
		_fail("register")
	frappe.enqueue(
		"frappe.sendmail",
		enqueue_after_commit=True,
		recipients=frappe.db.get_value("User", user, "email"),
		subject=_("A passkey was added to your account"),
		message=_(
			"A passkey named {0} was added to your account at {1}. If this wasn't you, remove it and change your password"
		).format(escape_html(doc.label), format_datetime(now_datetime())),
	)
	return {"name": doc.name, "label": doc.label}


@frappe.whitelist(allow_guest=True, methods=["POST"])
@rate_limit(limit=30, seconds=60)
def begin_login():
	from webauthn import generate_authentication_options, options_to_json
	from webauthn.helpers.structs import UserVerificationRequirement

	policy = _policy("login")
	options = generate_authentication_options(
		rp_id=policy["rp_id"], user_verification=UserVerificationRequirement.REQUIRED
	)
	return _store_state("login", json.loads(options_to_json(options)), policy)


@frappe.whitelist(allow_guest=True, methods=["POST"])
@rate_limit(limit=10, seconds=60)
def verify_login(credential: str) -> None:
	from webauthn import verify_authentication_response
	from webauthn.helpers import base64url_to_bytes, bytes_to_base64url
	from webauthn.helpers.exceptions import WebAuthnException

	state = _consume_state("login")
	try:
		parsed = _parse(credential, "login")
	except (WebAuthnException, ValueError, TypeError, KeyError, IndexError):
		_fail("login")
	digest = hashlib.sha256(parsed.raw_id).hexdigest()
	name = frappe.db.get_value("User Passkey", {"credential_id_hash": digest})
	if not name:
		_fail("login")
	try:
		doc = frappe.get_doc("User Passkey", name, for_update=True)
	except frappe.DoesNotExistError:
		_fail("login")
	if (
		parsed.id != doc.credential_id
		or not parsed.response.user_handle
		or bytes_to_base64url(parsed.response.user_handle) != doc.user_handle
	):
		_fail("login")
	try:
		result = verify_authentication_response(
			credential=parsed,
			expected_challenge=base64url_to_bytes(state["challenge"]),
			expected_origin=state["origin"],
			expected_rp_id=state["rp_id"],
			credential_public_key=base64url_to_bytes(doc.public_key),
			credential_current_sign_count=doc.sign_count,
			require_user_verification=True,
		)
	except (WebAuthnException, ValueError, TypeError, KeyError, IndexError):
		_fail("login")
	if not 0 <= result.new_sign_count <= 2**32 - 1 or cint(doc.backup_eligible) != (
		result.credential_device_type.value == "multi_device"
	):
		_fail("login")
	if not frappe.db.get_value("User", doc.user, "enabled") or should_run_2fa(doc.user):
		_fail("login")
	# Only server-verified counters and backup state are written to the locked row.
	doc.db_set(
		{
			"sign_count": result.new_sign_count,
			"backed_up": result.credential_backed_up,
			"last_used_at": now_datetime(),
		}
	)
	login_manager = frappe.local.login_manager
	login_manager.run_trigger("before_login")
	login_manager.login_as(doc.user)


@frappe.whitelist(methods=["POST"])
@rate_limit(limit=30, seconds=3600, user_based=True)
def rename_passkey(name: str, label: str) -> dict:
	doc = frappe.get_doc("User Passkey", name)
	if doc.user != frappe.session.user:
		raise frappe.PermissionError
	doc.label = label
	# Owners may rename through this endpoint despite the DocType's write restriction.
	doc.save(ignore_permissions=True)
	return {"name": doc.name, "label": doc.label}


@frappe.whitelist(methods=["POST"])
def remove_passkey(name: str) -> None:
	frappe.delete_doc("User Passkey", name)


@frappe.whitelist(methods=["POST"])
def get_passkeys(user: str | None = None) -> list:
	return frappe.get_list(
		"User Passkey",
		filters={"user": user or frappe.session.user},
		fields=["name", "label", "creation", "last_used_at", "backed_up"],
		order_by="creation asc, name asc",
		limit=0,
	)
