# Copyright (c) 2026, Frappe Technologies and contributors
# License: MIT. See LICENSE

import json
from http.cookies import SimpleCookie
from unittest.mock import patch

import pyotp

import frappe
from frappe.auth import CookieManager, LoginManager, get_login_attempt_tracker
from frappe.core.doctype.system_settings.system_settings import clear_system_settings_cache
from frappe.core.doctype.user_passkey import user_passkey as passkey
from frappe.tests import IntegrationTestCase
from frappe.tests.test_api import FrappeAPITestCase
from frappe.tests.utils.webauthn import SoftAuthenticator, decode, encode
from frappe.utils import format_datetime, get_datetime, get_test_client, set_request
from frappe.utils.password import update_password

ORIGIN = "https://passkeys.example.com"
METHOD = "frappe.core.doctype.user_passkey.user_passkey."
PASSWORD = "Passkey-test-password-872!"
GUEST_ERROR = "Couldn't sign you in with this passkey. Use your password instead."

LIMITS = {
	"begin_registration": (10, 3600),
	"verify_registration": (10, 3600),
	"rename_passkey": (30, 3600),
	"begin_login": (30, 60),
	"verify_login": (10, 60),
}


def make_user(email, roles=()):
	frappe.get_doc(
		doctype="User",
		email=email,
		first_name="Passkey Test",
		enabled=1,
		send_welcome_email=0,
		roles=[{"role": role} for role in roles],
	).insert(ignore_permissions=True)
	update_password(email, PASSWORD)
	return email


class PasskeyTestCase(IntegrationTestCase):
	def setUp(self):
		super().setUp()
		frappe.set_user("Administrator")
		self.addCleanup(frappe.set_user, "Administrator")
		self.enterContext(patch.dict(frappe.conf, host_name=ORIGIN, http_port=None, webserver_port=None))
		settings = dict(
			login_with_passkey=1,
			enable_two_factor_auth=0,
			two_factor_method="OTP App",
			allow_consecutive_login_attempts=3,
			allow_login_after_fail=300,
			bypass_2fa_for_retricted_ip_users=0,
		)
		self.settings = {field: frappe.db.get_single_value("System Settings", field) for field in settings}
		self.role_two_factor = frappe.db.get_value("Role", "All", "two_factor_auth")
		enqueue = frappe.enqueue

		def isolated_enqueue(method, **kwargs):
			# Keep deletion hooks effective without creating unrelated contacts or sending mail.
			if method == "frappe.model.delete_doc.delete_dynamic_links":
				kwargs["now"] = True
				return enqueue(method, **kwargs)

		self.enqueue = self.enterContext(patch("frappe.enqueue", side_effect=isolated_enqueue))
		self.deleted_documents = set()
		self.deletion_subjects = set()
		self.state_keys = set()
		from frappe.model.delete_doc import add_to_deleted_document

		def record_deletion(doc):
			add_to_deleted_document(doc)
			self.deleted_documents.add((doc.doctype, doc.name))
			self.deletion_subjects.add(f"{frappe._(doc.doctype)} {doc.name}")

		self.enterContext(
			patch("frappe.model.delete_doc.add_to_deleted_document", side_effect=record_deletion)
		)
		store_state = passkey.store_ceremony_state

		def record_state(kind, options, policy, **values):
			result = store_state(kind, options, policy, **values)
			state_id = frappe.local.cookie_manager.cookies[passkey._cookie_name(policy)]["value"]
			self.state_keys.add(frappe.cache.make_key(f"passkey:{state_id}"))
			return result

		self.enterContext(patch.object(passkey, "store_ceremony_state", side_effect=record_state))
		self.users = []
		self.addCleanup(self.cleanup_fixtures)
		self.set_settings(settings)
		for prefix, roles in (("passkey", ()), ("other", ()), ("manager", ("System Manager",))):
			user = f"{prefix}-{frappe.generate_hash(length=8)}@example.com"
			self.users.append(user)
			make_user(user, roles)
		self.user, self.other, self.manager = self.users
		frappe.set_user(self.user)
		self.authenticator = SoftAuthenticator()
		self.cookie = None
		self.request()
		self.clear_limits()
		self.addCleanup(self.clear_limits)

	def cleanup_fixtures(self):
		frappe.db.rollback()
		frappe.set_user("Administrator")
		committed_users = [user for user in self.users if frappe.db.exists("User", user)]
		has_committed_changes = bool(committed_users)
		for user in committed_users:
			frappe.delete_doc("User", user, ignore_permissions=True)
		for doctype, name in self.deleted_documents.copy():
			for archive in frappe.get_all(
				"Deleted Document", filters={"deleted_doctype": doctype, "deleted_name": name}, pluck="name"
			):
				has_committed_changes = True
				frappe.delete_doc(
					"Deleted Document", archive, ignore_permissions=True, delete_permanently=True
				)
		if self.users:
			for activity in frappe.get_all(
				"Activity Log", filters={"user": ["in", self.users]}, pluck="name"
			):
				has_committed_changes = True
				self.deletion_subjects.add(f"{frappe._('Activity Log')} {activity}")
				frappe.delete_doc("Activity Log", activity, ignore_permissions=True, delete_permanently=True)
		# Deletion feeds have no reference_name, so normal dynamic-link cleanup cannot find them.
		if self.deletion_subjects:
			for comment in frappe.get_all(
				"Comment",
				filters={"comment_type": "Deleted", "subject": ["in", list(self.deletion_subjects)]},
				pluck="name",
			):
				has_committed_changes = True
				frappe.delete_doc("Comment", comment, ignore_permissions=True, delete_permanently=True)
		for key in self.state_keys:
			frappe.cache.delete(key)
		if has_committed_changes:
			self.set_settings(self.settings)
			frappe.db.set_value("Role", "All", "two_factor_auth", self.role_two_factor)
			# HTTP requests and successful logins commit; their fixture cleanup must persist too.
			frappe.db.commit()  # nosemgrep
		frappe.clear_document_cache("System Settings", "System Settings")
		clear_system_settings_cache()

	def set_settings(self, values):
		frappe.db.set_single_value("System Settings", values)
		clear_system_settings_cache()

	def verify(self, kind, credential, **kwargs):
		payload = credential if isinstance(credential, str) else json.dumps(credential)
		if kind == "register":
			return passkey.verify_registration(payload, kwargs.pop("password", PASSWORD), **kwargs)
		return passkey.verify_login(payload)

	def reject(self, kind, credential, message=None, **kwargs):
		error = frappe.ValidationError if kind == "register" else frappe.AuthenticationError
		with self.assertRaisesRegex(error, message or (GUEST_ERROR if kind == "login" else "Couldn't add")):
			self.verify(kind, credential, **kwargs)

	def request(self, origin=ORIGIN, cookie=None):
		headers = {"Origin": origin}
		if cookie:
			headers["Cookie"] = f"__Host-passkey_state={cookie}"
		set_request(method="POST", base_url=ORIGIN, path="/", headers=headers)
		frappe.local.request_ip = "192.0.2.81"
		frappe.local.cookie_manager = CookieManager()

	def clear_limits(self):
		for endpoint, (_, seconds) in LIMITS.items():
			identities = ("192.0.2.81", "127.0.0.1") if endpoint.endswith("login") else self.users
			for identity in identities:
				frappe.cache.delete(frappe.cache.make_key(f"rl:{METHOD}{endpoint}:{identity}:{seconds}"))
		for identity in (*self.users, "192.0.2.81", "127.0.0.1"):
			get_login_attempt_tracker(identity, raise_locked_exception=False).add_success_attempt()

	def begin(self, kind):
		self.request()
		options = passkey.begin_registration(PASSWORD) if kind == "register" else passkey.begin_login()
		self.cookie = frappe.local.cookie_manager.cookies["__Host-passkey_state"]["value"]
		self.request(cookie=self.cookie)
		return options

	def read_state(self):
		# Match the site-prefixed raw JSON key used by store_ceremony_state; do not consume it.
		key = frappe.cache.make_key(f"passkey:{self.cookie}")
		return frappe.cache.get(key)  # nosemgrep: frappe-cache-breaks-multitenancy

	def register(self, **kwargs):
		options = self.begin("register")
		credential = self.authenticator.credential(options, origin=ORIGIN, is_registration=True, **kwargs)
		return passkey.verify_registration(json.dumps(credential), PASSWORD, "My passkey")

	def assertion(self, **kwargs):
		options = self.begin("login")
		return self.authenticator.credential(options, origin=ORIGIN, **kwargs)

	def login_manager(self):
		manager = LoginManager.__new__(LoginManager)
		manager.user = "Guest"
		manager.full_name = None
		manager.info = None
		manager.user_type = None
		frappe.local.login_manager = manager
		return manager

	def enable_two_factor(self, method="OTP App"):
		from frappe import twofactor

		self.set_settings({"enable_two_factor_auth": 1, "two_factor_method": method})
		frappe.db.set_value("Role", "All", "two_factor_auth", 1)
		secret = pyotp.random_base32()
		self.enterContext(
			patch.object(
				twofactor,
				"get_otpsecret_for_",
				side_effect=lambda user: secret if user == self.user else pyotp.random_base32(),
			)
		)
		self.enterContext(patch.object(twofactor, "send_token_via_email", return_value=True))
		self.enterContext(patch.object(twofactor, "send_token_via_sms", return_value=True))
		frappe.db.set_value("User", self.user, "mobile_no", "+12025550123")
		self.enterContext(patch.object(twofactor, "get_default", return_value=1))
		return secret


class TestUserPasskey(PasskeyTestCase):
	def test_round_trip_and_login_hooks(self):
		frappe.db.set_value("User", self.user, "email", "notice@example.com")
		added_at = get_datetime("2026-10-04 12:34:56")
		with patch.object(passkey, "now_datetime", return_value=added_at):
			row = self.register(backup_eligible=True, backed_up=True)
		self.assertEqual(set(row), {"name", "label"})
		notice = next(
			call.kwargs for call in self.enqueue.call_args_list if call.args == ("frappe.sendmail",)
		)
		self.assertTrue(notice["enqueue_after_commit"])
		self.assertEqual(notice["subject"], "A passkey was added to your account")
		self.assertEqual(notice["recipients"], "notice@example.com")
		self.assertIn(format_datetime(added_at), notice["message"])
		self.assertEqual(
			passkey.get_passkeys()["signal"],
			{
				"rp_id": "passkeys.example.com",
				"handles": [
					{
						"user_handle": encode(self.authenticator.user_handle),
						"credential_ids": [encode(self.authenticator.credential_id)],
					}
				],
				"name": self.user,
				"display_name": frappe.db.get_value("User", self.user, "full_name"),
			},
		)
		frappe.set_user("Guest")
		credential = self.assertion(backup_eligible=True, backed_up=True, sign_count=1)
		manager = self.login_manager()
		with patch.object(
			LoginManager, "run_trigger", autospec=True, side_effect=LoginManager.run_trigger
		) as trigger:
			self.assertIsNone(self.verify("login", credential))
		self.assertEqual(frappe.session.user, self.user)
		self.assertNotIn(frappe.session.sid, ("Guest", self.user))
		trigger.assert_any_call(manager, "on_login")
		trigger.assert_any_call(manager, "before_login")
		doc = frappe.get_doc("User Passkey", row["name"])
		self.assertEqual(doc.sign_count, 1)
		self.assertTrue(doc.backed_up)
		self.assertIsNotNone(doc.last_used_at)

	def test_crypto_rejections(self):
		for kind in ("register", "login"):
			if kind == "login":
				self.register()
			for overrides in (
				{"origin": "https://wrong.example.com"},
				{"rp_id": "wrong.example.com"},
				{"challenge": encode(b"wrong")},
				{"uv": False},
				{"up": False},
			):
				with self.subTest(kind=kind, overrides=overrides):
					credential = self.authenticator.credential(
						self.begin(kind),
						is_registration=kind == "register",
						**{"origin": ORIGIN, **overrides},
					)
					self.reject(kind, credential)

	def test_state_replay_expiry_wrong_kind_and_browser(self):
		from redis.exceptions import ConnectionError

		options = self.begin("register")
		self.assertTrue(0 < frappe.cache.ttl(frappe.cache.make_key(f"passkey:{self.cookie}")) <= 300)
		credential = self.authenticator.credential(options, origin=ORIGIN, is_registration=True)
		self.verify("register", credential)
		self.reject("register", credential)
		self.begin("register")
		self.reject("login", {})
		self.begin("login")
		frappe.cache.delete(frappe.cache.make_key(f"passkey:{self.cookie}"))
		self.reject("login", {})
		self.begin("login")
		with (
			patch.object(frappe.cache, "getdel", side_effect=ConnectionError),
			self.assertRaises(ConnectionError),
		):
			self.verify("login", {})

	def test_state_is_bound_to_session_and_policy(self):
		from frappe.sessions import hash_sid

		self.register()
		self.begin("register")
		# Only the hashed session id is kept at rest, as for core sessions.
		self.assertEqual(json.loads(self.read_state())["sid"], hash_sid(frappe.session.sid))
		self.assertNotEqual(hash_sid(frappe.session.sid), frappe.session.sid)
		for field, value in (("user", self.other), ("sid", "another-session")):
			options = self.begin("register")
			credential = SoftAuthenticator().credential(options, origin=ORIGIN, is_registration=True)
			with patch.dict(frappe.session, {field: value}):
				self.reject("register", credential)
		for kind in ("register", "login"):
			options = self.begin(kind)
			credential = self.authenticator.credential(
				options, origin=ORIGIN, is_registration=kind == "register"
			)
			with patch.dict(frappe.conf, host_name="https://changed.example.com"):
				self.request(origin="https://changed.example.com", cookie=self.cookie)
				self.reject(kind, credential)

	def test_handle_unknown_credential_and_case_sensitive_ids(self):
		self.authenticator.credential_id = decode("AaAA")
		first = self.register()
		self.authenticator.credential_id = decode("aaAA")
		second = self.register()
		self.assertNotEqual(first["name"], second["name"])
		self.assertEqual(
			set(passkey.get_passkeys()["signal"]["handles"][0]["credential_ids"]), {"AaAA", "aaAA"}
		)
		for handle in (None, encode(b"foreign")):
			credential = self.assertion()
			credential["response"]["userHandle"] = handle
			self.reject("login", credential)
		credential = self.assertion()
		credential["response"]["signature"] = encode(b"bad signature")
		with self.assertRaises(frappe.AuthenticationError) as bad_signature:
			self.verify("login", credential)
		self.assertIs(type(bad_signature.exception), frappe.AuthenticationError)
		self.authenticator = SoftAuthenticator()
		with self.assertRaisesRegex(passkey.UnknownPasskeyError, GUEST_ERROR):
			self.verify("login", self.assertion())
		self.assertEqual(passkey.remove_passkey(first["name"]), {})
		self.assertEqual(passkey.get_passkeys()["signal"]["handles"][0]["credential_ids"], ["aaAA"])

	def test_counters_and_regression(self):
		row = self.register()
		self.login_manager()
		for count in (0, 1, 2**31 - 1, 2**31, 2**32 - 1):
			self.verify("login", self.assertion(sign_count=count))
			self.assertEqual(frappe.db.get_value("User Passkey", row["name"], "sign_count"), count)
		for count in (0, 1, 2**31, 2**32 - 1):
			self.reject("login", self.assertion(sign_count=count))

	def test_registration_counter_and_id_limits(self):
		for count in (0, 2**31, 2**32 - 1):
			self.authenticator = SoftAuthenticator()
			row = self.register(sign_count=count)
			self.assertEqual(frappe.db.get_value("User Passkey", row["name"], "sign_count"), count)
		for count in (-1, 2**32):
			doc = frappe.get_doc("User Passkey", row["name"])
			doc.sign_count = count
			with self.assertRaises(frappe.ValidationError):
				doc.save(ignore_permissions=True)
		self.authenticator.credential_id = b"x" * 1023
		self.assertTrue(self.register()["name"])
		self.authenticator.credential_id = b"x" * 1024
		with self.assertRaises(frappe.ValidationError):
			self.register()

	def test_password_changed_between_begin_and_verify(self):
		options = self.begin("register")
		credential = self.authenticator.credential(options, origin=ORIGIN, is_registration=True)
		sid = frappe.session.sid
		state = self.read_state()
		self.assertNotIn("password", json.loads(state))
		self.assertNotIn(PASSWORD.encode(), state)
		update_password(self.user, "Changed-password-872!", logout_all_sessions=False)
		self.assertEqual(frappe.session.sid, sid)
		self.reject("register", credential, message="Couldn't add this passkey")
		self.assertEqual(get_login_attempt_tracker(self.user).login_failed_count, 1)
		self.assertEqual(get_login_attempt_tracker("192.0.2.81").login_failed_count, 1)
		self.assertEqual(passkey.get_passkeys()["passkeys"], [])

	def test_merged_credentials_and_new_registration(self):
		first_authenticator = self.authenticator
		first = self.register()
		frappe.set_user(self.other)
		self.authenticator = SoftAuthenticator()
		second_authenticator = self.authenticator
		second = self.register()
		self.assertNotEqual(first_authenticator.user_handle, second_authenticator.user_handle)
		frappe.set_user(self.manager)
		frappe.rename_doc("User", self.other, self.user, merge=True, show_alert=False)
		self.assertEqual(frappe.db.get_value("User Passkey", second["name"], "user"), self.user)
		for authenticator in (first_authenticator, second_authenticator):
			frappe.set_user("Guest")
			self.authenticator = authenticator
			self.login_manager()
			self.verify("login", self.assertion())
			self.assertEqual(frappe.session.user, self.user)
		options = self.begin("register")
		canonical = frappe.get_list(
			"User Passkey",
			filters={"user": self.user},
			fields=["name", "user_handle"],
			order_by="creation asc, name asc",
			limit=1,
		)[0]
		self.assertIn(canonical.name, (first["name"], second["name"]))
		self.assertEqual(options["user"]["id"], canonical.user_handle)
		credential = SoftAuthenticator().credential(options, origin=ORIGIN, is_registration=True)
		self.verify("register", credential)
		self.assertEqual(len(passkey.get_passkeys()["passkeys"]), 3)

		groups = {
			row["user_handle"]: row["credential_ids"] for row in passkey.get_passkeys()["signal"]["handles"]
		}
		self.assertEqual(
			groups[encode(second_authenticator.user_handle)], [encode(second_authenticator.credential_id)]
		)
		self.assertIn(
			encode(first_authenticator.credential_id), groups[encode(first_authenticator.user_handle)]
		)
		frappe.set_user(self.manager)
		self.assertEqual(
			passkey.remove_passkey(second["name"]),
			{"retired_handle": encode(second_authenticator.user_handle)},
		)
		self.assertNotIn("signal", passkey.get_passkeys(self.user))
		frappe.set_user(self.user)
		groups = {
			row["user_handle"]: row["credential_ids"] for row in passkey.get_passkeys()["signal"]["handles"]
		}
		self.assertNotIn(encode(second_authenticator.user_handle), groups)
		self.assertIn(
			encode(first_authenticator.credential_id), groups[encode(first_authenticator.user_handle)]
		)

	def test_list_is_ordered_and_not_truncated(self):
		# Populate through the public registration path, resetting only its hourly quota.
		for index in range(21):
			if index % 10 == 0:
				self.clear_limits()
			self.authenticator = SoftAuthenticator()
			self.register()
		rows = passkey.get_passkeys()["passkeys"]
		self.assertEqual(len(rows), 21)
		self.assertEqual(rows, sorted(rows, key=lambda row: (row.creation, row.name)))
		frappe.set_user(self.other)
		self.assertEqual(passkey.get_passkeys(self.user)["passkeys"], [])

	def test_setting_off_at_both_ends(self):
		for kind in ("register", "login"):
			error = frappe.ValidationError if kind == "register" else frappe.AuthenticationError
			self.begin(kind)
			self.set_settings({"login_with_passkey": 0})
			self.reject(kind, {})
			with self.assertRaises(error):
				(passkey.begin_registration(PASSWORD) if kind == "register" else passkey.begin_login())
			self.set_settings({"login_with_passkey": 1})

	def test_origin_policy_and_settings_validation(self):
		frappe.set_user(self.manager)
		for host in (
			None,
			"erp.example.com",
			"http://erp.example.com",
			"https://",
			"https://user:pass@erp.example.com",
			"http://127.0.0.1",
			"https://127.0.0.1",
			"http://[::1]",
			"https://[::1]",
			"https://192.0.2.1",
			"https://[2001:db8::1]",
		):
			with self.subTest(host=host), patch.dict(frappe.conf, host_name=host, hostname=None):
				self.assertIsNone(passkey.get_relying_party())
				with self.assertRaisesRegex(frappe.ValidationError, "Set host_name"):
					frappe.get_doc("System Settings").save()
		for configured, expected in (
			("https://ERP.example.com:443/path", "https://erp.example.com"),
			("http://LOCALHOST:80/path/", "http://localhost"),
			("http://localhost:8000/path", "http://localhost:8000"),
			("http://ERP.localhost:8000/path/", "http://erp.localhost:8000"),
			("https://ERP.example.com:8443/path/", "https://erp.example.com:8443"),
		):
			with patch.dict(frappe.conf, host_name=configured):
				self.assertEqual(passkey.get_relying_party()["origin"], expected)
		with patch.dict(
			frappe.conf, host_name="https://erp.example.com", http_port=8080, webserver_port=8000
		):
			self.assertEqual(passkey.get_relying_party()["origin"], "https://erp.example.com")

	def otp_challenge(self):
		# Core password login reads `{tmp_id}_otp_secret`; the add flow must never write one.
		login_otp_keys = set(frappe.cache.keys("*_otp_secret"))
		challenge = self.begin("register")
		self.assertEqual(set(challenge), {"two_factor"})
		self.assertEqual(set(frappe.cache.keys("*_otp_secret")), login_otp_keys)
		return json.loads(self.read_state())

	def test_two_factor_enrolment_and_uv_login(self):
		self.register()
		options = self.begin("register")
		credential = SoftAuthenticator().credential(options, origin=ORIGIN, is_registration=True)
		secret = self.enable_two_factor()
		get_login_attempt_tracker(self.user).add_failure_attempt()
		self.reject("register", credential)
		self.assertEqual(get_login_attempt_tracker(self.user).login_failed_count, 1)
		for method in ("OTP App", "Email", "SMS"):
			with self.subTest(method=method):
				self.clear_limits()
				self.set_settings({"two_factor_method": method})
				# A zero counter is a valid HOTP token and must not fall back to TOTP.
				with patch.object(
					pyotp.TOTP, "now", return_value="000000" if method == "Email" else "123456"
				):
					token = self.otp_challenge()["hotp_token"]
				self.assertEqual(token, None if method == "OTP App" else (0 if method == "Email" else 123456))
				otp_cookie = self.cookie
				otp = pyotp.HOTP(secret).at(token) if token is not None else pyotp.TOTP(secret).now()
				options = passkey.begin_registration(PASSWORD, otp)
				self.cookie = frappe.local.cookie_manager.cookies["__Host-passkey_state"]["value"]
				self.request(cookie=self.cookie)
				self.authenticator = SoftAuthenticator()
				credential = self.authenticator.credential(options, origin=ORIGIN, is_registration=True)
				self.verify("register", credential)
				self.request(cookie=otp_cookie)
				with self.assertRaises(frappe.ValidationError):
					passkey.begin_registration(PASSWORD, otp)
		frappe.set_user("Guest")
		self.login_manager()
		self.verify("login", self.assertion())
		self.assertEqual(frappe.session.user, self.user)
		self.set_settings({"bypass_2fa_for_retricted_ip_users": 1})
		frappe.db.set_value("User", self.user, "restrict_ip", "192.0.2.81")
		self.assertIn("challenge", passkey.begin_registration(PASSWORD))
		frappe.db.set_value("User", self.user, "enabled", 0)
		self.reject("login", self.assertion())

	def test_otp_binding_replay_expiry_and_lock(self):
		secret = self.enable_two_factor()
		for mismatch in ("user", "session", "expired", "method"):
			with self.subTest(mismatch=mismatch):
				self.clear_limits()
				frappe.set_user(self.user)
				self.otp_challenge()
				if mismatch == "user":
					frappe.set_user(self.other)
				elif mismatch == "session":
					frappe.session.sid = "another-session"
				elif mismatch == "method":
					self.set_settings({"two_factor_method": "Email"})
				else:
					frappe.cache.delete(frappe.cache.make_key(f"passkey:{self.cookie}"))
				with self.assertRaises(frappe.ValidationError):
					passkey.begin_registration(PASSWORD, pyotp.TOTP(secret).now())
		frappe.set_user(self.user)
		self.set_settings({"two_factor_method": "OTP App"})
		self.clear_limits()
		for attempt in range(4):
			self.otp_challenge()
			with self.assertRaisesRegex(frappe.ValidationError, "Incorrect Verification code"):
				passkey.begin_registration(PASSWORD, "invalid")
			if attempt == 0:
				with self.assertRaises(frappe.ValidationError):
					passkey.begin_registration(PASSWORD, pyotp.TOTP(secret).now())
		with self.assertRaises(frappe.SecurityException):
			passkey.begin_registration(PASSWORD)

	def test_password_tracker_and_lock(self):
		with self.assertRaises(frappe.ValidationError):
			passkey.begin_registration("wrong")
		passkey.begin_registration(PASSWORD)
		for identity in (self.user, "192.0.2.81"):
			self.assertFalse(get_login_attempt_tracker(identity).login_failed_count)

		for _ in range(4):
			with self.assertRaises(frappe.ValidationError):
				passkey.begin_registration("wrong-password")
		self.assertEqual(get_login_attempt_tracker(self.user, False).login_failed_count, 4)
		self.assertEqual(get_login_attempt_tracker("192.0.2.81", False).login_failed_count, 4)
		with self.assertRaises(frappe.SecurityException):
			passkey.begin_registration(PASSWORD)

	def test_impersonated_registration_at_both_ends(self):
		self.begin("register")
		frappe.session.data.impersonated_by = self.manager
		self.reject("register", {})
		with self.assertRaises(frappe.ValidationError):
			passkey.begin_registration(PASSWORD)

	def test_owner_and_manager_permissions(self):
		row = self.register()
		name = row["name"]
		doc = frappe.get_doc("User Passkey", name)
		doc.check_permission("read")
		self.assertEqual(passkey.rename_passkey(name, " Renamed ")["label"], "Renamed")
		with self.assertRaises(frappe.PermissionError):
			doc.save()
		with self.assertRaises(frappe.PermissionError):
			frappe.copy_doc(doc).insert()
		frappe.set_user(self.other)
		self.assertEqual(passkey.get_passkeys(self.user)["passkeys"], [])
		with self.assertRaises(frappe.PermissionError):
			frappe.get_doc("User Passkey", name).check_permission("read")
		with self.assertRaises(frappe.PermissionError):
			passkey.rename_passkey(name, "Foreign")
		frappe.set_user(self.manager)
		self.assertEqual(passkey.get_passkeys(self.user)["passkeys"][0].name, name)
		with self.assertRaises(frappe.PermissionError):
			passkey.rename_passkey(name, "Manager")
		self.assertEqual(passkey.remove_passkey(name), {"retired_handle": doc.user_handle})
		self.assertFalse(frappe.db.exists("User Passkey", name))
		frappe.set_user(self.user)
		self.assertEqual(passkey.get_passkeys()["signal"]["handles"], [])

	def test_controller_label_and_immutability(self):
		name = self.register()["name"]
		for label in (" ", "x" * 141, 123, ["label"]):
			error = frappe.ValidationError if isinstance(label, str) else frappe.FrappeTypeError
			with self.assertRaises(error):
				passkey.rename_passkey(name=name, label=label)
		for field, value in (
			("user", self.other),
			("credential_id", "other"),
			("credential_id_hash", "0" * 64),
			("public_key", "other"),
			("user_handle", "other"),
			("backup_eligible", 1),
		):
			doc = frappe.get_doc("User Passkey", name)
			doc.set(field, value)
			with self.subTest(field=field), self.assertRaises(frappe.ValidationError):
				doc.save(ignore_permissions=True)

	def test_user_delete_cascades(self):
		name = self.register()["name"]
		frappe.set_user(self.manager)
		frappe.delete_doc("User", self.user)
		self.assertFalse(frappe.db.exists("User Passkey", name))

	def test_malformed_credentials(self):
		self.register()
		for value in ("{", "[]", "null", {}, {"id": "!"}):
			self.begin("login")
			self.reject("login", value if isinstance(value, str) else json.dumps(value))
		for field in ("clientDataJSON", "authenticatorData", "signature", "userHandle"):
			credential = self.assertion()
			credential["response"][field] = "a"
			self.reject("login", credential)

		import cbor2

		for key in ({}, None, [], {1: 2, 3: -7, -1: 1, -2: "x", -3: "y"}):
			with self.subTest(key=key):
				options = self.begin("register")
				credential = self.authenticator.credential(options, origin=ORIGIN, is_registration=True)
				attestation = cbor2.loads(decode(credential["response"]["attestationObject"]))
				key_offset = 37 + 16 + 2 + len(self.authenticator.credential_id)
				attestation["authData"] = attestation["authData"][:key_offset] + cbor2.dumps(key)
				credential["response"]["attestationObject"] = encode(cbor2.dumps(attestation))
				self.reject("register", credential)
		# Only the passkey registered at the start remains.
		self.assertEqual(len(passkey.get_passkeys()["passkeys"]), 1)

	def test_concurrent_first_enrolment(self):
		first = self.begin("register")
		first_cookie = self.cookie
		second = self.begin("register")
		second_cookie = self.cookie
		self.assertNotEqual(first["user"]["id"], second["user"]["id"])
		self.request(cookie=first_cookie)
		self.verify("register", self.authenticator.credential(first, origin=ORIGIN, is_registration=True))
		self.request(cookie=second_cookie)
		self.reject(
			"register",
			SoftAuthenticator().credential(second, origin=ORIGIN, is_registration=True),
			message="Please try again",
		)
		self.assertEqual(len(passkey.get_passkeys()["passkeys"]), 1)
		name = passkey.get_passkeys()["passkeys"][0].name
		options = self.begin("register")
		self.assertEqual(options["user"]["id"], encode(self.authenticator.user_handle))
		self.assertEqual(options["excludeCredentials"][0]["id"], encode(self.authenticator.credential_id))
		credential = self.authenticator.credential(options, origin=ORIGIN, is_registration=True)
		self.reject("register", credential)
		self.assertEqual([entry.name for entry in passkey.get_passkeys()["passkeys"]], [name])

	def test_rate_limits_ignore_client_identity(self):
		for endpoint in ("begin_login", "begin_registration"):
			self.clear_limits()
			call = getattr(passkey, endpoint)
			args = {"password": PASSWORD} if endpoint == "begin_registration" else {}
			for index in range(LIMITS[endpoint][0]):
				frappe.form_dict.update(user=str(index), label=str(index), password=str(index))
				call(**args)
			with self.assertRaises(frappe.RateLimitExceededError):
				call(**args)

	def test_management_survives_disabled_setting_and_invalid_origin(self):
		name = self.register()["name"]
		doc = frappe.get_doc("User", self.user)
		doc.onload()
		self.assertTrue(doc.get_onload("can_add_passkey"))
		self.assertNotIn("passkey_signal", doc.get_onload())
		frappe.set_user(self.manager)
		doc.onload()
		self.assertNotIn("passkey_signal", doc.get_onload())
		self.assertNotIn("signal", passkey.get_passkeys(self.user))
		frappe.set_user(self.user)
		self.assertNotIn("passkey_origin_valid", doc.get_onload())
		self.set_settings({"login_with_passkey": 0})
		doc.onload()
		self.assertFalse(doc.get_onload("can_add_passkey"))
		with patch.dict(frappe.conf, host_name=None, hostname=None):
			self.set_settings({"login_with_passkey": 1})
			doc.onload()
			self.assertFalse(doc.get_onload("can_add_passkey"))
		self.set_settings({"login_with_passkey": 0})
		with patch.dict(frappe.conf, host_name=None, hostname=None):
			doc = frappe.get_doc("User", self.user)
			doc.onload()
			self.assertEqual(doc.get_onload("passkeys")[0].name, name)
			self.assertEqual(passkey.get_passkeys()["passkeys"][0].name, name)
			self.assertEqual(passkey.rename_passkey(name, "Changed")["label"], "Changed")
			passkey.remove_passkey(name)
			self.assertEqual(passkey.get_passkeys()["passkeys"], [])
		self.assertEqual(passkey.get_passkeys()["signal"]["handles"], [])

		frappe.set_user(self.other)
		with (
			patch("frappe.has_permission", return_value=False),
			patch.object(passkey, "get_passkey_list") as query,
		):
			frappe.get_doc("User", self.user).onload()
			query.assert_not_called()

	def test_retirement_never_reuses_handle(self):
		row = self.register()
		handle = encode(self.authenticator.user_handle)
		options = self.begin("register")
		credential = SoftAuthenticator().credential(options, origin=ORIGIN, is_registration=True)
		self.assertEqual(passkey.remove_passkey(row["name"]), {"retired_handle": handle})
		self.assertEqual(passkey.get_passkeys()["signal"]["handles"], [])
		self.reject("register", credential, message="Please try again")
		self.assertNotEqual(self.begin("register")["user"]["id"], handle)


class TestPasskeyHTTP(PasskeyTestCase, FrappeAPITestCase):
	origin = ORIGIN
	backend_scheme = "https"

	@property
	def site_url(self):
		return self.origin

	@property
	def request_options(self):
		# Werkzeug does not infer the WSGI scheme/host from an absolute request path.
		return {"base_url": self.origin, "environ_overrides": {"wsgi.url_scheme": self.backend_scheme}}

	def get(self, path, params=None, **kwargs):
		return super().get(path, params, **self.request_options, **kwargs)

	def post(self, path, data, **kwargs):
		return super().post(path, data, **self.request_options, **kwargs)

	def delete(self, path, **kwargs):
		return super().delete(path, **self.request_options, **kwargs)

	def setUp(self):
		super().setUp()
		from frappe.config import get_site_config

		self.TEST_CLIENT = get_test_client()

		def configured_site(*args, **kwargs):
			config = get_site_config(*args, **kwargs).copy()
			config.update(host_name=self.origin, http_port=None, webserver_port=None, ignore_csrf=1)
			return frappe._dict(config)

		self.enterContext(patch("frappe.config.get_site_config", configured_site))
		# HTTP requests use another connection and must see these users and settings.
		frappe.db.commit()  # nosemgrep

	def call(self, endpoint, data=None, origin=None, status=200):
		response = self.post(
			self.method(METHOD + endpoint),
			data or {},
			headers={"Origin": self.origin if origin is None else origin},
		)

		self.assertEqual(response.status_code, status, response.text)
		return response

	def password_login(self, user):
		response = self.post(self.method("login"), {"usr": user, "pwd": PASSWORD}, headers={"Origin": ORIGIN})
		self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
		self.assertIn(response.json["message"], ("Logged In", "No App"))
		response = self.get(self.method("frappe.auth.get_logged_user"))
		self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
		self.assertEqual(response.json["message"], user)

	def register(self):
		self.password_login(self.user)
		response = self.call("begin_registration", {"password": PASSWORD})
		options = response.json["message"]
		credential = self.authenticator.credential(options, origin=ORIGIN, is_registration=True)
		response = self.call(
			"verify_registration",
			{"credential": json.dumps(credential), "password": PASSWORD, "label": "HTTP passkey"},
		)
		return response.json["message"]["name"]

	def check_state_cookie(self, response, age, secure=True):
		name = "__Host-passkey_state" if secure else "passkey_state"
		cookies = SimpleCookie()
		for header in response.headers.getlist("Set-Cookie"):
			cookies.load(header)
		cookie = cookies[name]
		for key, value in {
			"max-age": str(age),
			"httponly": True,
			"samesite": "Strict",
			"path": "/",
			"domain": "",
			"secure": True if secure else "",
		}.items():
			self.assertEqual(cookie[key], value)

	def test_login_cookies_proxy_expired_sid_and_replay(self):
		self.register()
		for scheme in ("https", "http"):
			with self.subTest(scheme=scheme):
				self.backend_scheme = scheme
				self.TEST_CLIENT = get_test_client()
				response = self.call("begin_login")
				self.check_state_cookie(response, 300)
				credential = self.authenticator.credential(response.json["message"], origin=ORIGIN)
				self.TEST_CLIENT.set_cookie("sid", "expired-session", domain="passkeys.example.com")
				response = self.call("verify_login", {"credential": json.dumps(credential)})
				self.assertIn(response.json["message"], ("Logged In", "No App"))
				self.check_state_cookie(response, 0)
				sid_headers = [
					value for value in response.headers.getlist("Set-Cookie") if value.startswith("sid=")
				]
				self.assertEqual(len(sid_headers), 1)
				self.assertNotIn(
					self.TEST_CLIENT.get_cookie("sid", domain="passkeys.example.com").value,
					("", "Guest", "expired-session"),
				)
				self.assertEqual(
					self.get(self.method("frappe.auth.get_logged_user")).json["message"], self.user
				)
				self.call("verify_login", {"credential": json.dumps(credential)}, status=401)

	def test_missing_foreign_cookie_and_origin_headers(self):
		self.register()
		for endpoint, data in (("begin_registration", {"password": PASSWORD}), ("begin_login", {})):
			for origin in ("", "https://foreign.example.com"):
				response = self.call(
					endpoint, data, origin=origin, status=417 if endpoint == "begin_registration" else 401
				)
		self.password_login(self.user)
		for kind in ("registration", "login"):
			response = self.call("begin_" + kind, {"password": PASSWORD} if kind == "registration" else {})
			response = self.call(
				"verify_" + kind,
				{"credential": "{}", "password": PASSWORD},
				origin="https://foreign.example.com",
				status=417 if kind == "registration" else 401,
			)
		response = self.call("begin_login")
		credential = self.authenticator.credential(response.json["message"], origin=ORIGIN)
		self.TEST_CLIENT = get_test_client()
		self.call("verify_login", {"credential": json.dumps(credential)}, status=401)
		self.TEST_CLIENT.set_cookie(
			"__Host-passkey_state", "x" * 32, domain="passkeys.example.com", secure=True
		)
		self.call("verify_login", {"credential": json.dumps(credential)}, status=401)

	def test_loopback_state_cookie_is_expired(self):
		self.origin = "http://passkeys.localhost:8000"
		self.backend_scheme = "http"
		response = self.call("begin_login")
		self.check_state_cookie(response, 300, secure=False)
		response = self.call("verify_login", {"credential": "{}"}, status=401)
		self.check_state_cookie(response, 0, secure=False)

	def test_enrolment_code_step_cannot_complete_password_login(self):
		self.password_login(self.user)
		secret = self.enable_two_factor()
		frappe.db.commit()  # nosemgrep
		response = self.call("begin_registration", {"password": PASSWORD})
		self.assertEqual(set(response.json["message"]), {"two_factor"})
		state_id = self.TEST_CLIENT.get_cookie("__Host-passkey_state", domain="passkeys.example.com").value
		for tmp_id in (state_id, None):
			with self.subTest(tmp_id=tmp_id):
				data = {"usr": self.other, "pwd": PASSWORD, "otp": pyotp.TOTP(secret).now()}
				if tmp_id:
					data["tmp_id"] = tmp_id
				response = self.post(self.method("login"), data, headers={"Origin": ORIGIN})
				self.assertNotEqual(response.status_code, 200, response.get_data(as_text=True))
				response = self.get(self.method("frappe.auth.get_logged_user"))
				self.assertNotEqual(response.json.get("message"), self.other)
		self.TEST_CLIENT = get_test_client()
		response = self.post(
			self.method("login"), {"usr": self.user, "pwd": PASSWORD}, headers={"Origin": ORIGIN}
		)
		data = {
			"usr": self.user,
			"pwd": PASSWORD,
			"otp": pyotp.TOTP(secret).now(),
			"tmp_id": response.json["tmp_id"],
		}
		response = self.post(self.method("login"), data, headers={"Origin": ORIGIN})
		self.assertIn(response.json["message"], ("Logged In", "No App"))
		self.assertEqual(self.get(self.method("frappe.auth.get_logged_user")).json["message"], self.user)

	def test_rest_owner_and_foreign_permissions(self):
		name = self.register()
		for user, allowed in ((self.user, True), (self.other, False)):
			self.password_login(user)
			response = self.get(
				self.method("frappe.client.get_list"), {"doctype": "User Passkey", "fields": ["name"]}
			)
			self.assertEqual([row["name"] for row in response.json["message"]], [name] if allowed else [])
			for path, args in (
				(self.resource("User Passkey", name), None),
				(self.method("frappe.client.get"), {"doctype": "User Passkey", "name": name}),
			):
				response = self.get(path, args)
				self.assertEqual(response.status_code, 200 if allowed else 403)
				if allowed:
					self.assertEqual(
						(response.json.get("message") or response.json.get("data"))["name"], name
					)
		self.assertEqual(self.delete(self.resource("User Passkey", name)).status_code, 403)
		self.password_login(self.user)
		self.assertEqual(self.delete(self.resource("User Passkey", name)).status_code, 202)
