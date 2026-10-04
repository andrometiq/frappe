# Copyright (c) 2026, Frappe Technologies and contributors
# License: MIT. See LICENSE

"""A P-256 software authenticator for real WebAuthn verification in server tests."""

import base64
import hashlib
import json
import secrets
import struct

import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec


def encode(value):
	return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def decode(value):
	return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


class SoftAuthenticator:
	def __init__(self):
		self.key = ec.generate_private_key(ec.SECP256R1())
		self.credential_id = secrets.token_bytes(32)
		self.user_handle = secrets.token_bytes(32)

	def credential(
		self,
		options,
		*,
		origin,
		is_registration=False,
		rp_id=None,
		challenge=None,
		uv=True,
		up=True,
		backed_up=False,
		backup_eligible=False,
		sign_count=0,
	):
		client_data = json.dumps(
			{
				"type": "webauthn.create" if is_registration else "webauthn.get",
				"challenge": challenge or options["challenge"],
				"origin": origin,
			}
		).encode()
		rp_id = rp_id or (options["rp"]["id"] if is_registration else options["rpId"])
		flags = int(up) | (int(uv) << 2) | (int(backup_eligible) << 3) | (int(backed_up) << 4)
		if is_registration:
			flags |= 0x40
			self.user_handle = decode(options["user"]["id"])
		auth_data = hashlib.sha256(rp_id.encode()).digest() + bytes([flags]) + struct.pack(">I", sign_count)
		response = {"clientDataJSON": encode(client_data)}
		if is_registration:
			numbers = self.key.public_key().public_numbers()
			public_key = cbor2.dumps(
				{
					1: 2,
					3: -7,
					-1: 1,
					-2: numbers.x.to_bytes(32, "big"),
					-3: numbers.y.to_bytes(32, "big"),
				}
			)
			auth_data += (
				bytes(16) + struct.pack(">H", len(self.credential_id)) + self.credential_id + public_key
			)
			response.update(
				{
					"attestationObject": encode(
						cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth_data})
					),
					"transports": ["internal", "hybrid"],
				}
			)
		else:
			signature = self.key.sign(
				auth_data + hashlib.sha256(client_data).digest(), ec.ECDSA(hashes.SHA256())
			)
			response.update(
				{
					"authenticatorData": encode(auth_data),
					"signature": encode(signature),
					"userHandle": encode(self.user_handle),
				}
			)
		return {
			"id": encode(self.credential_id),
			"rawId": encode(self.credential_id),
			"type": "public-key",
			"authenticatorAttachment": "platform",
			"clientExtensionResults": {},
			"response": response,
		}
