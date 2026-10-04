(() => {
	const method = "frappe.core.doctype.user_passkey.user_passkey.";
	const decode = (value) =>
		Uint8Array.from(atob(value.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));
	const encode = (value) =>
		btoa(String.fromCharCode(...new Uint8Array(value)))
			.replace(/\+/g, "-")
			.replace(/\//g, "_")
			.replace(/=+$/, "");

	function options_from_json(options, is_registration) {
		const parser = is_registration
			? "parseCreationOptionsFromJSON"
			: "parseRequestOptionsFromJSON";
		if (window.PublicKeyCredential[parser]) return window.PublicKeyCredential[parser](options);
		options.challenge = decode(options.challenge);
		if (is_registration) options.user.id = decode(options.user.id);
		const descriptors = is_registration ? "excludeCredentials" : "allowCredentials";
		options[descriptors] = (options[descriptors] || []).map((item) => ({
			...item,
			id: decode(item.id),
		}));
		return options;
	}

	function credential_to_json(credential) {
		if (credential.toJSON) return credential.toJSON();
		const response = {};
		for (const field of [
			"clientDataJSON",
			"attestationObject",
			"authenticatorData",
			"signature",
			"userHandle",
		]) {
			if (credential.response[field]) response[field] = encode(credential.response[field]);
		}
		if (credential.response.getTransports)
			response.transports = credential.response.getTransports();
		return {
			id: credential.id,
			rawId: encode(credential.rawId),
			type: credential.type,
			authenticatorAttachment: credential.authenticatorAttachment,
			clientExtensionResults: credential.getClientExtensionResults(),
			response,
		};
	}

	async function call(endpoint, args = {}) {
		return frappe.call({
			method: method + endpoint,
			args,
			type: "POST",
			// Website calls otherwise open a dialog before the login banner handles the error.
			error_msg: "section:visible .login-error-banner .es-alert__title",
		});
	}

	function signal(method, payload) {
		// Signal APIs may be absent or never settle; they must not delay account actions.
		try {
			if (typeof window.PublicKeyCredential?.[method] === "function") {
				Promise.resolve(window.PublicKeyCredential[method](payload)).catch(() => {});
			}
		} catch {
			return;
		}
	}

	function signal_credentials(data) {
		if (!data?.rp_id) return;
		for (const handle of data.handles || []) {
			const user = { rpId: data.rp_id, userId: handle.user_handle };
			signal("signalAllAcceptedCredentials", {
				...user,
				allAcceptedCredentialIds: handle.credential_ids,
			});
			signal("signalCurrentUserDetails", {
				...user,
				name: data.name,
				displayName: data.display_name,
			});
		}
	}

	frappe.passkey = {
		signal_credentials,
		async register(password, label, otp) {
			const { message } = await call("begin_registration", { password, otp });
			if (message.two_factor) return { message };
			const credential = await navigator.credentials.create({
				publicKey: options_from_json(message, true),
			});
			const result = await call("verify_registration", {
				credential: JSON.stringify(credential_to_json(credential)),
				password,
				label,
			});
			return result;
		},
		async authenticate() {
			const { message } = await call("begin_login");
			const credential = await navigator.credentials.get({
				publicKey: options_from_json(message, false),
			});
			try {
				return await call("verify_login", {
					credential: JSON.stringify(credential_to_json(credential)),
				});
			} catch (error) {
				if (error?.responseJSON?.exc_type === "UnknownPasskeyError") {
					signal("signalUnknownCredential", {
						rpId: message.rpId,
						credentialId: credential.id,
					});
				}
				throw error;
			}
		},
	};
})();
