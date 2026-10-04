/* eslint-env mocha */

context("User passkeys", { testIsolation: true, retries: 0 }, () => {
	const method = "frappe.core.doctype.user_passkey.user_passkey.";
	const user = Cypress.config("testUser") || "frappe@example.com";
	const prefix = "Cypress passkey ";
	const list = '[data-fieldname="passkey_list"]';
	let seeded, signal_failures;

	function stub_signals(win) {
		win.addEventListener("unhandledrejection", (event) => {
			if (event.reason?.message === "Unsupported signal") signal_failures.push(event.reason);
		});
		Object.defineProperty(win, "PublicKeyCredential", {
			configurable: true,
			value: {
				signalAllAcceptedCredentials: cy
					.stub()
					.callsFake(() => win.Promise.reject(new Error("Unsupported signal")))
					.as("accepted"),
				signalUnknownCredential: cy.stub().resolves().as("unknown"),
				signalCurrentUserDetails: cy
					.stub()
					.callsFake(() => new win.Promise(() => {}))
					.as("details"),
			},
		});
	}

	function seed(label) {
		return cy
			.call("frappe.tests.ui_test_helpers.seed_user_passkey", { label: prefix + label })
			.then(({ message }) => {
				seeded.push(message);
				return message;
			});
	}

	function latest_ids(included, excluded = []) {
		cy.get("@accepted").should((stub) => {
			const calls = stub
				.getCalls()
				.filter((call) => call.args[0].userId === seeded[0].user_handle);
			expect(calls.length).to.be.greaterThan(0);
			const ids = calls.at(-1).args[0].allAcceptedCredentialIds;
			included.forEach((id) => expect(ids).to.include(id));
			excluded.forEach((id) => expect(ids).not.to.include(id));
		});
	}

	function open_add_dialog() {
		cy.get(list).contains("button", "Add a passkey").click();
		// Bootstrap focuses the modal when its transition ends; type only after "shown".
		cy.window().its("cur_dialog.display").should("eq", true);
	}

	function clear_fixtures() {
		return cy.call(method + "get_passkeys", { user }).then(({ message }) => {
			message.passkeys
				.filter((row) => row.label.startsWith(prefix))
				.forEach((row) => {
					cy.call(method + "remove_passkey", { name: row.name });
				});
		});
	}

	beforeEach(() => {
		seeded = [];
		signal_failures = [];
		cy.login(user);
		cy.visit("/desk", { onBeforeLoad: stub_signals });
		clear_fixtures();
		cy.intercept("POST", `**/api/method/${method}get_passkeys`, (request) => {
			request.continue((response) => {
				const data = response.body.message;
				if (data.signal) return;
				// CI's HTTP host fails RP policy. Supply only the stubbed signal envelope;
				// like production, it groups the real endpoint's fresh list, so a handle
				// without remaining passkeys has no group.
				const handles = new Map();
				for (const row of data.passkeys) {
					const fixture = seeded.find((entry) => entry.name === row.name);
					if (!fixture) continue;
					if (!handles.has(fixture.user_handle)) handles.set(fixture.user_handle, []);
					handles.get(fixture.user_handle).push(fixture.credential_id);
				}
				data.signal = {
					rp_id: "test_site_ui",
					name: user,
					display_name: "Cypress User",
					handles: Array.from(handles, ([user_handle, credential_ids]) => ({
						user_handle,
						credential_ids,
					})),
				};
			});
		}).as("passkeys");
		seed("A");
		cy.visit(`/desk/user/${encodeURIComponent(user)}`, { onBeforeLoad: stub_signals });
		cy.window().its("cur_frm.doc.name").should("eq", user);
		cy.get(".form-tabs .nav-link").contains("Settings").click();
		cy.contains(".section-head", "Passkeys").then(($head) => {
			if ($head.hasClass("collapsed")) cy.wrap($head).click();
		});
		cy.get(list)
			.should("be.visible")
			.and("contain", prefix + "A");
		cy.then(() => latest_ids([seeded[0].credential_id]));
	});

	afterEach(() => {
		cy.window().then((win) => {
			if (win.cur_frm?.doc) win.cur_frm.doc.__unsaved = 0;
		});
		clear_fixtures();
	});

	it("keeps unsaved edits through rename and remove while signaling fresh remaining IDs", () => {
		seed("B");
		cy.window().then((win) => win.cur_frm.events.refresh_passkeys(win.cur_frm));
		cy.get(list).should("contain", prefix + "B");
		cy.window().then((win) => win.cur_frm.set_value("first_name", "Unsaved passkey edit"));
		cy.contains(`${list} strong`, prefix + "A")
			.closest(".justify-between")
			.contains("button", "Rename")
			.click();
		cy.get_open_dialog()
			.find('[data-fieldname="label"] input')
			.clear()
			.type(prefix + "Renamed");
		cy.get_open_dialog().find(".btn-modal-primary").click();
		cy.get(list)
			.should("contain", prefix + "Renamed")
			.and("not.contain", prefix + "A");
		cy.window().should((win) => {
			expect(win.cur_frm.doc.first_name).to.eq("Unsaved passkey edit");
			expect(win.cur_frm.is_dirty()).to.eq(true);
		});
		cy.contains(`${list} strong`, prefix + "Renamed")
			.closest(".justify-between")
			.contains("button", "Remove")
			.click();
		cy.get_open_dialog().contains("button", "Yes").click();
		cy.get(list)
			.should("not.contain", prefix + "Renamed")
			.and("contain", prefix + "B");
		cy.then(() => latest_ids([seeded[1].credential_id], [seeded[0].credential_id]));
		cy.get("@details").should("have.been.called");
		cy.then(() => expect(signal_failures).to.be.empty);
		cy.window().should((win) => {
			expect(win.cur_frm.doc.first_name).to.eq("Unsaved passkey edit");
			expect(win.cur_frm.is_dirty()).to.eq(true);
		});
	});

	it("signals an empty list for a handle after its last passkey is removed", () => {
		cy.intercept("POST", `**/api/method/${method}remove_passkey`).as("remove");
		cy.intercept("POST", `**/api/method/${method}get_passkeys`).as("fresh");
		cy.contains(`${list} strong`, prefix + "A")
			.closest(".justify-between")
			.contains("button", "Remove")
			.click();
		cy.get_open_dialog().contains("button", "Yes").click();
		cy.wait("@remove").then(({ response }) => {
			expect(response.body.message).to.deep.equal({
				retired_handle: seeded[0].user_handle,
			});
		});
		cy.wait("@fresh").then(({ response }) => {
			const handles = response.body.message.signal.handles.map((row) => row.user_handle);
			expect(handles).not.to.include(seeded[0].user_handle);
		});
		cy.get(list).should("not.contain", prefix + "A");
		cy.get("@accepted").should((stub) => {
			const calls = stub
				.getCalls()
				.filter((call) => call.args[0].userId === seeded[0].user_handle);
			expect(calls.at(-1).args[0].allAcceptedCredentialIds).to.deep.equal([]);
		});
	});

	it("fetches fresh IDs when re-rendering a cached form after another registration", () => {
		seed("B");
		cy.window().then((win) => win.cur_frm.events.render_passkeys(win.cur_frm));
		cy.get(list).should("contain", prefix + "B");
		cy.then(() => latest_ids([seeded[0].credential_id, seeded[1].credential_id]));
	});

	it("discards an older response after a newer refresh", () => {
		let resolve_old, old_data, pending;
		cy.window().then((win) => {
			old_data = {
				passkeys: win.cur_frm.doc.__onload.passkeys,
				signal: {
					rp_id: "test_site_ui",
					name: user,
					display_name: "User",
					handles: [
						{
							user_handle: seeded[0].user_handle,
							credential_ids: [seeded[0].credential_id],
						},
					],
				},
			};
			const xcall = win.frappe.xcall;
			let first = true;
			cy.stub(win.frappe, "xcall").callsFake((endpoint, ...args) => {
				if (endpoint === method + "get_passkeys" && first) {
					first = false;
					return new win.Promise((resolve) => {
						resolve_old = resolve;
					});
				}
				return xcall(endpoint, ...args);
			});
			pending = win.cur_frm.events.refresh_passkeys(win.cur_frm);
		});
		seed("B");
		cy.window().then((win) => win.cur_frm.events.refresh_passkeys(win.cur_frm));
		cy.then(() => latest_ids([seeded[1].credential_id]));
		cy.then(() => {
			resolve_old(old_data);
			return pending;
		});
		cy.get(list).should("contain", prefix + "B");
		cy.then(() => latest_ids([seeded[1].credential_id]));
	});

	it("signals unknown credentials only and preserves other login failures", () => {
		cy.window().then(async (win) => {
			Object.defineProperty(win.navigator, "credentials", {
				configurable: true,
				value: {
					get: cy.stub().resolves({ id: "Y3JlZA", toJSON: () => ({ id: "Y3JlZA" }) }),
				},
			});
			const call = win.frappe.call;
			let failure;
			cy.stub(win.frappe, "call").callsFake((options, ...args) => {
				if (options.method === method + "begin_login")
					return win.Promise.resolve({
						message: { challenge: "YQ", rpId: "test_site_ui" },
					});
				if (options.method === method + "verify_login") return win.Promise.reject(failure);
				return call(options, ...args);
			});
			for (const rejection of [
				{ responseJSON: { exc_type: "UnknownPasskeyError" } },
				{ responseJSON: { exc_type: "AuthenticationError" } },
				undefined,
			]) {
				failure = rejection;
				await win.frappe.passkey.authenticate().then(
					() => {
						throw new Error("Expected sign-in to fail");
					},
					(error) => expect(error).to.eq(rejection)
				);
			}
		});
		cy.get("@unknown").should("have.been.calledOnce").and("have.been.calledWith", {
			rpId: "test_site_ui",
			credentialId: "Y3JlZA",
		});
	});

	for (const duplicate of [false, true]) {
		it(
			duplicate
				? "shows the duplicate message and allows a successful retry"
				: "keeps dirty edits after a successful add and syncs only the fresh list",
			() => {
				let sync_offset;
				cy.window().then((win) => {
					win.cur_frm.doc.__onload.can_add_passkey = true;
					win.cur_frm.events.show_passkeys(
						win.cur_frm,
						win.cur_frm.doc.__onload.passkeys
					);
					win.cur_frm.set_value("first_name", "Unsaved add edit");
					const create = cy
						.stub()
						.resolves({ toJSON: () => ({ id: "YQ" }) })
						.as("create");
					if (duplicate)
						create
							.onFirstCall()
							.rejects(new win.DOMException("Exists", "InvalidStateError"));
					Object.defineProperty(win.navigator, "credentials", {
						configurable: true,
						value: { create },
					});
					const call = win.frappe.call;
					cy.stub(win.frappe, "call").callsFake((options, ...args) => {
						if (options.method === method + "begin_registration") {
							return win.Promise.resolve({
								message: { challenge: "YQ", user: { id: "YQ" } },
							});
						}
						if (options.method === method + "verify_registration") {
							return win.frappe
								.xcall("frappe.tests.ui_test_helpers.seed_user_passkey", {
									label: prefix + "Added",
								})
								.then((row) => {
									seeded.push(row);
									// Reproduce a delayed legacy snapshot after a newer list has already synced.
									return win.cur_frm.events
										.refresh_passkeys(win.cur_frm)
										.then(() => {
											sync_offset =
												win.PublicKeyCredential
													.signalAllAcceptedCredentials.callCount;
											return {
												message: {
													name: row.name,
													label: row.label,
													signal: {
														rp_id: "test_site_ui",
														name: user,
														display_name: "User",
														handles: [
															{
																user_handle: row.user_handle,
																credential_ids: [
																	seeded[0].credential_id,
																],
															},
														],
													},
												},
											};
										});
								});
						}
						return call(options, ...args);
					});
				});
				open_add_dialog();
				const submit = () => {
					cy.get_open_dialog()
						.find('[data-fieldname="password"] input')
						.type("unused-password")
						.blur();
					cy.window().then((win) =>
						win.cur_dialog.primary_action(win.cur_dialog.get_values())
					);
				};
				submit();
				if (duplicate) {
					cy.get_open_dialog().should(
						"contain",
						"This device already has a passkey for your account."
					);
					cy.get_open_dialog().find(".btn-modal-close").click();
					submit();
				}
				cy.get(list).should("contain", prefix + "Added");
				cy.then(() => latest_ids([seeded[0].credential_id, seeded[1].credential_id]));
				cy.get("@accepted").should((stub) => {
					const calls = stub.getCalls().slice(sync_offset);
					expect(calls).not.to.be.empty;
					calls.forEach((call) =>
						expect(call.args[0].allAcceptedCredentialIds).to.include(
							seeded[1].credential_id
						)
					);
				});
				cy.window().should((win) => {
					expect(win.cur_frm.doc.first_name).to.eq("Unsaved add edit");
					expect(win.cur_frm.is_dirty()).to.eq(true);
				});
				cy.then(() => expect(signal_failures).to.be.empty);
			}
		);
	}

	it("requests an OTP in the same add dialog before creating a credential", () => {
		cy.window().then((win) => {
			win.cur_frm.doc.__onload.can_add_passkey = true;
			win.cur_frm.events.show_passkeys(win.cur_frm, win.cur_frm.doc.__onload.passkeys);
			cy.stub(win.frappe.passkey, "register")
				.onFirstCall()
				.resolves({
					message: { two_factor: { method: "OTP App", setup: true } },
				})
				.onSecondCall()
				.resolves({ message: {} })
				.as("register");
		});
		open_add_dialog();
		cy.get_open_dialog()
			.find('[data-fieldname="password"] input')
			.type("unused-password")
			.blur();
		cy.window().then((win) => win.cur_dialog.primary_action(win.cur_dialog.get_values()));
		cy.get_open_dialog().should("contain", "Enter Code displayed in OTP App.");
		cy.get_open_dialog().find('[data-fieldname="otp"] input').type("123456").blur();
		cy.window().then((win) => win.cur_dialog.primary_action(win.cur_dialog.get_values()));
		cy.get("@register").should(
			"have.been.calledWithExactly",
			"unused-password",
			"Passkey",
			"123456"
		);
		cy.get(".modal:visible").should("not.exist");
	});

	it("does not throw when a successful registration is followed by an undefined refresh rejection", () => {
		cy.window().then((win) => {
			win.cur_frm.doc.__onload.can_add_passkey = true;
			cy.stub(win.frappe.passkey, "register").resolves({ message: {} });
			win.cur_frm.events.show_passkeys(win.cur_frm, win.cur_frm.doc.__onload.passkeys);
		});
		open_add_dialog();
		cy.get_open_dialog()
			.find('[data-fieldname="password"] input')
			.type("unused-password")
			.blur();
		cy.window().then((win) => {
			cy.stub(win.cur_frm.events, "refresh_passkeys")
				.callsFake(() => win.Promise.reject())
				.as("failedRefresh");
			// The suite suppresses uncaught errors globally, so await the actual handler's promise.
			return win.cur_dialog.primary_action(win.cur_dialog.get_values());
		});
		cy.get("@failedRefresh").should("have.been.calledOnce");
		cy.get(".modal:visible").should("not.exist");
		cy.get(list).contains("button", "Add a passkey").should("be.enabled");
		cy.window().then((win) => {
			delete win.PublicKeyCredential.signalAllAcceptedCredentials;
			delete win.PublicKeyCredential.signalCurrentUserDetails;
			win.cur_frm.events.render_passkeys(win.cur_frm);
		});
		cy.get("@failedRefresh").should("have.been.calledOnce");
	});
});
