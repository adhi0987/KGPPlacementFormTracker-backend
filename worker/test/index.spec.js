import {
	env,
	createExecutionContext,
	waitOnExecutionContext,
} from "cloudflare:test";
import { describe, it, expect, beforeAll } from "vitest";
import worker from "../src";

/*
 * Integration tests for the licensing worker.
 *
 * An ephemeral ECDSA keypair is generated per run and injected as
 * LICENSE_SIGNING_KEY, so no signing key is committed to the repo.
 * The public half is used to check the tokens the worker mints,
 * which is the same check the extension performs.
 */

let privateJwk;
let publicJwk;

beforeAll(async () => {
	const pair = await crypto.subtle.generateKey(
		{ name: "ECDSA", namedCurve: "P-256" },
		true,
		["sign", "verify"]
	);

	privateJwk = await crypto.subtle.exportKey("jwk", pair.privateKey);
	publicJwk = await crypto.subtle.exportKey("jwk", pair.publicKey);
});

function testEnv() {
	return {
		...env,
		LICENSE_SIGNING_KEY: JSON.stringify(privateJwk),
		CASHFREE_APP_ID: "test_app_id",
		CASHFREE_SECRET_KEY: "test_secret_key",
	};
}

async function call(path, { method = "GET", body, headers = {} } = {}) {
	const request = new Request(`https://example.com${path}`, {
		method,
		headers: body ? { "Content-Type": "application/json", ...headers } : headers,
		body: body ? JSON.stringify(body) : undefined,
	});

	const ctx = createExecutionContext();
	const response = await worker.fetch(request, testEnv(), ctx);
	await waitOnExecutionContext(ctx);

	return response;
}

function base64UrlToBytes(value) {
	const padded =
		value.replace(/-/g, "+").replace(/_/g, "/") +
		"===".slice((value.length + 3) % 4);
	const binary = atob(padded);
	const bytes = new Uint8Array(binary.length);
	for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
	return bytes;
}

async function verifyToken(token) {
	const [payload, signature] = token.split(".");

	const key = await crypto.subtle.importKey(
		"jwk",
		publicJwk,
		{ name: "ECDSA", namedCurve: "P-256" },
		false,
		["verify"]
	);

	const valid = await crypto.subtle.verify(
		{ name: "ECDSA", hash: "SHA-256" },
		key,
		base64UrlToBytes(signature),
		new TextEncoder().encode(payload)
	);

	if (!valid) return null;

	return JSON.parse(new TextDecoder().decode(base64UrlToBytes(payload)));
}

const newId = () => `kgp_install_${crypto.randomUUID()}`;

describe("health", () => {
	it("reports service metadata", async () => {
		const response = await call("/");
		const body = await response.json();

		expect(response.status).toBe(200);
		expect(body.status).toBe("ok");
	});
});

describe("register-installation", () => {
	it("issues a secret once and refuses to re-issue", async () => {
		const installationId = newId();

		const first = await call("/register-installation", {
			method: "POST",
			body: { installation_id: installationId },
		});
		const firstBody = await first.json();

		expect(first.status).toBe(200);
		expect(firstBody.install_secret).toMatch(/^[0-9a-f]{64}$/);

		const second = await call("/register-installation", {
			method: "POST",
			body: { installation_id: installationId },
		});

		expect(second.status).toBe(409);
		expect((await second.json()).code).toBe("ALREADY_REGISTERED");
	});

	it("rejects a malformed installation id", async () => {
		const response = await call("/register-installation", {
			method: "POST",
			body: { installation_id: "short" },
		});

		expect(response.status).toBe(400);
	});
});

describe("verify-license", () => {
	it("returns NOT_FOUND for an unknown installation", async () => {
		const response = await call("/verify-license", {
			method: "POST",
			body: { installation_id: newId() },
		});

		expect(response.status).toBe(200);
		expect(await response.json()).toMatchObject({
			pro: false,
			status: "NOT_FOUND",
		});
	});

	it("rejects a registered installation with a wrong secret", async () => {
		const installationId = newId();

		await call("/register-installation", {
			method: "POST",
			body: { installation_id: installationId },
		});

		const response = await call("/verify-license", {
			method: "POST",
			body: {
				installation_id: installationId,
				install_secret: "0".repeat(64),
			},
		});

		expect(response.status).toBe(401);
	});

	it("requires a secret for a registered installation", async () => {
		const installationId = newId();

		await call("/register-installation", {
			method: "POST",
			body: { installation_id: installationId },
		});

		const response = await call("/verify-license", {
			method: "POST",
			body: { installation_id: installationId },
		});

		expect(response.status).toBe(401);
	});

	it("mints a verifiable token for an ACTIVE license", async () => {
		const installationId = newId();

		const registration = await call("/register-installation", {
			method: "POST",
			body: { installation_id: installationId },
		});
		const { install_secret } = await registration.json();

		/*
		 * Stand in for the payment webhook: create an ACTIVE
		 * license and attach it to this installation.
		 */
		const licenseId = `lic_test_${crypto.randomUUID().replaceAll("-", "")}`;
		const now = Date.now();

		await env.kgp_placement_form_tracker_db
			.prepare(
				`INSERT INTO licenses
				 (license_id, supabase_user_id, customer_email, status,
				  max_installations, created_at, activated_at, last_verified_at)
				 VALUES (?, NULL, ?, 'ACTIVE', 5, ?, ?, NULL)`
			)
			.bind(licenseId, "buyer@example.com", now, now)
			.run();

		await env.kgp_placement_form_tracker_db
			.prepare(
				`UPDATE installations
				 SET license_id = ?, last_seen_at = ?
				 WHERE installation_id = ?`
			)
			.bind(licenseId, now, installationId)
			.run();

		const response = await call("/verify-license", {
			method: "POST",
			body: {
				installation_id: installationId,
				install_secret,
			},
		});
		const body = await response.json();

		expect(response.status).toBe(200);
		expect(body.pro).toBe(true);
		expect(body.status).toBe("ACTIVE");

		/*
		 * The token must verify against the public key and be
		 * bound to this installation.
		 */
		const claims = await verifyToken(body.license_token);

		expect(claims).not.toBeNull();
		expect(claims.license_id).toBe(licenseId);
		expect(claims.installation_id).toBe(installationId);
		expect(claims.exp).toBeGreaterThan(Date.now());
	});

	it("will not mint a token for a PENDING license", async () => {
		const installationId = newId();

		const registration = await call("/register-installation", {
			method: "POST",
			body: { installation_id: installationId },
		});
		const { install_secret } = await registration.json();

		const licenseId = `lic_test_${crypto.randomUUID().replaceAll("-", "")}`;
		const now = Date.now();

		await env.kgp_placement_form_tracker_db
			.prepare(
				`INSERT INTO licenses
				 (license_id, supabase_user_id, customer_email, status,
				  max_installations, created_at, activated_at, last_verified_at)
				 VALUES (?, NULL, ?, 'PENDING', 5, ?, NULL, NULL)`
			)
			.bind(licenseId, "pending@example.com", now)
			.run();

		await env.kgp_placement_form_tracker_db
			.prepare(
				`UPDATE installations
				 SET license_id = ?
				 WHERE installation_id = ?`
			)
			.bind(licenseId, installationId)
			.run();

		const response = await call("/verify-license", {
			method: "POST",
			body: {
				installation_id: installationId,
				install_secret,
			},
		});
		const body = await response.json();

		expect(body.pro).toBe(false);
		expect(body.license_token).toBeUndefined();
	});
});

describe("create-order", () => {
	it("rejects a registered installation with a wrong secret", async () => {
		const installationId = newId();

		await call("/register-installation", {
			method: "POST",
			body: { installation_id: installationId },
		});

		const response = await call("/create-order", {
			method: "POST",
			body: {
				installation_id: installationId,
				install_secret: "0".repeat(64),
				email: "buyer@example.com",
			},
		});

		expect(response.status).toBe(401);
	});

	it("rejects a registered installation with no secret", async () => {
		const installationId = newId();

		await call("/register-installation", {
			method: "POST",
			body: { installation_id: installationId },
		});

		const response = await call("/create-order", {
			method: "POST",
			body: {
				installation_id: installationId,
				email: "buyer@example.com",
			},
		});

		expect(response.status).toBe(401);
	});
});

describe("payment-webhook", () => {
	it("rejects a request with no signature headers", async () => {
		const response = await call("/payment-webhook", {
			method: "POST",
			body: { type: "PAYMENT_SUCCESS_WEBHOOK" },
		});

		expect(response.status).toBe(401);
	});

	it("rejects a stale timestamp", async () => {
		const response = await call("/payment-webhook", {
			method: "POST",
			body: { type: "PAYMENT_SUCCESS_WEBHOOK" },
			headers: {
				"x-webhook-timestamp": String(Date.now() - 60 * 60 * 1000),
				"x-webhook-signature": "deadbeef",
			},
		});

		expect(response.status).toBe(401);
	});
});

describe("payment-return", () => {
	it("rejects an order id that is not server-generated", async () => {
		const response = await call(
			"/payment-return?order_id=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E"
		);

		expect(response.status).toBe(400);

		const html = await response.text();
		expect(html).not.toContain("<img src=x");
	});

	it("rejects a missing order id", async () => {
		const response = await call("/payment-return");

		expect(response.status).toBe(400);
	});
});
