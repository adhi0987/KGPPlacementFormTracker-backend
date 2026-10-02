const ALLOWED_ORIGINS = new Set([
  "*",

  "https://kgp-placement-form-tracker-backend.noticeboard.workers.dev",

  "http://127.0.0.1:8787",

  "http://localhost:8787",
]);


function getCorsHeaders(request) {

  const origin =
    request.headers.get(
      "Origin"
    );


  const headers = {
    "Access-Control-Allow-Methods":
      "GET, POST, OPTIONS",

    "Access-Control-Allow-Headers":
      "Content-Type, Authorization",

    "Access-Control-Max-Age":
      "86400",

  };


  if (
    origin &&
    ALLOWED_ORIGINS.has(
      origin
    )
  ) {

    headers[
      "Access-Control-Allow-Origin"
    ] =
      origin;

  }


  return headers;
}

const SUPABASE_URL =
  "https://clgjswrlcwzmdxhhegtk.supabase.co";

const CASHFREE_BASE_URL =
  "https://api.cashfree.com/pg";

const CASHFREE_MODE =
  "production";

// Keep ₹1 while testing in Cashfree Sandbox.
// Change to 45 only when moving to production.
const PRO_PRICE_INR =
  27.0;

// Extension caches successful license checks
// for 6 hours.
const LICENSE_CACHE_HOURS =
  6;


function jsonResponse(
  data,
  status = 200,
  request = null
) {

  const cors =
    request
      ? getCorsHeaders(
        request
      )
      : {};


  return Response.json(
    data,
    {
      status,

      headers: {
        ...cors,
      },
    }
  );
}


function htmlResponse(
  html,
  status = 200,
  request = null
) {

  const cors =
    request
      ? getCorsHeaders(
        request
      )
      : {};


  return new Response(
    html,
    {
      status,

      headers: {
        "Content-Type":
          "text/html; charset=UTF-8",

        "Cache-Control":
          "no-store",

        /*
         * These pages only ever need the Cashfree SDK plus
         * their own inline script, styles and same-origin API
         * calls. Locking this down means a reflected value in the
         * markup cannot execute.
         *
         * connect-src must include 'self': the checkout page
         * calls back into this Worker to create the order.
         */

        "Content-Security-Policy":
          "default-src 'none'; script-src https://sdk.cashfree.com 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self' https://api.cashfree.com https://sdk.cashfree.com; img-src 'self' https://sdk.cashfree.com data:; frame-src https://sdk.cashfree.com https://api.cashfree.com https://payments.cashfree.com; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",

        "X-Content-Type-Options":
          "nosniff",

        "Referrer-Policy":
          "no-referrer",

        ...cors,
      },
    }
  );
}


function escapeHtml(
  value
) {
  return String(
    value ?? ""
  ).replace(
    /[&<>"']/g,
    char =>
      ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#39;",
      })[char]
  );
}


function isValidEmail(
  email
) {
  return (
    typeof email ===
    "string" &&

    email.length >= 5 &&

    email.length <= 254 &&

    /^[^\s@]+@[^\s@]+\.[^\s@]+$/
      .test(email)
  );
}


function isValidInstallationId(
  value
) {
  return (
    typeof value ===
    "string" &&

    value.length >= 10 &&

    value.length <= 200
  );
}


function getBearerToken(
  request
) {
  const header =
    request.headers.get(
      "Authorization"
    ) || "";

  if (
    !header
      .toLowerCase()
      .startsWith(
        "bearer "
      )
  ) {
    return null;
  }

  const token =
    header
      .slice(7)
      .trim();

  return token || null;
}


function cashfreeHeaders(
  env
) {
  return {
    "x-client-id":
      env.CASHFREE_APP_ID,

    "x-client-secret":
      env.CASHFREE_SECRET_KEY,

    "x-api-version":
      "2025-01-01",

    Accept:
      "application/json",

    "Content-Type":
      "application/json",
  };
}


/*
 * ============================================================
 * CASHFREE WEBHOOK SIGNATURE
 * ============================================================
 */

async function generateCashfreeSignature(
  timestamp,
  rawBody,
  secret
) {
  const encoder =
    new TextEncoder();

  const key =
    await crypto.subtle.importKey(
      "raw",
      encoder.encode(
        secret
      ),
      {
        name:
          "HMAC",
        hash:
          "SHA-256",
      },
      false,
      ["sign"]
    );

  const signatureBytes =
    await crypto.subtle.sign(
      "HMAC",
      key,
      encoder.encode(
        timestamp +
        rawBody
      )
    );

  let binary = "";

  for (
    const byte of
    new Uint8Array(
      signatureBytes
    )
  ) {
    binary +=
      String.fromCharCode(
        byte
      );
  }

  return btoa(
    binary
  );
}


function safeCompare(
  a,
  b
) {
  if (
    !a ||
    !b ||
    a.length !==
    b.length
  ) {
    return false;
  }

  const encoder =
    new TextEncoder();

  const left =
    encoder.encode(a);

  const right =
    encoder.encode(b);

  let result = 0;

  for (
    let i = 0;
    i < left.length;
    i++
  ) {
    result |=
      left[i] ^
      right[i];
  }

  return (
    result === 0
  );
}


/*
 * ============================================================
 * INSTALLATION SECRETS
 * ============================================================
 *
 * An installation_id is not a credential: it is stored in the
 * extension, appears in the /checkout URL and is sent to
 * Cashfree. Every installation therefore gets a companion
 * random secret, issued once at registration.
 *
 * Only sha256(secret) is stored, so a database leak does not
 * hand out working credentials.
 * ============================================================
 */

function randomHex(bytes) {
  const buffer =
    new Uint8Array(bytes);

  crypto.getRandomValues(
    buffer
  );

  return [
    ...buffer,
  ]
    .map(
      byte =>
        byte
          .toString(16)
          .padStart(2, "0")
    )
    .join("");
}


function isValidInstallSecret(
  value
) {
  return (
    typeof value ===
      "string" &&
    /^[0-9a-f]{64}$/.test(
      value
    )
  );
}


async function hashInstallSecret(
  secret
) {
  const digest =
    await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(
        secret
      )
    );

  return [
    ...new Uint8Array(
      digest
    ),
  ]
    .map(
      byte =>
        byte
          .toString(16)
          .padStart(2, "0")
    )
    .join("");
}


/*
 * Confirm the caller owns this installation.
 *
 * Returns one of:
 *   "ok"     — registered, secret matches
 *   "legacy" — no secret on record yet: an installation created
 *              before secrets existed, or by an extension version
 *              that predates them. Allowed so a worker deploy does
 *              not lock existing paying users out; these installs
 *              gain full protection the first time the updated
 *              extension registers them.
 *   "deny"   — a secret is on record and the supplied one is
 *              missing or wrong. Someone is using an id they do
 *              not own.
 */

async function verifyInstallSecret(
  db,
  installationId,
  secret
) {
  const row =
    await db
      .prepare(
        `SELECT secret_hash
         FROM installation_secrets
         WHERE installation_id = ?
         LIMIT 1`
      )
      .bind(
        installationId
      )
      .first();

  if (!row) {
    return "legacy";
  }

  if (
    !isValidInstallSecret(
      secret
    )
  ) {
    return "deny";
  }

  const candidate =
    await hashInstallSecret(
      secret
    );

  return safeCompare(
    candidate,
    row.secret_hash
  )
    ? "ok"
    : "deny";
}


/*
 * ============================================================
 * RATE LIMITING
 * ============================================================
 *
 * Fixed-window counters. `consumeRateLimit` returns false when
 * the caller has exceeded `limit` within `windowMs`.
 *
 * Fails open on database errors: a D1 hiccup should not lock
 * paying users out of their license.
 * ============================================================
 */

async function consumeRateLimit(
  db,
  key,
  limit,
  windowMs
) {
  const now =
    Date.now();

  try {
    const row =
      await db
        .prepare(
          `SELECT
             count,
             window_start
           FROM rate_limits
           WHERE rl_key = ?
           LIMIT 1`
        )
        .bind(key)
        .first();

    if (
      !row ||
      now -
        Number(
          row.window_start
        ) >=
        windowMs
    ) {
      await db
        .prepare(
          `INSERT INTO rate_limits
           (
             rl_key,
             count,
             window_start
           )
           VALUES (?, 1, ?)
           ON CONFLICT(rl_key)
           DO UPDATE SET
             count = 1,
             window_start = excluded.window_start`
        )
        .bind(
          key,
          now
        )
        .run();

      return true;
    }

    if (
      Number(row.count) >=
      limit
    ) {
      return false;
    }

    await db
      .prepare(
        `UPDATE rate_limits
         SET count = count + 1
         WHERE rl_key = ?`
      )
      .bind(key)
      .run();

    return true;

  } catch (error) {

    console.error(
      "Rate limit check failed (failing open):",
      error
    );

    return true;
  }
}


/*
 * Cloudflare sets CF-Connecting-IP on every edge request, so it
 * cannot be spoofed by the client.
 */

function getClientIp(request) {
  return (
    request.headers.get(
      "CF-Connecting-IP"
    ) || "unknown"
  );
}


/*
 * ============================================================
 * SUPABASE USER VERIFICATION
 * ============================================================
 *
 * The extension never tells us which user it wants.
 * It sends a Supabase access token.
 *
 * We ask Supabase who owns that token.
 * ============================================================
 */

async function getSupabaseUser(
  accessToken,
  env
) {
  if (
    !env.SUPABASE_PUBLISHABLE_KEY
  ) {
    throw new Error(
      "Missing SUPABASE_PUBLISHABLE_KEY secret"
    );
  }

  const response =
    await fetch(
      `${SUPABASE_URL}/auth/v1/user`,
      {
        method:
          "GET",

        headers: {
          apikey:
            env.SUPABASE_PUBLISHABLE_KEY,

          Authorization:
            `Bearer ${accessToken}`,
        },
      }
    );

  if (
    !response.ok
  ) {
    console.error(
      "Supabase user verification failed:",
      await response.text()
    );

    return null;
  }

  return await response.json();
}


/*
 * ============================================================
 * PRO ENTITLEMENT TOKEN
 * ============================================================
 *
 * The ERP notice data never leaves the client, so the Worker
 * cannot enforce the paywall by withholding rows. Instead the
 * Worker signs a short-lived statement of entitlement and the
 * extension verifies that signature before unlocking the PRO
 * columns.
 *
 * Signing is ECDSA P-256. The private key lives only in the
 * Worker; the extension ships the public key. A user who edits
 * chrome.storage.local can flip a boolean, but cannot mint a
 * token, so the unlock cannot be forged offline — and unlike
 * HMAC, nothing in the extension is enough to produce one.
 *
 * Format: base64url(payload).base64url(signature)
 * ============================================================
 */

const LICENSE_TOKEN_TTL_MS =
  6 * 60 * 60 * 1000;


function getSigningKeyJwk(
  env
) {
  if (
    !env.LICENSE_SIGNING_KEY
  ) {
    throw new Error(
      "Missing LICENSE_SIGNING_KEY secret"
    );
  }

  return JSON.parse(
    env.LICENSE_SIGNING_KEY
  );
}


function bytesToBase64Url(
  bytes
) {
  let binary = "";

  for (
    const byte of bytes
  ) {
    binary +=
      String.fromCharCode(
        byte
      );
  }

  return btoa(binary)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replaceAll("=", "");
}


/*
 * Signs with an ECDSA P-256 private key.
 *
 * Asymmetric on purpose. HMAC would have been simpler, but the
 * extension has to verify the token, so it would need the same
 * secret — and anything shipped inside an extension can be read
 * by whoever unpacks it. With ECDSA the extension only ever
 * holds the matching public key, so a user who edits the
 * extension still cannot mint a token.
 */

async function signLicenseToken(
  claims,
  env
) {
  const privateKey =
    await crypto.subtle.importKey(
      "jwk",
      getSigningKeyJwk(env),
      {
        name: "ECDSA",
        namedCurve: "P-256",
      },
      false,
      ["sign"]
    );

  const payload =
    bytesToBase64Url(
      new TextEncoder().encode(
        JSON.stringify(
          claims
        )
      )
    );

  const signature =
    await crypto.subtle.sign(
      {
        name: "ECDSA",
        hash: "SHA-256",
      },
      privateKey,
      new TextEncoder().encode(
        payload
      )
    );

  return (
    payload +
    "." +
    bytesToBase64Url(
      new Uint8Array(
        signature
      )
    )
  );
}


/*
 * Builds the token for an ACTIVE license bound to one
 * installation. The installation_id is inside the signed payload
 * so a token cannot be replayed on a different browser.
 */

async function issueLicenseToken(
  licenseId,
  installationId,
  env
) {
  const now =
    Date.now();

  return await signLicenseToken(
    {
      v: 1,

      license_id:
        licenseId,

      installation_id:
        installationId,

      iat: now,

      exp:
        now +
        LICENSE_TOKEN_TTL_MS,
    },

    env
  );
}


/*
 * ============================================================
 * MAIN WORKER
 * ============================================================
 */

export default {
  async fetch(
    request,
    env
  ) {
    const url =
      new URL(
        request.url
      );

    const db =
      env
        .kgp_placement_form_tracker_db;


    /*
     * ========================================================
     * FAIL FAST ON MISSING SIGNING KEY
     * ========================================================
     *
     * Every entitlement decision depends on this key. Missing it
     * must be a deployment error, not a silent downgrade to
     * "everyone is free" or, worse, an unsigned token.
     */

    if (
      !env.LICENSE_SIGNING_KEY
    ) {

      console.error(
        "LICENSE_SIGNING_KEY is not configured"
      );


      return jsonResponse(
        {
          success: false,

          error:
            "Server is not configured",
        },
        500,
        request
      );
    }


    /*
     * ========================================================
     * CORS PREFLIGHT
     * ========================================================
     */

    if (
      request.method ===
      "OPTIONS"
    ) {

      return new Response(
        null,
        {
          status:
            204,

          headers:
            getCorsHeaders(
              request
            ),
        }
      );
    }


    /*
     * ========================================================
     * HEALTH CHECK
     * ========================================================
     */

    if (
      request.method ===
      "GET" &&
      url.pathname ===
      "/"
    ) {
      return jsonResponse({
        status:
          "ok",

        service:
          "KGP Placement Form Tracker Backend",

        mode:
          CASHFREE_MODE,

        pro_price:
          PRO_PRICE_INR,

        license_cache_hours:
          LICENSE_CACHE_HOURS,
      });
    }


    /*
     * ========================================================
     * REGISTER INSTALLATION
     * ========================================================
     *
     * POST /register-installation
     *
     * Body:
     * {
     *   installation_id: "kgp_install_<uuid>"
     * }
     *
     * Returns:
     * {
     *   install_secret: "<64 hex chars>"   // shown exactly once
     * }
     *
     * The secret is returned only when it is first minted. If the
     * client loses it, the installation is abandoned and a new
     * one is registered — this keeps the endpoint from becoming a
     * way to reset an installation someone else already owns.
     * ========================================================
     */

    if (
      request.method ===
      "POST" &&
      url.pathname ===
      "/register-installation"
    ) {

      const allowed =
        await consumeRateLimit(
          db,
          `register:${getClientIp(request)}`,
          20,
          60 * 60 * 1000
        );


      if (!allowed) {

        return jsonResponse(
          {
            success: false,

            error:
              "Too many registrations. Please try again later.",
          },
          429,
          request
        );
      }


      let body;

      try {

        body =
          await request.json();

      } catch {

        return jsonResponse(
          {
            success: false,

            error:
              "Invalid JSON body",
          },
          400,
          request
        );
      }


      const installationId =
        body?.installation_id;


      if (
        !isValidInstallationId(
          installationId
        )
      ) {

        return jsonResponse(
          {
            success: false,

            error:
              "Invalid installation_id",
          },
          400,
          request
        );
      }


      const existing =
        await db
          .prepare(
            `SELECT installation_id
             FROM installation_secrets
             WHERE installation_id = ?
             LIMIT 1`
          )
          .bind(
            installationId
          )
          .first();


      if (existing) {

        /*
         * Already registered. Do NOT re-issue: that would let
         * anyone who learns an installation_id rotate its
         * credential.
         */

        return jsonResponse(
          {
            success: false,

            error:
              "This installation is already registered.",

            code:
              "ALREADY_REGISTERED",
          },
          409,
          request
        );
      }


      const secret =
        randomHex(32);


      const secretHash =
        await hashInstallSecret(
          secret
        );


      const now =
        Date.now();


      await db
        .prepare(
          `INSERT INTO installations
           (
             installation_id,
             license_id,
             created_at,
             last_seen_at
           )
           VALUES (?, NULL, ?, ?)
           ON CONFLICT(installation_id)
           DO NOTHING`
        )
        .bind(
          installationId,
          now,
          now
        )
        .run();


      await db
        .prepare(
          `INSERT INTO installation_secrets
           (
             installation_id,
             secret_hash,
             created_at
           )
           VALUES (?, ?, ?)
           ON CONFLICT(installation_id)
           DO NOTHING`
        )
        .bind(
          installationId,
          secretHash,
          now
        )
        .run();


      return jsonResponse(
        {
          success: true,

          installation_id:
            installationId,

          install_secret:
            secret,
        },
        200,
        request
      );
    }


    /*
     * ========================================================
     * CREATE ORDER
     * ========================================================
     *
     * POST /create-order
     *
     * Body:
     * {
     *   installation_id: "...",
     *   install_secret: "...",
     *   email: "user@example.com"
     * }
     *
     * IMPORTANT:
     *
     * We do NOT link an ACTIVE license using only an
     * email entered into checkout.
     *
     * Email ownership is proven by Supabase OTP during
     * the Restore PRO flow.
     * ========================================================
     */

    if (
      request.method ===
      "POST" &&
      url.pathname ===
      "/create-order"
    ) {
      let body;

      try {
        body =
          await request.json();

      } catch {
        return jsonResponse(
          {
            success:
              false,

            error:
              "Invalid JSON body",
          },
          400
        );
      }


      const installationId =
        body?.installation_id;

      const installSecret =
        body?.install_secret;

      const email =
        body?.email
          ?.trim()
          ?.toLowerCase();


      /*
       * Validate installation ID.
       */

      if (
        !isValidInstallationId(
          installationId
        )
      ) {
        return jsonResponse(
          {
            success:
              false,

            error:
              "Invalid installation_id",
          },
          400,
          request
        );
      }


      /*
       * Validate email.
       */

      if (
        !isValidEmail(
          email
        )
      ) {
        return jsonResponse(
          {
            success:
              false,

            error:
              "Please provide a valid email address",
          },
          400,
          request
        );
      }


      /*
       * ------------------------------------------------------
       * AUTHENTICATE THE INSTALLATION
       * ------------------------------------------------------
       *
       * Creating an order mints a license and a real Cashfree
       * order, so it requires proof that the caller owns this
       * installation.
       * ------------------------------------------------------
       */

      const secretCheck =
        await verifyInstallSecret(
          db,
          installationId,
          installSecret
        );


      /*
       * "legacy" is allowed through: those installations have no
       * secret on record yet. "deny" means an id is being used
       * without its secret.
       */

      if (
        secretCheck ===
        "deny"
      ) {

        return jsonResponse(
          {
            success:
              false,

            error:
              "Invalid installation credentials",
          },
          401,
          request
        );
      }


      /*
       * ------------------------------------------------------
       * RATE LIMIT
       * ------------------------------------------------------
       */

      const rateOk =
        await consumeRateLimit(
          db,
          `create-order:${installationId}`,
          10,
          60 * 60 * 1000
        );


      if (!rateOk) {

        return jsonResponse(
          {
            success:
              false,

            error:
              "Too many checkout attempts. Please wait before trying again.",
          },
          429,
          request
        );
      }


      /*
       * ------------------------------------------------------
       * FIND EXISTING INSTALLATION
       * ------------------------------------------------------
       */

      const existingInstallation =
        await db
          .prepare(
            `SELECT
               i.installation_id,
               i.license_id,
               l.status,
               l.customer_email,
               l.supabase_user_id
             FROM installations i
             LEFT JOIN licenses l
               ON i.license_id = l.license_id
             WHERE i.installation_id = ?
             LIMIT 1`
          )
          .bind(
            installationId
          )
          .first();


      /*
       * ------------------------------------------------------
       * ALREADY ACTIVE FOR THIS INSTALLATION
       * ------------------------------------------------------
       */

      if (
        existingInstallation &&
        existingInstallation.status ===
        "ACTIVE"
      ) {
        return jsonResponse({
          success:
            true,

          already_active:
            true,

          pro:
            true,

          status:
            "ACTIVE",

          license_id:
            existingInstallation.license_id,
        });
      }


      /*
       * ------------------------------------------------------
       * GET OR CREATE PENDING LICENSE
       * ------------------------------------------------------
       *
       * Existing installation with a pending license:
       * reuse that license.
       *
       * New installation:
       * create a new pending license.
       * ------------------------------------------------------
       */

      let licenseId =
        existingInstallation?.license_id ||
        null;


      if (
        licenseId
      ) {
        const license =
          await db
            .prepare(
              `SELECT
                 license_id,
                 status
               FROM licenses
               WHERE license_id = ?
               LIMIT 1`
            )
            .bind(
              licenseId
            )
            .first();


        /*
         * If installation points to
         * a deleted/nonexistent license,
         * create a new one.
         */

        if (!license) {
          licenseId =
            null;

        } else if (
          license.status !==
          "ACTIVE"
        ) {

          /*
           * Update email while still pending.
           */
          await db
            .prepare(
              `UPDATE licenses
               SET customer_email = ?
               WHERE license_id = ?
                 AND status != 'ACTIVE'`
            )
            .bind(
              email,
              licenseId
            )
            .run();
        }
      }


      /*
       * ------------------------------------------------------
       * CREATE NEW PENDING LICENSE
       * ------------------------------------------------------
       */

      if (
        !licenseId
      ) {
        licenseId =
          `lic_${crypto
            .randomUUID()
            .replaceAll(
              "-",
              ""
            )}`;


        await db
          .prepare(
            `INSERT INTO licenses
             (
               license_id,
               supabase_user_id,
               customer_email,
               status,
               max_installations,
               created_at,
               activated_at,
               last_verified_at
             )
             VALUES (
               ?,
               NULL,
               ?,
               'PENDING',
               5,
               ?,
               NULL,
               NULL
             )`
          )
          .bind(
            licenseId,
            email,
            Date.now()
          )
          .run();


        /*
         * Attach the current installation.
         */

        if (
          existingInstallation
        ) {
          await db
            .prepare(
              `UPDATE installations
               SET
                 license_id = ?,
                 last_seen_at = ?
               WHERE installation_id = ?`
            )
            .bind(
              licenseId,
              Date.now(),
              installationId
            )
            .run();

        } else {
          await db
            .prepare(
              `INSERT INTO installations
               (
                 installation_id,
                 license_id,
                 created_at,
                 last_seen_at
               )
               VALUES (?, ?, ?, ?)`
            )
            .bind(
              installationId,
              licenseId,
              Date.now(),
              Date.now()
            )
            .run();
        }
      }


      /*
       * ------------------------------------------------------
       * PREVENT DUPLICATE PENDING ORDERS
       * ------------------------------------------------------
       *
       * A second click during the same payment attempt must not
       * create another Cashfree order. This is a hard block for as
       * long as an order is PENDING — a 10-minute window used to
       * let a slow checkout produce a second chargeable order.
       *
       * The lock is bounded by a staleness cutoff so an abandoned
       * checkout cannot wedge the license forever. It sits above
       * Cashfree's hosted-checkout expiry, so a live session is
       * always still blocked.
       * ------------------------------------------------------
       */

      const PENDING_ORDER_STALE_MS =
        30 * 60 * 1000;


      const recentPendingOrder =
        await db
          .prepare(
            `SELECT
               order_id
             FROM orders
             WHERE license_id = ?
               AND status = 'PENDING'
               AND created_at >= ?
             ORDER BY created_at DESC
             LIMIT 1`
          )
          .bind(
            licenseId,
            Date.now() -
            PENDING_ORDER_STALE_MS
          )
          .first();


      if (
        recentPendingOrder
      ) {
        return jsonResponse(
          {
            success:
              false,

            error:
              "A PRO payment is already in progress for this purchase. Please finish that checkout before starting another one.",

            code:
              "PAYMENT_ALREADY_PENDING",

            order_id:
              recentPendingOrder.order_id,
          },
          409,
          request
        );
      }


      /*
       * ------------------------------------------------------
       * SERVER-GENERATED ORDER ID
       * ------------------------------------------------------
       */

      const orderId =
        `kgp_pro_${Date.now()}_${crypto
          .randomUUID()
          .replaceAll(
            "-",
            ""
          )}`;


      const amountPaise =
        Math.round(
          PRO_PRICE_INR *
          100
        );

      const now =
        Date.now();


      /*
       * ------------------------------------------------------
       * INSERT LOCAL ORDER
       * ------------------------------------------------------
       */

      await db
        .prepare(
          `INSERT INTO orders
           (
             order_id,
             license_id,
             cashfree_payment_id,
             amount_paise,
             currency,
             status,
             created_at,
             paid_at
           )
           VALUES (
             ?,
             ?,
             NULL,
             ?,
             'INR',
             'PENDING',
             ?,
             NULL
           )`
        )
        .bind(
          orderId,
          licenseId,
          amountPaise,
          now
        )
        .run();


      /*
       * ------------------------------------------------------
       * CREATE CASHFREE ORDER
       * ------------------------------------------------------
       */

      const cashfreeResponse =
        await fetch(
          `${CASHFREE_BASE_URL}/orders`,
          {
            method:
              "POST",

            headers:
              cashfreeHeaders(
                env
              ),

            body:
              JSON.stringify({
                order_id:
                  orderId,

                order_amount:
                  PRO_PRICE_INR,

                order_currency:
                  "INR",

                customer_details: {
                  customer_id:
                    installationId,

                  customer_email:
                    email,

                  /*
                   * Sandbox placeholder.
                   * Revisit before production.
                   */
                  customer_phone:
                    "9999999999",
                },

                order_meta: {
                  return_url:
                    "https://kgp-placement-form-tracker-backend.noticeboard.workers.dev/payment-return?order_id={order_id}",

                  notify_url:
                    "https://kgp-placement-form-tracker-backend.noticeboard.workers.dev/payment-webhook",
                },

                order_note:
                  "KGP Placement Form Tracker PRO - Sandbox",
              }),
          }
        );


      /*
       * ------------------------------------------------------
       * CASHFREE FAILURE
       * ------------------------------------------------------
       */

      if (
        !cashfreeResponse.ok
      ) {
        const errorText =
          await cashfreeResponse.text();

        console.error(
          "Cashfree create-order error:",
          errorText
        );


        await db
          .prepare(
            `UPDATE orders
             SET status = 'FAILED'
             WHERE order_id = ?`
          )
          .bind(
            orderId
          )
          .run();


        return jsonResponse(
          {
            success:
              false,

            error:
              "Cashfree order creation failed",
          },
          502
        );
      }


      const cashfreeData =
        await cashfreeResponse.json();


      return jsonResponse({
        success:
          true,

        order_id:
          orderId,

        license_id:
          licenseId,

        payment_session_id:
          cashfreeData.payment_session_id,
      });
    }


    /*
     * ========================================================
     * HOSTED CHECKOUT PAGE
     * ========================================================
     */

    if (
      request.method ===
      "GET" &&
      url.pathname ===
      "/checkout"
    ) {
      const installationId =
        url.searchParams.get(
          "installation_id"
        );


      if (
        !isValidInstallationId(
          installationId
        )
      ) {
        return htmlResponse(
          `
<!doctype html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport"
      content="width=device-width, initial-scale=1.0">
<title>KGP Placement Form Tracker</title>
<style>
body{
  margin:0;
  min-height:100vh;
  display:flex;
  align-items:center;
  justify-content:center;
  font-family:Arial,sans-serif;
  background:#f5f7fb;
}
.card{
  width:min(92%,520px);
  padding:40px;
  background:#fff;
  border-radius:18px;
  box-shadow:0 12px 35px rgba(0,0,0,.08);
  text-align:center;
}
.error{
  color:#dc2626;
  font-weight:700;
}
</style>
</head>
<body>
<div class="card">
<h1>KGP Placement Form Tracker</h1>
<p class="error">Unable to start checkout</p>
<p>Invalid installation ID.</p>
</div>
</body>
</html>
`,
          400
        );
      }


      const safeInstallationId =
        JSON.stringify(
          installationId
        )
          .replace(
            /</g,
            "\\u003c"
          )
          .replace(
            />/g,
            "\\u003e"
          )
          .replace(
            /&/g,
            "\\u0026"
          );


      const priceDisplay =
        `₹${PRO_PRICE_INR.toFixed(2)}`;


      return htmlResponse(
        `
<!doctype html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta
  name="viewport"
  content="width=device-width, initial-scale=1.0"
>
<title>KGP Placement Form Tracker - PRO</title>

<script
  src="https://sdk.cashfree.com/js/v3/cashfree.js"
></script>

<style>

*{
  box-sizing:border-box;
}

body{
  margin:0;
  min-height:100vh;
  display:flex;
  justify-content:center;
  align-items:center;
  font-family:
    Arial,
    Helvetica,
    sans-serif;
  background:
    linear-gradient(
      135deg,
      #eef4ff,
      #f8f3ff,
      #fff8ed
    );
  color:#111827;
}

.card{
  width:min(92%,520px);
  padding:40px;
  background:white;
  border-radius:18px;
  box-shadow:
    0 12px 35px
    rgba(0,0,0,.10);
  text-align:center;
}

.brand{
  font-size:14px;
  font-weight:700;
  color:#6b7280;
  margin-bottom:10px;
}

h1{
  margin:0 0 8px;
}

.subtitle{
  color:#6b7280;
  line-height:1.5;
  margin-bottom:22px;
}

.price{
  font-size:36px;
  font-weight:800;
  margin:18px 0;
}

label{
  display:block;
  text-align:left;
  margin-bottom:6px;
  font-size:13px;
  font-weight:700;
  color:#374151;
}

input{
  width:100%;
  padding:12px 13px;
  border:1px solid #cbd5e1;
  border-radius:9px;
  font-size:14px;
  outline:none;
}

input:focus{
  border-color:#6366f1;
  box-shadow:
    0 0 0 3px
    rgba(99,102,241,.12);
}

button{
  width:100%;
  margin-top:14px;
  padding:13px 18px;
  border:none;
  border-radius:9px;
  background:
    linear-gradient(
      135deg,
      #2563eb,
      #7c3aed
    );
  color:white;
  font-size:15px;
  font-weight:700;
  cursor:pointer;
}

button:disabled{
  opacity:.55;
  cursor:not-allowed;
}

.message{
  margin-top:15px;
  font-size:13px;
  color:#dc2626;
}

.order{
  margin-top:18px;
  padding:10px;
  background:#f3f4f6;
  border-radius:8px;
  font-size:11px;
  word-break:break-all;
  color:#6b7280;
  display:none;
}

.privacy{
  margin-top:18px;
  font-size:11px;
  color:#6b7280;
  line-height:1.45;
}

</style>
</head>

<body>

<div class="card">

<div class="brand">
KGP Placement Form Tracker
</div>

<h1>
Unlock PRO
</h1>

<p class="subtitle">
Unlock live time remaining,
application links and
opportunity tracking.
</p>

<div class="price">
${priceDisplay}
</div>

<label for="email">
Email for PRO ownership
</label>

<input
  id="email"
  type="email"
  placeholder="you@example.com"
  autocomplete="email"
>

<button id="payButton">
Continue to Payment
</button>

<div
  id="loading"
  class="message"
></div>

<div
  id="message"
  class="message"
></div>

<div
  id="order"
  class="order"
></div>

<div class="privacy">
Your email is used for
PRO purchase and future
license recovery.
ERP credentials and ERP
notice data are not sent
to the payment system.
</div>

</div>

<script>

const API_BASE =
  window.location.origin;

const installationId =
  ${safeInstallationId};

/*
 * The installation secret arrives in the URL fragment, which
 * browsers never send to the server and never put in Referer.
 */
const installSecret =
  (function(){

    const match =
      /(?:^|[#&])s=([0-9a-f]{64})/
        .exec(
          window.location.hash ||
          ""
        );

    return match
      ? match[1]
      : "";
  })();

const button =
  document.getElementById(
    "payButton"
  );

const emailInput =
  document.getElementById(
    "email"
  );

const loading =
  document.getElementById(
    "loading"
  );

const message =
  document.getElementById(
    "message"
  );

const orderBox =
  document.getElementById(
    "order"
  );

let paymentSessionId =
  null;


function validEmail(
  email
){
  return /^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$/
    .test(email);
}


function escapeHtml(
  value
){
  return String(
    value
  )
    .replace(
      /&/g,
      "&amp;"
    )
    .replace(
      /</g,
      "&lt;"
    )
    .replace(
      />/g,
      "&gt;"
    )
    .replace(
      /"/g,
      "&quot;"
    );
}


async function createOrder(){

  const email =
    emailInput.value
      .trim()
      .toLowerCase();


  if (
    !validEmail(
      email
    )
  ){
    message.textContent =
      "Please enter a valid email address.";

    return;
  }


  button.disabled =
    true;

  loading.textContent =
    "Creating secure payment...";

  message.textContent =
    "";


  try{

    const response =
      await fetch(
        API_BASE +
          "/create-order",
        {
          method:
            "POST",

          headers:{
            "Content-Type":
              "application/json"
          },

          body:
            JSON.stringify({
              installation_id:
                installationId,

              install_secret:
                installSecret,

              email:
                email
            })
        }
      );


    const data =
      await response.json();


    if (
      !response.ok
    ){
      throw new Error(
        data?.error ||
        "Unable to create order"
      );
    }


    if (
      data.already_active ===
      true
    ){

      loading.textContent =
        "";

      button.disabled =
        true;

      button.textContent =
        "PRO Already Active";

      message.textContent =
        "This installation already has PRO.";

      return;
    }


    paymentSessionId =
      data.payment_session_id;


    if (
      !paymentSessionId
    ){
      throw new Error(
        "Missing payment session ID"
      );
    }


    orderBox.style.display =
      "block";


    orderBox.innerHTML =
      "<strong>Order ID</strong>" +
      "<br><br>" +
      escapeHtml(
        data.order_id
      );


    loading.textContent =
      "";

    button.textContent =
      "Proceed to Payment";


    button.onclick =
      startCheckout;


    button.disabled =
      false;

  }catch(error){

    console.error(
      "Create order failed:",
      error
    );

    loading.textContent =
      "";

    message.textContent =
      error.message ||
      "Unable to create payment.";

    button.disabled =
      false;

    button.textContent =
      "Try Again";
  }
}


async function startCheckout(){

  if (
    !paymentSessionId
  ){
    return;
  }


  button.disabled =
    true;

  button.textContent =
    "Opening Checkout...";


  try{

    const cashfree =
      Cashfree({
        mode:
          "${CASHFREE_MODE}"
      });


    const result =
      await cashfree.checkout({
        paymentSessionId:
          paymentSessionId,

        redirectTarget:
          "_self"
      });


    if (
      result?.error
    ){

      console.error(
        "Cashfree checkout error:",
        result.error
      );

      message.textContent =
        "Unable to open payment checkout.";

      button.disabled =
        false;

      button.textContent =
        "Proceed to Payment";
    }

  }catch(error){

    console.error(
      "Checkout error:",
      error
    );

    message.textContent =
      "Unable to open payment checkout.";

    button.disabled =
      false;

    button.textContent =
      "Proceed to Payment";
  }
}


button.addEventListener(
  "click",
  createOrder
);

</script>

</body>
</html>
`
      );
    }


    /*
     * ========================================================
     * PAYMENT RETURN
     * ========================================================
     */

    if (
      request.method ===
      "GET" &&
      url.pathname ===
      "/payment-return"
    ) {

      const orderId =
        url.searchParams.get(
          "order_id"
        );


      /*
       * Only server-generated order IDs are ever accepted. This
       * keeps arbitrary input out of the page below.
       */

      const ORDER_ID_PATTERN =
        /^kgp_pro_[0-9]{1,20}_[0-9a-f]{1,64}$/;


      if (
        !orderId ||
        !ORDER_ID_PATTERN.test(
          orderId
        )
      ) {
        return htmlResponse(
          `
<!doctype html>
<html>
<body
style="
font-family:Arial;
padding:40px;
text-align:center
"
>
<h1>KGP Placement Form Tracker</h1>
<h2>Payment Error</h2>
<p>Missing or invalid order ID.</p>
</body>
</html>
`,
          400
        );
      }


      const paymentResponse =
        await fetch(
          `${CASHFREE_BASE_URL}/orders/${encodeURIComponent(
            orderId
          )}/payments`,
          {
            method:
              "GET",

            headers:
              cashfreeHeaders(
                env
              ),
          }
        );


      if (
        !paymentResponse.ok
      ) {

        console.error(
          "Cashfree payment status error:",
          await paymentResponse.text()
        );


        return htmlResponse(
          `
<!doctype html>
<html>
<body
style="
font-family:Arial;
padding:40px;
text-align:center
"
>
<h1>KGP Placement Form Tracker</h1>
<h2>Unable to verify payment</h2>
<p>Please try again later.</p>
</body>
</html>
`,
          502
        );
      }


      const payments =
        await paymentResponse.json();


      const successfulPayment =
        Array.isArray(
          payments
        )
          ? payments.find(
            payment =>
              payment.payment_status ===
              "SUCCESS"
          )
          : null;


      const pendingPayment =
        Array.isArray(
          payments
        )
          ? payments.find(
            payment =>
              payment.payment_status ===
              "PENDING"
          )
          : null;


      let status =
        "FAILED";


      if (
        successfulPayment
      ) {

        status =
          "SUCCESS";


        /*
         * ----------------------------------------------------
         * DELIBERATELY READ-ONLY
         * ----------------------------------------------------
         *
         * This is a GET that a browser can trigger by refreshing
         * or prefetching a link, so it must not activate anything.
         * Activation happens only in /payment-webhook, which
         * carries a signature we can verify.
         *
         * The license row may still be PENDING here; the webhook
         * flips both the order and the license. We only report
         * what Cashfree says.
         * ----------------------------------------------------
         */

      } else if (
        pendingPayment
      ) {

        status =
          "PENDING";
      }


      let heading =
        "Payment Failed";


      let message =
        "The payment was not completed successfully.";


      if (
        status ===
        "SUCCESS"
      ) {

        heading =
          "Payment Successful";


        message =
          "You can close this page and return to the extension.<br>Your license is being activated.";

      } else if (
        status ===
        "PENDING"
      ) {

        heading =
          "Payment Pending";


        message =
          "Your payment is still being processed. PRO will activate after confirmation.";
      }


      const statusClass =
        status ===
          "SUCCESS"
          ? "success"
          : status ===
            "PENDING"
            ? "pending"
            : "failed";


      return htmlResponse(
        `
<!doctype html>
<html lang="en">

<head>

<meta charset="UTF-8">

<meta
name="viewport"
content="width=device-width, initial-scale=1.0"
>

<title>
KGP Placement Form Tracker - PRO
</title>

<style>

body{
  margin:0;
  padding:40px 20px;
  font-family:
    Arial,
    Helvetica,
    sans-serif;
  background:#f5f7fb;
  color:#111827;
  text-align:center;
}

.card{
  max-width:540px;
  margin:60px auto;
  padding:40px;
  background:white;
  border-radius:16px;
  box-shadow:
    0 10px 30px
    rgba(0,0,0,.08);
}

.status{
  margin:20px 0;
  font-size:22px;
  font-weight:800;
}

.success{
  color:#16a34a;
}

.pending{
  color:#ca8a04;
}

.failed{
  color:#dc2626;
}

.order{
  margin-top:25px;
  padding:12px;
  background:#f3f4f6;
  border-radius:8px;
  word-break:break-all;
  font-size:13px;
}

</style>

</head>

<body>

<div class="card">

<h1>
KGP Placement Form Tracker
</h1>

<h2>
PRO Payment
</h2>

<div
class="status ${statusClass}"
>
${heading}
</div>

<p>
${message}
</p>

<div class="order">

<strong>
Order ID
</strong>

<br><br>

${escapeHtml(orderId)}

</div>

</div>

</body>

</html>
`
      );
    }


    /*
     * ========================================================
     * CASHFREE PAYMENT WEBHOOK
     * ========================================================
     */

    if (
      request.method ===
      "POST" &&
      url.pathname ===
      "/payment-webhook"
    ) {

      /*
       * Raw body MUST be read before JSON parsing
       * for Cashfree signature verification.
       */

      const rawBody =
        await request.text();


      const signature =
        request.headers.get(
          "x-webhook-signature"
        );


      const timestamp =
        request.headers.get(
          "x-webhook-timestamp"
        );

      const webhookTimestampMs = Number(timestamp);

const nowMs = Date.now();

const MAX_WEBHOOK_AGE_MS =
  5 * 60 * 1000;

if (
  !Number.isFinite(webhookTimestampMs) ||
  Math.abs(
    nowMs - webhookTimestampMs
  ) > MAX_WEBHOOK_AGE_MS
) {
  console.error(
    "Rejected stale webhook:",
    {
      webhookTimestampMs,
      nowMs,
    }
  );

  return jsonResponse(
    {
      success: false,
      error:
        "Webhook timestamp is too old or invalid",
    },
    401
  );
}
      if (
        !signature ||
        !timestamp
      ) {

        return jsonResponse(
          {
            success:
              false,

            error:
              "Missing webhook signature headers",
          },
          401
        );
      }


      const expectedSignature =
        await generateCashfreeSignature(
          timestamp,
          rawBody,
          env.CASHFREE_SECRET_KEY
        );


      if (
        !safeCompare(
          signature,
          expectedSignature
        )
      ) {

        console.error(
          "Invalid Cashfree webhook signature"
        );


        return jsonResponse(
          {
            success:
              false,

            error:
              "Invalid webhook signature",
          },
          401
        );
      }


      let payload;

      try {

        payload =
          JSON.parse(
            rawBody
          );

      } catch {

        return jsonResponse(
          {
            success:
              false,

            error:
              "Invalid webhook JSON payload",
          },
          400
        );
      }


      const orderId =
        payload?.data
          ?.order
          ?.order_id;


      const webhookPaymentId =
        payload?.data
          ?.payment
          ?.cf_payment_id;


      const webhookPaymentStatus =
        payload?.data
          ?.payment
          ?.payment_status;


      const eventType =
        payload?.type;


      console.log(
        "Cashfree webhook received:",
        {
          eventType,
          orderId,
          webhookPaymentId,
          webhookPaymentStatus,
        }
      );


      if (
        !orderId
      ) {

        return jsonResponse(
          {
            success:
              false,

            error:
              "Missing order_id",
          },
          400
        );
      }


      /*
       * Ignore events other than payment success.
       */

      if (
        eventType !==
        "PAYMENT_SUCCESS_WEBHOOK" ||
        webhookPaymentStatus !==
        "SUCCESS"
      ) {

        return jsonResponse({
          success:
            true,

          message:
            "Webhook received but no activation required",

          order_id:
            orderId,

          status:
            webhookPaymentStatus ||
            "UNKNOWN",
        });
      }


      /*
       * Verify directly with Cashfree.
       */

      const paymentResponse =
        await fetch(
          `${CASHFREE_BASE_URL}/orders/${encodeURIComponent(
            orderId
          )}/payments`,
          {
            method:
              "GET",

            headers:
              cashfreeHeaders(
                env
              ),
          }
        );


      if (
        !paymentResponse.ok
      ) {

        console.error(
          "Cashfree payment verification failed:",
          await paymentResponse.text()
        );


        return jsonResponse(
          {
            success:
              false,

            error:
              "Could not verify payment with Cashfree",
          },
          502
        );
      }


      const payments =
        await paymentResponse.json();


      const successfulPayment =
        Array.isArray(
          payments
        )
          ? payments.find(
            payment =>
              payment.payment_status ===
              "SUCCESS"
          )
          : null;


      if (
        !successfulPayment
      ) {

        return jsonResponse(
          {
            success:
              false,

            error:
              "Cashfree payment is not confirmed as successful",
          },
          400,
          request
        );
      }


      /*
       * The confirmed payment must belong to this order. Without
       * this the array lookup could match an unrelated payment.
       */

      if (
        successfulPayment.order_id &&
        successfulPayment.order_id !==
          orderId
      ) {

        console.error(
          "Payment/order mismatch:",
          {
            orderId,

            paymentOrderId:
              successfulPayment
                .order_id,
          }
        );


        return jsonResponse(
          {
            success:
              false,

            error:
              "Payment does not belong to this order",
          },
          400,
          request
        );
      }


      const paymentId =
        successfulPayment
          .cf_payment_id ||

        webhookPaymentId ||

        null;


      /*
       * Find our local order.
       */

      const order =
        await db
          .prepare(
            `SELECT
               o.order_id,
               o.license_id,
               o.status AS order_status,
               o.amount_paise,
               l.status AS license_status
             FROM orders o
             JOIN licenses l
               ON o.license_id =
                  l.license_id
             WHERE o.order_id = ?
             LIMIT 1`
          )
          .bind(
            orderId
          )
          .first();


      if (
        !order
      ) {

        console.error(
          "No order found for webhook:",
          orderId
        );


        return jsonResponse(
          {
            success:
              false,

            error:
              "No matching order found",
          },
          404
        );
      }


      /*
       * Idempotency.
       */

      if (
        order.license_status ===
        "ACTIVE"
      ) {

        return jsonResponse({
          success:
            true,

          message:
            "License was already active",

          order_id:
            orderId,

          payment_id:
            paymentId,

          status:
            "ACTIVE",
        });
      }


      /*
       * Server-side amount validation.
       */

      const expectedAmountPaise =
        Math.round(
          PRO_PRICE_INR *
          100
        );


      if (
        Number(
          order.amount_paise
        ) !==
        expectedAmountPaise
      ) {

        console.error(
          "Order amount mismatch:",
          {
            orderId,

            databaseAmount:
              order.amount_paise,

            expectedAmount:
              expectedAmountPaise,
          }
        );


        return jsonResponse(
          {
            success:
              false,

            error:
              "Order amount mismatch",
          },
          400
        );
      }


      /*
       * The confirmed payment must actually cover the order.
       * Cashfree returns order_amount in rupees.
       */

      const expectedRupees =
        Math.round(
          PRO_PRICE_INR *
          100
        ) / 100;


      const paidAmount =
        successfulPayment
          .payment_amount ??
        successfulPayment
          .order_amount;


      if (
        paidAmount !==
          undefined &&
        paidAmount !==
          null &&
        Number(paidAmount) <
          expectedRupees
      ) {

        console.error(
          "Webhook payment amount mismatch:",
          {
            orderId,

            paidAmount,

            expectedRupees,
          }
        );


        return jsonResponse(
          {
            success:
              false,

            error:
              "Payment amount does not match the order",
          },
          400,
          request
        );
      }


      const paidAt =
        Date.now();


      /*
       * Mark order PAID.
       */

      await db
        .prepare(
          `UPDATE orders
           SET
             cashfree_payment_id = ?,
             status = 'PAID',
             paid_at = ?
           WHERE order_id = ?
             AND status != 'PAID'`
        )
        .bind(
          paymentId,
          paidAt,
          orderId
        )
        .run();


      /*
       * Activate license.
       */

      const updateResult =
        await db
          .prepare(
            `UPDATE licenses
             SET
               status = 'ACTIVE',
               activated_at = ?
             WHERE license_id = ?
               AND status != 'ACTIVE'`
          )
          .bind(
            paidAt,
            order.license_id
          )
          .run();


      console.log(
        "License activation completed:",
        {
          orderId,

          licenseId:
            order.license_id,

          paymentId,

          changes:
            updateResult.meta
              ?.changes,
        }
      );


      return jsonResponse({
        success:
          true,

        message:
          "Payment verified and license activated",

        order_id:
          orderId,

        license_id:
          order.license_id,

        payment_id:
          paymentId,

        status:
          "ACTIVE",
      });
    }


    /*
     * ========================================================
     * VERIFY LICENSE
     * ========================================================
     *
     * POST /verify-license
     *
     * Body:
     * {
     *   installation_id: "...",
     *   install_secret: "..."
     * }
     *
     * On an ACTIVE license the response also carries a signed
     * entitlement token. The extension verifies that signature
     * before unlocking PRO, so editing chrome.storage.local is no
     * longer enough to spoof an unlock.
     * ========================================================
     */

    if (
      request.method ===
      "POST" &&
      url.pathname ===
      "/verify-license"
    ) {

      let body;

      try {

        body =
          await request.json();

      } catch {

        return jsonResponse(
          {
            success:
              false,

            error:
              "Invalid JSON body",
          },
          400,
          request
        );
      }


      const installationId =
        body?.installation_id;

      const installSecret =
        body?.install_secret;


      if (
        !isValidInstallationId(
          installationId
        )
      ) {

        return jsonResponse(
          {
            success:
              false,

            error:
              "Invalid installation_id",
          },
          400,
          request
        );
      }


      /*
       * Throttle per installation. This endpoint is unauthenticated
       * for unregistered callers, so it needs a ceiling.
       */

      const rateOk =
        await consumeRateLimit(
          db,
          `verify:${installationId}`,
          60,
          60 * 60 * 1000
        );


      if (!rateOk) {

        return jsonResponse(
          {
            success:
              false,

            error:
              "Too many verification attempts. Please try again later.",
          },
          429,
          request
        );
      }


      const secretCheck =
        await verifyInstallSecret(
          db,
          installationId,
          installSecret
        );


      /*
       * "legacy" is allowed through: those installations have no
       * secret on record yet. "deny" means an id is being used
       * without its secret.
       */

      if (
        secretCheck ===
        "deny"
      ) {

        return jsonResponse(
          {
            success:
              false,

            error:
              "Invalid installation credentials",
          },
          401,
          request
        );
      }


      /*
       * Installation → License.
       */

      const result =
        await db
          .prepare(
            `SELECT
               i.installation_id,
               i.license_id,
               l.status,
               l.activated_at
             FROM installations i
             LEFT JOIN licenses l
               ON i.license_id =
                  l.license_id
             WHERE i.installation_id = ?
             LIMIT 1`
          )
          .bind(
            installationId
          )
          .first();


      if (
        !result ||
        !result.license_id
      ) {

        return jsonResponse(
          {
            success:
              true,

            pro:
              false,

            status:
              "NOT_FOUND",
          },
          200,
          request
        );
      }


      const isPro =
        result.status ===
        "ACTIVE";


      const now =
        Date.now();


      /*
       * Update usage timestamps.
       *
       * These are coalesced to at most once every 10 minutes so a
       * client cannot turn verification into unbounded D1 writes.
       */

      const TOUCH_INTERVAL_MS =
        10 * 60 * 1000;


      const stale =
        await db
          .prepare(
            `SELECT
               i.last_seen_at AS last_seen_at,
               l.last_verified_at AS last_verified_at
             FROM installations i
             LEFT JOIN licenses l
               ON i.license_id =
                  l.license_id
             WHERE i.installation_id = ?
             LIMIT 1`
          )
          .bind(
            installationId
          )
          .first();


      const seenAgo =
        now -
        Number(
          stale?.last_seen_at ||
          0
        );

      const verifiedAgo =
        now -
        Number(
          stale?.last_verified_at ||
          0
        );


      if (
        !stale ||
        seenAgo >=
          TOUCH_INTERVAL_MS
      ) {

        await db
          .prepare(
            `UPDATE installations
             SET
               last_seen_at = ?
             WHERE installation_id = ?`
          )
          .bind(
            now,
            installationId
          )
          .run();
      }


      if (
        verifiedAgo >=
        TOUCH_INTERVAL_MS
      ) {

        await db
          .prepare(
            `UPDATE licenses
             SET
               last_verified_at = ?
             WHERE license_id = ?`
          )
          .bind(
            now,
            result.license_id
          )
          .run();
      }


      /*
       * Only ACTIVE licenses get a token. Anything else (PENDING,
       * REVOKED) is reported as not pro with no token.
       */

      if (!isPro) {

        return jsonResponse(
          {
            success:
              true,

            pro:
              false,

            status:
              result.status,
          },
          200,
          request
        );
      }


      const licenseToken =
        await issueLicenseToken(
          result.license_id,
          installationId,
          env
        );


      return jsonResponse(
        {
          success:
            true,

          pro:
            true,

          status:
            result.status,

          license_token:
            licenseToken,

          expires_in:
            Math.floor(
              LICENSE_TOKEN_TTL_MS /
              1000
            ),
        },
        200,
        request
      );
    }


    /*
     * ========================================================
     * RESTORE / LINK PRO LICENSE
     * ========================================================
     *
     * POST /restore-license
     *
     * Header:
     * Authorization: Bearer <Supabase access token>
     *
     * Body:
     * {
     *   installation_id: "..."
     * }
     *
     * Flow:
     *
     * extension
     *    ↓
     * Supabase OTP verification
     *    ↓
     * access token
     *    ↓
     * Worker asks Supabase who owns token
     *    ↓
     * verified email / user ID
     *    ↓
     * D1 license
     *    ↓
     * installation linked
     * ========================================================
     */

    if (
      request.method ===
      "POST" &&
      url.pathname ===
      "/restore-license"
    ) {

      let body;

      try {

        body =
          await request.json();

      } catch {

        return jsonResponse(
          {
            success:
              false,

            error:
              "Invalid JSON body",
          },
          400,
          request
        );
      }


      const installationId =
        body?.installation_id;

      const installSecret =
        body?.install_secret;


      if (
        !isValidInstallationId(
          installationId
        )
      ) {

        return jsonResponse(
          {
            success:
              false,

            error:
              "Invalid installation_id",
          },
          400,
          request
        );
      }


      /*
       * Throttle restore attempts. This endpoint adopts licenses by
       * verified email, so it is the most attractive one to hammer.
       */

      const restoreRateOk =
        await consumeRateLimit(
          db,
          `restore:${getClientIp(request)}`,
          20,
          60 * 60 * 1000
        );


      if (!restoreRateOk) {

        return jsonResponse(
          {
            success:
              false,

            error:
              "Too many restore attempts. Please try again later.",
          },
          429,
          request
        );
      }


      /*
       * Require proof of installation ownership before this browser
       * can become the target of a license link.
       */

      const secretCheck =
        await verifyInstallSecret(
          db,
          installationId,
          installSecret
        );


      /*
       * "legacy" is allowed through: those installations have no
       * secret on record yet. "deny" means an id is being used
       * without its secret.
       */

      if (
        secretCheck ===
        "deny"
      ) {

        return jsonResponse(
          {
            success:
              false,

            error:
              "Invalid installation credentials",
          },
          401,
          request
        );
      }


      const accessToken =
        getBearerToken(
          request
        );


      if (
        !accessToken
      ) {

        return jsonResponse(
          {
            success:
              false,

            error:
              "Missing Supabase access token",
          },
          401,
          request
        );
      }


      /*
       * ------------------------------------------------------
       * VERIFY ACCESS TOKEN WITH SUPABASE
       * ------------------------------------------------------
       */

      let supabaseUser;

      try {

        supabaseUser =
          await getSupabaseUser(
            accessToken,
            env
          );

      } catch (
      error
      ) {

        console.error(
          "Supabase verification error:",
          error
        );


        return jsonResponse(
          {
            success:
              false,

            error:
              "Unable to verify Supabase identity",
          },
          502,
          request
        );
      }


      if (
        !supabaseUser?.id ||
        !isValidEmail(
          supabaseUser.email
        )
      ) {

        return jsonResponse(
          {
            success:
              false,

            error:
              "Invalid or expired Supabase session",
          },
          401,
          request
        );
      }


      const supabaseUserId =
        supabaseUser.id;


      const email =
        supabaseUser.email
          .trim()
          .toLowerCase();


      /*
       * ------------------------------------------------------
       * FIRST LOOK FOR A LICENSE ALREADY OWNED BY THIS
       * SUPABASE USER.
       * ------------------------------------------------------
       */

      let license =
        await db
          .prepare(
            `SELECT
               license_id,
               supabase_user_id,
               customer_email,
               status,
               max_installations
             FROM licenses
             WHERE supabase_user_id = ?
             LIMIT 1`
          )
          .bind(
            supabaseUserId
          )
          .first();


      /*
       * If the account has a linked non-active license,
       * do not silently claim another license.
       */

      if (
        license &&
        license.status !==
        "ACTIVE"
      ) {

        return jsonResponse(
          {
            success:
              true,

            pro:
              false,

            status:
              license.status,

            error:
              "Your linked PRO license is not active.",
          },
          403,
          request
        );
      }


      /*
       * ------------------------------------------------------
       * FIRST RECOVERY FOR THIS USER:
       * FIND ACTIVE LICENSE BY VERIFIED EMAIL.
       * ------------------------------------------------------
       */

      if (
        !license
      ) {

        license =
          await db
            .prepare(
              `SELECT
                 license_id,
                 supabase_user_id,
                 customer_email,
                 status,
                 max_installations
               FROM licenses
               WHERE lower(customer_email) = ?
                 AND status = 'ACTIVE'
               ORDER BY created_at DESC
               LIMIT 1`
            )
            .bind(
              email
            )
            .first();
      }


      /*
       * No active PRO license.
       */

      if (
        !license
      ) {

        return jsonResponse(
          {
            success:
              true,

            pro:
              false,

            status:
              "NO_LICENSE",

            error:
              "No active PRO license was found for this email address.",
          },
          404,
          request
        );
      }


      /*
       * ------------------------------------------------------
       * CLAIM UNCLAIMED LICENSE
       * ------------------------------------------------------
       */

      if (
        !license.supabase_user_id
      ) {

        const claimResult =
          await db
            .prepare(
              `UPDATE licenses
               SET
                 supabase_user_id = ?
               WHERE license_id = ?
                 AND supabase_user_id IS NULL
                 AND status = 'ACTIVE'`
            )
            .bind(
              supabaseUserId,
              license.license_id
            )
            .run();


        /*
         * Another simultaneous request may have claimed it.
         */

        if (
          !claimResult.meta
            ?.changes
        ) {

          license =
            await db
              .prepare(
                `SELECT
                   license_id,
                   supabase_user_id,
                   customer_email,
                   status,
                   max_installations
                 FROM licenses
                 WHERE license_id = ?
                 LIMIT 1`
              )
              .bind(
                license.license_id
              )
              .first();


          if (
            !license ||
            license.status !==
            "ACTIVE" ||
            license.supabase_user_id !==
            supabaseUserId
          ) {

            return jsonResponse(
              {
                success:
                  false,

                error:
                  "This PRO license has already been linked to another account.",

                code:
                  "LICENSE_ALREADY_CLAIMED",
              },
              409,
              request
            );
          }
        }

      } else if (
        license.supabase_user_id !==
        supabaseUserId
      ) {

        return jsonResponse(
          {
            success:
              false,

            error:
              "This PRO license belongs to another account.",

            code:
              "LICENSE_OWNED_BY_ANOTHER_USER",
          },
          403,
          request
        );
      }


      /*
       * ------------------------------------------------------
       * CHECK CURRENT INSTALLATION
       * ------------------------------------------------------
       */

      const existingInstallation =
        await db
          .prepare(
            `SELECT
               installation_id,
               license_id
             FROM installations
             WHERE installation_id = ?
             LIMIT 1`
          )
          .bind(
            installationId
          )
          .first();


      /*
       * Do not move an installation already belonging to
       * another license.
       */

      if (
        existingInstallation &&
        existingInstallation.license_id &&
        existingInstallation.license_id !==
        license.license_id
      ) {

        return jsonResponse(
          {
            success:
              false,

            error:
              "This browser installation is already linked to a different license.",

            code:
              "INSTALLATION_ALREADY_LINKED",
          },
          409,
          request
        );
      }


      /*
       * ------------------------------------------------------
       * LINK INSTALLATION
       * ------------------------------------------------------
       */

      if (
        !existingInstallation
      ) {

        const countRow =
          await db
            .prepare(
              `SELECT
                 COUNT(*) AS count
               FROM installations
               WHERE license_id = ?`
            )
            .bind(
              license.license_id
            )
            .first();


        let installationCount =
          Number(
            countRow?.count ||
            0
          );


        const maxInstallations =
          Number(
            license.max_installations ||
            5
          );


        /*
         * If all slots are occupied, replace the
         * least-recently-seen installation.
         *
         * This allows reinstall/recovery to work even
         * after all slots have been used.
         */

        if (
          installationCount >=
          maxInstallations
        ) {

          const oldest =
            await db
              .prepare(
                `SELECT
                   installation_id
                 FROM installations
                 WHERE license_id = ?
                 ORDER BY
                   COALESCE(
                     last_seen_at,
                     created_at
                   ) ASC
                 LIMIT 1`
              )
              .bind(
                license.license_id
              )
              .first();


          if (
            oldest?.installation_id
          ) {

            await db
              .prepare(
                `DELETE FROM installations
                 WHERE installation_id = ?
                   AND license_id = ?`
              )
              .bind(
                oldest.installation_id,
                license.license_id
              )
              .run();

            installationCount -=
              1;
          }
        }


        await db
          .prepare(
            `INSERT INTO installations
             (
               installation_id,
               license_id,
               created_at,
               last_seen_at
             )
             VALUES (?, ?, ?, ?)`
          )
          .bind(
            installationId,
            license.license_id,
            Date.now(),
            Date.now()
          )
          .run();

      } else {

        await db
          .prepare(
            `UPDATE installations
             SET
               license_id = ?,
               last_seen_at = ?
             WHERE installation_id = ?`
          )
          .bind(
            license.license_id,
            Date.now(),
            installationId
          )
          .run();
      }


      /*
       * Update verification timestamp.
       */

      const now =
        Date.now();


      await db
        .prepare(
          `UPDATE licenses
           SET
             last_verified_at = ?
           WHERE license_id = ?`
        )
        .bind(
          now,
          license.license_id
        )
        .run();


      return jsonResponse(
        {
          success:
            true,

          pro:
            true,

          status:
            "ACTIVE",

          license_id:
            license.license_id,

          installation_id:
            installationId,

          license_token:
            await issueLicenseToken(
              license.license_id,
              installationId,
              env
            ),

          expires_in:
            Math.floor(
              LICENSE_TOKEN_TTL_MS /
              1000
            ),
        },
        200,
        request
      );
    }


    /*
     * ========================================================
     * UNKNOWN ROUTE
     * ========================================================
     */

    return jsonResponse(
      {
        success:
          false,

        error:
          "Not found",
      },
      404
    );
  },
};