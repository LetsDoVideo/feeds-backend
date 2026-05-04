/**
 * Feeds Backend - Entitlement Verification Service
 *
 * Receives Zoom monetization webhooks and serves entitlement queries
 * from the Feeds desktop plugin.
 *
 * Endpoints:
 *   POST /webhook  - Zoom monetization webhook receiver
 *   GET  /tier     - Tier query for Feeds plugin (auth: Zoom OAuth token)
 *   GET  /health   - Health check
 */

interface Env {
  ENTITLEMENTS: KVNamespace;
  ZOOM_WEBHOOK_SECRET: string;
}

interface EntitlementRecord {
  tier: number;        // 0=free, 1=basic, 2=streamer, 3=broadcaster
  plan_name: string;
  plan_id: string;
  email: string;
  updated_at: number;  // unix ms
}

const PLAN_NAME_TO_TIER: Record<string, number> = {
  "Free": 0,
  "Basic": 1,
  "Streamer": 2,
  "Broadcaster": 3,
};

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === "/health") {
      return jsonResponse({ status: "ok", time: Date.now() });
    }

    if (url.pathname === "/webhook" && request.method === "POST") {
      return handleWebhook(request, env);
    }

    if (url.pathname === "/tier" && request.method === "GET") {
      return handleTierQuery(request, env);
    }

    return new Response("Not Found", { status: 404 });
  },
};

// --- Webhook handler ---

async function handleWebhook(request: Request, env: Env): Promise<Response> {
  const bodyText = await request.text();

  // Verify Zoom signature
  const signature = request.headers.get("x-zm-signature");
  const timestamp = request.headers.get("x-zm-request-timestamp");

  if (!signature || !timestamp) {
    return new Response("Missing signature headers", { status: 401 });
  }

  const valid = await verifyZoomSignature(
    env.ZOOM_WEBHOOK_SECRET,
    timestamp,
    bodyText,
    signature
  );

  if (!valid) {
    return new Response("Invalid signature", { status: 401 });
  }

  let payload: any;
  try {
    payload = JSON.parse(bodyText);
  } catch {
    return new Response("Invalid JSON", { status: 400 });
  }

  // Zoom URL validation challenge
  if (payload.event === "endpoint.url_validation") {
    const plainToken = payload.payload?.plainToken;
    if (!plainToken) {
      return new Response("Missing plainToken", { status: 400 });
    }
    const encryptedToken = await hmacSha256Hex(env.ZOOM_WEBHOOK_SECRET, plainToken);
    return jsonResponse({ plainToken, encryptedToken });
  }

  console.log("webhook event:", payload.event);

  // Route by event type
  switch (payload.event) {
    case "marketplace.app_user_entitlements_added":
    case "marketplace.app_subscription_added":
    case "marketplace.app_purchase_success":
    case "marketplace.app_renewal_success":
    case "marketplace.app_convert_to_paid_in_trial":
      await handleEntitlementsAdded(payload, env);
      break;

    case "marketplace.app_user_entitlements_removed":
    case "marketplace.app_subscription_canceled":
    case "marketplace.app_subscription_ended":
    case "marketplace.app_subscription_removed":
    case "marketplace.app_trial_end":
      await handleEntitlementsRemoved(payload, env);
      break;

    default:
      console.log("unhandled event type:", payload.event);
  }

  return new Response("OK", { status: 200 });
}

async function handleEntitlementsAdded(payload: any, env: Env): Promise<void> {
  const p = payload.payload || payload["payload:"];
  if (!p) return;

  // Bulk-style: users[] with email + plan_name + plan_id + user_id
  if (Array.isArray(p.users)) {
    for (const u of p.users) {
      if (!u.user_id) continue;
      const tier = planNameToTier(u.plan_name);
      const record: EntitlementRecord = {
        tier,
        plan_name: u.plan_name || "",
        plan_id: u.plan_id || "",
        email: u.email || "",
        updated_at: Date.now(),
      };
      await env.ENTITLEMENTS.put(u.user_id, JSON.stringify(record));
      console.log(`upsert ${u.user_id} -> tier ${tier} (${u.plan_name})`);
    }
    return;
  }

  // Single-user-style: userId + planName at top level
  const userId = p.userId || p.user_id;
  if (!userId) return;
  const planName = p.planName || p.newPlanName || p.plan_name || "";
  const tier = planNameToTier(planName);
  const record: EntitlementRecord = {
    tier,
    plan_name: planName,
    plan_id: p.plan_id || "",
    email: p.email || "",
    updated_at: Date.now(),
  };
  await env.ENTITLEMENTS.put(userId, JSON.stringify(record));
  console.log(`upsert ${userId} -> tier ${tier} (${planName})`);
}

async function handleEntitlementsRemoved(payload: any, env: Env): Promise<void> {
  const p = payload.payload || payload["payload:"];
  if (!p) return;

  // Bulk-style
  if (Array.isArray(p.users)) {
    for (const u of p.users) {
      if (!u.user_id) continue;
      const record: EntitlementRecord = {
        tier: 0,
        plan_name: "Free",
        plan_id: "",
        email: u.email || "",
        updated_at: Date.now(),
      };
      await env.ENTITLEMENTS.put(u.user_id, JSON.stringify(record));
      console.log(`downgrade ${u.user_id} -> tier 0`);
    }
    return;
  }

  // Single-user-style
  const userId = p.userId || p.user_id;
  if (!userId) return;
  const record: EntitlementRecord = {
    tier: 0,
    plan_name: "Free",
    plan_id: "",
    email: p.email || "",
    updated_at: Date.now(),
  };
  await env.ENTITLEMENTS.put(userId, JSON.stringify(record));
  console.log(`downgrade ${userId} -> tier 0`);
}

function planNameToTier(name: string | undefined): number {
  if (!name) return 0;
  const trimmed = name.trim();
  if (PLAN_NAME_TO_TIER[trimmed] !== undefined) {
    return PLAN_NAME_TO_TIER[trimmed];
  }
  // Case-insensitive fallback
  const lower = trimmed.toLowerCase();
  for (const [key, val] of Object.entries(PLAN_NAME_TO_TIER)) {
    if (key.toLowerCase() === lower) return val;
  }
  return 0;
}

// --- Tier query handler ---

async function handleTierQuery(request: Request, env: Env): Promise<Response> {
  const auth = request.headers.get("authorization");
  if (!auth || !auth.startsWith("Bearer ")) {
    return new Response("Missing or malformed Authorization header", { status: 401 });
  }
  const token = auth.slice(7);

  // Validate token with Zoom and get user ID
  const userResp = await fetch("https://api.zoom.us/v2/users/me", {
    headers: { Authorization: `Bearer ${token}` },
  });

  if (!userResp.ok) {
    return new Response("Invalid Zoom token", { status: 401 });
  }

  const user = await userResp.json() as { id?: string; email?: string };
  if (!user.id) {
    return new Response("Zoom user response missing id", { status: 502 });
  }

  // Look up entitlement
  const stored = await env.ENTITLEMENTS.get(user.id);
  if (!stored) {
    // No record means free tier
    return jsonResponse({
      tier: 0,
      plan_name: "Free",
      plan_id: "",
      source: "default",
    });
  }

  const record: EntitlementRecord = JSON.parse(stored);
  return jsonResponse({
    tier: record.tier,
    plan_name: record.plan_name,
    plan_id: record.plan_id,
    source: "kv",
    updated_at: record.updated_at,
  });
}

// --- Helpers ---

async function verifyZoomSignature(
  secret: string,
  timestamp: string,
  body: string,
  receivedSignature: string
): Promise<boolean> {
  const message = `v0:${timestamp}:${body}`;
  const computedHash = await hmacSha256Hex(secret, message);
  const computedSignature = `v0=${computedHash}`;
  return constantTimeEquals(computedSignature, receivedSignature);
}

async function hmacSha256Hex(secret: string, message: string): Promise<string> {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(message));
  return Array.from(new Uint8Array(sig))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function constantTimeEquals(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

function jsonResponse(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json" },
  });
}
