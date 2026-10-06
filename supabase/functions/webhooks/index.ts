// Setup type definitions for built-in Supabase Runtime APIs
import "@supabase/functions-js/edge-runtime.d.ts";
import { Webhook, WebhookVerificationError } from "standardwebhooks";

// The same secret the sender signs with, e.g. from `select webhooks.generate_secret()`.
// The "whsec_" prefix is optional.
const secret = Deno.env.get("WEBHOOK_SECRET");
if (!secret) {
  throw new Error("WEBHOOK_SECRET is not set");
}
const wh = new Webhook(secret);

// Test receiver for webhooks sent by pg_standard_webhooks. There is no apiKey or
// JWT check here: the Standard Webhooks signature is what authenticates the sender.
export default {
  fetch: async (req: Request) => {
    if (req.method !== "POST") {
      return new Response("Method Not Allowed", { status: 405 });
    }

    // Verify against the raw body; re-serialized JSON would not match the signature.
    const body = await req.text();

    let payload: unknown;
    try {
      // Checks the webhook-id, webhook-timestamp (5 minute tolerance) and
      // webhook-signature headers, then returns the parsed JSON body.
      payload = wh.verify(body, Object.fromEntries(req.headers));
    } catch (err) {
      if (err instanceof WebhookVerificationError) {
        console.warn("Rejected webhook:", err.message);
        return Response.json({ error: err.message }, { status: 401 });
      }
      throw err;
    }

    console.log("Verified webhook", req.headers.get("webhook-id"), payload);

    return new Response(null, { status: 204 });
  },
};

/* To invoke locally:

  1. Put the secret in supabase/functions/.env:
       WEBHOOK_SECRET=whsec_...
  2. Run `supabase start` (or `supabase functions serve`)
  3. Send a signed webhook from Postgres:

  select *
  from webhooks.send_webhook(
      url     => 'http://host.docker.internal:54321/functions/v1/webhooks',
      msg_id  => 'msg_test_1',
      payload => webhooks.build_payload('test.ping', '{"hello": "world"}'),
      secret  => 'whsec_...'
  );

*/
