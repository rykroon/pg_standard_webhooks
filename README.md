# pg_standard_webhooks

A [Trusted Language Extension](https://github.com/aws/pg_tle) for Postgres that helps you send webhooks compliant with the [Standard Webhooks](https://github.com/standard-webhooks/standard-webhooks/blob/main/spec/standard-webhooks.md) specification.

It signs payloads (`v1`, HMAC-SHA256), sends them with the `webhook-id`, `webhook-timestamp` and `webhook-signature` headers, and logs every delivery attempt. Storing events, choosing endpoints and scheduling retries is left to you.

## Requirements

- [`http`](https://github.com/pramsey/pgsql-http)
- [`pgcrypto`](https://www.postgresql.org/docs/current/pgcrypto.html)
- [`pg_tle`](https://github.com/aws/pg_tle) (when installing as a TLE)

## Installation

Create the dependencies first, then install the extension (here into its own `webhooks` schema):

```sql
create extension if not exists http with schema extensions;
create extension if not exists pgcrypto with schema extensions;

-- via database.dev
select dbdev.install('rykroon@pg_standard_webhooks');
create schema webhooks;
create extension "rykroon@pg_standard_webhooks" schema webhooks;
```

Or with pg_tle directly:

```sql
select pgtle.install_extension(
    'pg_standard_webhooks', '0.0.1',
    'Helpers for sending Standard Webhooks compliant webhooks',
    $_pgtle_$ <contents of pg_standard_webhooks--0.0.1.sql> $_pgtle_$,
    '{http,pgcrypto}'
);
create schema webhooks;
create extension pg_standard_webhooks schema webhooks;
```

The examples below assume the `webhooks` schema.

## Usage

```sql
-- once per endpoint; store the secret and share it with the consumer
select webhooks.generate_secret();  -- whsec_...

-- send a webhook
select *
from webhooks.send_webhook(
    url     => 'https://example.com/webhooks',
    msg_id  => 'msg_2KWPBgLlAfxdpx2AI54pPJ85f4W',
    payload => webhooks.build_payload('invoice.paid', '{"invoice_id": 42}'),
    secret  => 'whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw'
);
```

> Use `select * from webhooks.send_webhook(...)`, not `select (webhooks.send_webhook(...)).*`. Postgres evaluates the latter once per output column, which sends the webhook multiple times.

### Example: your own events table and a pg_cron job

```sql
create table public.events (
    id uuid primary key default gen_random_uuid(),
    type webhooks.event_type not null,
    occurred_at timestamptz not null default now(),
    data jsonb not null,
    delivered_at timestamptz
);

create function public.deliver_pending_events() returns void language plpgsql as $$
declare
    e public.events;
    attempt webhooks.webhook_attempts;
begin
    for e in select * from public.events where delivered_at is null order by occurred_at limit 100 loop
        select * into attempt from webhooks.send_webhook(
            'https://example.com/webhooks',
            'msg_' || replace(e.id::text, '-', ''),  -- stable across retries
            webhooks.build_payload(e.type, e.data, e.occurred_at),
            (select secret from public.endpoint_secrets limit 1)
        );
        if attempt.response_status between 200 and 299 then
            update public.events set delivered_at = now() where id = e.id;
        end if;
    end loop;
end;
$$;

select cron.schedule('deliver-webhooks', '* * * * *', 'select public.deliver_pending_events()');
```

## API

### Types

| Domain | Description |
| --- | --- |
| `event_type` | Full-stop delimited event type made of `[a-zA-Z0-9_]` segments, e.g. `user.created`. |
| `msg_id` | Non-empty message id, sent as `webhook-id`. Must not contain `.`. |

### Functions

| Function | Returns | Description |
| --- | --- | --- |
| `generate_secret(num_bytes int = 32)` | `text` | New `whsec_` secret of 24–64 random bytes. |
| `build_payload(type event_type, data jsonb, occurred_at timestamptz = now())` | `jsonb` | `{"type", "timestamp" (ISO 8601 UTC), "data"}`. |
| `sign(msg_id, ts bigint, payload text, secret text)` | `text` | `v1,<base64 HMAC-SHA256>` of `msg_id.ts.payload`. |
| `sign(msg_id, ts bigint, payload text, secrets text[])` | `text` | Space delimited signatures, one per secret (key rotation). |
| `verify(msg_id, ts bigint, payload text, signature_header text, secret text, tolerance interval = '5 minutes')` | `boolean` | Checks the timestamp tolerance and whether any `v1` signature matches. Useful when Postgres is the receiver. |
| `send_webhook(url text, msg_id, payload jsonb, secret text, timeout_ms int = 30000)` | `webhook_attempts` | Signs and POSTs `payload`, logs the attempt and returns the logged row. |
| `send_webhook(url text, msg_id, payload jsonb, secrets text[], timeout_ms int = 30000)` | `webhook_attempts` | Same, signed with every secret (key rotation). |

### `webhook_attempts`

One row per call to `send_webhook`: `msg_id`, `url`, `request_timestamp` (the `webhook-timestamp` sent), `payload`, `response_status`, `response_headers`, `response_body`, `error` (transport errors and timeouts, which are recorded rather than raised), `duration` and `created_at`. Secrets and signatures are not stored. Rows are included in `pg_dump`.

## Caveats

- **Synchronous HTTP.** `send_webhook` blocks until the response arrives or the timeout expires (the spec recommends 15–30s). Do not call it from triggers or user-facing transactions. Call it from a background job such as pg_cron instead.
- **Reuse `msg_id` on retries.** Consumers use `webhook-id` as an idempotency key, so every retry of the same message must use the same id. Derive it from your event's primary key.
- **Retries are up to you.** The spec recommends exponential backoff with jitter, for example 5s, 5m, 30m, 2h, 5h, 10h, 14h, 20h, 24h. Treat any 2xx as success. Disable the endpoint on `410 Gone`. Throttle on `429`, `502` and `504`, and respect `retry-after`.
- **Session curl options.** `send_webhook` sets `CURLOPT_TIMEOUT_MS` with `http_set_curlopt`, which persists for the rest of the database session.
- **Only `v1` signatures.** Asymmetric `v1a` (Ed25519) signatures are not supported because pgcrypto does not implement Ed25519.
- **Payload bytes.** The signature covers `payload::text`, and that exact text is the request body. Consumers must verify the raw body, not a re-serialized one.
