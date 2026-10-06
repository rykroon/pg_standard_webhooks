-- complain if script is sourced in psql, rather than via CREATE EXTENSION
\echo Use "CREATE EXTENSION pg_standard_webhooks" to load this file. \quit

-- Standard Webhooks: https://github.com/standard-webhooks/standard-webhooks/blob/main/spec/standard-webhooks.md
--
-- During CREATE EXTENSION the search_path is the extension's schema followed by the
-- schemas of the required extensions (http, pgcrypto). Every function pins that path
-- with `set search_path from current`, so they work regardless of the caller's
-- search_path or of which schema http and pgcrypto were installed into.


--------------------------------------------------------------------------------
-- Domains
--------------------------------------------------------------------------------

-- Hierarchical, full-stop delimited event type, e.g. 'user.created' or 'invoice.paid'.
create domain @extschema@.event_type as text
    check (value ~ '^[a-zA-Z0-9_]+(\.[a-zA-Z0-9_]+)*$');

comment on domain @extschema@.event_type is
    'Full-stop delimited event type made of [a-zA-Z0-9_] segments, e.g. user.created';

-- The webhook-id. Must not contain '.', which delimits the parts of the signed content.
create domain @extschema@.msg_id as text
    check (value <> '' and position('.' in value) = 0);

comment on domain @extschema@.msg_id is
    'Unique message id sent as the webhook-id header. Reuse it across retries of the same message.';


--------------------------------------------------------------------------------
-- Pure helpers
--------------------------------------------------------------------------------

-- Generate a new symmetric secret serialized as 'whsec_' || base64(random bytes).
create function @extschema@.generate_secret(num_bytes int default 32)
returns text
language plpgsql
set search_path from current
volatile
as $$
begin
    if num_bytes not between 24 and 64 then
        raise exception 'num_bytes must be between 24 and 64, got %', num_bytes;
    end if;
    return 'whsec_' || replace(
        encode(gen_random_bytes(num_bytes), 'base64'), E'\n', ''
    );
end;
$$;

comment on function @extschema@.generate_secret(int) is
    'Generate a symmetric webhook secret (whsec_ prefixed, base64 encoded).';


-- Build a spec compliant payload: {"type": ..., "timestamp": <ISO 8601>, "data": ...}.
create function @extschema@.build_payload(
    type @extschema@.event_type,
    data jsonb,
    occurred_at timestamptz default now()
)
returns jsonb
language sql
set search_path from current
stable
as $$
    select jsonb_build_object(
        'type', type,
        'timestamp', to_char(occurred_at at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
        'data', data
    );
$$;

comment on function @extschema@.build_payload(@extschema@.event_type, jsonb, timestamptz) is
    'Build a Standard Webhooks payload with type, ISO 8601 timestamp and data.';


-- Sign '<msg_id>.<ts>.<payload>' with HMAC-SHA256 and return 'v1,<base64 signature>'.
create function @extschema@.sign(
    msg_id @extschema@.msg_id,
    ts bigint,
    payload text,
    secret text
)
returns text
language sql
set search_path from current
immutable
strict
as $$
    select 'v1,' || replace(encode(
        hmac(
            convert_to(msg_id || '.' || ts || '.' || payload, 'UTF8'),
            decode(regexp_replace(secret, '^whsec_', ''), 'base64'),
            'sha256'
        ),
        'base64'
    ), E'\n', '');
$$;

comment on function @extschema@.sign(@extschema@.msg_id, bigint, text, text) is
    'Return the v1 (HMAC-SHA256) signature for a message.';


-- Sign with several secrets (key rotation); returns a space delimited signature list.
create function @extschema@.sign(
    msg_id @extschema@.msg_id,
    ts bigint,
    payload text,
    secrets text[]
)
returns text
language sql
set search_path from current
immutable
strict
as $$
    select string_agg(@extschema@.sign(msg_id, ts, payload, s), ' ' order by ord)
    from unnest(secrets) with ordinality as t(s, ord);
$$;

comment on function @extschema@.sign(@extschema@.msg_id, bigint, text, text[]) is
    'Return a space delimited list of v1 signatures, one per secret.';


-- Verify a webhook-signature header. Returns false when the timestamp is outside the
-- tolerance or when no v1 signature in the header matches.
create function @extschema@.verify(
    msg_id @extschema@.msg_id,
    ts bigint,
    payload text,
    signature_header text,
    secret text,
    tolerance interval default interval '5 minutes'
)
returns boolean
language plpgsql
set search_path from current
volatile
as $$
declare
    expected text;
    candidate text;
    -- Compare HMACs of both values under a random key so the comparison time does not
    -- leak how much of the expected signature matched.
    cmp_key bytea := gen_random_bytes(32);
begin
    if abs(extract(epoch from now()) - ts) > extract(epoch from tolerance) then
        return false;
    end if;

    expected := @extschema@.sign(msg_id, ts, payload, secret);

    foreach candidate in array regexp_split_to_array(trim(coalesce(signature_header, '')), '\s+') loop
        if candidate like 'v1,%'
            and hmac(convert_to(candidate, 'UTF8'), cmp_key, 'sha256')
              = hmac(convert_to(expected, 'UTF8'), cmp_key, 'sha256')
        then
            return true;
        end if;
    end loop;

    return false;
end;
$$;

comment on function @extschema@.verify(@extschema@.msg_id, bigint, text, text, text, interval) is
    'Verify a webhook-signature header against a secret, with timestamp tolerance.';


--------------------------------------------------------------------------------
-- Delivery log
--------------------------------------------------------------------------------

create table @extschema@.webhook_attempts (
    id bigint generated always as identity primary key,
    msg_id text not null,
    url text not null,
    request_timestamp timestamptz not null,
    payload jsonb not null,
    response_status int,
    response_headers jsonb,
    response_body text,
    error text,
    duration interval,
    created_at timestamptz not null default now()
);

comment on table @extschema@.webhook_attempts is
    'One row per webhook delivery attempt made by send_webhook().';
comment on column @extschema@.webhook_attempts.request_timestamp is
    'Value sent in the webhook-timestamp header.';
comment on column @extschema@.webhook_attempts.error is
    'Transport level error (connection refused, timeout, ...). Null when a response was received.';

create index webhook_attempts_msg_id_idx on @extschema@.webhook_attempts (msg_id);
create index webhook_attempts_created_at_idx on @extschema@.webhook_attempts (created_at);

select pg_catalog.pg_extension_config_dump('@extschema@.webhook_attempts', '');


--------------------------------------------------------------------------------
-- Delivery
--------------------------------------------------------------------------------

-- POST a signed payload to url and log the attempt. Transport errors are recorded in
-- webhook_attempts.error rather than raised. The HTTP call is synchronous, so do not
-- call this from a trigger; call it from a job (e.g. pg_cron) instead.
create function @extschema@.send_webhook(
    url text,
    msg_id @extschema@.msg_id,
    payload jsonb,
    secrets text[],
    timeout_ms int default 30000
)
returns @extschema@.webhook_attempts
language plpgsql
set search_path from current
volatile
as $$
declare
    body text := payload::text;
    ts bigint := extract(epoch from now())::bigint;
    started_at timestamptz := clock_timestamp();
    response http_response;
    err text;
    attempt @extschema@.webhook_attempts;
begin
    if coalesce(array_length(secrets, 1), 0) = 0 then
        raise exception 'at least one secret is required';
    end if;

    begin
        perform http_set_curlopt('CURLOPT_TIMEOUT_MS', timeout_ms::text);
        response := http((
            'POST',
            url,
            array[
                http_header('webhook-id', msg_id),
                http_header('webhook-timestamp', ts::text),
                http_header('webhook-signature', @extschema@.sign(msg_id, ts, body, secrets))
            ],
            'application/json',
            body
        )::http_request);
    exception when others then
        err := sqlerrm;
    end;

    insert into @extschema@.webhook_attempts (
        msg_id, url, request_timestamp, payload,
        response_status, response_headers, response_body, error, duration
    )
    values (
        msg_id, url, to_timestamp(ts), payload,
        response.status,
        (select jsonb_object_agg(h.field, h.value) from unnest(response.headers) as h),
        response.content,
        err,
        clock_timestamp() - started_at
    )
    returning * into attempt;

    return attempt;
end;
$$;

comment on function @extschema@.send_webhook(text, @extschema@.msg_id, jsonb, text[], int) is
    'POST a signed Standard Webhooks request and log it in webhook_attempts.';


create function @extschema@.send_webhook(
    url text,
    msg_id @extschema@.msg_id,
    payload jsonb,
    secret text,
    timeout_ms int default 30000
)
returns @extschema@.webhook_attempts
language sql
set search_path from current
volatile
as $$
    select @extschema@.send_webhook(url, msg_id, payload, array[secret], timeout_ms);
$$;

comment on function @extschema@.send_webhook(text, @extschema@.msg_id, jsonb, text, int) is
    'POST a signed Standard Webhooks request using a single secret and log it in webhook_attempts.';
