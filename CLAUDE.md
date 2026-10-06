# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A Postgres Trusted Language Extension (pg_tle) that signs and sends [Standard Webhooks](https://github.com/standard-webhooks/standard-webhooks/blob/main/spec/standard-webhooks.md) (`v1`, HMAC-SHA256) and logs each delivery attempt. It's published to database.dev as `rykroon@pg_standard_webhooks`. The README is the user-facing API reference. Update it when function signatures or behavior change.

## Layout

- `pg_standard_webhooks--<version>.sql` is the whole extension: domains, helpers (`generate_secret`, `build_payload`, `sign`, `verify`), the `webhook_attempts` log table and `send_webhook`.
- `pg_standard_webhooks.control` holds the version, comment and `requires` (`http, pgcrypto`). `default_version` decides which SQL file the generator script reads.
- `supabase/` is a local sandbox project, not part of the extension:
  - `migrations/20261006000000_extension_dependencies.sql` creates `pg_tle`, `http` and `pgcrypto` (the last two in the `extensions` schema).
  - `migrations/20261006000001_install_pg_standard_webhooks.sql` is **generated**, so never edit it by hand. It wraps the extension SQL in `pgtle.install_extension(...)` and creates the extension in the `webhooks` schema.
  - `functions/webhooks/` is a Deno edge function that receives webhooks and verifies them with the official `standardwebhooks` npm package. It checks interop between the SQL signer and a reference verifier. It needs `WEBHOOK_SECRET` in `supabase/functions/.env` (see `sample.env`), and it has `verify_jwt = false` in `config.toml`.

## Commands

```sh
# after editing the extension SQL or control file
scripts/generate-supabase-migration.sh
supabase db reset

supabase start            # local stack (DB on port 54322) + edge functions
supabase functions serve  # edge functions only
```

There is no automated test suite. To check changes, run SQL against the local DB. The comment at the bottom of `supabase/functions/webhooks/index.ts` has an end-to-end example that calls `webhooks.send_webhook` against the local edge function URL (`http://host.docker.internal:54321/functions/v1/webhooks`).

## Conventions in the extension SQL

- Qualify every object with `@extschema@`. The extension is `relocatable = false` and installs into whatever schema the caller picks (`webhooks` in the sandbox).
- Every function uses `set search_path from current`, which pins the search path from `CREATE EXTENSION` time (the extension schema plus the `http`/`pgcrypto` schemas). This lets functions call `hmac`, `gen_random_bytes` and `http(...)` without schema qualification.
- The file must not contain the `$_pgtle_$` dollar-quote tag. The generator uses it to wrap the script and refuses to run if it's present.
- `webhook_attempts` is registered with `pg_extension_config_dump`, so it's included in dumps.
- `send_webhook` catches transport errors into `webhook_attempts.error` instead of raising. The single-secret overload delegates to the `text[]` overload.
- Signatures cover `payload::text` exactly, and that text is also the request body. Keep the two identical.
- Changing the extension in a released version means a new `pg_standard_webhooks--<new>.sql` (and possibly an upgrade script) plus a bump of `default_version` in the control file.
