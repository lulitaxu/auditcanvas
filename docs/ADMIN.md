# AuditCanvas admin panel — founder setup

The admin panel code is shipped, but it is **inert** until you finish
the steps below: there is no default password and no fallback. Until
then, `/admin/login` just says "Admin is not configured." and every
admin API returns a generic 503. Nothing about the public site
changes either way.

Total time: about 10 minutes. Everything here can be done from a
phone browser.

## 1. Create the Neon database

Use your existing Neon account (the one from Verro is fine — this is
a separate project/database inside it).

1. Create a project, suggested name `auditcanvas-admin`
   (Singapore region if offered).
2. Create a database in it named `auditcanvas_admin`.
3. Open the project's SQL Editor, paste the **entire** contents of
   [`db/migrations/0001_admin.sql`](../db/migrations/0001_admin.sql)
   from this repo, and run it once.
4. Confirm the tables exist: `admin_sessions`, `admin_events`,
   `admin_scan_runs`, `visit_events`, `admin_meta`.
5. Copy the **serverless connection string** for the database (the
   one with the host ending in `.neon.tech`). Keep it for step 3.
   Do not paste it into this repo or any chat that gets logged.

## 2. Generate the admin password hash

On any machine with Node (your Arch laptop is easiest), run this
one-liner. It asks for the password without echoing it and prints
only the salted hash. Pick a strong password you do not reuse
anywhere else.

```bash
read -r -s -p "AuditCanvas admin password: " AC_ADMIN_PW; echo; AC_ADMIN_PW="$AC_ADMIN_PW" node -e 'const {randomBytes,scryptSync}=require("node:crypto"); const salt=randomBytes(16); const key=scryptSync(process.env.AC_ADMIN_PW,salt,64,{N:16384,r:8,p:1,maxmem:64*1024*1024}); console.log(`scrypt$v=1$N=16384$r=8$p=1$${salt.toString("base64url")}$${key.toString("base64url")}`);'; unset AC_ADMIN_PW
```

Copy the printed line (it starts with `scrypt$v=1$`). That line —
never the password itself — is what goes into Vercel.

Also generate three independent random secrets, one per variable:

```bash
openssl rand -hex 32   # run three times, use a different output for each
```

## 3. Set the Vercel environment variables

In the **AuditCanvas** Vercel project only, environment
**Production** only (never Preview — preview deploys must not reach
the production admin database):

| Variable | Value |
| --- | --- |
| `AUDITCANVAS_DATABASE_URL` | the Neon connection string from step 1 |
| `ADMIN_PASSWORD_HASH` | the `scrypt$...` line from step 2 |
| `ADMIN_CSRF_SECRET` | first `openssl rand -hex 32` output |
| `VISITOR_HASH_SECRET` | second `openssl rand -hex 32` output |
| `BUNDLE_SIGNING_SECRET` | third `openssl rand -hex 32` output (skip if already set in Production) |

Rules that matter:

- Every secret is generated independently. Never reuse one value
  for two variables.
- Never create a `NEXT_PUBLIC_` version of any of these, and never
  put the plaintext admin password in any variable.
- `BUNDLE_SIGNING_SECRET` may already exist from the scan work; if
  it does, leave it as is.

## 4. Redeploy

Environment changes need a new deployment: trigger a redeploy of the
latest `main` commit in Vercel (or push any commit). The public site
is unaffected.

## 5. Smoke test (2 minutes)

1. Open `https://auditcanvas.vercel.app/admin/login`, sign in with
   the password from step 2.
2. The console should show **SESSION ACTIVE** and **NEON CONNECTED**,
   with no configuration warning.
3. Sign out, then sign in again. (This also proves session rotation:
   the first session is revoked the moment the second is created.)
4. Run an admin scan of the seeded demo target. The readout should
   show origin **ADMIN**, policy **FULL**.
5. Open the finished report, then open **Scan history** and reopen
   the same report from there. It loads from the database, so this
   proves persistence.
6. Download the evidence JSON and confirm it contains
   `"origin": "admin"` and `"provenance": "server-admin"`.
7. Scan a site you own that has **not** done the DNS TXT
   verification. The report must say authorization state **ADMIN**
   (not VERIFIED) and run the full group set.

## If you lose the password

There is no reset email and no backdoor, by design:

1. Generate a new hash (step 2) with a new password.
2. Replace `ADMIN_PASSWORD_HASH` in Vercel Production and redeploy.
3. To kill every live session immediately, run this in the Neon SQL
   Editor:

```sql
update public.admin_sessions set revoked_at = now() where revoked_at is null;
```

## What the panel is (and is not)

- Full scans mean the existing full **non-destructive** check set.
  The panel cannot exploit, bypass authentication, guess
  credentials, submit forms, reach private/loopback targets, or act
  as a fetch proxy. The SSRF rules apply unchanged.
- Admin scans of unverified targets are labeled
  `authorizationState: 'admin'` — never 'verified' — in the UI, the
  report, the stamp, and the downloads.
- Sessions last 12 hours, rotate at every login, and live only in
  the database (stored as hashes). Login attempts are rate-limited
  with durable exponential backoff, and logins, scans, and downloads
  are audit-logged.
- Admin reports are retained for 180 days. (The automatic prune job
  arrives in a later phase; until then nothing is deleted.)
