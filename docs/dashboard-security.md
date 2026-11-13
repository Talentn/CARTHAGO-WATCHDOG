# How access to the dashboard is protected

The studio dashboard shows who is playing, who was flagged and why. This page says, in plain
words, who can open it, what protects that, and what is not covered yet.

The dashboard stays server-rendered HTML and CSS with no JavaScript. That is a security
choice, not a shortcut: a page that runs no script has nothing for an injected script to
hook into, and the browser is told to refuse any script, inline style or outside resource
anyway. The work described here went into sign-in and access instead.

## Accounts

- Every person has their own account in their studio: a user name and a password. Accounts
  of one studio do not exist in another, and every page and query is limited to the studio
  of the signed-in account.
- There are no default accounts and no default passwords.
- The first admin of a studio is created on the PC that runs the gateway:
  `carthago-gateway dashboard-user add-admin -data DIR -tenant ID -name NAME`. It prints a
  link that works once, for 24 hours. Whoever opens it chooses the password.
- Further users are invited by an admin under **Users**. An invite is also a one-time link
  (72 hours) that the admin passes on by hand. There is no email service, so no mail server
  ever holds a link.
- An admin can change a role, sign a user out, make a password-reset link, reset a lost
  second factor and disable an account. Accounts are disabled, not deleted, so the audit
  log keeps its names. Nobody can change their own role or disable themselves, so a studio
  cannot lose its last admin by accident.

## Passwords

- Stored only as argon2id hashes (64 MiB of memory, 3 passes), each with its own salt. The
  password itself is never written to the database or to a log.
- At least 12 characters. Common passwords, repeated patterns, and passwords that contain
  the user name, the studio name or the product name are refused.
- Changing a password signs out every other browser of that account.

## Two-factor sign-in

- Any authenticator app works (TOTP, RFC 6238: 6 digits, 30 seconds). The QR code on the
  setup page is drawn by the dashboard itself; no outside service sees the secret.
- Each code is accepted once, so a code read over someone's shoulder cannot be used again.
- Setting it up gives 10 recovery codes for a lost phone. Each works once.
- An admin can require two-factor sign-in for the whole studio. Accounts without it are
  then held at the setup page until they have it, and cannot turn it off.
- The authenticator secret is stored encrypted, the recovery codes as keyed hashes. The key
  for both is in a file next to the database (`dashboard-secret.key`), so a copy of the
  database alone gives neither.

## Roles

| Role | Can do |
| --- | --- |
| Read-only | See every page of their studio |
| Reviewer | The same, plus review actions on sessions |
| Admin | The same, plus manage users, set the two-factor rule, read the audit log |

The role is checked on the server for every page and every action, and read from the account
on every request. A changed role or a disabled account takes effect on the next click.

## Sessions

- Signing in gives the browser a random session id in a cookie that script cannot read and
  that is only sent to the dashboard itself. The session lives on the server, which stores
  only a hash of the id, so it can be ended there at any time.
- A session ends after 30 minutes without activity and at the latest 12 hours after signing
  in. Both can be changed with gateway flags.
- The session id is replaced at every sign-in and whenever the way the account signs in
  changes (password, two-factor).
- Under **Account** a user sees their signed-in browsers, can sign out any one of them, or
  all of them at once.

## Guessing and probing

- Five wrong attempts lock an account for a minute, and every further wrong attempt doubles
  the lock, up to an hour. Wrong two-factor codes count the same way.
- An address that fails 20 times in 10 minutes is refused for the rest of those 10 minutes.
- A wrong password, an unknown user, an unknown studio and a disabled account all get the
  same answer and take about the same time, so the sign-in page does not reveal which user
  names exist.

## Audit log

- Every sign-in, failed attempt, lockout, invite, role change, password or two-factor change
  and every other action that changes something is recorded with who did it, when, and from
  which address. Admins read it under **Audit log**.
- The log can only be added to. The dashboard has no way to change or delete an entry, the
  database refuses it too, and each entry carries a fingerprint of the one before it. An
  entry that was edited or cut out behind the dashboard's back shows up when an admin runs
  the check on that page.

## Browser and network

- Every form that changes something carries a secret token tied to the session, and requests
  from other sites are refused, so another web page cannot act in a signed-in user's name.
- The browser is instructed to run no script, load nothing from other hosts, never show the
  dashboard inside another page, send no referrer, and keep no copy of a page.
- Away from the gateway PC the dashboard requires HTTPS: the gateway does not start a
  dashboard on a network address in plain HTTP. Give it a certificate
  (`-dashboard-tls-cert`, `-dashboard-tls-key`) or put it behind a proxy that terminates TLS
  (`-dashboard-secure-cookie`, and `-dashboard-trusted-proxy` so the real client address is
  used for limits and the audit log).

## The demo login

For trying the product on one PC there is still a shared studio key (studio `demo`, key
`demo-dashboard-key`). It is deliberately weak, so it is fenced in:

- it works only when the dashboard listens on the PC itself (loopback), only for requests
  made from that PC, and the gateway does not start a network-facing dashboard with it;
- it works only while the studio has no user account. Once the first admin exists it is off
  for that studio for good, and any demo session ends;
- it acts as a reviewer: no user management, no audit log;
- every page shows a **Demo login** mark while it is in use.

## Not covered yet

- **No email.** Invites and reset links are passed on by hand. A user who forgets their
  password needs an admin; an admin with no second admin needs the gateway command line.
- **No passkeys or hardware keys (WebAuthn), and no single sign-on** (SAML, OIDC). Two-factor
  is authenticator-app codes only.
- **Sign-in limits are kept in memory.** They start again when the gateway restarts, and
  they are per gateway process.
- **Lockout can be used against a user.** Someone who knows a user name can keep that account
  locked by failing on purpose. The per-address limit slows this down and the audit log shows
  it, but there is no automatic defence.
- **Admin actions do not ask for the password again.** A signed-in admin session that is left
  unattended can manage users until it times out. Changing one's own password or second
  factor does ask.
- **The key file matters.** If `dashboard-secret.key` is lost, passwords still work but every
  user has to set up two-factor again (an admin or the command line resets it). If someone
  copies both the database and the key file, they can read the authenticator secrets. Back
  the file up with the database and protect both the same way.
- **The audit log resists careless tampering, not a determined one.** The check catches an
  entry that was edited or removed while the entries after it were left alone. Someone with
  write access to the database file and the skill to recompute every later fingerprint, or
  who only cuts off the newest entries, would pass the check. Closing that needs copies of
  the log kept somewhere else, which is not built yet.
- **The audit log is not pruned or exported.** It grows, and there is no download.
- **Passwords are not checked against breach lists**, only against a built-in list of common
  ones.
- **No certificate helper for the dashboard.** HTTPS needs a certificate you bring, or a
  proxy.
- **Reviewer actions.** There is one so far: labelling a session (the "Reviewer label" card,
  see `docs/oracle.md`). It needs the reviewer role, is recorded under the signed-in
  account's name and is written to the audit log. A read-only account sees labels and the
  Oracle's results and cannot change them.
