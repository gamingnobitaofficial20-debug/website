# Northstar Market

Northstar is a customer storefront with a separate server-protected admin application.

## Run locally

```bash
npm install
ADMIN_EMAIL=admin@example.test ADMIN_PASSWORD='use-a-local-password-at-least-12-characters' npm start
```

Open `http://localhost:4173/admin/login`. The first launch creates the admin account from the environment variables and stores only a salted `scrypt` password hash in SQLite.

## Admin security model

- `/admin/dashboard` and every `/api/admin/*` endpoint are checked server-side against a short-lived, hashed session token.
- The session is held in an `httpOnly`, `SameSite=Lax` cookie. The CSRF token is kept in session storage only and must be sent on mutations.
- Passwords are never stored or returned in plaintext. Login attempts are rate-limited and errors are intentionally generic.
- Product, order, settings, logout, and password mutations require both authentication, CSRF validation, and role authorization.
- Helmet headers, SQLite foreign keys, parameterized SQL, input length limits, audit logs, and confirmation dialogs are enabled.
- Set `NODE_ENV=production` behind HTTPS. This enables the `Secure` session cookie. Use a process manager and a managed database/storage layer before deploying at scale; the included SQLite setup is a single-instance starting point.

The admin UI intentionally does not contain credentials, API keys, payment secrets, or database credentials. Payment, email, file storage, and 2FA integrations should be connected server-side through environment-backed providers before enabling those features in production.