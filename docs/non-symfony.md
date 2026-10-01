# Using the SSO without Symfony

The SSO is a standard OpenID Connect provider, so any certified OpenID Connect client library works: Laravel Socialite (with an OIDC provider), `jumbojett/openid-connect-php`, `league/oauth2-client` with an OIDC provider, Auth.js / NextAuth, `openid-client` (Node), Authlib (Python), and so on.

## Settings

| Setting | Value |
|---|---|
| Issuer / discovery | `https://sso.janivanorpilla.com` (locally `https://sso-local.janivanorpilla.com`). Discovery document: `{issuer}/.well-known/openid-configuration`. Let the library read every endpoint from it. |
| Flow | Authorization Code (`response_type=code`) |
| PKCE | Required, `S256` only |
| `state` | Required: random, single use, checked on return |
| `nonce` | Send one and check it in the ID token |
| Scopes | `openid` (required) plus any of `profile`, `email`, `roles` |
| Client authentication | `client_secret_basic` (confidential clients) or none (public clients, PKCE only) |
| Redirect URI | Must exactly match one registered with `app:client:create --redirect-uri=...` |
| Token signing | RS256, with `kid`. Verify against `jwks_uri`, and refetch the keys once when you see an unknown `kid`. |
| ID token claims | `sub` (stable user ID: key your users on it), `email`, `email_verified`, `name`, `roles`, `nonce`, `auth_time` |
| Access token | RS256 JWT, 10 minutes; claims `sub`, `aud` (= client ID), `scopes`, `client_id`, `jti` |
| Refresh token | Opaque, 30 days, **rotated on every use**: always store the new one |

## Checklist

- Validate `iss`, `aud` (= your client ID), `exp` and the signature on every token you accept.
- Never accept `alg: none` or HS256.
- Store tokens server-side (or in an encrypted, HttpOnly cookie), never in `localStorage`.
- Treat a failed refresh as "signed out".
