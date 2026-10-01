# SSO Client Bundle

Sign in to a Symfony app through [the SSO](https://github.com/jiorpilla/sso) (or any OpenID Connect provider).

- Authorization Code flow with **PKCE (S256)**, `state` and `nonce`, always
- ID and access tokens (RS256 JWTs) **verified locally** against the SSO's cached public keys (JWKS); a rotated key is picked up automatically
- Access tokens **refreshed automatically**; refresh tokens rotated on every use
- Logout from the app, and from the SSO too when it supports it
- **Back-channel logout**: the SSO can end a user's session in this app
- Optional **bearer-token authentication** for APIs
- Users kept only in the session, or **synced to your own users table**

Requires PHP 8.4+ and Symfony 8.1+.

## Install

### 1. Require the package

Until it's on Packagist, add the repository to your app's `composer.json`:

```json
"repositories": [
    {"type": "vcs", "url": "https://github.com/jiorpilla/sso-client-bundle"}
]
```

```bash
composer require jiorpilla/sso-client-bundle
```

If Flex doesn't register it, add it to `config/bundles.php`:

```php
Jiorpilla\SsoClientBundle\SsoClientBundle::class => ['all' => true],
```

### 2. Register the app on the SSO

On the SSO server:

```bash
php bin/console app:client:create "My App" --redirect-uri=https://myapp.example/sso/callback
```

It prints a client ID and a secret (shown once). Use `--public` instead for apps that can't keep a secret; PKCE protects them.

### 3. Set three environment variables

In `.env.local` (never commit the secret):

```dotenv
SSO_ISSUER=https://sso.janivanorpilla.com
SSO_CLIENT_ID=the-client-id
SSO_CLIENT_SECRET=the-client-secret
```

Locally: `SSO_ISSUER=https://sso-local.janivanorpilla.com`.

### 4. Import the routes

`config/routes/sso_client.yaml`:

```yaml
sso_client:
    resource: '@SsoClientBundle/config/routes.php'
```

This adds:

| Route | Path | Purpose |
|---|---|---|
| `sso_client_login` | `GET /sso/login` | Starts the login. Optional `?target=/some/page` and `?prompt=login` |
| `sso_client_callback` | `GET /sso/callback` | The SSO sends users back here (register this exact URL on the SSO) |
| `sso_client_logout` | `GET/POST /sso/logout` | Logs out (handled by the firewall) |
| `sso_client_backchannel_logout` | `POST /sso/backchannel-logout` | Called by the SSO server-to-server |

### 5. Configure security

`config/packages/security.yaml`:

```yaml
security:
    providers:
        sso:
            id: sso_client.user_provider

    firewalls:
        dev:
            pattern: ^/(_profiler|_wdt|assets|build)/
            security: false
        main:
            lazy: true
            provider: sso
            custom_authenticators: [sso_client.authenticator]
            entry_point: sso_client.authenticator
            logout:
                path: sso_client_logout

    access_control:
        - { path: ^/sso/, roles: PUBLIC_ACCESS }
        - { path: ^/, roles: ROLE_USER }
```

Done. Visiting any protected page now sends users to the SSO and back.

In templates:

```twig
<a href="{{ path('sso_client_login') }}">Sign in</a>
<a href="{{ path('sso_client_logout') }}">Sign out</a>
{{ app.user.name }} {# with the default session-only user #}
```

## Configuration

All options, with defaults (`config/packages/sso_client.yaml`, optional):

```yaml
sso_client:
    issuer: '%env(SSO_ISSUER)%'
    client_id: '%env(SSO_CLIENT_ID)%'
    client_secret: '%env(default::SSO_CLIENT_SECRET)%'   # empty = public client
    scopes: [openid, profile, email, roles]
    firewall: main                    # firewall using sso_client.authenticator
    default_target_path: /            # after login, when no page was requested first
    failure_path: null                # redirect here on login failure; null = plain error page
    post_logout_redirect_route: null  # after SSO logout; null = home page. Register it on the SSO client.
    user_provider: sso_client.session_user_provider
    api_audiences: []                 # accepted "aud" for bearer tokens; empty = client_id
    leeway: 30                        # seconds of clock drift tolerated
    http_client: http_client
    cache: cache.app                  # discovery, keys, back-channel logouts; share it across servers
    cache_ttl: 3600
    backchannel_logout: true
```

## Users

### Session-only users (default)

With no users table, the user is built from the SSO claims and lives in the session: `Jiorpilla\SsoClientBundle\Security\SsoUser`, with `getUserIdentifier()` (the SSO user ID), `getEmail()`, `getName()` and `getRoles()`. Roles come from the SSO's `roles` claim, plus `ROLE_USER`.

### Syncing to your own users table

Implement `SsoUserProviderInterface`. Key users by `sub`, which never changes; emails can.

```php
use Jiorpilla\SsoClientBundle\Model\SsoClaims;
use Jiorpilla\SsoClientBundle\Security\SsoUserProviderInterface;

final class AppUserProvider implements SsoUserProviderInterface
{
    public function __construct(private UserRepository $users, private EntityManagerInterface $em) {}

    public function loadOrCreateUser(SsoClaims $claims): UserInterface
    {
        $user = $this->users->findOneBy(['ssoId' => $claims->sub]) ?? new User($claims->sub);
        $user->setEmail($claims->email);
        $user->setName($claims->name);
        $user->setRoles($claims->roles);
        $this->em->persist($user);
        $this->em->flush();

        return $user;
    }
}
```

```yaml
sso_client:
    user_provider: App\Security\AppUserProvider

security:
    providers:
        app_users:
            entity: { class: App\Entity\User, property: ssoId }
    firewalls:
        main:
            provider: app_users
            # ...rest as above
```

### Reacting to logins

```php
#[AsEventListener]
final class OnSsoLogin
{
    public function __invoke(SsoLoginEvent $event): void
    {
        // $event->user, $event->claims (sub, email, name, roles, scopes, all), $event->tokens
    }
}
```

## Calling APIs as the user

`SsoTokenStorage::getAccessToken()` returns a valid access token, refreshing it first if it's about to expire:

```php
public function __construct(private SsoTokenStorage $sso, private HttpClientInterface $http) {}

$this->http->request('GET', 'https://api.example/orders', ['auth_bearer' => $this->sso->getAccessToken()]);
```

If the refresh fails (the user signed out of the SSO, or was disabled), the user is signed out of this app and sent through the login again.

## Protecting an API with bearer tokens

For an app that is an API, verify `Authorization: Bearer <access token>` locally:

```yaml
security:
    firewalls:
        api:
            pattern: ^/api/
            stateless: true
            provider: sso
            custom_authenticators: [sso_client.bearer_authenticator]
```

By default the token's audience must be this app's client ID. To accept tokens issued to other clients (e.g. a front end calling this API), list them in `sso_client.api_audiences`.

The verified claims (including `scopes`) are on the security token: `$security->getToken()->getAttribute('sso_claims')`.

Note: the SSO's access tokens carry `sub`, `scopes` and `client_id`, but not `email`, `name` or `roles`. For roles in an API, look the user up by `sub` in your `SsoUserProviderInterface`.

## Logout

`/sso/logout` signs the user out of this app. If the SSO advertises an `end_session_endpoint`, the user is then sent there (with `id_token_hint`), signing them out of the SSO and its other apps too, and comes back to `post_logout_redirect_route` (register that URL on the SSO).

### Back-channel logout

When the SSO supports it, it calls `POST /sso/backchannel-logout` with a signed logout token when a user signs out elsewhere. The bundle verifies it and ends that user's session in this app on their next request. Requirements:

- The route must be reachable without login (covered by `^/sso/` → `PUBLIC_ACCESS` above) and has no CSRF protection (it's server-to-server and the token is signed).
- `sso_client.cache` must be shared by all servers running the app (e.g. Redis), since the request may hit a different server than the user.
- Register `https://myapp.example/sso/backchannel-logout` as the back-channel logout URI on the SSO.

Listen to `SsoBackchannelLogoutEvent` to do more (e.g. revoke API tokens).

## Security notes

- Only RS256 is accepted; `alg: none` and HS256/RS256 confusion are rejected.
- `iss`, `aud`, `exp` (and `nonce` for ID tokens) are always checked, with `leeway` seconds of tolerance.
- `state` values are single-use, expire after 10 minutes, and are compared in constant time. Several tabs can log in at once.
- The `target` login parameter only accepts paths on this app, so it can't be used as an open redirect.
- A token signed with an unknown key ID triggers at most one key download per minute, so forged tokens can't hammer the SSO.

## Development

```bash
composer install
vendor/bin/phpunit
vendor/bin/phpstan analyse
vendor/bin/php-cs-fixer fix --dry-run --diff
```

Not using Symfony? See [docs/non-symfony.md](docs/non-symfony.md).

## Troubleshooting

| Problem | Cause / fix |
|---|---|
| A new SSO feature (e.g. logout) isn't used | The discovery document is cached for `cache_ttl` (1 hour). `cache:clear` does **not** empty it: run `php bin/console cache:pool:clear cache.app` (or your `sso_client.cache` pool). |
| "Invalid issuer" | `SSO_ISSUER` must match the SSO's `issuer` exactly, including no trailing slash. |
| `redirect_uri` error page on the SSO | The callback URL (scheme, host, port, path) must be registered on the SSO client exactly. |
| Tokens rejected right after login | Server clocks differ by more than `leeway` (30s). Sync the clock (NTP). |
| TLS errors locally | The app container must trust the SSO's local CA (see `demo/`). |
