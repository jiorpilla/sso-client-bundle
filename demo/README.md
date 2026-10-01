# Demo app

A minimal Symfony app that signs in through the local SSO with this bundle (installed from `..` as a
path repository). Used to test the whole flow end to end.

Requires the SSO stack running (`cd ~/dev/sso && make up`): the demo joins its Docker network, reaches
it at `https://sso.local`, and reuses its local certificates (which already cover `app1.local`).

```bash
# 1. Hosts entry (once)
echo "127.0.0.1 app1.local" | sudo tee -a /etc/hosts

# 2. Register the demo on the SSO (once); note the client_id and secret it prints
cd ~/dev/sso
docker compose exec php php bin/console app:client:create "Demo App 1" --redirect-uri=https://app1.local:8443/sso/callback

# 3. demo/.env.local (gitignored)
DEFAULT_URI=https://app1.local:8443
SSO_ISSUER=https://sso.local
SSO_CLIENT_ID=...
SSO_CLIENT_SECRET=...

# 4. Start it
cd ~/dev/sso-client-bundle/demo
docker compose run --rm app1-php composer install
docker compose up -d
```

Open https://app1.local:8443: you're sent to the SSO, and back to the demo signed in.
