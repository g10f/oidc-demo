OpenID Connect demo
===================
Django web app that acts as OpenID Connect relying party. It logs in at an identity provider and shows what comes
back and how it is checked: ID token, access token, refresh, user info and the result of every check of the specs.

The protocol is in `apps/relying_party/protocol.py`, one function per step with the section of the spec. It is
written on PyJWT and requests on purpose, without an OIDC library, so the steps can be read.

Identity providers and clients are configured in the Django admin (`/admin/`). The fixture `initial_data`
contains the configuration for sso.g10f.de.

Layout
------
| Path                                | Content                                                         |
|-------------------------------------|-----------------------------------------------------------------|
| `apps/the_site/`                    | settings, urls, wsgi, Jinja2 environment                        |
| `apps/relying_party/models.py`      | identity providers, clients, API clients, user                  |
| `apps/relying_party/protocol.py`    | the protocol steps, the only place that reads the protocol options |
| `apps/relying_party/discovery.py`   | discovery document and signing keys (JWKS)                      |
| `apps/relying_party/browser_session.py` | what is kept in the session: started logins, tokens          |
| `apps/relying_party/users.py`       | claims → local user, roles → staff/superuser                    |
| `apps/relying_party/api.py`         | the demo as API (resource server) with JWT access tokens        |
| `apps/relying_party/views.py`       | the pages                                                       |
| `apps/relying_party/middleware.py`  | end of the session after `session_max_age`                      |
| `apps/relying_party/admin.py`       | admin, with the discovery button and the URIs to register       |
| `apps/templates/`                   | Jinja2 templates of the pages (the admin uses Django templates) |

Pages
-----
| URL                          | Description                                                            |
|------------------------------|------------------------------------------------------------------------|
| `/oidc/login/`               | authorization code flow with PKCE                                      |
| `/oidc/login/<client>/`      | starts the login with a client (code or implicit flow)                 |
| `/oidc/callback/`            | redirect URI of the code flow (`/oauth2/login/` of the versions < 3.0 also works) |
| `/oidc/device/`              | device authorization grant (RFC 8628)                                  |
| `/oidc/device/<client>/`, `/oidc/device/poll/`, `/oidc/device/cancel/` | start, poll and cancel of the device flow (POST) |
| `/oidc/implicit/`            | implicit flow (legacy), also the redirect URI of the implicit clients  |
| `/oidc/tokens/`              | tokens of the current login, the checks and the refresh                |
| `/oidc/tokens/refresh/`      | refreshes the tokens (POST)                                            |
| `/oidc/userinfo/`            | user info, with picture upload at the g10f SSO                         |
| `/oidc/userinfo/picture/`    | uploads or deletes the picture at the g10f SSO (POST)                  |
| `/oidc/profile/`             | redirect to the profile page of the identity provider                  |
| `/oidc/logout/`              | RP-initiated logout (POST)                                             |
| `/oidc/logged-out/`          | post logout redirect URI                                               |
| `/oidc/initiate/`            | login initiated by the identity provider (Core 4)                      |
| `/oidc/frontchannel-logout/` | front-channel logout URI, needs `iss` and `sid`                        |
| `/oidc/backchannel-logout/`  | back-channel logout URI                                                |
| `/oidc/session-iframe/`      | RP iframe of Session Management; a POST stops the checks for the login |
| `/api/v1/test/`              | API that accepts JWT access tokens (`Authorization: Bearer`)           |
| `/admin/`                    | Django admin, login with OpenID Connect or a local password            |

The admin page of a client lists the URIs to register at the identity provider.

What is checked
---------------
- `state` (random, kept in the session, valid once and for 10 minutes), `nonce` and PKCE with S256
- `iss` of the authentication response (RFC 9207), required if the discovery document says so
- ID token: signature with the algorithm configured at the client (never the `alg` of the token), `iss`, `aud`,
  `azp`, `exp`, `iat`, `nonce`, `at_hash`, `auth_time` against `max_age`, `acr` (only shown); after a refresh that
  `iss`, `sub`, `aud` and `auth_time` are unchanged (Core 12.2)
- user info: `sub` must be the one of the ID token, signed answers (`application/jwt`) are verified
- discovery: the `issuer` of the document must be the one the URL was built from (no redirects are followed)
- logout token: signature, `iss`, `aud`, `events`, no `nonce`, `typ` if present, each `jti` only once
- API: only the `Authorization` header, `typ` `at+jwt` (RFC 9068) unless turned off per API client

Options of older identity providers (TLS verification off, access token in the userinfo query, PKCE off, the role
check of the g10f SSO) are in the "Legacy" section of the admin. Password grant and the oob
redirect URI are gone.

Tokens are not stored in tables: they are in the session (stored in the database) and gone after the logout.
Expired sessions are not removed by Django itself, run `manage.py clearsessions` daily (cron or job).

A session ends when the browser is closed (the cookie has no expiry date) and, if the client has `session_max_age`,
at the latest that many seconds after the login. A silent login of Session Management starts that time again, as
long as the identity provider confirms the session. The end is kept in the session on the server and checked on
every request (`relying_party/middleware.py`). Django ends every session after 2 weeks (`SESSION_COOKIE_AGE`), a
longer `session_max_age` has no effect.

Session Management: if the OP iframe can't read its state (third-party cookies blocked, e.g. a demo on localhost
with the identity provider on another site), it answers "changed" right after a silent login. The checks then stop
for this login instead of reloading the page again and again.

The signing keys and the used `jti` of the logout tokens are kept in the memory of the process. The demo is meant
to run as one process (one gunicorn worker, one replica); with more, a logout token could be used once per process.

Staff and superuser status come from the roles claim (`roles_claim`, default `roles`) only for clients with
`staff_roles` or `superuser_roles`; they are set at each login. Otherwise the status set in the admin stays.

The admin of an identity provider has a button "Load from discovery document" below the issuer: it loads
`<issuer>/.well-known/openid-configuration` on the server and replaces the endpoints in the form, nothing is saved
until you save.

Features of the g10f SSO, set at the identity provider:
- `user_navigation_uri`: the navigation bar shows the applications, the profile and the picture of the user like
  the bar of the SSO, loaded on the server with the access token and kept 5 minutes in the session
- `picture_endpoint`: upload and delete the picture on the user info page, needs the scope `picture`; the size
  limit (`max_size`) comes from the SSO
- `strong_acr_values` (`2` for the SSO): a shield next to the user after a two factor login; `amr` with `mfa`
  (RFC 8176) counts for any identity provider
- `home_uri`: the name of the identity provider in the navigation bar links there

Configuration
-------------
| Variable                              | Default                                                     | Description                                   |
|---------------------------------------|-------------------------------------------------------------|-----------------------------------------------|
| `DATABASE_URL`                        | `postgres://oidc_demo:oidc_demo@localhost:5432/oidc_demo`   | PostgreSQL database                           |
| `SECRET_KEY`                          | none, required for the server (gunicorn); `manage.py` commands use a development key | Django secret key |
| `ALLOWED_HOSTS`                       | `oidc-demo.g10f.de`                                         | comma separated list, localhost is always allowed |
| `ABOUT_URL`                           | `https://g10f.de/`                                          | target of the about link                      |
| `ENABLE_PLAUSIBLE`, `DOMAIN`          | `False`, `localhost:8000`                                   | Plausible analytics                           |
| `EMAIL_HOST`, `EMAIL_PORT`            | `localhost`, `25`                                           | mail server for error mails                   |
| `DEFAULT_FROM_EMAIL`, `SERVER_EMAIL`  | `webmaster@g10f.de`                                         | sender of mails                               |
| `DJANGO_LOG_LEVEL`                    | `INFO`                                                      | log level                                     |
| `REQUESTS_LOG_LEVEL`                  | `INFO`                                                      | `DEBUG` logs every request to the identity providers, including the tokens |
| `STATIC_ROOT`                         | `htdocs/static`                                             | directory of the static files (collectstatic) |

The entrypoint of the image evaluates:

| Variable                      | Description                                                                         |
|-------------------------------|-------------------------------------------------------------------------------------|
| `DJANGO_MIGRATE=on`           | runs `manage.py migrate` on start                                                   |
| `DJANGO_CREATE_SUPERUSER=on`  | creates a superuser (`DJANGO_SUPERUSER_USERNAME`, `DJANGO_SUPERUSER_EMAIL`, `DJANGO_SUPERUSER_PASSWORD`) if there are no users |
| `DJANGO_LOAD_INITIAL_DATA=on` | loads the fixture `initial_data` if there are no users                              |

`DEBUG` is on only with `manage.py runserver`. With every other command the session cookie is marked as
secure, so the login needs https there.

Upgrade from 2.x
----------------
Version 3.0 has a new data model with a new initial migration. It needs a new, empty database: `migrate` refuses
to run on the database of 2.x (`InconsistentMigrationHistory`). Keep the old database for a rollback and take the
identity providers and clients over (users and tokens are not migrated, users are created again at their next login):

    # the export contains the client secrets: umask 077 makes the file readable only by you
    (umask 077; psql "$OLD_DATABASE_URL" --no-align --tuples-only \
        --file apps/relying_party/management/commands/legacy_export.sql > legacy.json)
    # in the new instance, without initial_data (DJANGO_LOAD_INITIAL_DATA off); --dry-run shows the result first
    ./manage.py import_legacy_config legacy.json --dry-run
    ./manage.py import_legacy_config legacy.json
    rm legacy.json

The docstring of `import_legacy_config` lists how the old fields are mapped and what is skipped (providers without
issuer, native and service clients). The redirect URI of 2.x (`/oauth2/login/`) still
works; new are the post logout redirect URI `/oidc/logged-out/` and the logout URIs, see the admin page of a client.
The environment variables `SSO.STAFF_GROUPS`, `SSO.SUPERUSER_GROUP`, `OPENID_SSO_SERVER_BASE_URL` and
`ALWAYS_REFRESH_TOKENS` are gone; staff and superuser roles are set per client.

The entrypoint stops if `SECRET_KEY` is not set, before it runs any `manage.py` command.

Development
-----------
A PostgreSQL database `oidc_demo` on localhost is required:

    sudo -u postgres createuser --createdb --pwprompt oidc_demo    # password oidc_demo
    sudo -u postgres createdb --owner oidc_demo oidc_demo

    python3 -m venv .venv
    .venv/bin/pip install -r requirements/dev.txt
    cd apps
    ../.venv/bin/python manage.py migrate
    ../.venv/bin/python manage.py loaddata initial_data
    ../.venv/bin/python manage.py createsuperuser
    ../.venv/bin/python manage.py test
    ../.venv/bin/python manage.py runserver

The Python packages are pinned in `requirements/base.txt` (installed in the Docker image) and `requirements/dev.txt`
(the same versions plus pip-tools and Babel), generated from `base.in` and `dev.in`. After changing a `.in` file, run from the
repo root (psycopg-c is compiled, so `libpq-dev` is needed for the local install):

    pip-compile requirements/base.in
    pip-compile requirements/dev.in

The pages are in English and German, chosen by the language of the browser. Django's `makemessages` can't read
the Jinja2 templates, so the texts are extracted and compiled with Babel (`babel.cfg`, installed by `dev.txt`).
After changing texts in the templates or the views, run from the repo root, translate the new entries in
`apps/locale/de/LC_MESSAGES/django.po` and commit the `.po` and the `.mo` file:

    .venv/bin/pybabel extract -F babel.cfg --no-location -o /tmp/oidc-demo.pot .
    .venv/bin/pybabel update -i /tmp/oidc-demo.pot -d apps/locale -D django
    .venv/bin/pybabel compile -d apps/locale -D django

The admin is translated by Django. The checks and error descriptions of `protocol.py` stay in English, they use the
terms of the specs.

Or with docker compose (uses the database on the host, see the note on https above):

    SECRET_KEY=$(openssl rand -hex 32) docker compose up --build

The CSS is built from `apps/static/scss` with Sass. The build also copies Bootstrap and the
Bootstrap icons from `node_modules` to `apps/static`. The results are committed.

    npm install
    npm run build

Release
-------
A release is a git tag `X.Y.Z`. It is created with `git release` (a small release script):

    git release patch        # or minor, major, X.Y.Z

It writes the new version to `apps/the_site/__init__.py`, commits it as `release X.Y.Z`,
creates the tag and pushes both. The CI checks that the tag matches `__version__`.

The CI builds the image `ghcr.io/g10f/oidc-demo:X.Y.Z` (and `latest`) natively for amd64
and arm64 and starts the deploy: if the secret `DEPLOY_WORKFLOW` (`owner/repo/workflow-file`) is set, it starts that
workflow with the inputs `image` and `version`, using the secret `DEPLOY_TOKEN`. Without it, e.g. in a fork,
nothing is deployed. A push without a tag does not start the CI.
