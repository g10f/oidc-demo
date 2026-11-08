OpenID Connect demo client
==========================
Django web app that logs in at an OpenID Connect identity provider with the authorization code flow
and shows the ID token, the access token and the user info of the logged in user.

Identity providers and clients are configured in the Django admin (`/admin/`). The fixture
`initial_data` contains an example configuration.

Pages
-----

| URL                        | Description                                         |
|----------------------------|-----------------------------------------------------|
| `/`                        | start page                                          |
| `/oauth2/login/`           | starts the login at the identity provider           |
| `/oauth2/logout/`          | logout, also at the identity provider               |
| `/oauth2/userinfo/me/`     | user info of the logged in user                     |
| `/oauth2/tokeninfo/me/`    | token info of the access token                      |
| `/oauth2/userinfo/client/` | user info loaded in the browser with JavaScript (implicit client profile) |
| `/oauth2/session/`         | session data                                        |
| `/api/v1/test/`            | page for testing an API with the access token       |
| `/admin/`                  | Django admin                                        |

Configuration
-------------
Environment variables:

| Variable                                  | Default                                          | Description                                  |
|-------------------------------------------|--------------------------------------------------|----------------------------------------------|
| `DATABASE_URL`                            | `postgres://client:client@localhost:5432/client` | PostgreSQL database                          |
| `SECRET_KEY`                              | none, required except for `runserver` and `test` | Django secret key, signs the session cookies, the app does not start without it |
| `ALLOWED_HOSTS`                           | `oidc-demo.g10f.de`                              | comma separated list, localhost is always allowed |
| `OPENID_SSO_SERVER_BASE_URL`              | `https://sso.g10f.de/`                           | base URL of the identity provider            |
| `ALWAYS_REFRESH_TOKENS`                   | `False`                                          | refresh the tokens on every request          |
| `SSO.STAFF_GROUPS`                        | `Staff,Superuser`                                | groups that get staff status                 |
| `SSO.SUPERUSER_GROUP`                     | `Superuser`                                      | group that gets superuser status             |
| `ABOUT_URL`                               | `https://g10f.de/`                               | target of the about link                     |
| `ENABLE_PLAUSIBLE`, `DOMAIN`              | `False`, `localhost:8000`                        | Plausible analytics                          |
| `EMAIL_HOST`, `EMAIL_PORT`                | `localhost`, `25`                                | mail server for error mails                  |
| `DEFAULT_FROM_EMAIL`, `SERVER_EMAIL`      | `webmaster@g10f.de`                              | sender of mails                              |
| `ROOT_LOG_LEVEL`, `DJANGO_LOG_LEVEL`, `REQUESTS_LOG_LEVEL` | `INFO`                          | log levels                                   |
| `STATIC_ROOT`, `MEDIA_ROOT`               | `htdocs/static`, `htdocs/media`                  | directories for static and uploaded files    |

The entrypoint of the image evaluates:

| Variable                   | Description                                                        |
|----------------------------|--------------------------------------------------------------------|
| `DJANGO_MIGRATE=on`        | runs `manage.py migrate` on start                                  |
| `DJANGO_CREATE_SUPERUSER=on` | creates a superuser (`DJANGO_SUPERUSER_USERNAME`, `DJANGO_SUPERUSER_PASSWORD`) if there are no users |
| `DJANGO_LOAD_INITIAL_DATA=on` | loads the fixture `initial_data` if there are no users          |

`DEBUG` is on only with `manage.py runserver`. With every other command the session cookie is marked as
secure, so the login needs https there.

Security
--------
As a template this client follows RFC 9700 and OpenID Connect Core:

- The `state` is bound to the browser session, can be used once and expires after 10 minutes. A login that
  was started in one browser can't be finished in another one.
- The `nonce` of the ID token is checked. The identity provider must repeat it, otherwise the login is rejected.
- ID tokens and API access tokens are verified with the keys from the `jwks_uri` of the identity provider.
  Without a `jwks_uri` the signature of an ID token is not checked, it only comes directly over TLS.
- PKCE is used for clients with `use_pkce`.
- Unsetting `is_secure` of an identity provider turns off the TLS verification of all requests to it, also
  for its signing keys. That is only meant for development.

Not implemented: the `iss` of the ID token is not compared with the identity provider, and the JavaScript page
`/oauth2/userinfo/client/` doesn't check the `nonce`.

Development
-----------
A PostgreSQL database with user, password and database `client` on localhost is required.

    python3 -m venv .venv
    .venv/bin/pip install -r requirements/dev.txt
    export SECRET_KEY=$(openssl rand -hex 32)
    cd apps
    ../.venv/bin/python manage.py migrate
    ../.venv/bin/python manage.py loaddata initial_data
    ../.venv/bin/python manage.py runserver

The Python packages are pinned in `requirements/base.txt` (installed in the Docker image) and `requirements/dev.txt`
(the same versions plus pip-tools), generated from `base.in` and `dev.in`. After changing a `.in` file, run from the
repo root (psycopg-c is compiled, so `libpq-dev` is needed for the local install):

    pip-compile requirements/base.in
    pip-compile requirements/dev.in

Or with docker compose (uses the database on the host, see the note on https above):

    SECRET_KEY=$(openssl rand -hex 32) docker compose up --build

The CSS is built from `apps/static/scss` with Sass. The build also copies Bootstrap, jQuery and the
Bootstrap icons from `node_modules` to `apps/static`. The results are committed.

    npm install
    npm run build

Release
-------
A release is a git tag `X.Y.Z`. It is created with `git release` (a small release script):

    git release patch        # or minor, major, X.Y.Z

It writes the new version to `apps/client/__init__.py`, commits it as `release X.Y.Z`,
creates the tag and pushes both. The CI checks that the tag matches `__version__`.

The CI builds the image `ghcr.io/g10f/oidc-demo:X.Y.Z` (and `latest`) natively for amd64
and arm64 and starts the deploy: if the secret `DEPLOY_WORKFLOW` (`owner/repo/workflow-file`) is set, it starts that
workflow with the inputs `image` and `version`, using the secret `DEPLOY_TOKEN`. Without it, e.g. in a fork,
nothing is deployed. A push without a tag does not start the CI.
