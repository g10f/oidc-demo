"""
Imports the identity providers, clients and API clients of oidc-demo 2.x into the data model of 3.x.

The old database is read in one of two ways (see the README, "Upgrade from 2.x"):
- --from-database: the URL of the old database comes through stdin, the command runs legacy_export.sql (next to this
  file) itself. migrate-legacy-config.sh uses it with kubectl exec, so no export file is written anywhere.
- an export file: the JSON written by psql with legacy_export.sql.

How the old fields are taken over:
- Identity providers without issuer are skipped with their clients: they were plain OAuth2 providers (Facebook,
  GitHub, ...) or were set up before discovery. An OpenID provider among them is added again with the discovery button.
- uri → home_uri, is_secure → verify_tls, is_supporting_http_auth_header → not userinfo_token_in_query.
  revoke_uri is dropped, 3.x doesn't revoke tokens.
- Client type web → authorization code flow, javascript → implicit flow (id_token token, as 2.x requested it).
  native (oob redirect) and service/trusted (client credentials/password grant) are skipped, 3.x has no such flows.
- default_scopes → scope (empty: the default of 3.x), kc_idp_hint → extra_authorization_params, max_age → seconds.
- The redirect URI of 2.x (/oauth2/login/) is dropped, 3.x always uses /oidc/callback/: register it at each
  identity provider, otherwise the login there fails with an invalid redirect_uri.
- PKCE is always used, as RFC 9700 requires (use_pkce is not taken over). A provider that rejects the
  code_challenge parameter fails visibly at the login; then set "disable PKCE" in the admin.
- staff_roles and superuser_roles stay empty: 2.x gave staff status for the groups of SSO.STAFF_GROUPS of every
  provider, 3.x only for roles set per client. Set them in the admin where you trust the provider.
- API clients keep their client_id; "require typ at+jwt" is off, because 2.x didn't check it and the g10f SSO
  doesn't set it.
"""
import json
import sys
from pathlib import Path

import psycopg

from django.core.exceptions import ValidationError
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from relying_party.models import ApiClient, Client, IdentityProvider

FLOW_BY_LEGACY_TYPE = {
    'web': Client.FLOW_CODE,
    'javascript': Client.FLOW_IMPLICIT,
}
EXPORT_SQL = Path(__file__).with_name('legacy_export.sql')

REASON_BY_SKIPPED_TYPE = {
    'native': 'native clients used the oob redirect URI, which is gone',
    'service': 'the client credentials grant is not part of the demo',
    'trusted': 'the password grant is not part of the demo',
}


class Command(BaseCommand):
    help = ('Imports the identity providers and clients of oidc-demo 2.x, from the JSON written by legacy_export.sql '
            'or with --from-database directly from the 2.x database.')

    def add_arguments(self, parser):
        parser.add_argument('export_file', nargs='?', help='JSON file written by legacy_export.sql')
        parser.add_argument('--from-database', action='store_true',
                            help='Reads the URL of the 2.x database from stdin and exports it with legacy_export.sql '
                                 'directly, instead of reading an export file.')
        parser.add_argument('--dry-run', action='store_true',
                            help='Shows what would be imported and rolls the import back.')

    def handle(self, *args, **options):
        if options['from_database'] and options['export_file']:
            raise CommandError('Give either an export file or --from-database, not both.')
        if options['from_database']:
            data = self.read_database()
        elif options['export_file']:
            data = self.read_export(options['export_file'])
        else:
            raise CommandError('Give the export file written by legacy_export.sql, or --from-database.')

        # The import maps the old ids to new rows. Mixing it with existing rows (e.g. the fixture initial_data,
        # which the entrypoint loads with DJANGO_LOAD_INITIAL_DATA=on) would create duplicates or fail on the
        # unique issuer, so it only runs on an empty configuration.
        if IdentityProvider.objects.exists():
            raise CommandError(
                'The database already contains identity providers (maybe from the fixture initial_data). The import '
                'only runs on an empty configuration: delete the identity providers in the admin first.')

        with transaction.atomic():
            try:
                self.import_data(data)
            except KeyError as e:
                # The export of an older 2.x schema or a hand edited file can lack a column. The rows imported so
                # far are rolled back with the CommandError; the output above shows the last row that was read.
                raise CommandError(
                    f'A row after the last one shown above lacks the field {e}. Was the file written by the current '
                    f'legacy_export.sql?')
            if options['dry_run']:
                transaction.set_rollback(True)
                self.stdout.write(self.style.WARNING('Dry run: nothing was saved.'))
            else:
                self.stdout.write(self.style.SUCCESS('Import saved.'))

    def read_export(self, path):
        try:
            with open(path, encoding='utf-8') as f:
                data = json.load(f)
        except (OSError, ValueError) as e:
            raise CommandError(f'The export file {path} could not be read: {e}')
        self.check_export(data, f'The export file {path}')
        return data

    def read_database(self):
        # The URL contains the password of the old database. It comes through stdin and not as an argument or
        # environment variable, so it shows up neither in the process list nor in the Kubernetes API.
        database_url = sys.stdin.readline().strip()
        if not database_url:
            raise CommandError('--from-database expects the URL of the 2.x database on stdin, but stdin was empty.')
        # libpq repeats the part of a URL it can't parse in its error message, which can be the password. So the URL
        # is parsed first and that error is not shown.
        try:
            psycopg.conninfo.conninfo_to_dict(database_url)
        except psycopg.ProgrammingError:
            raise CommandError('The URL of the 2.x database on stdin could not be parsed (the error is not shown, it '
                               'could contain the password). It must start with postgres:// or postgresql://, and '
                               'special characters in the password must be percent-encoded.') from None
        try:
            # Without a timeout an unreachable database (wrong host, a network policy that drops the packets)
            # would keep the command waiting for minutes without any message.
            with psycopg.connect(database_url, connect_timeout=10) as connection:
                # The old database is only read; read_only makes sure of it.
                connection.read_only = True
                data = connection.execute(EXPORT_SQL.read_text(encoding='utf-8')).fetchone()[0]
        except psycopg.Error as e:
            # The message of psycopg names host, port and user, but not the password.
            raise CommandError(f'The 2.x database could not be read: {e}')
        self.check_export(data, 'The 2.x database')
        return data

    def check_export(self, data, source):
        for key in ('identity_providers', 'clients', 'api_clients'):
            if not isinstance(data.get(key), list):
                raise CommandError(f'{source} has no list "{key}", it was not written by legacy_export.sql.')

    def import_data(self, data):
        identity_providers = {}  # old id → new IdentityProvider
        for row in data['identity_providers']:
            identity_provider = self.import_identity_provider(row)
            if identity_provider is not None:
                identity_providers[row['id']] = identity_provider

        for row in data['clients']:
            identity_provider = identity_providers.get(row['identity_provider_id'])
            if identity_provider is None:
                self.skip(f'client {row["id"]} ({row["name"] or row["type"]})', 'its identity provider was skipped')
                continue
            self.import_client(row, identity_provider)

        for row in data['api_clients']:
            identity_provider = identity_providers.get(row['identity_provider_id'])
            if identity_provider is None:
                self.skip(f'API client {row["client_id"]}', 'its identity provider was skipped')
                continue
            api_client = ApiClient(
                identity_provider=identity_provider,
                client_id=row['client_id'],
                is_active=row['is_active'],
                require_jwt_access_token_type=False,
            )
            self.save(api_client, f'API client {row["client_id"]}')
            self.stdout.write(f'API client {row["client_id"]} of {identity_provider}: imported')

    def import_identity_provider(self, row):
        label = f'identity provider {row["id"]} ({row["name"]})'
        if not row['issuer']:
            self.skip(label, 'it has no issuer, so it is no OpenID provider for 3.x')
            return None

        identity_provider = IdentityProvider(
            name=row['name'],
            issuer=row['issuer'],
            is_active=row['is_active'],
            order=row['order'],
            authorization_endpoint=row['authorization_endpoint'],
            token_endpoint=row['token_endpoint'],
            userinfo_endpoint=row['userinfo_endpoint'],
            jwks_uri=row['jwks_uri'],
            home_uri=row['uri'],
            end_session_endpoint=row['end_session_endpoint'],
            check_session_iframe=row['check_session_iframe'],
            profile_uri=row['profile_uri'],
            picture_endpoint=row['picture_endpoint'],
            user_navigation_uri=row['user_navigation_uri'],
            verify_tls=row['is_secure'],
            userinfo_token_in_query=not row['is_supporting_http_auth_header'],
            check_roles=row['check_roles'],
            extend_access_uri=row['extend_access_uri'],
        )
        self.save(identity_provider, label)
        notes = []
        if row['revoke_uri']:
            notes.append(f'revoke_uri {row["revoke_uri"]} dropped')
        self.stdout.write(f'{label}: imported' + ''.join(f'; {note}' for note in notes))
        return identity_provider

    def import_client(self, row, identity_provider):
        label = f'client {row["id"]} ({row["name"] or row["type"]}) of {identity_provider}'
        legacy_type = row['type']
        if legacy_type in REASON_BY_SKIPPED_TYPE:
            self.skip(label, REASON_BY_SKIPPED_TYPE[legacy_type])
            return
        if legacy_type not in FLOW_BY_LEGACY_TYPE:
            raise CommandError(f'The {label} has the unknown type "{legacy_type}".')

        extra_authorization_params = {}
        if row['kc_idp_hint']:
            extra_authorization_params['kc_idp_hint'] = row['kc_idp_hint']

        client = Client(
            identity_provider=identity_provider,
            name=row['name'],
            is_active=row['is_active'],
            flow=FLOW_BY_LEGACY_TYPE[legacy_type],
            client_id=row['client_id'],
            client_secret=row['client_secret'],
            token_endpoint_auth_method=Client.AUTH_BASIC,  # 2.x sent the secret with HTTP Basic
            # 2.x left the scope out when it was empty, 3.x always sends one.
            scope=row['default_scopes'] or Client._meta.get_field('scope').default,
            prompt=row['prompt'],
            # 2.x left max_age out when it was 0 (an empty timedelta is false), 3.x would send max_age=0.
            max_age=row['max_age_seconds'] or None,
            acr_values=row['acr_values'],
            ui_locales=row['ui_locales'],
            claims_locales=row['claims_locales'],
            claims=row['claims'],
            extra_authorization_params=json.dumps(extra_authorization_params) if extra_authorization_params else '',
            roles_claim=row['roles_claim'],
        )
        self.save(client, label)

        notes = [f'flow {client.get_flow_display()}']
        if row['response_type'] and row['response_type'] != 'code':
            notes.append(f'response_type "{row["response_type"]}" of 2.x not taken over')
        if not row['default_scopes']:
            notes.append(f'no scope in 2.x, set to "{client.scope}"')
        self.stdout.write(f'{label}: imported; ' + '; '.join(notes))

    def save(self, obj, label):
        # full_clean() checks the old values against the validators of 3.x (URLs, JSON, lengths). A row that
        # doesn't fit stops the whole import, so nothing is half imported; fix the row in the export file.
        try:
            obj.full_clean()
        except ValidationError as e:
            raise CommandError(f'The {label} does not fit the data model of 3.x: {e.message_dict}')
        obj.save()

    def skip(self, label, reason):
        self.stdout.write(self.style.WARNING(f'{label}: skipped, {reason}'))
