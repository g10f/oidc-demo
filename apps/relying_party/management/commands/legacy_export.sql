-- Export of the configuration of oidc-demo 2.x (oauth-python-sample) as one JSON document, the input of
-- `manage.py import_legacy_config`. Only the identity providers, clients and API clients are exported: users and
-- tokens are not migrated, users are created again at their next login.
-- Usage (the output contains the client secrets, keep the file private):
--   (umask 077; psql "$OLD_DATABASE_URL" --no-align --tuples-only --file legacy_export.sql > legacy.json)
-- max_age is an interval in 2.x, it is exported as seconds so the import doesn't have to parse PostgreSQL intervals.
select json_build_object(
    'identity_providers', (
        select coalesce(json_agg(row_to_json(idp) order by idp.id), '[]')
        from oauth2_identityprovider idp
    ),
    'clients', (
        select coalesce(json_agg(row_to_json(c) order by c.id), '[]')
        from (
            select client.*, extract(epoch from client.max_age)::integer as max_age_seconds
            from oauth2_client client
        ) c
    ),
    'api_clients', (
        select coalesce(json_agg(row_to_json(api) order by api.id), '[]')
        from oauth2_apiclient api
    )
);
