DELETE
FROM public.hydra_oauth2_authentication_session
WHERE authenticated_at < NOW() AT TIME ZONE 'UTC' - INTERVAL '1 DAY';

DELETE
FROM public.hydra_oauth2_code
WHERE requested_at < NOW() AT TIME ZONE 'UTC' - INTERVAL '1 DAY';

DELETE
FROM public.hydra_oauth2_oidc
WHERE requested_at < NOW() AT TIME ZONE 'UTC' - INTERVAL '1 DAY';

DELETE
FROM public.hydra_oauth2_pkce
WHERE requested_at < NOW() AT TIME ZONE 'UTC' - INTERVAL '1 DAY';

DELETE
FROM public.hydra_oauth2_flow
WHERE requested_at < NOW() AT TIME ZONE 'UTC' - INTERVAL '1 DAY';

-- hydra_oauth2_access is cleaned by flush/janitor tools

-- hydra_oauth2_jti_blacklist, hydra_oauth2_obfuscated_authentication_session, hydra_oauth2_refresh, hydra_oauth2_trusted_jwt_bearer_issuer
-- are empty in our use cases

DELETE
FROM public.hydra_oauth2_logout_request
WHERE sid NOT IN (SELECT id FROM public.hydra_oauth2_authentication_session);

-- hydra_client, hydra_jwk, schema_migration must NOT be cleaned
