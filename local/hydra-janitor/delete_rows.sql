DELETE
FROM public.hydra_oauth2_authentication_session
WHERE id IN (SELECT login_session_id FROM public.hydra_oauth2_authentication_request WHERE requested_at < NOW() AT TIME ZONE 'UTC' - INTERVAL '1 DAY');

DELETE
FROM public.hydra_oauth2_authentication_session
WHERE id IN (SELECT login_session_id FROM public.hydra_oauth2_consent_request WHERE requested_at < NOW() AT TIME ZONE 'UTC' - INTERVAL '1 DAY');

DELETE
FROM public.hydra_oauth2_authentication_request
WHERE requested_at < NOW() AT TIME ZONE 'UTC' - INTERVAL '1 DAY';

-- hydra_oauth2_authentication_request_handled is handled by FOREIGN KEY + NOT NULL + ON DELETE CASCADE

DELETE
FROM public.hydra_oauth2_consent_request
WHERE requested_at < NOW() AT TIME ZONE 'UTC' - INTERVAL '1 DAY';

-- hydra_oauth2_consent_request_handled is handled by FOREIGN KEY + NOT NULL + ON DELETE CASCADE

DELETE
FROM public.hydra_oauth2_code
WHERE requested_at < NOW() AT TIME ZONE 'UTC' - INTERVAL '1 DAY';

DELETE
FROM public.hydra_oauth2_oidc
WHERE requested_at < NOW() AT TIME ZONE 'UTC' - INTERVAL '1 DAY';

DELETE
FROM public.hydra_oauth2_pkce
WHERE requested_at < NOW() AT TIME ZONE 'UTC' - INTERVAL '1 DAY';

-- hydra_oauth2_access is cleaned by flush/janitor tools

-- hydra_oauth2_jti_blacklist, hydra_oauth2_obfuscated_authentication_session, hydra_oauth2_refresh, hydra_oauth2_trusted_jwt_bearer_issuer
-- are empty in our use cases

DELETE FROM public.hydra_oauth2_authentication_session WHERE id NOT IN (
    SELECT auth.login_session_id
    FROM public.hydra_oauth2_authentication_request AS auth
    WHERE auth.login_session_id IS NOT NULL
    UNION SELECT consent.login_session_id
    FROM public.hydra_oauth2_consent_request AS consent
    WHERE consent.login_session_id IS NOT NULL
);

DELETE
FROM public.hydra_oauth2_logout_request
WHERE sid NOT IN (SELECT id FROM public.hydra_oauth2_authentication_session);

-- hydra_client, hydra_jwk, schema_migration must NOT be cleaned
