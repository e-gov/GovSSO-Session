-- Delete flows first to avoid unnecessary ON DELETE SET NULL updates on
-- hydra_oauth2_flow.login_session_id when sessions are removed.
-- Cascades to: hydra_oauth2_access, hydra_oauth2_code, hydra_oauth2_oidc,
-- hydra_oauth2_pkce, hydra_oauth2_refresh (all have challenge_id FK to
-- hydra_oauth2_flow.consent_challenge_id with ON DELETE CASCADE).
-- No separate DELETE statements are needed for those 5 tables because GovSSO
-- uses only the authorization code flow, where challenge_id is always populated.
DELETE
FROM public.hydra_oauth2_flow
WHERE requested_at < NOW() AT TIME ZONE 'UTC' - INTERVAL '1 DAY';

DELETE
FROM public.hydra_oauth2_authentication_session s
WHERE s.authenticated_at < NOW() AT TIME ZONE 'UTC' - INTERVAL '1 DAY'
   OR (s.authenticated_at IS NULL
  AND NOT EXISTS (SELECT 1
    FROM public.hydra_oauth2_flow f
    WHERE f.login_session_id = s.id
  AND f.requested_at >= NOW() AT TIME ZONE 'UTC' - INTERVAL '1 DAY'));

-- hydra_oauth2_jti_blacklist, hydra_oauth2_obfuscated_authentication_session, hydra_oauth2_refresh, hydra_oauth2_trusted_jwt_bearer_issuer
-- are empty in our use cases

DELETE
FROM public.hydra_oauth2_logout_request lr
WHERE NOT EXISTS (
    SELECT 1 FROM public.hydra_oauth2_authentication_session s
    WHERE s.id = lr.sid
);

-- hydra_client, hydra_jwk, schema_migration must NOT be cleaned
